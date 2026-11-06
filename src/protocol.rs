use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const MAX_HANDSHAKE_FRAME_LEN: usize = 16 * 1024;

/// Step 1 of Handshake: Sent from `olp-proxy` to `olp-server` immediately after TLS 1.3 handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHelloChallenge {
    pub proxy_nonce: [u8; 32],
}

impl ProxyHelloChallenge {
    pub fn new() -> Self {
        let mut proxy_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut proxy_nonce);
        Self { proxy_nonce }
    }
}

impl Default for ProxyHelloChallenge {
    fn default() -> Self {
        Self::new()
    }
}

/// Step 2 of Handshake: Sent from `olp-server` to `olp-proxy` to register a tunnel with `passkey_proxy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthRegister {
    pub remote_port: u16,
    pub auth_token: [u8; 32],
}

impl ServerAuthRegister {
    pub fn new(remote_port: u16, passkey_proxy: &str, proxy_nonce: &[u8; 32]) -> Self {
        let auth_token = compute_proxy_auth_token(passkey_proxy, proxy_nonce);
        Self {
            remote_port,
            auth_token,
        }
    }
}

/// Step 3 of Handshake: Sent from `olp-proxy` to `olp-server` to confirm or reject registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEstablished {
    pub accepted: bool,
    pub message: String,
}

/// Computes a cryptographically secure token binding `passkey_proxy` to `proxy_nonce` using BLAKE3.
pub fn compute_proxy_auth_token(passkey_proxy: &str, proxy_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"olp-tunnel-auth-v2:");
    hasher.update(proxy_nonce);
    hasher.update(passkey_proxy.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Constant-time verification of `passkey_proxy` authentication token.
pub fn verify_proxy_auth_token(
    candidate_token: &[u8; 32],
    passkey_proxy: &str,
    proxy_nonce: &[u8; 32],
) -> bool {
    let expected = compute_proxy_auth_token(passkey_proxy, proxy_nonce);
    candidate_token.ct_eq(&expected).into()
}

/// Sends a length-prefixed JSON frame over an async stream.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_HANDSHAKE_FRAME_LEN {
        return Err(anyhow!("Handshake frame exceeds maximum allowed size"));
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a length-prefixed JSON frame from an async stream.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_FRAME_LEN {
        return Err(anyhow!("Invalid handshake frame length: {}", len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let parsed = serde_json::from_slice(&buf)?;
    Ok(parsed)
}

/// Configures OS-level TCP keep-alive, `TCP_NODELAY`, and Linux `TCP_USER_TIMEOUT`
/// to detect silent NAT drops quickly even if write buffers are full.
pub fn configure_tunnel_socket(stream: &TcpStream) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let sock_ref = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    #[cfg(not(target_os = "windows"))]
    let keepalive = keepalive.with_retries(3);
    let _ = sock_ref.set_tcp_keepalive(&keepalive);

    #[cfg(target_os = "linux")]
    {
        let _ = sock_ref.set_tcp_user_timeout(Some(Duration::from_secs(20)));
    }
    Ok(())
}

/// Generates an ephemeral self-signed TLS 1.3 `rustls::ServerConfig` for the tunnel control port.
pub fn create_tunnel_tls_server_config() -> Result<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["olp-tunnel.internal".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    Ok(Arc::new(server_cfg))
}

/// Builds a `rustls::ClientConfig` for `olp-server` restricted strictly to TLS 1.3.
/// End-to-end encryption is established; authentication is performed via `passkey_proxy`.
pub fn create_tunnel_tls_client_config() -> Result<Arc<rustls::ClientConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TunnelCertVerifier { provider }))
        .with_no_client_auth();

    Ok(Arc::new(client_cfg))
}

#[derive(Debug)]
struct TunnelCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for TunnelCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::ServerDoesNotSupportTls12Or13,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_auth_token_constant_time() {
        let nonce = [42u8; 32];
        let token = compute_proxy_auth_token("secret-passkey", &nonce);
        assert!(verify_proxy_auth_token(&token, "secret-passkey", &nonce));
        assert!(!verify_proxy_auth_token(&token, "wrong-passkey", &nonce));

        let diff_nonce = [43u8; 32];
        assert!(!verify_proxy_auth_token(&token, "secret-passkey", &diff_nonce));
    }
}
