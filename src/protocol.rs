use crate::keys::{sign_message, verify_signature, PasskeyVerifier};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-olp-tunnel-v1";
pub const MAX_HANDSHAKE_FRAME_LEN: usize = 16 * 1024;

/// Step 1 of Handshake: Sent from `olp-proxy` to `olp-server` immediately after TLS 1.3 handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHelloChallenge {
    pub proxy_nonce: [u8; 32],
    pub proxy_pubkey: [u8; 32],
    pub proxy_signature_b64: String,
}

/// Step 2 of Handshake: Sent from `olp-server` to `olp-proxy` after verifying `ProxyHelloChallenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthRegister {
    pub server_pubkey: [u8; 32],
    pub server_nonce: [u8; 32],
    pub remote_port: u16,
    pub passkey_verifier: PasskeyVerifier,
    pub server_signature_b64: String,
}

/// Step 3 of Handshake: Sent from `olp-proxy` to `olp-server` to confirm port binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEstablished {
    pub accepted: bool,
    pub message: String,
}

/// Builds the byte payload signed by `olp-proxy` in `ProxyHelloChallenge`.
pub fn build_proxy_challenge_transcript(
    tls_exporter: &[u8; 32],
    proxy_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(b"olp-proxy-challenge-v1:");
    buf.extend_from_slice(tls_exporter);
    buf.extend_from_slice(proxy_nonce);
    buf
}

/// Builds the byte payload signed by `olp-server` in `ServerAuthRegister`.
pub fn build_server_register_transcript(
    tls_exporter: &[u8; 32],
    proxy_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    remote_port: u16,
    verifier: &PasskeyVerifier,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(200);
    buf.extend_from_slice(b"olp-server-register-v1:");
    buf.extend_from_slice(tls_exporter);
    buf.extend_from_slice(proxy_nonce);
    buf.extend_from_slice(server_nonce);
    buf.extend_from_slice(&remote_port.to_be_bytes());
    buf.extend_from_slice(&verifier.salt);
    buf.extend_from_slice(&verifier.hash);
    buf
}

impl ProxyHelloChallenge {
    pub fn create(signing_key: &SigningKey, tls_exporter: &[u8; 32]) -> Self {
        let mut proxy_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut proxy_nonce);
        let transcript = build_proxy_challenge_transcript(tls_exporter, &proxy_nonce);
        let sig = sign_message(signing_key, &transcript);
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        Self {
            proxy_nonce,
            proxy_pubkey: signing_key.verifying_key().to_bytes(),
            proxy_signature_b64: BASE64.encode(sig),
        }
    }

    pub fn verify(
        &self,
        expected_proxy_key: &VerifyingKey,
        tls_exporter: &[u8; 32],
    ) -> Result<()> {
        if &self.proxy_pubkey != expected_proxy_key.as_bytes() {
            return Err(anyhow!(
                "MITM / Key mismatch: olp-proxy presented a public key that does not match known_proxy.pub"
            ));
        }
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        let sig_raw = BASE64
            .decode(&self.proxy_signature_b64)
            .context("Invalid base64 signature in ProxyHelloChallenge")?;
        let sig_bytes: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| anyhow!("Invalid Ed25519 signature length in ProxyHelloChallenge"))?;
        let transcript = build_proxy_challenge_transcript(tls_exporter, &self.proxy_nonce);
        if !verify_signature(expected_proxy_key, &transcript, &sig_bytes) {
            return Err(anyhow!(
                "Invalid Ed25519 signature in ProxyHelloChallenge (TLS channel binding failed)"
            ));
        }
        Ok(())
    }
}

impl ServerAuthRegister {
    pub fn create(
        signing_key: &SigningKey,
        tls_exporter: &[u8; 32],
        proxy_nonce: &[u8; 32],
        remote_port: u16,
        passkey_verifier: PasskeyVerifier,
    ) -> Self {
        let mut server_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut server_nonce);
        let transcript = build_server_register_transcript(
            tls_exporter,
            proxy_nonce,
            &server_nonce,
            remote_port,
            &passkey_verifier,
        );
        let sig = sign_message(signing_key, &transcript);
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        Self {
            server_pubkey: signing_key.verifying_key().to_bytes(),
            server_nonce,
            remote_port,
            passkey_verifier,
            server_signature_b64: BASE64.encode(sig),
        }
    }

    pub fn verify(&self, tls_exporter: &[u8; 32], proxy_nonce: &[u8; 32]) -> Result<VerifyingKey> {
        let server_key = VerifyingKey::from_bytes(&self.server_pubkey)
            .context("Invalid Ed25519 public key in ServerAuthRegister")?;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        let sig_raw = BASE64
            .decode(&self.server_signature_b64)
            .context("Invalid base64 signature in ServerAuthRegister")?;
        let sig_bytes: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| anyhow!("Invalid Ed25519 signature length in ServerAuthRegister"))?;
        let transcript = build_server_register_transcript(
            tls_exporter,
            proxy_nonce,
            &self.server_nonce,
            self.remote_port,
            &self.passkey_verifier,
        );
        if !verify_signature(&server_key, &transcript, &sig_bytes) {
            return Err(anyhow!(
                "Invalid Ed25519 signature in ServerAuthRegister (TLS channel binding failed)"
            ));
        }
        Ok(server_key)
    }
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
/// Identity verification is enforced via mutual Ed25519 signature over RFC 8446 TLS Exporter.
pub fn create_tunnel_tls_client_config() -> Result<Arc<rustls::ClientConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ChannelBoundCertVerifier { provider }))
        .with_no_client_auth();

    Ok(Arc::new(client_cfg))
}

#[derive(Debug)]
struct ChannelBoundCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for ChannelBoundCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        // Server identity is cryptographically verified immediately after the TLS 1.3 handshake
        // via Ed25519 signature over the RFC 8446 TLS Exporter value (`EXPORTER-olp-tunnel-v1`).
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
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

