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

/// Strict alphanumeric and safe symbol validation for identifiers (olp_api_key, olp_server_id).
/// Prevents directory traversal attacks, illegal filenames, and control-character injections.
pub fn is_safe_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

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

/// Step 2 of Handshake: Sent from `olp-server` to `olp-proxy` to register a tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthRegister {
    pub olp_api_key: String,
    pub olp_server_id: String,
    pub recommended_port: Option<u16>,
    pub passkey_user: String,
    pub auth_token: [u8; 32],
    #[serde(default)]
    pub policy_override: Option<bool>,
    #[serde(default)]
    pub keys: std::collections::HashMap<String, ScopedKeyRegistration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedKeyRegistration {
    #[serde(default)]
    pub passkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default)]
    pub scope: String,
}

impl ServerAuthRegister {
    pub fn new(
        olp_api_key: &str,
        olp_server_id: &str,
        recommended_port: Option<u16>,
        passkey_user: &str,
        proxy_nonce: &[u8; 32],
    ) -> Self {
        Self::with_policy(
            olp_api_key,
            olp_server_id,
            recommended_port,
            passkey_user,
            proxy_nonce,
            None,
        )
    }

    pub fn with_policy(
        olp_api_key: &str,
        olp_server_id: &str,
        recommended_port: Option<u16>,
        passkey_user: &str,
        proxy_nonce: &[u8; 32],
        policy_override: Option<bool>,
    ) -> Self {
        let auth_token = compute_server_auth_token(proxy_nonce, olp_server_id, olp_api_key);
        Self {
            olp_api_key: olp_api_key.to_string(),
            olp_server_id: olp_server_id.to_string(),
            recommended_port,
            passkey_user: passkey_user.to_string(),
            auth_token,
            policy_override,
            keys: std::collections::HashMap::new(),
        }
    }

    pub fn with_keys(
        olp_api_key: &str,
        olp_server_id: &str,
        recommended_port: Option<u16>,
        passkey_user: &str,
        proxy_nonce: &[u8; 32],
        policy_override: Option<bool>,
        keys: std::collections::HashMap<String, ScopedKeyRegistration>,
    ) -> Self {
        let auth_token = compute_server_auth_token(proxy_nonce, olp_server_id, olp_api_key);
        Self {
            olp_api_key: olp_api_key.to_string(),
            olp_server_id: olp_server_id.to_string(),
            recommended_port,
            passkey_user: passkey_user.to_string(),
            auth_token,
            policy_override,
            keys,
        }
    }
}

// Targeted Ollama version: 0.5.x - 0.6.x
//
// Endpoint allowlist for read-only inference scope:
//   GET/HEAD /, /api, /api/version, /api/tags, /api/ps, /v1/models, /v1/models/{id}
//   POST /api/generate, /api/chat, /api/embed, /api/embeddings, /api/show,
//        /v1/chat/completions, /v1/completions, /v1/embeddings
// Everything else is denied under inference scope (pull, push, create, copy, delete, blobs, etc.).

/// Returns true if the HTTP method and path target a sensitive or mutating Ollama operation
/// (such as downloading/pulling models, deleting models, creating custom models, copying, or pushing).
/// Read-only inference and status endpoints return false:
/// - Native Ollama: generate, chat, embeddings, embed, tags, version, show, ps
/// - OpenAI-compatible: /v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models (and /v1/models/*)
pub fn is_sensitive_ollama_op(method: &hyper::Method, path: &str) -> bool {
    let raw_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    let normalized_path = if raw_path.is_empty() { "/" } else { raw_path };

    match (method, normalized_path) {
        (
            &hyper::Method::GET | &hyper::Method::HEAD,
            "/" | "/api" | "/api/version" | "/api/tags" | "/api/ps" | "/v1/models",
        ) => false,
        (&hyper::Method::GET | &hyper::Method::HEAD, p) if p.starts_with("/v1/models/") => false,
        (
            &hyper::Method::POST,
            "/api/generate"
            | "/api/chat"
            | "/api/embeddings"
            | "/api/embed"
            | "/api/show"
            | "/v1/chat/completions"
            | "/v1/completions"
            | "/v1/embeddings",
        ) => false,
        // All mutating operations (e.g. POST /api/pull, DELETE /api/delete, POST /api/push,
        // POST /api/create, POST /api/copy, /api/blobs/*, etc.) or unknown verbs are sensitive.
        _ => true,
    }
}

/// Returns protocol-correct HTTP 403 error body and human-readable reason string.
/// - Paths starting with `/v1/` return OpenAI-compatible JSON:
///   `{"error":{"message":"<reason>","type":"permission_error","code":"forbidden"}}`
/// - Other paths return native Ollama-compatible JSON:
///   `{"error":"<reason>"}`
pub fn format_read_only_error(path: &str, method: &hyper::Method) -> (String, &'static str) {
    let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    let normalized = if clean_path.is_empty() {
        "/"
    } else {
        clean_path
    };

    let reason: &'static str = match (method, normalized) {
        (&hyper::Method::POST, p) if p.ends_with("/pull") => {
            "model downloads are disabled on this server (read-only mode)"
        }
        (&hyper::Method::DELETE, _) => "model deletion is disabled on this server (read-only mode)",
        (&hyper::Method::POST, p) if p.ends_with("/push") => {
            "model pushing is disabled on this server (read-only mode)"
        }
        (&hyper::Method::POST, p) if p.ends_with("/create") => {
            "model creation is disabled on this server (read-only mode)"
        }
        (&hyper::Method::POST, p) if p.ends_with("/copy") => {
            "model copying is disabled on this server (read-only mode)"
        }
        (&hyper::Method::POST, p) if p.starts_with("/api/blobs") => {
            "blob uploads are disabled on this server (read-only mode)"
        }
        _ => "operation forbidden: sensitive Ollama operations are disabled (read-only mode)",
    };

    let is_openai = normalized.starts_with("/v1/") || normalized == "/v1";
    let body = if is_openai {
        serde_json::json!({
            "error": {
                "message": reason,
                "type": "permission_error",
                "code": "forbidden"
            }
        })
        .to_string()
    } else {
        serde_json::json!({
            "error": reason
        })
        .to_string()
    };

    (body, reason)
}

/// Step 3 of Handshake: Sent from `olp-proxy` to `olp-server` to confirm or reject registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEstablished {
    pub accepted: bool,
    pub assigned_port: u16,
    pub message: String,
}

/// Computes a cryptographically secure token binding `proxy_nonce` and `olp_server_id` to `olp_api_key` using BLAKE3.
pub fn compute_server_auth_token(
    proxy_nonce: &[u8; 32],
    olp_server_id: &str,
    olp_api_key: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"olp-tunnel-auth-v3:");
    hasher.update(proxy_nonce);
    hasher.update(olp_server_id.as_bytes());
    hasher.update(b":");
    hasher.update(olp_api_key.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Constant-time verification of `olp_api_key` authentication token.
pub fn verify_server_auth_token(
    candidate_token: &[u8; 32],
    proxy_nonce: &[u8; 32],
    olp_server_id: &str,
    olp_api_key: &str,
) -> bool {
    let expected = compute_server_auth_token(proxy_nonce, olp_server_id, olp_api_key);
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

/// Extracts the host string from a `host:port` or `[ipv6]:port` address string.
pub fn extract_host(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    addr.split(':').next().unwrap_or(addr)
}

/// Builds a `rustls::ClientConfig` for `olp-server` restricted strictly to TLS 1.3.
/// When `verify_ca` is true (default when connecting to domain names), validates the proxy's TLS
/// certificate using Mozilla's WebPKI root store (Let's Encrypt / CA roots), preventing MITM attacks.
/// When `verify_ca` is false (e.g. 127.0.0.1 testing), establishes an encrypted TLS 1.3 channel
/// authenticated via `olp_api_key`.
pub fn create_tunnel_tls_client_config(verify_ca: bool) -> Result<Arc<rustls::ClientConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    if verify_ca {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Arc::new(client_cfg))
    } else {
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TunnelCertVerifier { provider }))
            .with_no_client_auth();

        Ok(Arc::new(client_cfg))
    }
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
    fn test_server_auth_token_constant_time() {
        let nonce = [42u8; 32];
        let token = compute_server_auth_token(&nonce, "srv_123", "secret-key-1");
        assert!(verify_server_auth_token(
            &token,
            &nonce,
            "srv_123",
            "secret-key-1"
        ));
        assert!(!verify_server_auth_token(
            &token,
            &nonce,
            "srv_123",
            "wrong-key"
        ));
        assert!(!verify_server_auth_token(
            &token,
            &nonce,
            "srv_456",
            "secret-key-1"
        ));

        let diff_nonce = [43u8; 32];
        assert!(!verify_server_auth_token(
            &token,
            &diff_nonce,
            "srv_123",
            "secret-key-1"
        ));
    }

    #[test]
    fn test_is_safe_identifier() {
        assert!(is_safe_identifier("srv_123"));
        assert!(is_safe_identifier("ABcd123"));
        assert!(is_safe_identifier("user-key_456"));
        assert!(!is_safe_identifier(""));
        assert!(!is_safe_identifier("../bad"));
        assert!(!is_safe_identifier("bad/path"));
        assert!(!is_safe_identifier("bad\\path"));
        assert!(!is_safe_identifier("bad key with spaces"));
    }

    #[test]
    fn test_is_sensitive_ollama_op() {
        use hyper::Method;

        // Safe / Read-Only endpoints
        assert!(!is_sensitive_ollama_op(&Method::GET, "/"));
        assert!(!is_sensitive_ollama_op(&Method::GET, "/api"));
        assert!(!is_sensitive_ollama_op(&Method::GET, "/api/version"));
        assert!(!is_sensitive_ollama_op(&Method::GET, "/api/tags"));
        assert!(!is_sensitive_ollama_op(
            &Method::GET,
            "/api/tags?verbose=true"
        ));
        assert!(!is_sensitive_ollama_op(&Method::GET, "/api/ps"));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/api/generate"));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/api/chat"));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/api/embeddings"));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/api/embed"));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/api/show"));

        // OpenAI-Compatible Safe / Read-Only endpoints
        assert!(!is_sensitive_ollama_op(&Method::GET, "/v1/models"));
        assert!(!is_sensitive_ollama_op(&Method::HEAD, "/v1/models"));
        assert!(!is_sensitive_ollama_op(&Method::GET, "/v1/models/llama3"));
        assert!(!is_sensitive_ollama_op(
            &Method::POST,
            "/v1/chat/completions"
        ));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/v1/completions"));
        assert!(!is_sensitive_ollama_op(&Method::POST, "/v1/embeddings"));

        // Sensitive / Mutating endpoints
        assert!(is_sensitive_ollama_op(&Method::POST, "/api/pull"));
        assert!(is_sensitive_ollama_op(&Method::POST, "/api/push"));
        assert!(is_sensitive_ollama_op(&Method::DELETE, "/api/delete"));
        assert!(is_sensitive_ollama_op(&Method::POST, "/api/create"));
        assert!(is_sensitive_ollama_op(&Method::POST, "/api/copy"));
        assert!(is_sensitive_ollama_op(
            &Method::POST,
            "/api/blobs/sha256:1234"
        ));
        assert!(is_sensitive_ollama_op(
            &Method::PUT,
            "/api/blobs/sha256:1234"
        ));
        assert!(is_sensitive_ollama_op(
            &Method::DELETE,
            "/api/blobs/sha256:1234"
        ));
        assert!(is_sensitive_ollama_op(&Method::POST, "/unknown/endpoint"));
    }

    #[test]
    fn test_format_read_only_error() {
        use hyper::Method;

        // OpenAI routes get OpenAI JSON structure with permission_error
        let (body, reason) = format_read_only_error("/v1/models/custom", &Method::DELETE);
        assert_eq!(
            reason,
            "model deletion is disabled on this server (read-only mode)"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"], "forbidden");
        assert_eq!(v["error"]["type"], "permission_error");
        assert_eq!(v["error"]["message"], reason);

        // Native Ollama routes get {"error": "<reason>"}
        let (body2, reason2) = format_read_only_error("/api/pull", &Method::POST);
        assert_eq!(
            reason2,
            "model downloads are disabled on this server (read-only mode)"
        );
        let v2: serde_json::Value = serde_json::from_str(&body2).unwrap();
        assert_eq!(v2["error"], reason2);
    }
}
