use crate::cidr::IpFilter;
use crate::config::{expand_path, olp_config_dir, ProxyConfig, UserProfile, UserServerConfig};
use crate::keys::{enforce_private_file_permissions, IpRateLimiter, PasskeyVerifier};
use crate::mux::{spawn_mux_session, MuxHandle};
use crate::protocol::{
    configure_tunnel_socket, create_tunnel_tls_server_config, is_safe_identifier,
    is_sensitive_ollama_op, read_frame, verify_server_auth_token, write_frame, ProxyHelloChallenge,
    ServerAuthRegister, TunnelEstablished,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{AUTHORIZATION, RETRY_AFTER, WWW_AUTHENTICATE};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use yamux::Mode;

pub type BoxHttpBody = BoxBody<Bytes, hyper::Error>;

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxHttpBody {
    Full::new(chunk.into()).map_err(|e| match e {}).boxed()
}

pub fn build_public_tls_acceptor(config: &ProxyConfig) -> Result<Option<TlsAcceptor>> {
    match config.tls.mode.as_str() {
        "off" => {
            warn!(
                "\n================================================================================\n\
                 [TLS WARNING] Public endpoint TLS is disabled (mode = 'off').\n\
                 Connections between clients and proxy will be sent unencrypted over plaintext HTTP!\n\
                 This mode is INSECURE and NOT RECOMMENDED for production deployments.\n\
                 ================================================================================"
            );
            Ok(None)
        }
        "self-signed" => {
            if !config.tls.allow_broken_certs {
                return Err(anyhow!(
                    "CRITICAL TLS ERROR: `tls.mode = \"self-signed\"` produces untrusted/broken certificates, \
                     which are disabled by default. Run ./renew-tls.sh to issue valid Let's Encrypt certificates, \
                     or explicitly set `allow_broken_certs = true` under [tls] in proxy.toml (not recommended)."
                ));
            }
            warn!("[TLS NOTICE] Using ephemeral self-signed TLS for public endpoints (allow_broken_certs = true).");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_der = CertificateDer::from(cert.cert);
            let key_der =
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)?;
            Ok(Some(TlsAcceptor::from(Arc::new(server_cfg))))
        }
        "manual" => {
            let cert_path_str = config
                .tls
                .cert_path
                .as_deref()
                .unwrap_or("~/.olp/tls/cert.pem");
            let key_path_str = config
                .tls
                .key_path
                .as_deref()
                .unwrap_or("~/.olp/tls/key.pem");
            let cert_path = expand_path(cert_path_str)?;
            let key_path = expand_path(key_path_str)?;

            if !cert_path.exists() || !key_path.exists() {
                if !config.tls.allow_broken_certs {
                    return Err(anyhow!(
                        "CRITICAL TLS ERROR: TLS certificates not found:\n  cert: {}\n  key:  {}\n\
                         Non-TLS connections and broken certificates are DISABLED BY DEFAULT.\n\
                         Run ./renew-tls.sh to issue Let's Encrypt certificates, or configure `allow_broken_certs = true` \
                         under [tls] in proxy.toml (not recommended) to bypass.",
                        cert_path.display(),
                        key_path.display()
                    ));
                }
                warn!(
                    "[TLS NOTICE] TLS certificate files not found; falling back to ephemeral self-signed TLS \
                     because allow_broken_certs = true."
                );
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
                let cert_der = CertificateDer::from(cert.cert);
                let key_der =
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
                    .with_no_client_auth()
                    .with_single_cert(vec![cert_der], key_der)?;
                return Ok(Some(TlsAcceptor::from(Arc::new(server_cfg))));
            }

            enforce_private_file_permissions(&key_path)?;

            let cert_file = File::open(&cert_path)
                .with_context(|| format!("Failed to open TLS cert {}", cert_path.display()))?;
            let mut cert_reader = BufReader::new(cert_file);
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

            let key_file = File::open(&key_path)
                .with_context(|| format!("Failed to open TLS key {}", key_path.display()))?;
            let mut key_reader = BufReader::new(key_file);
            let key = rustls_pemfile::private_key(&mut key_reader)?
                .ok_or_else(|| anyhow!("No private key found in {}", key_path.display()))?;

            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            Ok(Some(TlsAcceptor::from(Arc::new(server_cfg))))
        }
        other => Err(anyhow!(
            "Invalid tls.mode '{}' (expected 'manual', 'self-signed', or 'off')",
            other
        )),
    }
}

pub struct PortWorker {
    pub port: u16,
    pub active_mux: RwLock<Option<MuxHandle>>,
    pub session_gen: AtomicU64,
    pub shutdown_notify: Notify,
    pub user_verifier: RwLock<PasskeyVerifier>,
    pub user_ip_filter: RwLock<Arc<IpFilter>>,
    pub assigned_server_id: RwLock<Option<String>>,
    pub assigned_api_key: RwLock<Option<String>>,
    pub server_policy_override: RwLock<Option<bool>>,
    pub read_only: AtomicBool,
    pub max_num_ctx: std::sync::atomic::AtomicUsize,
    pub concurrency_semaphore: Arc<tokio::sync::Semaphore>,
    pub request_rate_limiter: Arc<crate::keys::RequestRateLimiter>,
    pub resolved_keys: RwLock<Vec<crate::config::ResolvedKey>>,
}

#[derive(Debug, Default, Clone)]
pub struct BlockedPathTracker {
    counters: Arc<std::sync::RwLock<HashMap<String, u64>>>,
}

impl BlockedPathTracker {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    pub fn record(&self, path: &str) {
        let clean = path.split('?').next().unwrap_or(path);
        if let Ok(mut map) = self.counters.write() {
            *map.entry(clean.to_string()).or_insert(0) += 1;
        }
    }

    pub fn get_counts(&self) -> HashMap<String, u64> {
        self.counters.read().map(|m| m.clone()).unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub struct MatchedKey {
    pub label: String,
    pub scope: crate::config::KeyScope,
}

pub fn verify_http_headers_with_keys(
    headers: &hyper::HeaderMap,
    keys: &[crate::config::ResolvedKey],
) -> Option<MatchedKey> {
    let mut candidate_tokens: Vec<String> = Vec::new();
    if let Some(auth_header) = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        let auth_header = auth_header.trim();
        if let Some(token) = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
        {
            candidate_tokens.push(token.trim().to_string());
        } else if let Some(b64) = auth_header
            .strip_prefix("Basic ")
            .or_else(|| auth_header.strip_prefix("basic "))
        {
            if let Ok(decoded_bytes) = BASE64.decode(b64.trim()) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                    let candidate = match decoded_str.split_once(':') {
                        Some((_user, pass)) => pass.trim(),
                        None => decoded_str.trim(),
                    };
                    candidate_tokens.push(candidate.to_string());
                }
            }
        }
    }

    for header_name in &["x-api-key", "api-key", "ollama-api-key", "x-auth-token"] {
        if let Some(val) = headers.get(*header_name).and_then(|h| h.to_str().ok()) {
            candidate_tokens.push(val.trim().to_string());
        }
    }

    for candidate in &candidate_tokens {
        for key in keys {
            if key.verifier.verify(candidate) {
                return Some(MatchedKey {
                    label: key.label.clone(),
                    scope: key.scope,
                });
            }
        }
    }

    None
}

impl PortWorker {
    pub fn has_active_session(&self) -> bool {
        if let Some(ref mux) = *self.active_mux.read().unwrap() {
            !mux.is_closed()
        } else {
            false
        }
    }
}

/// Background access logger for writing Apache-style access log entries to file and tracing.
#[derive(Clone)]
pub struct AccessLogger {
    tx: tokio::sync::mpsc::UnboundedSender<String>,
}

impl AccessLogger {
    pub fn new(log_path: Option<PathBuf>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            let mut file = if let Some(ref path) = log_path {
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                {
                    Ok(f) => {
                        let _ = enforce_private_file_permissions(path);
                        Some(f)
                    }
                    Err(e) => {
                        warn!("Failed to open access log file {}: {}", path.display(), e);
                        None
                    }
                }
            } else {
                None
            };

            while let Some(line) = rx.recv().await {
                info!(target: "access", "{}", line);
                if let Some(ref mut f) = file {
                    let _ = f.write_all(line.as_bytes()).await;
                    let _ = f.write_all(b"\n").await;
                    let _ = f.flush().await;
                }
            }
        });

        Self { tx }
    }

    pub fn log(&self, line: String) {
        let _ = self.tx.send(line);
    }
}

/// Formats a SystemTime into Apache Common Log Format timestamp: DD/Mon/YYYY:HH:MM:SS +0000
pub fn format_apache_timestamp(now: std::time::SystemTime) -> String {
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut days = (secs / 86400) as i64;
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y } as i32;

    let month_str = match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "Jan",
    };

    let rem = (secs % 86400) as u32;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    format!(
        "{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000",
        d, month_str, y, hour, min, sec
    )
}

/// Sanitizes a string for single-line log output, escaping quotes, backslashes, and newlines.
pub fn sanitize_for_log(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(max_len + 8);
    for ch in s.chars() {
        if out.len() >= max_len {
            out.push_str("...");
            break;
        }
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    if out.is_empty() {
        "-".to_string()
    } else {
        out
    }
}

/// Extracts the model name from a JSON request body or URI query string.
pub fn extract_model(body_bytes: &[u8], uri: &hyper::Uri) -> String {
    if !body_bytes.is_empty() {
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
            if let Some(m) = val.get("model").and_then(|v| v.as_str()) {
                if !m.is_empty() {
                    return m.to_string();
                }
            }
        }
    }

    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "model" && !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }

    "-".to_string()
}

/// Extracts client authentication scheme indicator for access logging without logging raw tokens or passkeys.
pub fn extract_auth_scheme(headers: &hyper::HeaderMap) -> &'static str {
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        let auth = auth.trim();
        if auth.starts_with("Bearer ") || auth.starts_with("bearer ") {
            return "auth=bearer";
        }
        if auth.starts_with("Basic ") || auth.starts_with("basic ") {
            return "auth=basic";
        }
        return "auth=present";
    }

    for header_name in &["x-api-key", "api-key", "ollama-api-key", "x-auth-token"] {
        if headers.contains_key(*header_name) {
            return "auth=api_key";
        }
    }

    "-"
}

/// Streaming body wrapper that passes chunks in real-time, counts total bytes,
/// and triggers a callback with byte count when complete or dropped without retaining body contents.
pub struct LoggingBody<B> {
    inner: B,
    on_complete: Option<Box<dyn FnOnce(usize) + Send + Sync + 'static>>,
    total_bytes: usize,
}

impl<B> LoggingBody<B> {
    pub fn new(inner: B, on_complete: impl FnOnce(usize) + Send + Sync + 'static) -> Self {
        Self {
            inner,
            on_complete: Some(Box::new(on_complete)),
            total_bytes: 0,
        }
    }

    fn finish(&mut self) {
        if let Some(cb) = self.on_complete.take() {
            cb(self.total_bytes);
        }
    }
}

impl<B> Body for LoggingBody<B>
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin,
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.total_bytes += data.len();
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                this.finish();
                std::task::Poll::Ready(Some(Err(e)))
            }
            std::task::Poll::Ready(None) => {
                this.finish();
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for LoggingBody<B> {
    fn drop(&mut self) {
        self.finish();
    }
}

pub struct ProxyState {
    pub config: ProxyConfig,
    pub config_dir: PathBuf,
    pub allowed_port_range: (u16, u16),
    pub control_port: u16,
    pub server_ip_filter: Arc<IpFilter>,
    pub workers: Mutex<HashMap<u16, Arc<PortWorker>>>,
    pub allocation_lock: tokio::sync::Mutex<()>,
    pub rate_limiter: Arc<IpRateLimiter>,
    pub public_tls_acceptor: Option<TlsAcceptor>,
    pub access_logger: Arc<AccessLogger>,
    pub blocked_paths: BlockedPathTracker,
}

impl ProxyState {
    pub fn is_authorized_api_key(&self, api_key: &str) -> bool {
        if !is_safe_identifier(api_key) {
            return false;
        }
        if self.config.auth.olp_api_keys.iter().any(|k| k == api_key) {
            return true;
        }
        let profile_path = self.config_dir.join(format!("{}.toml", api_key));
        profile_path.is_file()
    }

    pub fn load_user_profile(&self, api_key: &str) -> Result<UserProfile> {
        let profile_path = self.config_dir.join(format!("{}.toml", api_key));
        if profile_path.is_file() {
            UserProfile::load_from_path(&profile_path)
        } else if self.config.auth.olp_api_keys.iter().any(|k| k == api_key) {
            let profile = UserProfile::new(api_key);
            profile.save_atomic(&profile_path)?;
            Ok(profile)
        } else {
            Err(anyhow!("User profile not found for key"))
        }
    }

    pub fn save_user_profile(&self, profile: &UserProfile) -> Result<()> {
        let profile_path = self
            .config_dir
            .join(format!("{}.toml", profile.user.api_key));
        profile.save_atomic(&profile_path)
    }

    pub async fn allocate_server_port(
        &self,
        api_key: &str,
        server_id: &str,
        recommended_port: Option<u16>,
        passkey_user: &str,
        keys: &std::collections::HashMap<String, crate::protocol::ScopedKeyRegistration>,
    ) -> Result<u16> {
        let _guard = self.allocation_lock.lock().await;

        let mut profile = self.load_user_profile(api_key)?;
        if profile.user.disabled {
            return Err(anyhow!("ERR_USER_DISABLED: this API key has been disabled"));
        }

        let (min_port, max_port) = self.allowed_port_range;

        // 1. Check if server already has a registered port in this profile
        if let Some(existing_srv) = profile.servers.get_mut(server_id) {
            let p = existing_srv.port;
            if p >= min_port && p <= max_port && p != self.control_port {
                let in_use_by_other = {
                    let workers = self.workers.lock().unwrap();
                    if let Some(w) = workers.get(&p) {
                        let current_sid = w.assigned_server_id.read().unwrap();
                        current_sid.as_deref() != Some(server_id) && w.has_active_session()
                    } else {
                        false
                    }
                };
                if !in_use_by_other {
                    existing_srv.passkey_user = passkey_user.to_string();
                    for (label, reg_key) in keys {
                        if !existing_srv.keys.contains_key(label) {
                            let (passkey_val, hash_val) = if self.config.security.hash_passkeys {
                                (
                                    "".to_string(),
                                    Some(
                                        PasskeyVerifier::from_passkey(&reg_key.passkey)
                                            .to_encoded_hash(),
                                    ),
                                )
                            } else {
                                (reg_key.passkey.clone(), reg_key.hash.clone())
                            };
                            let scope = match reg_key.scope.as_str() {
                                "manage" => crate::config::KeyScope::Manage,
                                _ => crate::config::KeyScope::Inference,
                            };
                            existing_srv.keys.insert(
                                label.clone(),
                                crate::config::ScopedKeyConfig {
                                    passkey: passkey_val,
                                    hash: hash_val,
                                    scope,
                                },
                            );
                        }
                    }
                    self.save_user_profile(&profile)?;
                    return Ok(p);
                }
            }
        }

        // 2. New server for this user: enforce max_servers limit
        if !profile.servers.contains_key(server_id)
            && profile.servers.len() >= profile.user.max_servers
        {
            return Err(anyhow!(
                "ERR_MAX_SERVERS_EXCEEDED: account server limit ({}) reached",
                profile.user.max_servers
            ));
        }

        // 3. Collect all ports currently assigned or reserved across ALL user profiles
        let mut used_ports = std::collections::HashSet::new();
        used_ports.insert(self.control_port);

        {
            let workers = self.workers.lock().unwrap();
            for (&port, w) in workers.iter() {
                if w.has_active_session() {
                    used_ports.insert(port);
                }
            }
        }

        if let Ok(entries) = std::fs::read_dir(&self.config_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    if let Ok(up) = UserProfile::load_from_path(&path) {
                        for (sid, s_cfg) in &up.servers {
                            if up.user.api_key == api_key && sid == server_id {
                                continue;
                            }
                            used_ports.insert(s_cfg.port);
                        }
                    }
                }
            }
        }

        // 4. Try recommended_port if available
        let assigned_port = recommended_port
            .filter(|&rec| rec >= min_port && rec <= max_port && !used_ports.contains(&rec));

        // 5. Otherwise allocate first free port in range
        let port = match assigned_port {
            Some(p) => p,
            None => {
                let mut found = None;
                for p in min_port..=max_port {
                    if !used_ports.contains(&p) {
                        found = Some(p);
                        break;
                    }
                }
                found.ok_or_else(|| {
                    anyhow!(
                        "ERR_NO_PORTS_AVAILABLE: all ports in range {}-{} are assigned or in use",
                        min_port,
                        max_port
                    )
                })?
            }
        };

        // 6. Persist into user profile (plaintext by default for easy manual editing; salted hash if hash_passkeys is enabled)
        let existing = profile.servers.get(server_id).cloned();
        let (passkey_user_val, passkey_user_hash_val) = if self.config.security.hash_passkeys {
            (
                "".to_string(),
                Some(PasskeyVerifier::from_passkey(passkey_user).to_encoded_hash()),
            )
        } else {
            (passkey_user.to_string(), None)
        };
        let mut keys_map = existing
            .as_ref()
            .map(|s| s.keys.clone())
            .unwrap_or_default();
        for (label, reg_key) in keys {
            if !keys_map.contains_key(label) {
                let (passkey_val, hash_val) = if self.config.security.hash_passkeys {
                    (
                        "".to_string(),
                        Some(PasskeyVerifier::from_passkey(&reg_key.passkey).to_encoded_hash()),
                    )
                } else {
                    (reg_key.passkey.clone(), reg_key.hash.clone())
                };
                let scope = match reg_key.scope.as_str() {
                    "manage" => crate::config::KeyScope::Manage,
                    _ => crate::config::KeyScope::Inference,
                };
                keys_map.insert(
                    label.clone(),
                    crate::config::ScopedKeyConfig {
                        passkey: passkey_val,
                        hash: hash_val,
                        scope,
                    },
                );
            }
        }
        profile.servers.insert(
            server_id.to_string(),
            UserServerConfig {
                port,
                reserved: existing.as_ref().map(|s| s.reserved).unwrap_or(false),
                passkey_user: passkey_user_val,
                passkey_user_hash: passkey_user_hash_val,
                allowed_user_cidrs: existing
                    .as_ref()
                    .map(|s| s.allowed_user_cidrs.clone())
                    .unwrap_or_else(|| self.config.security.allowed_user_cidrs.clone()),
                allowed_server_cidrs: existing
                    .as_ref()
                    .map(|s| s.allowed_server_cidrs.clone())
                    .unwrap_or_else(|| self.config.security.allowed_server_cidrs.clone()),
                created_at: existing
                    .as_ref()
                    .and_then(|s| s.created_at.clone())
                    .or_else(|| Some(format_apache_timestamp(std::time::SystemTime::now()))),
                read_only: existing.as_ref().and_then(|s| s.read_only),
                max_num_ctx: existing.as_ref().and_then(|s| s.max_num_ctx),
                keys: keys_map,
            },
        );

        self.save_user_profile(&profile)?;
        Ok(port)
    }
}

pub fn verify_http_headers_auth(headers: &hyper::HeaderMap, verifier: &PasskeyVerifier) -> bool {
    // 1. Standard Authorization header (Bearer token or Basic auth)
    if let Some(auth_header) = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        let auth_header = auth_header.trim();
        if let Some(token) = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
        {
            if verifier.verify(token.trim()) {
                return true;
            }
        }

        if let Some(b64) = auth_header
            .strip_prefix("Basic ")
            .or_else(|| auth_header.strip_prefix("basic "))
        {
            if let Ok(decoded_bytes) = BASE64.decode(b64.trim()) {
                if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                    let candidate = match decoded_str.split_once(':') {
                        Some((_user, pass)) => pass.trim(),
                        None => decoded_str.trim(),
                    };
                    if verifier.verify(candidate) {
                        return true;
                    }
                }
            }
        }
    }

    // 2. Custom API key headers commonly sent by LLM clients (Cline, Roo Code, etc.)
    for header_name in &["x-api-key", "api-key", "ollama-api-key", "x-auth-token"] {
        if let Some(val) = headers.get(*header_name).and_then(|h| h.to_str().ok()) {
            if verifier.verify(val.trim()) {
                return true;
            }
        }
    }

    false
}

pub fn verify_http_request_auth(req: &Request<Incoming>, verifier: &PasskeyVerifier) -> bool {
    verify_http_headers_auth(req.headers(), verifier)
}

pub fn bind_reusable_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub async fn start_proxy_server(
    config: ProxyConfig,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let allowed_port_range = config.parse_allowed_port_range()?;
    let public_tls_acceptor = build_public_tls_acceptor(&config)?;
    let config_dir = olp_config_dir()?;

    let server_ip_filter = Arc::new(
        IpFilter::new(&config.security.allowed_server_cidrs)
            .context("Invalid allowed_server_cidrs")?,
    );

    let listen_sock_addr: SocketAddr = config
        .proxy
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid proxy.listen_addr '{}'", config.proxy.listen_addr))?;

    let listener = bind_reusable_listener(listen_sock_addr)?;
    let local_addr = listener.local_addr()?;

    let tunnel_tls_acceptor = if config.tls.mode == "manual" {
        let cert_path_str = config
            .tls
            .cert_path
            .as_deref()
            .unwrap_or("~/.olp/tls/cert.pem");
        let key_path_str = config
            .tls
            .key_path
            .as_deref()
            .unwrap_or("~/.olp/tls/key.pem");
        let cert_path = expand_path(cert_path_str)?;
        let key_path = expand_path(key_path_str)?;
        if cert_path.exists() && key_path.exists() {
            let cert_file = File::open(&cert_path)
                .with_context(|| format!("Failed to open TLS cert {}", cert_path.display()))?;
            let mut cert_reader = BufReader::new(cert_file);
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

            let key_file = File::open(&key_path)
                .with_context(|| format!("Failed to open TLS key {}", key_path.display()))?;
            let mut key_reader = BufReader::new(key_file);
            let key = rustls_pemfile::private_key(&mut key_reader)?
                .ok_or_else(|| anyhow!("No private key found in {}", key_path.display()))?;

            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            info!(
                "Tunnel control port (:4443) secured with CA TLS certificate ({})",
                cert_path.display()
            );
            TlsAcceptor::from(Arc::new(server_cfg))
        } else {
            if !config.tls.allow_broken_certs {
                return Err(anyhow!(
                    "CRITICAL TLS ERROR: TLS certificates not found:\n  cert: {}\n  key:  {}\n\
                     Non-TLS connections and broken certificates are DISABLED BY DEFAULT.\n\
                     Run ./renew-tls.sh to issue Let's Encrypt certificates, or pass --allow-broken-certs / set allow_broken_certs = true (not recommended) to bypass.",
                    cert_path.display(),
                    key_path.display()
                ));
            }
            warn!(
                "\n================================================================================\n\
                 [TLS WARNING] Configured TLS certificate/key not found:\n  cert: {}\n  key:  {}\n\
                 Falling back to ephemeral self-signed TLS certificate on control port (:4443) because allow_broken_certs = true.\n\
                 ================================================================================",
                cert_path.display(),
                key_path.display()
            );
            TlsAcceptor::from(create_tunnel_tls_server_config()?)
        }
    } else {
        if !config.tls.allow_broken_certs {
            return Err(anyhow!(
                "CRITICAL TLS ERROR: Ephemeral/self-signed certificates on tunnel control port (:4443) are disabled by default when tls.mode != 'manual'.\n\
                 Set tls.mode = 'manual' with valid Let's Encrypt certificates, or pass --allow-broken-certs / set allow_broken_certs = true (not recommended)."
            ));
        }
        warn!(
            "[TLS NOTICE] TLS mode is '{}'. Tunnel control port (:4443) is using ephemeral self-signed TLS (allow_broken_certs = true).",
            config.tls.mode
        );
        TlsAcceptor::from(create_tunnel_tls_server_config()?)
    };

    let access_log_path = match &config.proxy.access_log {
        Some(val) if val == "off" || val.is_empty() => None,
        Some(path_str) => Some(expand_path(path_str)?),
        None => None,
    };
    let access_logger = Arc::new(AccessLogger::new(access_log_path));

    let state = Arc::new(ProxyState {
        rate_limiter: Arc::new(IpRateLimiter::new(
            config.security.max_auth_failures_per_min,
        )),
        config,
        config_dir,
        allowed_port_range,
        control_port: local_addr.port(),
        server_ip_filter,
        workers: Mutex::new(HashMap::new()),
        allocation_lock: tokio::sync::Mutex::new(()),
        public_tls_acceptor,
        access_logger,
        blocked_paths: BlockedPathTracker::new(),
    });

    info!(
        "olp-proxy listening for olp-server tunnels on {} (TLS 1.3 encrypted)",
        local_addr
    );

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let state_clone = state.clone();
                    let acceptor = tunnel_tls_acceptor.clone();
                    tokio::spawn(async move {
                        if !state_clone.server_ip_filter.is_allowed(&peer_addr.ip()) {
                            warn!(
                                "[IP FILTER] Dropped tunnel connection from {} (not in allowed_server_cidrs)",
                                peer_addr
                            );
                            return;
                        }

                        if let Err(e) =
                            handle_incoming_tunnel(tcp_stream, peer_addr, acceptor, state_clone)
                                .await
                        {
                            let err_msg = format!("{:#}", e);
                            if err_msg.contains("TLS handshake failed")
                                || err_msg.contains("Handshake")
                                || err_msg.contains("AlertReceived")
                            {
                                warn!(
                                    "Tunnel connection from {} ended: {}. (Note: If connecting via domain name, client requires valid CA/Let's Encrypt certificates on proxy. Run ./renew-tls.sh if certificates are missing or expired).",
                                    peer_addr, err_msg
                                );
                            } else {
                                warn!("Tunnel connection from {} ended: {}", peer_addr, err_msg);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting tunnel connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok((local_addr, handle))
}

async fn handle_incoming_tunnel(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    state: Arc<ProxyState>,
) -> Result<()> {
    configure_tunnel_socket(&tcp_stream)?;

    let mut tls_stream = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp_stream))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")?;

    // Step 1: Send ProxyHelloChallenge with fresh CSPRNG nonce
    let challenge = ProxyHelloChallenge::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        write_frame(&mut tls_stream, &challenge),
    )
    .await
    .context("Timed out sending ProxyHelloChallenge")??;

    // Step 2: Receive ServerAuthRegister
    let register: ServerAuthRegister =
        tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls_stream))
            .await
            .context("Timed out waiting for ServerAuthRegister")??;

    // Step 3: Validate safe alphanumeric identifiers
    if !is_safe_identifier(&register.olp_api_key) || !is_safe_identifier(&register.olp_server_id) {
        let msg = "ERR_INVALID_IDENTIFIER: olp_api_key and olp_server_id must be alphanumeric, dash, or underscore (1-64 chars)".to_string();
        let _ = write_frame(
            &mut tls_stream,
            &TunnelEstablished {
                accepted: false,
                assigned_port: 0,
                message: msg.clone(),
            },
        )
        .await;
        warn!(
            "[SECURITY] Rejected tunnel with invalid identifier chars from {}",
            peer_addr
        );
        return Err(anyhow!(msg));
    }

    // Step 4: Verify that olp_api_key is recognized
    if !state.is_authorized_api_key(&register.olp_api_key) {
        let msg = "ERR_UNAUTHORIZED_KEY: olp_api_key is not recognized by this proxy".to_string();
        let _ = write_frame(
            &mut tls_stream,
            &TunnelEstablished {
                accepted: false,
                assigned_port: 0,
                message: msg.clone(),
            },
        )
        .await;
        error!(
            "[AUTH ERROR] Tunnel connection from {} rejected: unknown olp_api_key",
            peer_addr
        );
        return Err(anyhow!(msg));
    }

    // Step 5: Verify cryptographic token binding nonce + olp_server_id to olp_api_key in constant time
    let is_valid = verify_server_auth_token(
        &register.auth_token,
        &challenge.proxy_nonce,
        &register.olp_server_id,
        &register.olp_api_key,
    );

    if !is_valid {
        let msg = "ERR_INVALID_AUTH_TOKEN: server authentication failed".to_string();
        let _ = write_frame(
            &mut tls_stream,
            &TunnelEstablished {
                accepted: false,
                assigned_port: 0,
                message: msg.clone(),
            },
        )
        .await;

        error!(
            "[AUTH ERROR] Tunnel connection from {} rejected: authentication token mismatch for server {}",
            peer_addr, register.olp_server_id
        );
        return Err(anyhow!(msg));
    }

    // Step 6: Allocate or assign public port for this server
    let assigned_port = match state
        .allocate_server_port(
            &register.olp_api_key,
            &register.olp_server_id,
            register.recommended_port,
            &register.passkey_user,
            &register.keys,
        )
        .await
    {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("ERR_PORT_ALLOCATION_FAILED: {}", e);
            let _ = write_frame(
                &mut tls_stream,
                &TunnelEstablished {
                    accepted: false,
                    assigned_port: 0,
                    message: msg.clone(),
                },
            )
            .await;
            return Err(e);
        }
    };

    // Step 7: Enforce per-server CIDR ACL
    let profile = state.load_user_profile(&register.olp_api_key)?;
    let mut server_cfg = profile
        .servers
        .get(&register.olp_server_id)
        .cloned()
        .ok_or_else(|| anyhow!("Server configuration missing after allocation"))?;

    let srv_filter = IpFilter::new(&server_cfg.allowed_server_cidrs)?;
    if !srv_filter.is_allowed(&peer_addr.ip()) {
        let msg = "ERR_SERVER_IP_FORBIDDEN: your IP is not in allowed_server_cidrs for this server"
            .to_string();
        let _ = write_frame(
            &mut tls_stream,
            &TunnelEstablished {
                accepted: false,
                assigned_port: 0,
                message: msg.clone(),
            },
        )
        .await;
        warn!(
            "[IP FILTER] Dropped tunnel connection for server {} from {} (not in allowed_server_cidrs)",
            register.olp_server_id, peer_addr
        );
        return Err(anyhow!(msg));
    }

    // Step 8: Acquire or initialize PortWorker for assigned_port
    let worker = match get_or_create_port_worker(&state, assigned_port) {
        Ok(w) => w,
        Err(e) => {
            let _ = write_frame(
                &mut tls_stream,
                &TunnelEstablished {
                    accepted: false,
                    assigned_port: 0,
                    message: format!("ERR_PORT_CONFLICT: {}", e),
                },
            )
            .await;
            return Err(e);
        }
    };

    // Configure worker credentials & ACL specifically for this server
    {
        *worker.user_verifier.write().unwrap() = server_cfg.get_verifier();
        *worker.resolved_keys.write().unwrap() = server_cfg.get_resolved_keys();
        *worker.user_ip_filter.write().unwrap() =
            Arc::new(IpFilter::new(&server_cfg.allowed_user_cidrs)?);
        *worker.assigned_server_id.write().unwrap() = Some(register.olp_server_id.clone());
        *worker.assigned_api_key.write().unwrap() = Some(register.olp_api_key.clone());
        *worker.server_policy_override.write().unwrap() = register.policy_override;
        if let Some(ctx) = register.max_num_ctx {
            worker.max_num_ctx.store(ctx, Ordering::Relaxed);
        } else if let Some(ctx) = server_cfg.max_num_ctx {
            worker.max_num_ctx.store(ctx, Ordering::Relaxed);
        }
    }

    if let Some(ctx) = register.max_num_ctx {
        if server_cfg.max_num_ctx != Some(ctx) {
            server_cfg.max_num_ctx = Some(ctx);
            let mut p = profile.clone();
            p.servers
                .insert(register.olp_server_id.clone(), server_cfg.clone());
            let _ = state.save_user_profile(&p);
            info!(
                "[CONTEXT] Synchronized server '{}' context window setting to {} tokens from olp-server",
                register.olp_server_id, ctx
            );
        }
    }

    // Step 8b: Policy enforcement and conflict checking
    // Rule:
    // 1. Both proxy and server can configure policy as long as they are aligned.
    // 2. The stricter setting wins (a server can always restrict itself further to read_only = true).
    // 3. Only an attempt by a server to loosen the proxy's stricter policy (proxy RO=true, server RO=false) is rejected.
    let proxy_ro = server_cfg
        .read_only
        .unwrap_or(state.config.security.read_only);
    let server_ro = register.policy_override;

    let effective_ro = if state.config.security.policy_authority == "proxy" {
        match (proxy_ro, server_ro) {
            // Case 1: Proxy enforces read_only = true, but server attempts to loosen it with read_only = false -> CONFLICT!
            (true, Some(false)) => {
                let conflict_msg = format!(
                    "CRITICAL CONFIG CONFLICT: Server '{}' attempted to loosen security policy!\n\
                     olp-proxy enforces stricter policy (read_only = true), but server requested read_only = false.\n\
                     A server can restrict itself further or align with proxy policy, but cannot loosen proxy restrictions.",
                    register.olp_server_id
                );
                error!("\n================================================================================\n{}\n================================================================================", conflict_msg);
                let _ = write_frame(
                    &mut tls_stream,
                    &TunnelEstablished {
                        accepted: false,
                        assigned_port: 0,
                        message: conflict_msg.clone(),
                    },
                )
                .await;
                return Err(anyhow!(conflict_msg));
            }
            // Case 2: Proxy has read_only = false, but server restricts itself with read_only = true -> Stricter wins!
            (false, Some(true)) => {
                info!(
                    "[POLICY] Server '{}' restricted policy to read_only = true (stricter setting wins over proxy read_only = false)",
                    register.olp_server_id
                );
                true
            }
            // Case 3: Both proxy and server are aligned on read_only = true
            (true, Some(true)) => {
                info!(
                    "[POLICY] Server '{}' and proxy are aligned on read_only = true (sensitive Ollama operations BLOCKED)",
                    register.olp_server_id
                );
                true
            }
            // Case 4: Both proxy and server are aligned on read_only = false
            (false, Some(false)) => {
                info!(
                    "[POLICY] Server '{}' and proxy are aligned on read_only = false (sensitive Ollama operations ALLOWED)",
                    register.olp_server_id
                );
                false
            }
            // Case 5: Server did not specify policy (None) -> proxy setting applies
            (proxy_val, None) => {
                info!(
                    "[POLICY] Proxy controls policy for server '{}': read_only = {} (sensitive Ollama operations {})",
                    register.olp_server_id,
                    proxy_val,
                    if proxy_val { "BLOCKED" } else { "ALLOWED" }
                );
                proxy_val
            }
        }
    } else if state.config.security.policy_authority == "server" {
        if let Some(s_ro) = server_ro {
            info!(
                "[POLICY] Server '{}' controls policy (delegated by proxy): read_only = {} (sensitive Ollama operations {})",
                register.olp_server_id,
                s_ro,
                if s_ro { "BLOCKED" } else { "ALLOWED" }
            );
            s_ro
        } else {
            let conflict_msg = format!(
                "CRITICAL CONFIG ERROR: Proxy is configured with `policy_authority = \"server\"`, but server '{}' did not specify policy (read_only is unset in server.toml).\n\
                 Specify `read_only = true` or `read_only = false` in server.toml.",
                register.olp_server_id
            );
            error!("\n================================================================================\n{}\n================================================================================", conflict_msg);
            let _ = write_frame(
                &mut tls_stream,
                &TunnelEstablished {
                    accepted: false,
                    assigned_port: 0,
                    message: conflict_msg.clone(),
                },
            )
            .await;
            return Err(anyhow!(conflict_msg));
        }
    } else {
        return Err(anyhow!(
            "Invalid security.policy_authority '{}' in proxy.toml (must be 'proxy' or 'server')",
            state.config.security.policy_authority
        ));
    };

    worker.read_only.store(effective_ro, Ordering::Relaxed);

    // Step 9: Acknowledge tunnel registration before upgrading stream to Yamux
    write_frame(
        &mut tls_stream,
        &TunnelEstablished {
            accepted: true,
            assigned_port,
            message: format!("Port {} bound successfully", assigned_port),
        },
    )
    .await?;

    let (mux_handle, mut inbound_rx) = spawn_mux_session(
        tls_stream,
        Mode::Server,
        state.config.security.max_concurrent_streams,
    );

    let my_gen = worker.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
    {
        *worker.active_mux.write().unwrap() = Some(mux_handle);
    }

    info!(
        "Tunnel established from {} [user: {}, srv: {}] -> public port :{} (session #{})",
        peer_addr, register.olp_api_key, register.olp_server_id, assigned_port, my_gen
    );

    // Process control/heartbeat streams opened by `olp-server`
    while let Some(stream) = inbound_rx.recv().await {
        tokio::spawn(async move {
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_ok() && line.trim() == "PING" {
                let _ = reader.get_mut().write_all(b"PONG\n").await;
                let _ = reader.get_mut().flush().await;
            }
        });
    }

    // Clear active_mux only if we are still the current session generation
    if worker.session_gen.load(Ordering::SeqCst) == my_gen {
        *worker.active_mux.write().unwrap() = None;
        info!(
            "Tunnel on port :{} disconnected (holding port for {}s grace period)",
            assigned_port, state.config.proxy.listener_grace_period_sec
        );
    }

    Ok(())
}

fn get_or_create_port_worker(state: &Arc<ProxyState>, port: u16) -> Result<Arc<PortWorker>> {
    let mut guard = state.workers.lock().unwrap();
    if let Some(existing) = guard.get(&port) {
        return Ok(existing.clone());
    }

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let public_listener = bind_reusable_listener(bind_addr)
        .with_context(|| format!("Failed to bind public port {}", port))?;

    let default_user_filter = Arc::new(IpFilter::new(&state.config.security.allowed_user_cidrs)?);
    let max_active = if state.config.security.max_active_requests_per_server > 0 {
        state.config.security.max_active_requests_per_server
    } else {
        usize::MAX / 2
    };
    let worker = Arc::new(PortWorker {
        port,
        active_mux: RwLock::new(None),
        session_gen: AtomicU64::new(0),
        shutdown_notify: Notify::new(),
        user_verifier: RwLock::new(PasskeyVerifier::from_passkey("")),
        user_ip_filter: RwLock::new(default_user_filter),
        assigned_server_id: RwLock::new(None),
        assigned_api_key: RwLock::new(None),
        server_policy_override: RwLock::new(None),
        read_only: AtomicBool::new(state.config.security.read_only),
        max_num_ctx: std::sync::atomic::AtomicUsize::new(32768),
        concurrency_semaphore: Arc::new(tokio::sync::Semaphore::new(max_active)),
        request_rate_limiter: Arc::new(crate::keys::RequestRateLimiter::new(
            state.config.security.max_requests_per_min,
        )),
        resolved_keys: RwLock::new(Vec::new()),
    });

    guard.insert(port, worker.clone());

    let worker_clone = worker.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        run_public_port_listener(public_listener, worker_clone, state_clone).await;
    });

    Ok(worker)
}

async fn run_public_port_listener(
    listener: TcpListener,
    worker: Arc<PortWorker>,
    state: Arc<ProxyState>,
) {
    info!(
        "Public Ollama endpoint listening on 0.0.0.0:{}",
        worker.port
    );
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let _ = stream.set_nodelay(true);
                let worker_ref = worker.clone();
                let state_ref = state.clone();
                tokio::spawn(async move {
                    if let Some(ref acceptor) = state_ref.public_tls_acceptor {
                        // Detect plaintext HTTP requests sent to an HTTPS port
                        let mut peek_buf = [0u8; 4];
                        if let Ok(n) = stream.peek(&mut peek_buf).await {
                            if n >= 3
                                && peek_buf[0] != 0x16
                                && (&peek_buf[..3] == b"GET"
                                    || &peek_buf[..4] == b"POST"
                                    || &peek_buf[..4] == b"HEAD"
                                    || &peek_buf[..4] == b"OPTI"
                                    || &peek_buf[..3] == b"PUT"
                                    || &peek_buf[..4] == b"DELE")
                            {
                                let err_resp = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"The plain HTTP request was sent to HTTPS port. Please use https:// instead of http://\"}\r\n";
                                let mut s = stream;
                                let _ = tokio::io::AsyncWriteExt::write_all(&mut s, err_resp).await;
                                return;
                            }
                        }

                        if let Ok(Ok(tls_stream)) =
                            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
                                .await
                        {
                            serve_public_http_connection(
                                tls_stream,
                                client_addr.ip(),
                                worker_ref,
                                state_ref,
                            )
                            .await;
                        }
                    } else {
                        serve_public_http_connection(
                            stream,
                            client_addr.ip(),
                            worker_ref,
                            state_ref,
                        )
                        .await;
                    }
                });
            }
            Err(e) => {
                error!(
                    "Error accepting connection on public port {}: {}",
                    worker.port, e
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve_public_http_connection<S>(
    io: S,
    client_ip: IpAddr,
    worker: Arc<PortWorker>,
    state: Arc<ProxyState>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let state_ref = state.clone();
    let service = service_fn(move |req: Request<Incoming>| {
        let worker = worker.clone();
        let state = state_ref.clone();
        async move { handle_public_http_request(req, client_ip, worker, state).await }
    });

    let timeout_dur = Duration::from_secs(state.config.security.connection_timeout_sec.max(10));
    let _ = tokio::time::timeout(
        timeout_dur,
        server_http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(io), service),
    )
    .await;
}

async fn handle_public_http_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    worker: Arc<PortWorker>,
    state: Arc<ProxyState>,
) -> std::result::Result<Response<BoxHttpBody>, hyper::Error> {
    let start_time = std::time::Instant::now();
    let timestamp_str = format_apache_timestamp(std::time::SystemTime::now());
    let method = req.method().clone();
    let uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path())
        .to_string();
    let version = format!("{:?}", req.version());
    let auth_scheme = extract_auth_scheme(req.headers());

    let access_logger = state.access_logger.clone();
    let log_event = {
        let timestamp_str = timestamp_str.clone();
        let method = method.clone();
        let uri = uri.clone();
        let version = version.clone();
        move |status: StatusCode,
              resp_bytes: usize,
              req_size: usize,
              model: &str,
              key_label: &str| {
            let duration_ms = start_time.elapsed().as_millis();
            let line = format!(
                r#"{ip} - {auth_scheme} [{timestamp}] "{method} {uri} {version}" {status} {resp_bytes} {duration_ms}ms key="{key_label}" model="{model}" req_bytes={req_bytes}"#,
                ip = client_ip,
                auth_scheme = auth_scheme,
                timestamp = timestamp_str,
                method = method,
                uri = uri,
                version = version,
                status = status.as_u16(),
                resp_bytes = resp_bytes,
                duration_ms = duration_ms,
                key_label = key_label,
                model = model,
                req_bytes = req_size,
            );
            access_logger.log(line);
        }
    };

    // 0. Reject CONNECT method immediately with 405 Method Not Allowed
    if method == Method::CONNECT {
        let err_json = r#"{"error":"CONNECT method is forbidden"}"#;
        log_event(StatusCode::METHOD_NOT_ALLOWED, err_json.len(), 0, "-", "-");
        let mut resp = Response::new(full_body(err_json));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    // 1. Handle CORS preflight without requiring authentication
    if method == Method::OPTIONS {
        log_event(StatusCode::NO_CONTENT, 0, 0, "-", "-");
        let mut resp = Response::new(full_body(Bytes::new()));
        *resp.status_mut() = StatusCode::NO_CONTENT;
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
            hyper::header::HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS, HEAD"),
        );
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
            hyper::header::HeaderValue::from_static("*"),
        );
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_MAX_AGE,
            hyper::header::HeaderValue::from_static("86400"),
        );
        return Ok(resp);
    }

    // 2. Check CIDR IP filter for user HTTP connections
    let ip_filter = worker.user_ip_filter.read().unwrap().clone();
    if !ip_filter.is_allowed(&client_ip) {
        warn!(
            "[IP FILTER] Rejected user HTTP connection from {} on port {} (not in allowed_user_cidrs)",
            client_ip, worker.port
        );
        let err_json = r#"{"error":"forbidden: IP address not allowed by proxy filter"}"#;
        log_event(StatusCode::FORBIDDEN, err_json.len(), 0, "-", "-");
        let mut resp = Response::new(full_body(err_json));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    // 3. Check pre-tunnel IP brute-force rate limiter
    if state.rate_limiter.is_locked_out(&client_ip).is_some() {
        let err_json = r#"{"error":"too many failed authentication attempts, try again later"}"#;
        log_event(StatusCode::TOO_MANY_REQUESTS, err_json.len(), 0, "-", "-");
        let mut resp = Response::new(full_body(err_json));
        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        resp.headers_mut()
            .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("60"));
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    // 4. Verify credentials against scoped keys in constant time BEFORE body collection
    let mut matched_key: Option<MatchedKey> = {
        let keys = worker.resolved_keys.read().unwrap();
        verify_http_headers_with_keys(req.headers(), &keys)
    };

    // If initial verification failed against in-memory cache, reload profile from disk
    // in case the user manually edited ~/.olp/config/<api_key>.toml
    if matched_key.is_none() {
        let ids = {
            let s_id = worker.assigned_server_id.read().unwrap().clone();
            let a_key = worker.assigned_api_key.read().unwrap().clone();
            match (s_id, a_key) {
                (Some(s), Some(k)) => Some((s, k)),
                _ => None,
            }
        };
        if let Some((server_id, api_key)) = ids {
            if let Ok(profile) = state.load_user_profile(&api_key) {
                if let Some(fresh_server_cfg) = profile.servers.get(&server_id) {
                    let fresh_keys = fresh_server_cfg.get_resolved_keys();
                    if let Some(m) = verify_http_headers_with_keys(req.headers(), &fresh_keys) {
                        *worker.resolved_keys.write().unwrap() = fresh_keys;
                        *worker.user_verifier.write().unwrap() = fresh_server_cfg.get_verifier();
                        if let Ok(new_filter) = IpFilter::new(&fresh_server_cfg.allowed_user_cidrs)
                        {
                            *worker.user_ip_filter.write().unwrap() = Arc::new(new_filter);
                        }
                        matched_key = Some(m);
                    }
                }
            }
        }
    }

    let matched_info = match matched_key {
        Some(m) => m,
        None => {
            state.rate_limiter.record_failure(client_ip);
            let err_json = r#"{"error":"unauthorized: valid Basic Auth (username:passkey_user) or Bearer passkey_user required"}"#;
            log_event(StatusCode::UNAUTHORIZED, err_json.len(), 0, "-", "-");
            let mut resp = Response::new(full_body(err_json));
            *resp.status_mut() = StatusCode::UNAUTHORIZED;
            resp.headers_mut().insert(
                WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static(r#"Basic realm="Ollama Proxy""#),
            );
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            return Ok(resp);
        }
    };

    let active_key_label = matched_info.label.clone();
    state.rate_limiter.record_success(&client_ip);

    // 5. Check authenticated request rate limiter
    if !worker.request_rate_limiter.check_and_record(worker.port) {
        warn!(
            "[RATE LIMIT] Request on port {} exceeded max_requests_per_min ({})",
            worker.port, state.config.security.max_requests_per_min
        );
        let err_json = r#"{"error":"rate limit exceeded: too many requests per minute"}"#;
        log_event(
            StatusCode::TOO_MANY_REQUESTS,
            err_json.len(),
            0,
            "-",
            &active_key_label,
        );
        let mut resp = Response::new(full_body(err_json));
        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        resp.headers_mut()
            .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("10"));
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    // 6. Enforce read-only policy for sensitive Ollama operations
    // If a sensitive mutating operation is attempted, refresh server policy from disk
    // so dynamically toggled read-only settings in the UI take effect immediately.
    if is_sensitive_ollama_op(&method, &uri) {
        let ids = {
            let s_id = worker.assigned_server_id.read().unwrap().clone();
            let a_key = worker.assigned_api_key.read().unwrap().clone();
            match (s_id, a_key) {
                (Some(s), Some(k)) => Some((s, k)),
                _ => None,
            }
        };
        if let Some((server_id, api_key)) = ids {
            if let Ok(profile) = state.load_user_profile(&api_key) {
                if let Some(srv_cfg) = profile.servers.get(&server_id) {
                    if let Some(fresh_ro) = srv_cfg.read_only {
                        let client_locked_ro =
                            *worker.server_policy_override.read().unwrap() == Some(true);
                        let effective = if client_locked_ro { true } else { fresh_ro };
                        worker.read_only.store(effective, Ordering::Relaxed);
                        *worker.resolved_keys.write().unwrap() = srv_cfg.get_resolved_keys();
                    }
                }
            }
        }
    }

    let is_proxy_ro = worker.read_only.load(Ordering::Relaxed);
    let active_scope = worker
        .resolved_keys
        .read()
        .unwrap()
        .iter()
        .find(|k| k.label == matched_info.label)
        .map(|k| k.scope)
        .unwrap_or(matched_info.scope);
    let is_inference_only = is_proxy_ro || active_scope == crate::config::KeyScope::Inference;
    if is_inference_only && is_sensitive_ollama_op(&method, &uri) {
        let (err_json, reason) = crate::protocol::format_read_only_error(&uri, &method);
        let clean_path = uri.split('?').next().unwrap_or(&uri);
        state.blocked_paths.record(clean_path);
        warn!(
            "[POLICY BLOCKED] method={} path={} status=403 key_label={} reason=\"{}\"",
            method, clean_path, active_key_label, reason
        );
        log_event(
            StatusCode::FORBIDDEN,
            err_json.len(),
            0,
            "-",
            &active_key_label,
        );
        let mut resp = Response::new(full_body(err_json));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    // 7. Enforce maximum request body size limit via Content-Length header
    let max_bytes = state.config.security.max_request_body_size_mb * 1024 * 1024;
    if max_bytes > 0 {
        if let Some(cl_val) = req.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(cl_str) = cl_val.to_str() {
                if let Ok(cl) = cl_str.trim().parse::<usize>() {
                    if cl > max_bytes {
                        warn!(
                            "[SECURITY] Rejected request exceeding max body size ({} > {} bytes) on port {}",
                            cl, max_bytes, worker.port
                        );
                        let err_json = r#"{"error":"payload too large: request body exceeds maximum allowed size"}"#;
                        log_event(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            err_json.len(),
                            cl,
                            "-",
                            &active_key_label,
                        );
                        let mut resp = Response::new(full_body(err_json));
                        *resp.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                        resp.headers_mut().insert(
                            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                            hyper::header::HeaderValue::from_static("*"),
                        );
                        return Ok(resp);
                    }
                }
            }
        }
    }

    // 8. Backend concurrency throttling (GPU VRAM / saturation protection)
    let permit = match worker.concurrency_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                "[CONCURRENCY] Max active concurrent requests ({}) reached for worker port {}",
                state.config.security.max_active_requests_per_server, worker.port
            );
            let err_json =
                r#"{"error":"server busy: maximum concurrent requests reached for this backend"}"#;
            log_event(
                StatusCode::TOO_MANY_REQUESTS,
                err_json.len(),
                0,
                "-",
                &active_key_label,
            );
            let mut resp = Response::new(full_body(err_json));
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            resp.headers_mut()
                .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("5"));
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            return Ok(resp);
        }
    };

    // 9. Now collect request body with maximum size streaming cap
    let (mut parts, incoming_body) = req.into_parts();
    let max_cap = if max_bytes > 0 { max_bytes } else { usize::MAX };
    let mut collected = bytes::BytesMut::new();
    let mut body_stream = incoming_body;
    let mut overflow = false;

    if parts.method != Method::GET
        && parts.method != Method::HEAD
        && parts.method != Method::OPTIONS
    {
        while let Some(frame_res) = http_body_util::BodyExt::frame(&mut body_stream).await {
            match frame_res {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        if collected.len() + data.len() > max_cap {
                            overflow = true;
                            break;
                        }
                        collected.extend_from_slice(&data);
                    }
                }
                Err(_) => break,
            }
        }
    }

    if overflow {
        let err_json =
            r#"{"error":"payload too large: request body exceeds maximum allowed size"}"#;
        log_event(
            StatusCode::PAYLOAD_TOO_LARGE,
            err_json.len(),
            collected.len(),
            "-",
            &active_key_label,
        );
        let mut resp = Response::new(full_body(err_json));
        *resp.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    let body_bytes = collected.freeze();
    let req_size = body_bytes.len();
    let model = extract_model(&body_bytes, &parts.uri);

    // 10. Retrieve active Yamux session
    let mux = {
        let guard = worker.active_mux.read().unwrap();
        guard.clone()
    };

    let clean_path = uri.split('?').next().unwrap_or(&uri);
    let is_context_endpoint = clean_path == "/api/olp/context" || clean_path == "/api/olp/ctx";

    let mux = match mux {
        Some(m) if !m.is_closed() => m,
        _ => {
            let err_json = if is_context_endpoint {
                r#"{"error":"olp-server is currently offline. Context window can only be queried or modified when the server is connected."}"#
            } else {
                r#"{"error":"olp-server tunnel currently offline. Waiting for reconnection..."}"#
            };
            log_event(
                StatusCode::SERVICE_UNAVAILABLE,
                err_json.len(),
                req_size,
                &model,
                &active_key_label,
            );
            let mut resp = Response::new(full_body(err_json));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            return Ok(resp);
        }
    };

    // 11. Open new Yamux substream to `olp-server`
    let mux_stream = match mux.open_stream().await {
        Ok(s) => s,
        Err(_) => {
            let err_json = r#"{"error":"failed to open substream to olp-server"}"#;
            log_event(
                StatusCode::BAD_GATEWAY,
                err_json.len(),
                req_size,
                &model,
                &active_key_label,
            );
            let mut resp = Response::new(full_body(err_json));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            return Ok(resp);
        }
    };

    // 12. Forward HTTP request with stripped auth headers and injected scope headers
    let (mut client_sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(mux_stream)).await {
            Ok(pair) => pair,
            Err(_) => {
                let err_json = r#"{"error":"failed HTTP handshake over tunnel substream"}"#;
                log_event(
                    StatusCode::BAD_GATEWAY,
                    err_json.len(),
                    req_size,
                    &model,
                    &active_key_label,
                );
                let mut resp = Response::new(full_body(err_json));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                resp.headers_mut().insert(
                    hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    hyper::header::HeaderValue::from_static("*"),
                );
                return Ok(resp);
            }
        };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    parts.headers.remove(AUTHORIZATION);
    parts.headers.remove("x-api-key");
    parts.headers.remove("api-key");
    parts.headers.remove("ollama-api-key");
    parts.headers.remove("x-auth-token");

    let scope_str = if is_inference_only {
        "inference"
    } else {
        "manage"
    };
    parts.headers.insert(
        "x-olp-scope",
        hyper::header::HeaderValue::from_static(scope_str),
    );
    if let Ok(label_val) = hyper::header::HeaderValue::from_str(&active_key_label) {
        parts.headers.insert("x-olp-key-label", label_val);
    }

    let forward_req = Request::from_parts(parts, full_body(body_bytes));

    match client_sender.send_request(forward_req).await {
        Ok(upstream_resp) => {
            let (mut u_parts, u_body) = upstream_resp.into_parts();
            u_parts
                .headers
                .entry(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .or_insert_with(|| hyper::header::HeaderValue::from_static("*"));
            let status = u_parts.status;

            if is_context_endpoint && status == StatusCode::OK {
                let collected_bytes = match u_body.collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(_) => Bytes::new(),
                };
                let mut final_json: serde_json::Value = serde_json::from_slice(&collected_bytes)
                    .unwrap_or_else(|_| serde_json::json!({}));

                if let Some(n) = final_json
                    .get("num_ctx")
                    .or_else(|| final_json.get("max_num_ctx"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                {
                    worker.max_num_ctx.store(n, Ordering::Relaxed);
                    let ids = {
                        let s_id = worker.assigned_server_id.read().unwrap().clone();
                        let a_key = worker.assigned_api_key.read().unwrap().clone();
                        match (s_id, a_key) {
                            (Some(s), Some(k)) => Some((s, k)),
                            _ => None,
                        }
                    };
                    if let Some((s_id, a_key)) = ids {
                        if let Ok(mut profile) = state.load_user_profile(&a_key) {
                            if let Some(srv) = profile.servers.get_mut(&s_id) {
                                srv.max_num_ctx = Some(n);
                                let _ = state.save_user_profile(&profile);
                                info!(
                                    "[CONTEXT] olp-proxy synchronized max_num_ctx = {} for server '{}'",
                                    n, s_id
                                );
                            }
                        }
                    }
                    if let Some(obj) = final_json.as_object_mut() {
                        obj.insert("proxy_updated".to_string(), serde_json::json!(true));
                        obj.insert("confirmed".to_string(), serde_json::json!(true));
                    }
                }
                let resp_bytes =
                    serde_json::to_vec(&final_json).unwrap_or_else(|_| collected_bytes.to_vec());
                let resp_len = resp_bytes.len();
                let _hold_permit = permit;
                log_event(status, resp_len, req_size, &model, &active_key_label);
                u_parts.headers.insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                u_parts.headers.insert(
                    hyper::header::CONTENT_LENGTH,
                    hyper::header::HeaderValue::from(resp_len),
                );
                return Ok(Response::from_parts(u_parts, full_body(resp_bytes)));
            }

            let boxed_upstream = u_body.map_err(|e| e).boxed();
            let model_for_log = model.clone();
            let key_for_log = active_key_label.clone();
            let logging_body = LoggingBody::new(boxed_upstream, move |resp_bytes| {
                let _hold_permit_until_stream_finished = permit;
                log_event(status, resp_bytes, req_size, &model_for_log, &key_for_log);
            });
            Ok(Response::from_parts(u_parts, logging_body.boxed()))
        }
        Err(_) => {
            let err_json = r#"{"error":"upstream olp-server failed to respond"}"#;
            log_event(
                StatusCode::BAD_GATEWAY,
                err_json.len(),
                req_size,
                &model,
                &active_key_label,
            );
            let mut resp = Response::new(full_body(err_json));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            Ok(resp)
        }
    }
}
