use crate::config::{expand_path, ProxyConfig};
use crate::keys::{format_pubkey, load_or_generate_keypair, verify_authorized_key, PasskeyVerifier};
use crate::mux::{spawn_mux_session, MuxHandle};
use crate::protocol::{
    configure_tunnel_socket, create_tunnel_tls_server_config, read_frame, write_frame,
    ProxyHelloChallenge, ServerAuthRegister, TunnelEstablished, EXPORTER_LABEL,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, RETRY_AFTER, WWW_AUTHENTICATE};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use yamux::Mode;

type BoxHttpBody = BoxBody<Bytes, hyper::Error>;

fn full_body(s: impl Into<Bytes>) -> BoxHttpBody {
    Full::new(s.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Sliding-window per-IP authentication failure rate limiter.
pub struct IpRateLimiter {
    max_failures_per_min: u32,
    records: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl IpRateLimiter {
    pub fn new(max_failures_per_min: u32) -> Self {
        Self {
            max_failures_per_min: max_failures_per_min.max(1),
            records: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_rate_limited(&self, ip: IpAddr) -> bool {
        let mut guard = self.records.lock().unwrap();
        let now = Instant::now();
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        if let Some(times) = guard.get_mut(&ip) {
            times.retain(|&t| t > cutoff);
            times.len() as u32 >= self.max_failures_per_min
        } else {
            false
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut guard = self.records.lock().unwrap();
        let now = Instant::now();
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        let entry = guard.entry(ip).or_default();
        entry.retain(|&t| t > cutoff);
        entry.push(now);
    }

    pub fn clear_ip(&self, ip: IpAddr) {
        let mut guard = self.records.lock().unwrap();
        guard.remove(&ip);
    }
}

/// Manages a persistent public port listener and its hot-swappable tunnel session.
pub struct PortWorker {
    pub port: u16,
    pub owner_pubkey: RwLock<[u8; 32]>,
    pub verifier: RwLock<PasskeyVerifier>,
    pub active_mux: RwLock<Option<MuxHandle>>,
    pub session_gen: AtomicU64,
    pub shutdown_notify: Notify,
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

/// Shared state across the `olp-proxy` instance.
pub struct ProxyState {
    pub config: ProxyConfig,
    pub signing_key: SigningKey,
    pub auth_keys_path: PathBuf,
    pub allowed_port_range: (u16, u16),
    pub control_port: u16,
    pub workers: Mutex<HashMap<u16, Arc<PortWorker>>>,
    pub rate_limiter: Arc<IpRateLimiter>,
    pub public_tls_acceptor: Option<TlsAcceptor>,
}

/// Extracts and validates the user passkey from Basic Auth or Bearer Token headers.
pub fn verify_http_headers_auth(
    headers: &hyper::HeaderMap,
    verifier: &PasskeyVerifier,
) -> bool {
    let auth_header = match headers.get(AUTHORIZATION) {
        Some(h) => match h.to_str() {
            Ok(s) => s.trim(),
            Err(_) => return false,
        },
        None => return false,
    };

    if let Some(token) = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
    {
        return verifier.verify(token.trim());
    }

    if let Some(b64) = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))
    {
        if let Ok(decoded_bytes) = BASE64.decode(b64.trim()) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                let candidate = match decoded_str.split_once(':') {
                    Some((_user, pass)) => pass,
                    None => decoded_str.as_str(),
                };
                return verifier.verify(candidate);
            }
        }
    }

    false
}

/// Extracts and validates the user passkey from an incoming HTTP request.
pub fn verify_http_request_auth(
    req: &Request<Incoming>,
    verifier: &PasskeyVerifier,
) -> bool {
    verify_http_headers_auth(req.headers(), verifier)
}

/// Builds the optional TLS acceptor for public user ports (`off`, `self-signed`, or `manual`).
fn build_public_tls_acceptor(cfg: &ProxyConfig) -> Result<Option<TlsAcceptor>> {
    let mode = cfg.tls.mode.trim().to_lowercase();
    if mode == "off" || mode == "http" || mode.is_empty() {
        return Ok(None);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    if mode == "self-signed" {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = CertificateDer::from(cert.cert);
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;
        return Ok(Some(TlsAcceptor::from(Arc::new(tls_cfg))));
    }

    if mode == "manual" {
        let cert_path = expand_path(
            cfg.tls
                .cert_path
                .as_deref()
                .ok_or_else(|| anyhow!("tls.cert_path required when tls.mode = 'manual'"))?,
        )?;
        let key_path = expand_path(
            cfg.tls
                .key_path
                .as_deref()
                .ok_or_else(|| anyhow!("tls.key_path required when tls.mode = 'manual'"))?,
        )?;

        let cert_file = File::open(&cert_path)
            .with_context(|| format!("Failed to open TLS cert {}", cert_path.display()))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;

        let key_file = File::open(&key_path)
            .with_context(|| format!("Failed to open TLS key {}", key_path.display()))?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow!("No private key found in {}", key_path.display()))?;

        let tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        return Ok(Some(TlsAcceptor::from(Arc::new(tls_cfg))));
    }

    Err(anyhow!(
        "Unsupported tls.mode '{}' (supported: 'off', 'self-signed', 'manual')",
        mode
    ))
}

/// Binds a TCP listener with `SO_REUSEADDR` enabled.
pub fn bind_reusable_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

/// Starts the `olp-proxy` server using the provided configuration and returns the bound control address
/// and a join handle for the background server loop.
pub async fn start_proxy_server(
    config: ProxyConfig,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let priv_path = expand_path(&config.keys.private_key)?;
    let signing_key = load_or_generate_keypair(&priv_path, "olp-proxy-ed25519")?;
    let auth_keys_path = expand_path(&config.keys.authorized_keys)?;
    let allowed_port_range = config.parse_allowed_port_range()?;
    let public_tls_acceptor = build_public_tls_acceptor(&config)?;

    let listen_sock_addr: SocketAddr = config
        .proxy
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid proxy.listen_addr '{}'", config.proxy.listen_addr))?;

    let listener = bind_reusable_listener(listen_sock_addr)?;
    let local_addr = listener.local_addr()?;

    let tls_server_cfg = create_tunnel_tls_server_config()?;
    let tunnel_tls_acceptor = TlsAcceptor::from(tls_server_cfg);

    let state = Arc::new(ProxyState {
        rate_limiter: Arc::new(IpRateLimiter::new(
            config.security.max_auth_failures_per_min,
        )),
        config,
        signing_key,
        auth_keys_path,
        allowed_port_range,
        control_port: local_addr.port(),
        workers: Mutex::new(HashMap::new()),
        public_tls_acceptor,
    });

    info!(
        "olp-proxy listening for olp-server tunnels on {}",
        local_addr
    );

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let state_clone = state.clone();
                    let acceptor = tunnel_tls_acceptor.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_incoming_tunnel(tcp_stream, peer_addr, acceptor, state_clone)
                                .await
                        {
                            warn!("Tunnel connection from {} ended: {}", peer_addr, e);
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

    // Enforce 10-second handshake timeout against port scanners
    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        acceptor.accept(tcp_stream),
    )
    .await
    .context("TLS handshake timed out")?
    .context("TLS handshake failed")?;

    // Extract RFC 8446 TLS 1.3 Exporter channel binding value
    let mut exporter = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, EXPORTER_LABEL, None)
        .context("Failed to derive RFC 8446 TLS exporter")?;

    // Step 1: Send ProxyHelloChallenge
    let challenge = ProxyHelloChallenge::create(&state.signing_key, &exporter);
    tokio::time::timeout(
        Duration::from_secs(10),
        write_frame(&mut tls_stream, &challenge),
    )
    .await
    .context("Timed out sending ProxyHelloChallenge")??;

    // Step 2: Receive ServerAuthRegister
    let register: ServerAuthRegister = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame(&mut tls_stream),
    )
    .await
    .context("Timed out waiting for ServerAuthRegister")??;

    // Verify server signature over TLS exporter & challenge nonce
    let server_key = match register.verify(&exporter, &challenge.proxy_nonce) {
        Ok(k) => k,
        Err(e) => {
            let _ = write_frame(
                &mut tls_stream,
                &TunnelEstablished {
                    accepted: false,
                    message: format!("ERR_SIGNATURE_INVALID: {}", e),
                },
            )
            .await;
            return Err(e);
        }
    };

    let req_port = register.remote_port;

    // Check authorized_keys dynamically (supports hot-reload without restarting olp-proxy!)
    let is_authorized = verify_authorized_key(&state.auth_keys_path, &server_key, req_port)
        .unwrap_or(false);
    if !is_authorized {
        let key_str = format_pubkey("olp-server-ed25519", &server_key);
        let msg = format!(
            "ERR_UNAUTHORIZED_KEY: server public key '{}' is not in proxy authorized_keys (or port {} not permitted)",
            key_str, req_port
        );
        let _ = write_frame(
            &mut tls_stream,
            &TunnelEstablished {
                accepted: false,
                message: msg.clone(),
            },
        )
        .await;

        error!(
            "\n================================================================================\n\
             [UNAUTHORIZED TUNNEL ATTEMPT] from {}\n\
             Server Public Key : {}\n\
             Requested Port    : {}\n\n\
             To authorize this server on this proxy, run:\n\
               ./start-proxy.sh --add-key \"{}\"\n\
             (or append that line to {})\n\
             ================================================================================",
            peer_addr,
            key_str,
            req_port,
            key_str,
            state.auth_keys_path.display()
        );

        return Err(anyhow!(msg));
    }

    // Check port range guardrails
    let (min_port, max_port) = state.allowed_port_range;
    if req_port < min_port || req_port > max_port || req_port == state.control_port {
        let msg = format!(
            "ERR_PORT_FORBIDDEN: requested port {} is outside allowed range {}-{} (or conflicts with control port)",
            req_port, min_port, max_port
        );
        let _ = write_frame(
            &mut tls_stream,
            &TunnelEstablished {
                accepted: false,
                message: msg.clone(),
            },
        )
        .await;
        return Err(anyhow!(msg));
    }

    // Acquire or hot-swap PortWorker for `req_port`
    let worker = match get_or_create_port_worker(
        &state,
        req_port,
        register.server_pubkey,
        register.passkey_verifier.clone(),
    ) {
        Ok(w) => w,
        Err(e) => {
            let _ = write_frame(
                &mut tls_stream,
                &TunnelEstablished {
                    accepted: false,
                    message: format!("ERR_PORT_CONFLICT: {}", e),
                },
            )
            .await;
            return Err(e);
        }
    };

    // Acknowledge tunnel registration before upgrading stream to Yamux
    write_frame(
        &mut tls_stream,
        &TunnelEstablished {
            accepted: true,
            message: format!("Port {} bound successfully", req_port),
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
        *worker.owner_pubkey.write().unwrap() = register.server_pubkey;
        *worker.verifier.write().unwrap() = register.passkey_verifier;
        *worker.active_mux.write().unwrap() = Some(mux_handle);
    }

    info!(
        "Tunnel established from {} -> public port :{} (session #{})",
        peer_addr, req_port, my_gen
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
            req_port, state.config.proxy.listener_grace_period_sec
        );
    }

    Ok(())
}

fn get_or_create_port_worker(
    state: &Arc<ProxyState>,
    port: u16,
    server_pubkey: [u8; 32],
    verifier: PasskeyVerifier,
) -> Result<Arc<PortWorker>> {
    let mut guard = state.workers.lock().unwrap();
    if let Some(existing) = guard.get(&port) {
        let current_owner = *existing.owner_pubkey.read().unwrap();
        if current_owner != server_pubkey && existing.has_active_session() {
            return Err(anyhow!(
                "Port {} is currently in use by another authenticated olp-server",
                port
            ));
        }
        return Ok(existing.clone());
    }

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let public_listener = bind_reusable_listener(bind_addr)
        .with_context(|| format!("Failed to bind public port {}", port))?;

    let worker = Arc::new(PortWorker {
        port,
        owner_pubkey: RwLock::new(server_pubkey),
        verifier: RwLock::new(verifier),
        active_mux: RwLock::new(None),
        session_gen: AtomicU64::new(0),
        shutdown_notify: Notify::new(),
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
    info!("Public Ollama endpoint listening on 0.0.0.0:{}", worker.port);
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let _ = stream.set_nodelay(true);
                let worker_ref = worker.clone();
                let state_ref = state.clone();
                tokio::spawn(async move {
                    if let Some(ref acceptor) = state_ref.public_tls_acceptor {
                        match tokio::time::timeout(
                            Duration::from_secs(10),
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(tls_stream)) => {
                                serve_public_http_connection(
                                    tls_stream,
                                    client_addr.ip(),
                                    worker_ref,
                                    state_ref,
                                )
                                .await;
                            }
                            _ => {}
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
    let service = service_fn(move |req: Request<Incoming>| {
        let worker = worker.clone();
        let state = state.clone();
        async move { handle_public_http_request(req, client_ip, worker, state).await }
    });

    let _ = server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(io), service)
        .await;
}

async fn handle_public_http_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    worker: Arc<PortWorker>,
    state: Arc<ProxyState>,
) -> std::result::Result<Response<BoxHttpBody>, hyper::Error> {
    // 1. Check pre-tunnel IP brute-force rate limiter
    if state.rate_limiter.is_rate_limited(client_ip) {
        let mut resp = Response::new(full_body(
            r#"{"error":"too many failed authentication attempts, try again later"}"#,
        ));
        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        resp.headers_mut()
            .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("60"));
        return Ok(resp);
    }

    // 2. Verify Basic Auth or Bearer Token in constant time
    let verifier = worker.verifier.read().unwrap().clone();
    if !verify_http_request_auth(&req, &verifier) {
        state.rate_limiter.record_failure(client_ip);
        let mut resp = Response::new(full_body(
            r#"{"error":"unauthorized: valid Basic Auth or Bearer passkey required"}"#,
        ));
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        resp.headers_mut().insert(
            WWW_AUTHENTICATE,
            hyper::header::HeaderValue::from_static(r#"Basic realm="Ollama Proxy""#),
        );
        return Ok(resp);
    }

    // 3. Obtain current hot-swappable MuxHandle
    let mux_opt = worker.active_mux.read().unwrap().clone();
    let mux = match mux_opt {
        Some(m) if !m.is_closed() => m,
        _ => {
            let mut resp = Response::new(full_body(
                r#"{"error":"olp-server tunnel is currently disconnected or reconnecting"}"#,
            ));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut()
                .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("2"));
            return Ok(resp);
        }
    };

    // 4. Open multiplexed stream to `olp-server`
    let yamux_stream = match mux.open_stream().await {
        Ok(s) => s,
        Err(_) => {
            let mut resp = Response::new(full_body(
                r#"{"error":"failed to open multiplexed stream to olp-server"}"#,
            ));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut()
                .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("2"));
            return Ok(resp);
        }
    };

    // 5. Stream HTTP request & response over the yamux stream with zero full-body buffering
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(yamux_stream)).await {
            Ok(pair) => pair,
            Err(_) => {
                let mut resp = Response::new(full_body(
                    r#"{"error":"tunnel stream HTTP handshake failed"}"#,
                ));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    match sender.send_request(req).await {
        Ok(upstream_resp) => Ok(upstream_resp.map(|b| b.boxed())),
        Err(_) => {
            let mut resp = Response::new(full_body(
                r#"{"error":"olp-server tunnel disconnected or reconnecting"}"#,
            ));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut()
                .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("2"));
            Ok(resp)
        }
    }
}
