use crate::cidr::IpFilter;
use crate::config::{expand_path, ProxyConfig};
use crate::keys::{enforce_private_file_permissions, IpRateLimiter, PasskeyVerifier};
use crate::mux::{spawn_mux_session, MuxHandle};
use crate::protocol::{
    configure_tunnel_socket, create_tunnel_tls_server_config, read_frame, verify_proxy_auth_token,
    write_frame, ProxyHelloChallenge, ServerAuthRegister, TunnelEstablished,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
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
use std::sync::atomic::{AtomicU64, Ordering};
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
    Full::new(chunk.into())
        .map_err(|e| match e {})
        .boxed()
}

pub fn build_public_tls_acceptor(config: &ProxyConfig) -> Result<Option<TlsAcceptor>> {
    match config.tls.mode.as_str() {
        "off" => Ok(None),
        "self-signed" => {
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
            let cert_path_str = config.tls.cert_path.as_ref().ok_or_else(|| {
                anyhow!("tls.cert_path is required when tls.mode is set to 'manual'")
            })?;
            let key_path_str = config.tls.key_path.as_ref().ok_or_else(|| {
                anyhow!("tls.key_path is required when tls.mode is set to 'manual'")
            })?;
            let cert_path = expand_path(cert_path_str)?;
            let key_path = expand_path(key_path_str)?;
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
            "Invalid tls.mode '{}' (expected 'off', 'self-signed', or 'manual')",
            other
        )),
    }
}

pub struct PortWorker {
    pub port: u16,
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

pub struct ProxyState {
    pub config: ProxyConfig,
    pub user_verifier: PasskeyVerifier,
    pub allowed_port_range: (u16, u16),
    pub control_port: u16,
    pub server_ip_filter: Arc<IpFilter>,
    pub user_ip_filter: Arc<IpFilter>,
    pub workers: Mutex<HashMap<u16, Arc<PortWorker>>>,
    pub rate_limiter: Arc<IpRateLimiter>,
    pub public_tls_acceptor: Option<TlsAcceptor>,
}

pub fn verify_http_headers_auth(
    headers: &hyper::HeaderMap,
    verifier: &PasskeyVerifier,
) -> bool {
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
                        Some((_user, pass)) => pass,
                        None => decoded_str.as_str(),
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

pub fn verify_http_request_auth(
    req: &Request<Incoming>,
    verifier: &PasskeyVerifier,
) -> bool {
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
    let user_verifier = PasskeyVerifier::from_passkey(&config.auth.passkey_user);

    let server_ip_filter =
        Arc::new(IpFilter::new(&config.security.allowed_server_cidrs).context("Invalid allowed_server_cidrs")?);
    let user_ip_filter =
        Arc::new(IpFilter::new(&config.security.allowed_user_cidrs).context("Invalid allowed_user_cidrs")?);

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
        user_verifier,
        allowed_port_range,
        control_port: local_addr.port(),
        server_ip_filter,
        user_ip_filter,
        workers: Mutex::new(HashMap::new()),
        public_tls_acceptor,
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

    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        acceptor.accept(tcp_stream),
    )
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
    let register: ServerAuthRegister = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame(&mut tls_stream),
    )
    .await
    .context("Timed out waiting for ServerAuthRegister")??;

    // Step 3: Verify passkey_proxy in constant time
    let is_valid = verify_proxy_auth_token(
        &register.auth_token,
        &state.config.auth.passkey_proxy,
        &challenge.proxy_nonce,
    );

    if !is_valid {
        let msg = "ERR_INVALID_PASSKEY_PROXY: The proxy rejected your passkey_proxy. Ensure [server].passkey_proxy in server.toml matches [auth].passkey_proxy in proxy.toml.".to_string();
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
             [AUTH ERROR] Tunnel connection from {} rejected: invalid passkey_proxy!\n\
             Please verify that [server].passkey_proxy in server.toml on the client matches\n\
             [auth].passkey_proxy in proxy.toml on this proxy.\n\
             ================================================================================",
            peer_addr
        );

        return Err(anyhow!(msg));
    }

    let req_port = register.remote_port;

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
    let worker = match get_or_create_port_worker(&state, req_port) {
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
) -> Result<Arc<PortWorker>> {
    let mut guard = state.workers.lock().unwrap();
    if let Some(existing) = guard.get(&port) {
        return Ok(existing.clone());
    }

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let public_listener = bind_reusable_listener(bind_addr)
        .with_context(|| format!("Failed to bind public port {}", port))?;

    let worker = Arc::new(PortWorker {
        port,
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
    // 1. Handle CORS preflight without requiring authentication
    if req.method() == Method::OPTIONS {
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
    if !state.user_ip_filter.is_allowed(&client_ip) {
        warn!(
            "[IP FILTER] Rejected user HTTP connection from {} (not in allowed_user_cidrs)",
            client_ip
        );
        let mut resp = Response::new(full_body(
            r#"{"error":"forbidden: IP address not allowed by proxy filter"}"#,
        ));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    // 3. Check pre-tunnel IP brute-force rate limiter
    if state.rate_limiter.is_locked_out(&client_ip).is_some() {
        let mut resp = Response::new(full_body(
            r#"{"error":"too many failed authentication attempts, try again later"}"#,
        ));
        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        resp.headers_mut()
            .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("60"));
        resp.headers_mut().insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_static("*"),
        );
        return Ok(resp);
    }

    // 4. Verify passkey_user using Basic Auth or Bearer Token in constant time
    if !verify_http_request_auth(&req, &state.user_verifier) {
        state.rate_limiter.record_failure(client_ip);
        let mut resp = Response::new(full_body(
            r#"{"error":"unauthorized: valid Basic Auth (username:passkey_user) or Bearer passkey_user required"}"#,
        ));
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

    state.rate_limiter.record_success(&client_ip);

    // 5. Retrieve active Yamux session
    let mux = {
        let guard = worker.active_mux.read().unwrap();
        guard.clone()
    };

    let mux = match mux {
        Some(m) if !m.is_closed() => m,
        _ => {
            let mut resp = Response::new(full_body(
                r#"{"error":"olp-server tunnel currently offline. Waiting for reconnection..."}"#,
            ));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            return Ok(resp);
        }
    };

    // 6. Open new Yamux substream to `olp-server`
    let mux_stream = match mux.open_stream().await {
        Ok(s) => s,
        Err(_) => {
            let mut resp = Response::new(full_body(
                r#"{"error":"failed to open substream to olp-server"}"#,
            ));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            return Ok(resp);
        }
    };

    // 7. Forward HTTP request with stripped auth headers
    let (mut client_sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(mux_stream)).await {
            Ok(pair) => pair,
            Err(_) => {
                let mut resp = Response::new(full_body(
                    r#"{"error":"failed HTTP handshake over tunnel substream"}"#,
                ));
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

    let (mut parts, body) = req.into_parts();
    parts.headers.remove(AUTHORIZATION);
    parts.headers.remove("x-api-key");
    parts.headers.remove("api-key");
    parts.headers.remove("ollama-api-key");
    parts.headers.remove("x-auth-token");
    let forward_req = Request::from_parts(parts, body);

    match client_sender.send_request(forward_req).await {
        Ok(upstream_resp) => {
            let (mut u_parts, u_body) = upstream_resp.into_parts();
            u_parts
                .headers
                .entry(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .or_insert_with(|| hyper::header::HeaderValue::from_static("*"));
            let boxed_body = u_body.map_err(|e| e).boxed();
            Ok(Response::from_parts(u_parts, boxed_body))
        }
        Err(_) => {
            let mut resp = Response::new(full_body(
                r#"{"error":"upstream olp-server failed to respond"}"#,
            ));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            resp.headers_mut().insert(
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            );
            Ok(resp)
        }
    }
}
