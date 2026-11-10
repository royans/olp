use crate::backoff::FibonacciBackoff;
use crate::config::ServerConfig;
use crate::mux::{spawn_mux_session, CompatYamuxStream};
use crate::protocol::{
    configure_tunnel_socket, create_tunnel_tls_client_config, extract_host, is_sensitive_ollama_op,
    read_frame, write_frame, ProxyHelloChallenge, ServerAuthRegister, TunnelEstablished,
};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, HOST};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};
use yamux::Mode;

type BoxHttpBody = BoxBody<Bytes, hyper::Error>;

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxHttpBody {
    Full::new(chunk.into()).map_err(|e| match e {}).boxed()
}

/// Main entry point for `olp-server`. Maintains a persistent Yamux reverse tunnel
/// over TLS 1.3 to `olp-proxy` with Fibonacci reconnection backoff.
pub async fn run_server_with_shutdown(
    mut config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if config.server.olp_server_id.is_empty() {
        config.server.olp_server_id = crate::config::generate_random_server_id();
        let cfg_path = match std::env::var("OLP_CONFIG") {
            Ok(p) => std::path::PathBuf::from(p),
            Err(_) => match crate::config::olp_home_dir() {
                Ok(h) => h.join("server.toml"),
                Err(_) => std::path::PathBuf::from("server.toml"),
            },
        };
        let _ = config.save_to_path(&cfg_path);
    }

    let verify_ca = config.server.should_verify_ca();
    if verify_ca {
        info!("TLS certificate verification enabled (Mozilla WebPKI CA roots)");
    } else {
        info!("TLS certificate verification skipped (self-signed / internal / local tunnel)");
    }
    let tls_client_cfg = create_tunnel_tls_client_config(verify_ca)?;
    let connector = TlsConnector::from(tls_client_cfg);

    let mut backoff = FibonacciBackoff::new(
        config.reconnect.initial_delay_sec,
        config.reconnect.max_delay_sec,
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("olp-server shutdown signal received");
            return Ok(());
        }

        let session_start = Instant::now();
        let res = run_single_tunnel_session(&mut config, &connector, &mut shutdown_rx).await;

        if *shutdown_rx.borrow() {
            info!("olp-server shutting down cleanly");
            return Ok(());
        }

        // If the tunnel stayed alive for at least 30s, reset Fibonacci sequence
        if session_start.elapsed() >= Duration::from_secs(30) {
            backoff.reset();
        }

        let wait_dur = backoff.next_backoff();
        match res {
            Ok(()) => {
                warn!(
                    "Tunnel disconnected; reconnecting in {:.1}s (Fibonacci attempt #{})",
                    wait_dur.as_secs_f64(),
                    backoff.attempt()
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("CRITICAL CONFIG CONFLICT")
                    || err_str.contains("CRITICAL CONFIG ERROR")
                {
                    error!(
                        "\n================================================================================\n\
                         [CRITICAL CONFIG CONFLICT] Tunnel registration rejected!\n\
                         {}\n\
                         ================================================================================",
                        err_str
                    );
                    return Err(e);
                } else if (err_str.contains("ERR_UNAUTHORIZED_KEY")
                    || err_str.contains("ERR_INVALID_AUTH_TOKEN"))
                    && (backoff.attempt() == 1 || backoff.attempt().is_multiple_of(5))
                {
                    error!(
                        "\n================================================================================\n\
                         [AUTH ERROR] Proxy rejected your olp_api_key!\n\
                         Please check that [server].olp_api_key in ~/.olp/server.toml is a valid\n\
                         user API key recognized by the proxy.\n\
                         ================================================================================"
                    );
                } else if (err_str.contains("TLS 1.3 handshake failed")
                    || err_str.contains("certificate"))
                    && (backoff.attempt() == 1 || backoff.attempt().is_multiple_of(5))
                {
                    error!(
                        "\n================================================================================\n\
                         [TLS ERROR] TLS 1.3 handshake failed connecting to {}!\n\
                         CA verification: {}\n\
                         Broken, missing, or self-signed TLS certificates on the proxy are rejected by\n\
                         Mozilla WebPKI CA roots to prevent MITM attacks.\n\
                         Solutions:\n\
                         1. On olp-proxy: Generate a valid Let's Encrypt certificate (run ./renew-tls.sh).\n\
                         2. For testing/internal environments: Add `tls_verify = false` under [server] in\n\
                            ~/.olp/server.toml to bypass CA verification.\n\
                         ================================================================================",
                        config.server.proxy_addr,
                        if verify_ca { "ENABLED (enforced for domain names)" } else { "DISABLED" }
                    );
                }
                warn!(
                    "Tunnel error ({}); retrying in {:.1}s (Fibonacci attempt #{})",
                    e,
                    wait_dur.as_secs_f64(),
                    backoff.attempt()
                );
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(wait_dur) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Runs a single outbound tunnel session to `olp-proxy`.
pub async fn run_single_tunnel_session(
    config: &mut ServerConfig,
    connector: &TlsConnector,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    info!(
        "Connecting to olp-proxy at {} (TLS 1.3)...",
        config.server.proxy_addr
    );

    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&config.server.proxy_addr),
    )
    .await
    .context("Timed out connecting to olp-proxy")?
    .context("TCP connection to olp-proxy failed")?;

    configure_tunnel_socket(&tcp_stream)?;

    let host = extract_host(&config.server.proxy_addr);
    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("olp-tunnel.internal".to_string()).unwrap());
    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .context("TLS 1.3 handshake timed out")?
    .context("TLS 1.3 handshake failed")?;

    // Step 1: Read ProxyHelloChallenge
    let challenge: ProxyHelloChallenge =
        tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls_stream))
            .await
            .context("Timed out waiting for ProxyHelloChallenge")??;

    // Step 2: Send ServerAuthRegister with auth token computed from olp_api_key and optional policy override
    let mut reg_keys = std::collections::HashMap::new();
    for (label, kcfg) in &config.server.keys {
        reg_keys.insert(
            label.clone(),
            crate::protocol::ScopedKeyRegistration {
                passkey: kcfg.passkey.clone(),
                hash: kcfg.hash.clone(),
                scope: kcfg.scope.to_string(),
            },
        );
    }
    let register = ServerAuthRegister::with_keys(
        &config.server.olp_api_key,
        &config.server.olp_server_id,
        config.server.remote_port,
        &config.server.passkey_user,
        &challenge.proxy_nonce,
        config.server.read_only,
        reg_keys,
    );

    tokio::time::timeout(
        Duration::from_secs(10),
        write_frame(&mut tls_stream, &register),
    )
    .await
    .context("Timed out sending ServerAuthRegister")??;

    // Step 3: Read TunnelEstablished confirmation
    let established: TunnelEstablished =
        tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls_stream))
            .await
            .context("Timed out waiting for TunnelEstablished")??;

    if !established.accepted {
        return Err(anyhow!(
            "olp-proxy rejected tunnel registration: {}",
            established.message
        ));
    }

    info!(
        "TLS 1.3 tunnel established! Exposing local Ollama ({}) on remote port :{} (server_id: {})",
        config.server.ollama_addr, established.assigned_port, config.server.olp_server_id
    );

    // Save assigned_port back into server config if different
    if config.server.remote_port != Some(established.assigned_port) {
        config.server.remote_port = Some(established.assigned_port);
        let cfg_path = match std::env::var("OLP_CONFIG") {
            Ok(p) => std::path::PathBuf::from(p),
            Err(_) => match crate::config::olp_home_dir() {
                Ok(h) => h.join("server.toml"),
                Err(_) => std::path::PathBuf::from("server.toml"),
            },
        };
        if let Err(e) = config.save_to_path(&cfg_path) {
            warn!(
                "Failed to persist assigned port to {}: {}",
                cfg_path.display(),
                e
            );
        }
    }

    // Upgrade connection to Yamux multiplexer
    let (mux_handle, mut inbound_rx) = spawn_mux_session(tls_stream, Mode::Client, 128);

    let hb_interval = Duration::from_secs(config.reconnect.heartbeat_interval_sec.max(1));
    let hb_timeout = Duration::from_secs(config.reconnect.heartbeat_timeout_sec.max(1));
    let ollama_addr = config.server.ollama_addr.clone();
    let model_tracker = Arc::new(ActiveModelTracker::new(ollama_addr.clone()));
    let cfg_arc = Arc::new(config.clone());

    let mut ticker = tokio::time::interval(hb_interval);
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            maybe_stream = inbound_rx.recv() => {
                match maybe_stream {
                    Some(yamux_stream) => {
                        let cfg = cfg_arc.clone();
                        let tracker = model_tracker.clone();
                        tokio::spawn(async move {
                            serve_proxied_ollama_stream(yamux_stream, cfg, tracker).await;
                        });
                    }
                    None => {
                        return Err(anyhow!("Tunnel multiplexer closed by peer"));
                    }
                }
            }
            _ = ticker.tick() => {
                let ping_res = tokio::time::timeout(hb_timeout, async {
                    let mut stream = mux_handle.open_stream().await?;
                    stream.write_all(b"PING\n").await?;
                    stream.flush().await?;
                    let mut reader = TokioBufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).await?;
                    if line.trim() == "PONG" {
                        Ok::<(), anyhow::Error>(())
                    } else {
                        Err(anyhow!("Unexpected heartbeat response"))
                    }
                }).await;

                match ping_res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        return Err(anyhow!("Heartbeat ping failed: {}", e));
                    }
                    Err(_) => {
                        return Err(anyhow!("Heartbeat ping timed out after {:?}", hb_timeout));
                    }
                }
            }
        }
    }
}

type ModelCache = Arc<tokio::sync::RwLock<Option<(Option<String>, Instant)>>>;

/// Tracks the active loaded model on local Ollama with a short TTL cache.
/// When any client sends a request specifying any model name (e.g. `llama3.1`, `auto`, etc.),
/// olp-server rewrites the JSON model field to whatever is currently loaded in Ollama.
#[derive(Clone)]
pub struct ActiveModelTracker {
    pub ollama_addr: String,
    cache: ModelCache,
    ttl: Duration,
}

impl ActiveModelTracker {
    pub fn new(ollama_addr: String) -> Self {
        Self {
            ollama_addr,
            cache: Arc::new(tokio::sync::RwLock::new(None)),
            ttl: Duration::from_secs(3),
        }
    }

    /// Resolves the model to use:
    /// 1. If any model is currently loaded in VRAM (/api/ps), return that model name.
    /// 2. If nothing is currently loaded in /api/ps, check installed models (/api/tags) and return the first one.
    /// 3. Otherwise return None.
    pub async fn resolve_active_model(&self) -> Option<String> {
        // Fast path: cached resolution within TTL
        {
            let guard = self.cache.read().await;
            if let Some((ref maybe_model, ref timestamp)) = *guard {
                if timestamp.elapsed() < self.ttl {
                    return maybe_model.clone();
                }
            }
        }

        // Slow path: query local Ollama
        let discovered = self.query_ollama_for_active_model().await;
        let mut guard = self.cache.write().await;
        *guard = Some((discovered.clone(), Instant::now()));
        discovered
    }

    async fn query_ollama_for_active_model(&self) -> Option<String> {
        // 1. Try /api/ps (models loaded in VRAM)
        if let Ok(val) = query_ollama_json(&self.ollama_addr, "/api/ps").await {
            if let Some(models) = val.get("models").and_then(|m| m.as_array()) {
                if let Some(first) = models.first() {
                    if let Some(name) = first
                        .get("name")
                        .or_else(|| first.get("model"))
                        .and_then(|n| n.as_str())
                    {
                        let trimmed = name.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }

        // 2. Fall back to /api/tags (installed models on disk)
        if let Ok(val) = query_ollama_json(&self.ollama_addr, "/api/tags").await {
            if let Some(models) = val.get("models").and_then(|m| m.as_array()) {
                if let Some(first) = models.first() {
                    if let Some(name) = first
                        .get("name")
                        .or_else(|| first.get("model"))
                        .and_then(|n| n.as_str())
                    {
                        let trimmed = name.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }

        None
    }
}

async fn query_ollama_json(ollama_addr: &str, path: &str) -> Result<serde_json::Value> {
    let connect_res =
        tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(ollama_addr))
            .await
            .context("Connection timed out")?
            .context("Failed to connect to local Ollama")?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(connect_res))
        .await
        .context("Handshake with local Ollama failed")?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(HOST, ollama_addr)
        .body(full_body(Bytes::new()))
        .context("Failed to build request")?;

    let resp = tokio::time::timeout(Duration::from_millis(800), sender.send_request(req))
        .await
        .context("Request timed out")?
        .context("Failed to receive response from local Ollama")?;

    let body_bytes = tokio::time::timeout(Duration::from_millis(800), resp.into_body().collect())
        .await
        .context("Body read timed out")?
        .context("Failed to read response body")?
        .to_bytes();

    let json: serde_json::Value =
        serde_json::from_slice(&body_bytes).context("Failed to parse JSON response from Ollama")?;

    Ok(json)
}

async fn serve_proxied_ollama_stream(
    yamux_stream: CompatYamuxStream,
    config: Arc<ServerConfig>,
    model_tracker: Arc<ActiveModelTracker>,
) {
    let service = service_fn(move |req: Request<Incoming>| {
        let cfg = config.clone();
        let tracker = model_tracker.clone();
        async move { forward_to_local_ollama(req, &cfg, &tracker).await }
    });

    let _ = server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(yamux_stream), service)
        .await;
}

async fn forward_to_local_ollama(
    req: Request<Incoming>,
    config: &ServerConfig,
    model_tracker: &ActiveModelTracker,
) -> std::result::Result<Response<BoxHttpBody>, hyper::Error> {
    if req.method() == Method::CONNECT {
        let mut resp = Response::new(full_body(r#"{"error":"CONNECT method is forbidden"}"#));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let clean_path = path_and_query.split('?').next().unwrap_or(&path_and_query);

    // Stricter-wins determination of inference scope:
    // 1. If server config specifies read_only = true, authoritative defense-in-depth enforces inference scope.
    // 2. Otherwise check x-olp-scope header from proxy.
    // 3. If x-olp-scope is "manage", check if server's configured keys allow manage for x-olp-key-label.
    let server_read_only = config.server.read_only.unwrap_or(false);
    let proxy_scope_header = req
        .headers()
        .get("x-olp-scope")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("inference");
    let key_label_header = req
        .headers()
        .get("x-olp-key-label")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");

    let is_inference_scope = if server_read_only || proxy_scope_header != "manage" {
        true
    } else if let Some(key_cfg) = config.server.keys.get(key_label_header) {
        key_cfg.scope == crate::config::KeyScope::Inference
    } else {
        false
    };

    if is_inference_scope && is_sensitive_ollama_op(req.method(), &path_and_query) {
        let (err_json, reason) =
            crate::protocol::format_read_only_error(&path_and_query, req.method());
        warn!(
            "[POLICY BLOCKED] Blocked sensitive Ollama operation '{} {}' on server (read-only mode active: {})",
            req.method(),
            clean_path,
            reason
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

    let (mut parts, incoming_body) = req.into_parts();

    if let Ok(clean_uri) = Uri::builder().path_and_query(&path_and_query).build() {
        parts.uri = clean_uri;
    }

    parts.headers.remove(AUTHORIZATION);
    parts.headers.remove("x-olp-scope");
    parts.headers.remove("x-olp-key-label");
    let ollama_addr = &config.server.ollama_addr;
    if let Ok(host_val) = hyper::header::HeaderValue::from_str(ollama_addr) {
        parts.headers.insert(HOST, host_val);
    }

    // Determine outgoing request body. For inference requests, normalize options, keep_alive, and model.
    let outgoing_body: BoxHttpBody = if parts.method == Method::GET || parts.method == Method::HEAD
    {
        full_body(Bytes::new())
    } else {
        let body_bytes = match incoming_body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => return Err(e),
        };

        let mut final_bytes = body_bytes.clone();
        if let Ok(mut json_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if let Some(obj) = json_val.as_object_mut() {
                // Perform body normalization if in inference scope:
                if is_inference_scope {
                    // 1. keep_alive: clamp to range [keep_alive_min, keep_alive_max], never forward 0 or negative
                    let min_secs =
                        crate::config::parse_duration_seconds(&config.server.keep_alive_min)
                            .unwrap_or(60)
                            .max(1);
                    let max_secs =
                        crate::config::parse_duration_seconds(&config.server.keep_alive_max)
                            .unwrap_or(1800)
                            .max(min_secs);

                    if let Some(ka) = obj.get_mut("keep_alive") {
                        if let Some(num) = ka.as_i64() {
                            if num < 0 {
                                *ka = serde_json::json!(max_secs);
                            } else if num == 0 || num < min_secs {
                                *ka = serde_json::json!(min_secs);
                            } else if num > max_secs {
                                *ka = serde_json::json!(max_secs);
                            }
                        } else if let Some(s) = ka.as_str() {
                            if s == "-1" || s.starts_with('-') {
                                *ka = serde_json::json!(config.server.keep_alive_max);
                            } else {
                                let parsed = crate::config::parse_duration_seconds(s).unwrap_or(0);
                                if parsed == 0 || parsed < min_secs {
                                    *ka = serde_json::json!(config.server.keep_alive_min);
                                } else if parsed > max_secs {
                                    *ka = serde_json::json!(config.server.keep_alive_max);
                                }
                            }
                        }
                    }

                    // 2. options: cap num_ctx and num_predict, strip hardware placement options
                    let max_ctx = config.server.max_num_ctx;
                    let max_predict = config.server.max_num_predict;

                    const HARDWARE_OPTS: &[&str] = &[
                        "num_gpu",
                        "main_gpu",
                        "num_thread",
                        "use_mmap",
                        "use_mlock",
                        "low_vram",
                        "numa",
                    ];
                    for hw in HARDWARE_OPTS {
                        obj.remove(*hw);
                    }

                    let options = obj
                        .entry("options")
                        .or_insert_with(|| serde_json::json!({}))
                        .as_object_mut();
                    if let Some(options) = options {
                        for hw in HARDWARE_OPTS {
                            options.remove(*hw);
                        }
                        if let Some(ctx) = options.get_mut("num_ctx") {
                            if let Some(c) = ctx.as_u64() {
                                if c > max_ctx as u64 {
                                    *ctx = serde_json::json!(max_ctx);
                                }
                            }
                        } else {
                            options.insert("num_ctx".to_string(), serde_json::json!(max_ctx));
                        }
                        if let Some(predict) = options.get_mut("num_predict") {
                            if let Some(p) = predict.as_i64() {
                                if p == -1 || p > max_predict as i64 {
                                    *predict = serde_json::json!(max_predict);
                                }
                            }
                        }
                    }

                    // Cap /v1 max_tokens and max_completion_tokens
                    if clean_path.starts_with("/v1/chat/completions")
                        || clean_path.starts_with("/v1/completions")
                    {
                        if let Some(mt) = obj.get_mut("max_tokens") {
                            if mt.is_null() {
                                *mt = serde_json::json!(max_predict);
                            } else if let Some(p) = mt.as_i64() {
                                if p == -1 || p > max_predict as i64 {
                                    *mt = serde_json::json!(max_predict);
                                }
                            }
                        } else {
                            obj.insert("max_tokens".to_string(), serde_json::json!(max_predict));
                        }

                        if let Some(mct) = obj.get_mut("max_completion_tokens") {
                            if let Some(p) = mct.as_i64() {
                                if p == -1 || p > max_predict as i64 {
                                    *mct = serde_json::json!(max_predict);
                                }
                            }
                        }
                    }
                }

                // 3. Model selection & rewriting
                let allowed = &config.server.allowed_models;
                let default_model = &config.server.default_model;

                if !allowed.is_empty() {
                    // Explicit allowed_models list
                    let req_model = obj.get("model").and_then(|v| v.as_str()).unwrap_or("");
                    let is_allowed = allowed
                        .iter()
                        .any(|m| m == req_model || m == &format!("{}:latest", req_model));
                    if !is_allowed {
                        let fallback = if !default_model.is_empty() {
                            default_model.clone()
                        } else if let Some(loaded) = model_tracker.resolve_active_model().await {
                            loaded
                        } else {
                            allowed[0].clone()
                        };
                        info!(
                            "[Model-Filter] Disallowed model '{}' rewritten to fallback '{}' for {}",
                            req_model, fallback, path_and_query
                        );
                        obj.insert("model".to_string(), serde_json::Value::String(fallback));
                    }

                    if clean_path.starts_with("/api/show") {
                        let req_name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let is_allowed_name = allowed
                            .iter()
                            .any(|m| m == req_name || m == &format!("{}:latest", req_name));
                        if !is_allowed_name {
                            let fallback = if !default_model.is_empty() {
                                default_model.clone()
                            } else if let Some(loaded) = model_tracker.resolve_active_model().await
                            {
                                loaded
                            } else {
                                allowed[0].clone()
                            };
                            obj.insert("name".to_string(), serde_json::Value::String(fallback));
                        }
                    }
                } else {
                    // allowed_models is empty: auto-map to active loaded model if present
                    if let Some(active_model) = model_tracker.resolve_active_model().await {
                        if let Some(model_entry) = obj.get_mut("model") {
                            let current_requested = model_entry.as_str().unwrap_or_default();
                            if current_requested != active_model {
                                info!(
                                    "[Auto-Model] Rewriting requested model '{}' -> active loaded model '{}' for {}",
                                    current_requested, active_model, path_and_query
                                );
                                *model_entry = serde_json::Value::String(active_model.clone());
                            }
                        } else if clean_path.starts_with("/api/chat")
                            || clean_path.starts_with("/api/generate")
                            || clean_path.starts_with("/api/embeddings")
                            || clean_path.starts_with("/api/embed")
                            || clean_path.starts_with("/v1/chat/completions")
                            || clean_path.starts_with("/v1/completions")
                            || clean_path.starts_with("/v1/embeddings")
                        {
                            info!(
                                "[Auto-Model] Injecting active loaded model '{}' into request for {}",
                                active_model, path_and_query
                            );
                            obj.insert(
                                "model".to_string(),
                                serde_json::Value::String(active_model.clone()),
                            );
                        }

                        if clean_path.starts_with("/api/show") {
                            if let Some(name_entry) = obj.get_mut("name") {
                                let current_name = name_entry.as_str().unwrap_or_default();
                                if current_name != active_model {
                                    *name_entry = serde_json::Value::String(active_model.clone());
                                }
                            }
                        }
                    }
                }

                if let Ok(serialized) = serde_json::to_vec(&json_val) {
                    final_bytes = Bytes::from(serialized);
                }
            }
        }

        parts.headers.insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from(final_bytes.len()),
        );
        full_body(final_bytes)
    };

    let outgoing_req = Request::from_parts(parts, outgoing_body);

    let upstream_tcp =
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(ollama_addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                let msg = format!(
                    r#"{{"error":"local ollama service unreachable at {}"}}"#,
                    ollama_addr
                );
                let mut resp = Response::new(full_body(msg));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        };

    let (mut client_sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(upstream_tcp)).await {
            Ok(pair) => pair,
            Err(_) => {
                let mut resp = Response::new(full_body(
                    r#"{"error":"failed HTTP handshake with local ollama"}"#,
                ));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        };

    tokio::spawn(async move {
        let _ = conn.await;
    });

    match client_sender.send_request(outgoing_req).await {
        Ok(upstream_resp) => {
            let (mut u_parts, u_body) = upstream_resp.into_parts();
            // Check if discovery filtering or context clamping is required
            if (clean_path == "/api/tags" || clean_path == "/api/ps")
                && !config.server.allowed_models.is_empty()
            {
                match u_body.collect().await {
                    Ok(resp_bytes) => {
                        let mut b = resp_bytes.to_bytes();
                        if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&b) {
                            if let Some(models) =
                                json.get_mut("models").and_then(|v| v.as_array_mut())
                            {
                                models.retain(|m| {
                                    let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                    let model =
                                        m.get("model").and_then(|v| v.as_str()).unwrap_or("");
                                    config
                                        .server
                                        .allowed_models
                                        .iter()
                                        .any(|am| am == name || am == model)
                                });
                            }
                            if let Ok(s) = serde_json::to_vec(&json) {
                                b = Bytes::from(s);
                            }
                        }
                        u_parts.headers.remove(hyper::header::TRANSFER_ENCODING);
                        u_parts.headers.insert(
                            hyper::header::CONTENT_LENGTH,
                            hyper::header::HeaderValue::from(b.len()),
                        );
                        Ok(Response::from_parts(u_parts, full_body(b)))
                    }
                    Err(e) => Err(e),
                }
            } else if clean_path == "/v1/models" && !config.server.allowed_models.is_empty() {
                match u_body.collect().await {
                    Ok(resp_bytes) => {
                        let mut b = resp_bytes.to_bytes();
                        if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&b) {
                            if let Some(data) = json.get_mut("data").and_then(|v| v.as_array_mut())
                            {
                                data.retain(|m| {
                                    let id = m.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                    config.server.allowed_models.iter().any(|am| am == id)
                                });
                            }
                            if let Ok(s) = serde_json::to_vec(&json) {
                                b = Bytes::from(s);
                            }
                        }
                        u_parts.headers.remove(hyper::header::TRANSFER_ENCODING);
                        u_parts.headers.insert(
                            hyper::header::CONTENT_LENGTH,
                            hyper::header::HeaderValue::from(b.len()),
                        );
                        Ok(Response::from_parts(u_parts, full_body(b)))
                    }
                    Err(e) => Err(e),
                }
            } else if clean_path == "/api/show" {
                match u_body.collect().await {
                    Ok(resp_bytes) => {
                        let mut b = resp_bytes.to_bytes();
                        if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&b) {
                            let max_ctx = config.server.max_num_ctx;
                            if let Some(model_info) =
                                json.get_mut("model_info").and_then(|v| v.as_object_mut())
                            {
                                for (k, v) in model_info.iter_mut() {
                                    if k.ends_with(".context_length") {
                                        if let Some(num) = v.as_u64() {
                                            if num > max_ctx as u64 {
                                                *v = serde_json::json!(max_ctx);
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(details) =
                                json.get_mut("details").and_then(|v| v.as_object_mut())
                            {
                                if let Some(v) = details.get_mut("context_length") {
                                    if let Some(num) = v.as_u64() {
                                        if num > max_ctx as u64 {
                                            *v = serde_json::json!(max_ctx);
                                        }
                                    }
                                }
                            }
                            if let Ok(s) = serde_json::to_vec(&json) {
                                b = Bytes::from(s);
                            }
                        }
                        u_parts.headers.remove(hyper::header::TRANSFER_ENCODING);
                        u_parts.headers.insert(
                            hyper::header::CONTENT_LENGTH,
                            hyper::header::HeaderValue::from(b.len()),
                        );
                        Ok(Response::from_parts(u_parts, full_body(b)))
                    }
                    Err(e) => Err(e),
                }
            } else {
                let boxed_body = u_body.map_err(|e| e).boxed();
                Ok(Response::from_parts(u_parts, boxed_body))
            }
        }
        Err(_) => {
            let mut resp = Response::new(full_body(
                r#"{"error":"local ollama stream terminated prematurely"}"#,
            ));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}
