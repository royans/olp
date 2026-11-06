use crate::backoff::FibonacciBackoff;
use crate::config::{expand_path, ServerConfig};
use crate::keys::{format_pubkey, load_or_generate_keypair, parse_pubkey, PasskeyVerifier};
use crate::mux::{spawn_mux_session, CompatYamuxStream};
use crate::protocol::{
    configure_tunnel_socket, create_tunnel_tls_client_config, read_frame, write_frame,
    ProxyHelloChallenge, ServerAuthRegister, TunnelEstablished, EXPORTER_LABEL,
};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, HOST};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};
use yamux::Mode;

type BoxHttpBody = BoxBody<Bytes, hyper::Error>;

fn full_body(s: impl Into<Bytes>) -> BoxHttpBody {
    Full::new(s.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Runs the `olp-server` daemon with automatic Fibonacci backoff reconnection.
pub async fn run_server_with_shutdown(
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let priv_path = expand_path(&config.keys.private_key)?;
    let signing_key = Arc::new(load_or_generate_keypair(&priv_path, "olp-server-ed25519")?);

    let known_proxy_path = expand_path(&config.keys.known_proxy_key)?;
    let known_proxy_raw = fs::read_to_string(&known_proxy_path).with_context(|| {
        format!(
            "Failed to read known_proxy_key at {} (make sure you pasted olp-proxy's public key)",
            known_proxy_path.display()
        )
    })?;
    let expected_proxy_key = parse_pubkey(&known_proxy_raw)?;

    let tls_client_cfg = create_tunnel_tls_client_config()?;
    let connector = TlsConnector::from(tls_client_cfg);

    let mut backoff = FibonacciBackoff::new(
        config.reconnect.initial_delay_sec,
        config.reconnect.max_delay_sec,
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("olp-server shutting down cleanly");
            return Ok(());
        }

        let session_start = Instant::now();
        let res = run_single_tunnel_session(
            &config,
            &signing_key,
            &expected_proxy_key,
            &connector,
            &mut shutdown_rx,
        )
        .await;

        if *shutdown_rx.borrow() {
            info!("olp-server shutting down cleanly");
            return Ok(());
        }

        // If the tunnel stayed alive for at least one healthy cycle (>= 30s), reset Fibonacci sequence
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
                if err_str.contains("ERR_UNAUTHORIZED_KEY") {
                    let pubkey_str =
                        format_pubkey("olp-server-ed25519", &signing_key.verifying_key());
                    if backoff.attempt() == 1 || backoff.attempt() % 5 == 0 {
                        error!(
                            "\n================================================================================\n\
                             [AUTH ERROR] Proxy rejected this server's public key!\n\
                             Your Server Public Key is:\n\
                               {}\n\n\
                             To authorize this server on the proxy, run this command ON THE PROXY HOST:\n\
                               ./start-proxy.sh --add-key \"{}\"\n\
                             (or append that line to ~/.olp/keys/authorized_keys on the proxy)\n\
                             ================================================================================",
                            pubkey_str, pubkey_str
                        );
                    }
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
    config: &ServerConfig,
    signing_key: &Arc<SigningKey>,
    expected_proxy_key: &VerifyingKey,
    connector: &TlsConnector,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    info!("Connecting to olp-proxy at {} ...", config.server.proxy_addr);

    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&config.server.proxy_addr),
    )
    .await
    .context("Timed out connecting to olp-proxy")?
    .context("TCP connection to olp-proxy failed")?;

    configure_tunnel_socket(&tcp_stream)?;

    let server_name = ServerName::try_from("olp-tunnel.internal").unwrap();
    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .context("TLS 1.3 handshake timed out")?
    .context("TLS 1.3 handshake failed")?;

    // Derive RFC 8446 TLS Exporter value to bind authentication to this exact TLS session
    let mut exporter = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, EXPORTER_LABEL, None)
        .context("Failed to derive RFC 8446 TLS exporter")?;

    // Step 1: Read and verify ProxyHelloChallenge BEFORE sending passkey verifier
    let challenge: ProxyHelloChallenge = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame(&mut tls_stream),
    )
    .await
    .context("Timed out waiting for ProxyHelloChallenge")??;

    challenge.verify(expected_proxy_key, &exporter)?;

    // Step 2: Send ServerAuthRegister with salted BLAKE3 passkey verifier
    let verifier = PasskeyVerifier::from_passkey(&config.server.passkey);
    let register = ServerAuthRegister::create(
        signing_key,
        &exporter,
        &challenge.proxy_nonce,
        config.server.remote_port,
        verifier,
    );

    tokio::time::timeout(
        Duration::from_secs(10),
        write_frame(&mut tls_stream, &register),
    )
    .await
    .context("Timed out sending ServerAuthRegister")??;

    // Step 3: Read TunnelEstablished confirmation
    let established: TunnelEstablished = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame(&mut tls_stream),
    )
    .await
    .context("Timed out waiting for TunnelEstablished")??;

    if !established.accepted {
        return Err(anyhow!(
            "olp-proxy rejected tunnel registration: {}",
            established.message
        ));
    }

    info!(
        "Tunnel established! Exposing local Ollama ({}) on remote port :{}",
        config.server.ollama_addr, config.server.remote_port
    );

    // Upgrade connection to Yamux multiplexer
    let (mux_handle, mut inbound_rx) = spawn_mux_session(tls_stream, Mode::Client, 128);

    let hb_interval = Duration::from_secs(config.reconnect.heartbeat_interval_sec.max(1));
    let hb_timeout = Duration::from_secs(config.reconnect.heartbeat_timeout_sec.max(1));
    let ollama_addr = config.server.ollama_addr.clone();

    let mut ticker = tokio::time::interval(hb_interval);
    // Consume immediate first tick
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
                        let target = ollama_addr.clone();
                        tokio::spawn(async move {
                            serve_proxied_ollama_stream(yamux_stream, target).await;
                        });
                    }
                    None => {
                        return Err(anyhow!("Tunnel multiplexer closed by peer"));
                    }
                }
            }
            _ = ticker.tick() => {
                // Active application-level Ping/Pong over Yamux
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

/// Receives an HTTP request over a `yamux` stream from `olp-proxy`, sanitizes it,
/// and forwards it with zero buffering to the local Ollama instance.
async fn serve_proxied_ollama_stream(yamux_stream: CompatYamuxStream, ollama_addr: String) {
    let service = service_fn(move |req: Request<Incoming>| {
        let target_addr = ollama_addr.clone();
        async move { forward_to_local_ollama(req, &target_addr).await }
    });

    let _ = server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(yamux_stream), service)
        .await;
}

async fn forward_to_local_ollama(
    mut req: Request<Incoming>,
    ollama_addr: &str,
) -> std::result::Result<Response<BoxHttpBody>, hyper::Error> {
    // 1. SSRF & Method Sanitization: Reject CONNECT or non-Ollama tunnel methods
    if req.method() == Method::CONNECT {
        let mut resp = Response::new(full_body(r#"{"error":"CONNECT method is forbidden"}"#));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    // 2. Normalize URI to path_and_query only (preventing absolute-URI proxy abuse)
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    if let Ok(clean_uri) = Uri::builder().path_and_query(path_and_query).build() {
        *req.uri_mut() = clean_uri;
    }

    // 3. Strip external Authorization header (never leak passkey to local logs)
    // and rewrite Host header so Ollama's internal DNS-rebinding check succeeds
    req.headers_mut().remove(AUTHORIZATION);
    if let Ok(host_val) = hyper::header::HeaderValue::from_str(ollama_addr) {
        req.headers_mut().insert(HOST, host_val);
    }

    // 4. Connect to local Ollama with fast 5-second connect timeout
    let upstream_tcp = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(ollama_addr),
    )
    .await
    {
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
    let _ = upstream_tcp.set_nodelay(true);

    let (mut sender, conn) =
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

    // 5. Stream response chunks back to `olp-proxy` immediately without buffering
    match sender.send_request(req).await {
        Ok(resp) => Ok(resp.map(|b| b.boxed())),
        Err(e) => {
            error!("Error forwarding request to local Ollama: {}", e);
            let mut resp = Response::new(full_body(
                r#"{"error":"upstream local ollama connection closed unexpectedly"}"#,
            ));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}

