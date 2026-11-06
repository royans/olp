use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{AUTHORIZATION, HOST, WWW_AUTHENTICATE};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use olp::config::{
    ProxyConfig, ProxyKeysSection, ProxySection, ProxySecuritySection, ProxyTlsSection,
    ReconnectSection, ServerConfig, ServerKeysSection, ServerSection,
};
use olp::keys::{add_authorized_key, format_pubkey, load_or_generate_keypair, write_private_file};
use olp::protocol::create_tunnel_tls_client_config;
use olp::proxy::start_proxy_server;
use olp::server::{run_server_with_shutdown, run_single_tunnel_session};
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;

/// Starts a mock local Ollama HTTP server that verifies request sanitization and supports chunked token streaming.
async fn start_mock_ollama() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let expected_host = local_addr.to_string();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let expected_host = expected_host.clone();
                        async move {
                            // Verify that olp-server stripped Authorization header and rewrote Host
                            assert!(
                                req.headers().get(AUTHORIZATION).is_none(),
                                "Authorization header must be stripped before reaching local Ollama"
                            );
                            let host_hdr = req
                                .headers()
                                .get(HOST)
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("");
                            assert_eq!(host_hdr, expected_host);

                            let path = req.uri().path().to_string();
                            if req.method() == Method::GET && path == "/api/tags" {
                                let body = Full::new(Bytes::from_static(
                                    br#"{"models":[{"name":"llama3:latest"}]}"#,
                                ))
                                .map_err(|never| match never {})
                                .boxed();
                                return Ok::<_, hyper::Error>(Response::new(body));
                            }

                            if req.method() == Method::POST && path == "/api/generate" {
                                let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(8);
                                tokio::spawn(async move {
                                    let chunks = [
                                        &b"{\"model\":\"llama3\",\"response\":\"Hello\",\"done\":false}\n"[..],
                                        &b"{\"model\":\"llama3\",\"response\":\" world!\",\"done\":false}\n"[..],
                                        &b"{\"model\":\"llama3\",\"response\":\"\",\"done\":true}\n"[..],
                                    ];
                                    for c in chunks {
                                        let _ = tx.send(Ok(Frame::data(Bytes::from_static(c)))).await;
                                        tokio::time::sleep(Duration::from_millis(20)).await;
                                    }
                                });
                                let stream = futures::stream::unfold(rx, |mut rx| async move {
                                    rx.recv().await.map(|item| (item, rx))
                                });
                                let stream_body = StreamBody::new(Box::pin(stream)).boxed();
                                return Ok(Response::new(stream_body));
                            }

                            let mut not_found = Response::new(
                                Full::new(Bytes::from_static(b"not found"))
                                    .map_err(|never| match never {})
                                    .boxed(),
                            );
                            *not_found.status_mut() = StatusCode::NOT_FOUND;
                            Ok(not_found)
                        }
                    });

                    let _ = server_http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });

    local_addr
}

async fn send_http_request(
    addr: SocketAddr,
    method: Method,
    path: &str,
    auth_header: Option<&str>,
    body_bytes: &'static [u8],
) -> (StatusCode, hyper::HeaderMap, String) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, addr.to_string());
    if let Some(auth) = auth_header {
        builder = builder.header(AUTHORIZATION, auth);
    }

    let req = builder
        .body(Full::new(Bytes::from_static(body_bytes)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let collected = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&collected).to_string();
    (status, headers, text)
}

fn create_test_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(1);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "olp-test-{}-{}-{}",
        name,
        std::process::id(),
        id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn test_end_to_end_tunnel_auth_streaming_and_hotswap() {
    let test_dir = create_test_dir("e2e");
    let proxy_priv = test_dir.join("proxy_id_ed25519");
    let auth_keys = test_dir.join("authorized_keys");
    let server_priv = test_dir.join("server_id_ed25519");
    let known_proxy = test_dir.join("known_proxy.pub");

    // 1. Generate keys and authorize server on proxy
    let proxy_signing = load_or_generate_keypair(&proxy_priv, "olp-proxy-ed25519").unwrap();
    let server_signing = load_or_generate_keypair(&server_priv, "olp-server-ed25519").unwrap();

    let proxy_pub_str = format_pubkey("olp-proxy-ed25519", &proxy_signing.verifying_key());
    let server_pub_str = format_pubkey("olp-server-ed25519", &server_signing.verifying_key());

    write_private_file(&known_proxy, &format!("{}\n", proxy_pub_str)).unwrap();
    add_authorized_key(&auth_keys, &server_pub_str).unwrap();

    // 2. Start mock Ollama server
    let ollama_addr = start_mock_ollama().await;

    // 3. Start olp-proxy
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-19999".to_string(),
            listener_grace_period_sec: 60,
        },
        keys: ProxyKeysSection {
            private_key: proxy_priv.to_string_lossy().to_string(),
            authorized_keys: auth_keys.to_string_lossy().to_string(),
        },
        security: ProxySecuritySection {
            max_auth_failures_per_min: 3,
            max_concurrent_streams: 64,
        },
        tls: ProxyTlsSection {
            mode: "off".to_string(),
            cert_path: None,
            key_path: None,
        },
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();

    // Find a free port in 15000..19999 for the remote public port
    let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_port = 18434u16;
    drop(temp_listener);

    let passkey = "test-super-secret-passkey-99";
    let server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: ollama_addr.to_string(),
            remote_port,
            passkey: passkey.to_string(),
        },
        keys: ServerKeysSection {
            private_key: server_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection {
            strategy: "fibonacci".to_string(),
            initial_delay_sec: 1,
            max_delay_sec: 300,
            heartbeat_interval_sec: 2,
            heartbeat_timeout_sec: 2,
        },
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_cfg_clone = server_cfg.clone();
    let server_task = tokio::spawn(async move {
        let _ = run_server_with_shutdown(server_cfg_clone, shutdown_rx).await;
    });

    // Wait briefly for tunnel handshake and port binding
    let public_addr: SocketAddr = format!("127.0.0.1:{}", remote_port).parse().unwrap();
    for _ in 0..30 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 4. Test Unauthenticated Request -> 401 with WWW-Authenticate challenge
    let (status, headers, _body) =
        send_http_request(public_addr, Method::GET, "/api/tags", None, b"").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(WWW_AUTHENTICATE).is_some());

    // 5. Test Bearer Token Auth -> 200 OK
    let bearer = format!("Bearer {}", passkey);
    let (status, _headers, body) = send_http_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("llama3:latest"));

    // 6. Test Basic Auth + Chunked Token Streaming (`POST /api/generate`) -> 200 OK
    let basic_creds = BASE64.encode(format!("ollama-user:{}", passkey));
    let basic_hdr = format!("Basic {}", basic_creds);
    let (status, _headers, stream_text) = send_http_request(
        public_addr,
        Method::POST,
        "/api/generate",
        Some(&basic_hdr),
        br#"{"model":"llama3","prompt":"hi"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(stream_text.contains("\"response\":\"Hello\""));
    assert!(stream_text.contains("\"response\":\" world!\""));
    assert!(stream_text.contains("\"done\":true"));

    // 7. Test Hot-Swap Reconnection: shut down first server, verify 503 during drop, then reconnect
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status_during_drop, _, _) = send_http_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(status_during_drop, StatusCode::SERVICE_UNAVAILABLE);

    // Reconnect a new olp-server session on the exact same port (hot-swap!)
    let (shutdown_tx2, shutdown_rx2) = watch::channel(false);
    let server_task2 = tokio::spawn(async move {
        let _ = run_server_with_shutdown(server_cfg, shutdown_rx2).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (status_after_reconnect, _, body_after) = send_http_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(status_after_reconnect, StatusCode::OK);
    assert!(body_after.contains("llama3:latest"));

    // 8. Test CONNECT method rejection (SSRF defense -> 405 Method Not Allowed)
    let (connect_status, _, _) = send_http_request(
        public_addr,
        Method::CONNECT,
        "127.0.0.1:11434",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(connect_status, StatusCode::METHOD_NOT_ALLOWED);

    // 9. Test Brute-Force Rate Limiting (3 bad attempts -> 429 Too Many Requests)
    for _ in 0..2 {
        let (st, _, _) = send_http_request(
            public_addr,
            Method::GET,
            "/api/tags",
            Some("Bearer wrong-pass"),
            b"",
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (st_rate_limited, _, _) = send_http_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(st_rate_limited, StatusCode::TOO_MANY_REQUESTS);

    let _ = shutdown_tx2.send(true);
    let _ = server_task2.await;
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_mitm_and_unauthorized_key_rejection() {
    let test_dir = create_test_dir("mitm");
    let proxy_priv = test_dir.join("proxy_id_ed25519");
    let auth_keys = test_dir.join("authorized_keys");
    let server_priv = test_dir.join("server_id_ed25519");
    let known_proxy = test_dir.join("known_proxy.pub");

    let proxy_signing = load_or_generate_keypair(&proxy_priv, "olp-proxy-ed25519").unwrap();
    let server_signing = Arc::new(load_or_generate_keypair(&server_priv, "olp-server-ed25519").unwrap());

    write_private_file(&auth_keys, "# Empty authorized_keys\n").unwrap();

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-19999".to_string(),
            listener_grace_period_sec: 60,
        },
        keys: ProxyKeysSection {
            private_key: proxy_priv.to_string_lossy().to_string(),
            authorized_keys: auth_keys.to_string_lossy().to_string(),
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config().unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: 18440,
            passkey: "secret".to_string(),
        },
        keys: ServerKeysSection {
            private_key: server_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection::default(),
    };

    // Case A: MITM detection — olp-server expects a different proxy public key
    let wrong_proxy_key = SigningKey::generate(&mut OsRng).verifying_key();
    let (_tx, mut rx) = watch::channel(false);
    let mitm_res = run_single_tunnel_session(
        &server_cfg,
        &server_signing,
        &wrong_proxy_key,
        &connector,
        &mut rx,
    )
    .await;
    assert!(mitm_res.is_err());
    assert!(mitm_res.unwrap_err().to_string().contains("MITM"));

    // Case B: Proxy key matches, but server key is NOT in proxy's authorized_keys
    let unauth_res = run_single_tunnel_session(
        &server_cfg,
        &server_signing,
        &proxy_signing.verifying_key(),
        &connector,
        &mut rx,
    )
    .await;
    assert!(unauth_res.is_err());
    assert!(unauth_res
        .unwrap_err()
        .to_string()
        .contains("ERR_UNAUTHORIZED_KEY"));

    let _ = std::fs::remove_dir_all(&test_dir);
}
