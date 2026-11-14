use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};

type BoxHttpBody = BoxBody<Bytes, hyper::Error>;

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxHttpBody {
    Full::new(chunk.into())
        .map_err(|e: std::convert::Infallible| -> hyper::Error { match e {} })
        .boxed()
}
use hyper::header::{AUTHORIZATION, HOST, WWW_AUTHENTICATE};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use olp::config::{
    ProxyAuthSection, ProxyConfig, ProxySection, ProxySecuritySection, ProxyTlsSection,
    ReconnectSection, ServerConfig, ServerSection,
};
use olp::protocol::create_tunnel_tls_client_config;
use olp::proxy::start_proxy_server;
use olp::server::{run_server_with_shutdown, run_single_tunnel_session};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;

fn test_proxy_tls() -> ProxyTlsSection {
    ProxyTlsSection {
        mode: "off".to_string(),
        cert_path: None,
        key_path: None,
        allow_broken_certs: true,
    }
}

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
                            if req.method() == Method::GET
                                && (path == "/api/tags" || path == "/api/ps")
                            {
                                let body = Full::new(Bytes::from_static(
                                    br#"{"models":[{"name":"llama3:latest"}]}"#,
                                ))
                                .map_err(|never| match never {})
                                .boxed();
                                return Ok::<_, hyper::Error>(Response::new(body));
                            }

                            if req.method() == Method::POST && path == "/api/generate" {
                                let (tx, rx) =
                                    mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(8);
                                tokio::spawn(async move {
                                    let chunks = [
                                        &b"{\"model\":\"llama3\",\"response\":\"Hello\",\"done\":false}\n"[..],
                                        &b"{\"model\":\"llama3\",\"response\":\" world!\",\"done\":false}\n"[..],
                                        &b"{\"model\":\"llama3\",\"response\":\"\",\"done\":true}\n"[..],
                                    ];
                                    for c in chunks {
                                        let _ =
                                            tx.send(Ok(Frame::data(Bytes::from_static(c)))).await;
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

#[tokio::test]
async fn test_end_to_end_tunnel_auth_streaming_and_hotswap() {
    let ollama_addr = start_mock_ollama().await;

    let olp_api_key = "test_proxy_api_key_12345";
    let passkey_user = "test_user_secret_67890";

    // 1. Start olp-proxy
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-19999".to_string(),
            listener_grace_period_sec: 60,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![olp_api_key.to_string()],
        },
        security: ProxySecuritySection {
            allowed_server_cidrs: vec!["127.0.0.1/32".to_string()],
            allowed_user_cidrs: vec!["127.0.0.1/32".to_string()],
            max_auth_failures_per_min: 3,
            max_concurrent_streams: 64,
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let remote_port = 18434u16;

    // 2. Start olp-server
    let server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: ollama_addr.to_string(),
            olp_api_key: olp_api_key.to_string(),
            olp_server_id: "srv_integration_1".to_string(),
            passkey_user: passkey_user.to_string(),
            remote_port: Some(remote_port),
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection {
            strategy: "fibonacci".to_string(),
            initial_delay_sec: 1,
            max_delay_sec: 300,
            heartbeat_interval_sec: 2,
            heartbeat_timeout_sec: 2,
        },
        maintenance: Default::default(),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_cfg_clone = server_cfg.clone();
    let server_task = tokio::spawn(async move {
        let _ = run_server_with_shutdown(server_cfg_clone, shutdown_rx).await;
    });

    // Wait for tunnel registration
    let public_addr: SocketAddr = format!("127.0.0.1:{}", remote_port).parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 3. Test Unauthenticated Request -> 401 with WWW-Authenticate challenge
    let (status, headers, _body) =
        send_http_request(public_addr, Method::GET, "/api/tags", None, b"").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(WWW_AUTHENTICATE).is_some());

    // 4. Test Bearer Token Auth with passkey_user -> 200 OK
    let bearer = format!("Bearer {}", passkey_user);
    let (status, _headers, body) =
        send_http_request(public_addr, Method::GET, "/api/tags", Some(&bearer), b"").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("llama3:latest"));

    // 5. Test Basic Auth + Chunked Token Streaming (`POST /api/generate`) -> 200 OK
    let basic_creds = BASE64.encode(format!("user:{}", passkey_user));
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

    // 6. Test Hot-Swap: shutdown first server, verify 503 during disconnect, then reconnect
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status_during_drop, _, _) =
        send_http_request(public_addr, Method::GET, "/api/tags", Some(&bearer), b"").await;
    assert_eq!(status_during_drop, StatusCode::SERVICE_UNAVAILABLE);

    // Reconnect new session
    let (shutdown_tx2, shutdown_rx2) = watch::channel(false);
    let server_task2 = tokio::spawn(async move {
        let _ = run_server_with_shutdown(server_cfg, shutdown_rx2).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (status_after_reconnect, _, body_after) =
        send_http_request(public_addr, Method::GET, "/api/tags", Some(&bearer), b"").await;
    assert_eq!(status_after_reconnect, StatusCode::OK);
    assert!(body_after.contains("llama3:latest"));

    // 6b. Test /api/olp/context GET and POST
    let (ctx_status, _, ctx_body) = send_http_request(
        public_addr,
        Method::GET,
        "/api/olp/context",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(ctx_status, StatusCode::OK);
    assert!(ctx_body.contains("32768"));

    let (post_ctx_status, _, post_ctx_body) = send_http_request(
        public_addr,
        Method::POST,
        "/api/olp/context",
        Some(&bearer),
        br#"{"num_ctx":16384}"#,
    )
    .await;
    assert_eq!(post_ctx_status, StatusCode::OK);
    assert!(post_ctx_body.contains("\"success\":true"));
    assert!(post_ctx_body.contains("\"server_updated\":true"));
    assert!(post_ctx_body.contains("\"proxy_updated\":true"));
    assert!(post_ctx_body.contains("\"num_ctx\":16384"));

    let (ctx_status2, _, ctx_body2) = send_http_request(
        public_addr,
        Method::GET,
        "/api/olp/context",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(ctx_status2, StatusCode::OK);
    assert!(ctx_body2.contains("16384"));

    // 7. Test CONNECT method SSRF rejection (405 Method Not Allowed)
    let (connect_status, _, _) = send_http_request(
        public_addr,
        Method::CONNECT,
        "127.0.0.1:11434",
        Some(&bearer),
        b"",
    )
    .await;
    assert_eq!(connect_status, StatusCode::METHOD_NOT_ALLOWED);

    let _ = shutdown_tx2.send(true);
    let _ = server_task2.await;
}

#[tokio::test]
async fn test_passkey_proxy_rejection_and_cidr_filtering() {
    let legit_key = "legit_proxy_key";
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-19999".to_string(),
            listener_grace_period_sec: 60,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![legit_key.to_string()],
        },
        security: ProxySecuritySection {
            allowed_server_cidrs: vec!["127.0.0.1/32".to_string()],
            allowed_user_cidrs: vec!["192.168.99.0/24".to_string()], // 127.0.0.1 will NOT be allowed for user HTTP
            max_auth_failures_per_min: 60,
            max_concurrent_streams: 64,
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Case A: Wrong olp_api_key -> rejection with ERR_UNAUTHORIZED_KEY
    let mut wrong_passkey_server = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "wrong_api_key".to_string(),
            olp_server_id: "srv_wrong".to_string(),
            passkey_user: "some_user_pass".to_string(),
            remote_port: Some(18450),
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    let res = run_single_tunnel_session(&mut wrong_passkey_server, &connector, &mut rx).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("ERR_UNAUTHORIZED_KEY"));
    assert!(!err_msg.contains(legit_key));

    // Case B: Correct olp_api_key -> registration accepted
    let mut correct_passkey_server = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: legit_key.to_string(),
            olp_server_id: "srv_correct".to_string(),
            passkey_user: "legit-user-passkey".to_string(),
            remote_port: Some(18451),
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (server_shutdown_tx, mut server_shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = run_single_tunnel_session(
            &mut correct_passkey_server,
            &connector,
            &mut server_shutdown_rx,
        )
        .await;
    });

    let public_addr: SocketAddr = "127.0.0.1:18451".parse().unwrap();
    for _ in 0..30 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Case C: User CIDR filter blocks 127.0.0.1 because allowed_user_cidrs is 192.168.99.0/24
    let (status, _, body) = send_http_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some("Bearer legit-user-passkey"),
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("forbidden"));

    let _ = server_shutdown_tx.send(true);
}

#[tokio::test]
async fn test_model_auto_mapping_and_cors() {
    let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();

    let target_loaded_model = "hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M";

    // Mock Ollama server verifying that incoming requests have their model rewritten
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = mock_listener.accept().await {
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| async move {
                        let path = req.uri().path().to_string();

                        if req.method() == Method::GET && path == "/api/ps" {
                            let json = format!(
                                r#"{{"models":[{{"name":"{}","model":"{}"}}]}}"#,
                                target_loaded_model, target_loaded_model
                            );
                            return Ok::<_, hyper::Error>(Response::new(full_body(json)));
                        }

                        if req.method() == Method::GET && path == "/api/tags" {
                            let json = format!(
                                r#"{{"models":[{{"name":"{}","model":"{}"}}]}}"#,
                                target_loaded_model, target_loaded_model
                            );
                            return Ok::<_, hyper::Error>(Response::new(full_body(json)));
                        }

                        if req.method() == Method::POST && path == "/api/generate" {
                            let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
                            let parsed: serde_json::Value =
                                serde_json::from_slice(&body_bytes).unwrap();
                            // Assert that olp-server rewrote the requested model to target_loaded_model
                            assert_eq!(
                                parsed["model"].as_str().unwrap(),
                                target_loaded_model,
                                "olp-server must rewrite requested model to active loaded model"
                            );

                            return Ok(Response::new(full_body(
                                r#"{"response":"generated text","done":true}"#,
                            )));
                        }

                        if req.method() == Method::POST && path == "/api/show" {
                            let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
                            let parsed: serde_json::Value =
                                serde_json::from_slice(&body_bytes).unwrap();
                            assert_eq!(
                                parsed["name"].as_str().unwrap(),
                                target_loaded_model,
                                "olp-server must rewrite /api/show name to active loaded model"
                            );

                            return Ok(Response::new(full_body(
                                r#"{"license":"MIT","parameters":"9B"}"#,
                            )));
                        }

                        let mut not_found = Response::new(full_body(&b"not found"[..]));
                        *not_found.status_mut() = StatusCode::NOT_FOUND;
                        Ok(not_found)
                    });

                    let _ = server_http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });

    // Start proxy
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "18500-18600".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec!["test-proxy-passkey".to_string()],
        },
        security: ProxySecuritySection {
            allowed_server_cidrs: vec!["0.0.0.0/0".to_string()],
            allowed_user_cidrs: vec!["0.0.0.0/0".to_string()],
            max_auth_failures_per_min: 60,
            max_concurrent_streams: 64,
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();

    // Start server exposing mock Ollama on remote port 18550
    let server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: mock_addr.to_string(),
            olp_api_key: "test-proxy-passkey".to_string(),
            olp_server_id: "srv_model1".to_string(),
            passkey_user: "test-user-passkey".to_string(),
            remote_port: Some(18550),
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (server_shutdown_tx, server_shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = run_server_with_shutdown(server_cfg, server_shutdown_rx).await;
    });

    let public_addr: SocketAddr = "127.0.0.1:18550".parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 1. Verify CORS preflight OPTIONS returns 204 No Content without auth
    let tcp = TcpStream::connect(public_addr).await.unwrap();
    let (mut client_sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let opt_req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/tags")
        .header(HOST, public_addr.to_string())
        .header("Origin", "vscode-webview://cline")
        .header("Access-Control-Request-Method", "POST")
        .body(full_body(Bytes::new()))
        .unwrap();

    let opt_resp = client_sender.send_request(opt_req).await.unwrap();
    assert_eq!(opt_resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        opt_resp
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );

    // 2. Client sends request specifying "model": "llama3.1" (Cline default or typed by user)
    // with "x-api-key" auth header
    let tcp2 = TcpStream::connect(public_addr).await.unwrap();
    let (mut client_sender2, conn2) = hyper::client::conn::http1::handshake(TokioIo::new(tcp2))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn2.await;
    });

    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/api/generate")
        .header(HOST, public_addr.to_string())
        .header("x-api-key", "test-user-passkey")
        .header("content-type", "application/json")
        .body(full_body(&br#"{"model":"llama3.1","prompt":"hello"}"#[..]))
        .unwrap();

    let post_resp = client_sender2.send_request(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_body = post_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(post_body.starts_with(b"{\"response\":\"generated text\""));

    // 3. Client checks /api/show with {"name": "some-random-model"}
    let tcp3 = TcpStream::connect(public_addr).await.unwrap();
    let (mut client_sender3, conn3) = hyper::client::conn::http1::handshake(TokioIo::new(tcp3))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn3.await;
    });

    let show_req = Request::builder()
        .method(Method::POST)
        .uri("/api/show")
        .header(HOST, public_addr.to_string())
        .header(AUTHORIZATION, "Bearer test-user-passkey")
        .header("content-type", "application/json")
        .body(full_body(&br#"{"name":"random-unknown-model"}"#[..]))
        .unwrap();

    let show_resp = client_sender3.send_request(show_req).await.unwrap();
    assert_eq!(show_resp.status(), StatusCode::OK);
    let show_body = show_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(show_body.starts_with(b"{\"license\":\"MIT\""));

    let _ = server_shutdown_tx.send(true);
}

#[tokio::test]
async fn test_multi_user_and_multi_server_isolation_and_dynamic_ports() {
    let mock_addr = start_mock_ollama().await;

    let user_alice = "alice_api_key_111";
    let user_bob = "bob_api_key_222";

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "19100-19200".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![user_alice.to_string(), user_bob.to_string()],
        },
        security: ProxySecuritySection {
            allowed_server_cidrs: vec!["127.0.0.1/32".to_string()],
            allowed_user_cidrs: vec!["127.0.0.1/32".to_string()],
            max_auth_failures_per_min: 60,
            max_concurrent_streams: 64,
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();

    // Alice Server 1: dynamic port allocation (remote_port = None)
    let alice_srv1 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: mock_addr.to_string(),
            olp_api_key: user_alice.to_string(),
            olp_server_id: "srv_alice_1".to_string(),
            passkey_user: "alice_pass_1".to_string(),
            remote_port: None,
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx1, rx1) = watch::channel(false);
    tokio::spawn(async move {
        let res = run_server_with_shutdown(alice_srv1, rx1).await;
        if let Err(e) = res {
            eprintln!("alice_srv1 error: {:#}", e);
        }
    });

    // Alice Server 2: dynamic port allocation (remote_port = None)
    let alice_srv2 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: mock_addr.to_string(),
            olp_api_key: user_alice.to_string(),
            olp_server_id: "srv_alice_2".to_string(),
            passkey_user: "alice_pass_2".to_string(),
            remote_port: None,
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx2, rx2) = watch::channel(false);
    tokio::spawn(async move {
        let res = run_server_with_shutdown(alice_srv2, rx2).await;
        if let Err(e) = res {
            eprintln!("alice_srv2 error: {:#}", e);
        }
    });

    // Bob Server 1: dynamic port allocation (remote_port = None)
    let bob_srv1 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: mock_addr.to_string(),
            olp_api_key: user_bob.to_string(),
            olp_server_id: "srv_bob_1".to_string(),
            passkey_user: "bob_pass_1".to_string(),
            remote_port: None,
            tls_verify: Some(false),
            read_only: None,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx3, rx3) = watch::channel(false);
    tokio::spawn(async move {
        let res = run_server_with_shutdown(bob_srv1, rx3).await;
        if let Err(e) = res {
            eprintln!("bob_srv1 error: {:#}", e);
        }
    });

    // Ports should be sequentially allocated: 19100, 19101, 19102
    let alice_port1 = 19100;
    let alice_port2 = 19101;
    let bob_port1 = 19102;

    for _ in 0..40 {
        let p1 = TcpStream::connect(format!("127.0.0.1:{}", alice_port1)).await;
        let p2 = TcpStream::connect(format!("127.0.0.1:{}", alice_port2)).await;
        let p3 = TcpStream::connect(format!("127.0.0.1:{}", bob_port1)).await;
        if p1.is_ok() && p2.is_ok() && p3.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Verify User isolation on Alice Port 1
    let addr_alice1: SocketAddr = format!("127.0.0.1:{}", alice_port1).parse().unwrap();
    let (status_ok, _, _) = send_http_request(
        addr_alice1,
        Method::GET,
        "/api/tags",
        Some("Bearer alice_pass_1"),
        b"",
    )
    .await;
    assert_eq!(status_ok, StatusCode::OK);

    let (status_unauth, _, _) = send_http_request(
        addr_alice1,
        Method::GET,
        "/api/tags",
        Some("Bearer alice_pass_2"),
        b"",
    )
    .await;
    assert_eq!(status_unauth, StatusCode::UNAUTHORIZED);

    let (status_unauth_bob, _, _) = send_http_request(
        addr_alice1,
        Method::GET,
        "/api/tags",
        Some("Bearer bob_pass_1"),
        b"",
    )
    .await;
    assert_eq!(status_unauth_bob, StatusCode::UNAUTHORIZED);

    // Verify Bob's port
    let addr_bob: SocketAddr = format!("127.0.0.1:{}", bob_port1).parse().unwrap();
    let (status_bob_ok, _, _) = send_http_request(
        addr_bob,
        Method::GET,
        "/api/tags",
        Some("Bearer bob_pass_1"),
        b"",
    )
    .await;
    assert_eq!(status_bob_ok, StatusCode::OK);

    let (status_bob_reject, _, _) = send_http_request(
        addr_bob,
        Method::GET,
        "/api/tags",
        Some("Bearer alice_pass_1"),
        b"",
    )
    .await;
    assert_eq!(status_bob_reject, StatusCode::UNAUTHORIZED);

    let _ = tx1.send(true);
    let _ = tx2.send(true);
    let _ = tx3.send(true);
}
