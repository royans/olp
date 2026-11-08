use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};
use tokio_rustls::TlsConnector;

use olp::config::{
    KeyScope, ProxyAuthSection, ProxyConfig, ProxySection, ProxySecuritySection, ProxyTlsSection,
    ReconnectSection, ScopedKeyConfig, ServerConfig, ServerSection,
};
use olp::protocol::create_tunnel_tls_client_config;
use olp::proxy::start_proxy_server;
use olp::server::run_single_tunnel_session;

type BoxHttpBody = BoxBody<Bytes, hyper::Error>;

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxHttpBody {
    Full::new(chunk.into())
        .map_err(|e: std::convert::Infallible| -> hyper::Error { match e {} })
        .boxed()
}

fn empty_body() -> BoxHttpBody {
    Empty::<Bytes>::new()
        .map_err(|e: std::convert::Infallible| -> hyper::Error { match e {} })
        .boxed()
}

fn test_proxy_tls() -> ProxyTlsSection {
    ProxyTlsSection {
        mode: "off".to_string(),
        cert_path: None,
        key_path: None,
        allow_broken_certs: true,
    }
}

/// Shared state captured by mock Ollama to assert request normalization
#[derive(Clone, Default)]
struct CapturedRequests {
    requests: Arc<Mutex<Vec<(String, String, serde_json::Value)>>>,
}

/// Starts a mock local Ollama HTTP server that captures and inspects requests.
async fn start_mock_ollama_with_capture(
    captured: CapturedRequests,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let captured = captured.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let captured = captured.clone();
                        async move {
                            let method = req.method().to_string();
                            let path = req.uri().path().to_string();

                            // Read body
                            let body_bytes = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();
                            let json_val = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                                .unwrap_or(serde_json::Value::Null);

                            captured.requests.lock().await.push((
                                method.clone(),
                                path.clone(),
                                json_val.clone(),
                            ));

                            if method == "GET" && (path == "/api/tags" || path == "/api/ps") {
                                let resp_json = serde_json::json!({
                                    "models": [
                                        {"name": "llama3:8b", "model": "llama3:8b"},
                                        {"name": "mistral:7b", "model": "mistral:7b"},
                                        {"name": "secret-model:latest", "model": "secret-model:latest"}
                                    ]
                                });
                                return Ok::<_, hyper::Error>(Response::new(full_body(
                                    serde_json::to_vec(&resp_json).unwrap(),
                                )));
                            }

                            if method == "GET"
                                && (path == "/v1/models" || path.starts_with("/v1/models/"))
                            {
                                let resp_json = serde_json::json!({
                                    "object": "list",
                                    "data": [
                                        {"id": "llama3:8b", "object": "model"},
                                        {"id": "mistral:7b", "object": "model"},
                                        {"id": "secret-model:latest", "object": "model"}
                                    ]
                                });
                                return Ok(Response::new(full_body(
                                    serde_json::to_vec(&resp_json).unwrap(),
                                )));
                            }

                            if method == "GET"
                                && (path == "/" || path == "/api" || path == "/api/version")
                            {
                                return Ok(Response::new(full_body(
                                    b"{\"version\":\"0.5.4\"}".as_slice(),
                                )));
                            }

                            if method == "POST" && path == "/api/show" {
                                let resp_json = serde_json::json!({
                                    "model_info": {
                                        "llama.context_length": 131072
                                    },
                                    "details": {
                                        "context_length": 131072,
                                        "format": "gguf"
                                    }
                                });
                                return Ok(Response::new(full_body(
                                    serde_json::to_vec(&resp_json).unwrap(),
                                )));
                            }

                            if method == "POST" && (path == "/api/generate" || path == "/api/chat")
                            {
                                let resp_model = json_val
                                    .get("model")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                let resp_json = serde_json::json!({
                                    "model": resp_model,
                                    "response": "Hello from mock Ollama",
                                    "message": {"role": "assistant", "content": "Hello from mock Ollama"},
                                    "done": true
                                });
                                return Ok(Response::new(full_body(
                                    serde_json::to_vec(&resp_json).unwrap(),
                                )));
                            }

                            if method == "POST"
                                && (path == "/v1/chat/completions" || path == "/v1/completions")
                            {
                                let resp_model = json_val
                                    .get("model")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                let resp_json = serde_json::json!({
                                    "id": "chatcmpl-test",
                                    "object": "chat.completion",
                                    "model": resp_model,
                                    "choices": [{
                                        "index": 0,
                                        "message": {"role": "assistant", "content": "Hello from OpenAI compatible endpoint"},
                                        "finish_reason": "stop"
                                    }]
                                });
                                return Ok(Response::new(full_body(
                                    serde_json::to_vec(&resp_json).unwrap(),
                                )));
                            }

                            if method == "POST"
                                && (path == "/api/embed"
                                    || path == "/api/embeddings"
                                    || path == "/v1/embeddings")
                            {
                                let resp_json = serde_json::json!({
                                    "embeddings": [[0.1, 0.2, 0.3]]
                                });
                                return Ok(Response::new(full_body(
                                    serde_json::to_vec(&resp_json).unwrap(),
                                )));
                            }

                            // Mutating endpoints (pull, delete, etc.)
                            if path == "/api/pull"
                                || path == "/api/delete"
                                || path == "/api/push"
                                || path == "/api/create"
                                || path == "/api/copy"
                            {
                                return Ok(Response::new(full_body(
                                    b"{\"status\":\"success\"}".as_slice(),
                                )));
                            }

                            let mut not_found = Response::new(full_body(b"not found".as_slice()));
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

    (local_addr, handle)
}

async fn send_client_request(
    addr: SocketAddr,
    method: Method,
    path: &str,
    auth_header: Option<&str>,
    body_json: Option<serde_json::Value>,
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

    let req = if let Some(j) = body_json {
        let bytes = serde_json::to_vec(&j).unwrap();
        builder = builder.header(CONTENT_TYPE, "application/json");
        builder.body(full_body(bytes)).unwrap()
    } else {
        builder.body(empty_body()).unwrap()
    };

    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let collected = resp.into_body().collect().await.unwrap();
    let body_str = String::from_utf8_lossy(&collected.to_bytes()).to_string();

    (status, headers, body_str)
}

#[tokio::test]
async fn test_read_only_mode_and_scoped_keys_full_compatibility() {
    let captured = CapturedRequests::default();
    let (ollama_addr, _mock_task) = start_mock_ollama_with_capture(captured.clone()).await;

    let olp_api_key = "user_api_key_compat_test";
    let config_dir = olp::config::olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", olp_api_key));
    let _ = std::fs::remove_file(&profile_path);

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "18500-18600".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![olp_api_key.to_string()],
        },
        security: ProxySecuritySection {
            read_only: true, // Proxy enforces read_only
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let mut keys = HashMap::new();
    keys.insert(
        "laptop".to_string(),
        ScopedKeyConfig {
            passkey: "laptop_inference_key_12345".to_string(),
            hash: None,
            scope: KeyScope::Inference,
        },
    );
    keys.insert(
        "admin".to_string(),
        ScopedKeyConfig {
            passkey: "admin_manage_key_abcdef123".to_string(),
            hash: None,
            scope: KeyScope::Manage,
        },
    );

    let mut server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: ollama_addr.to_string(),
            olp_api_key: olp_api_key.to_string(),
            olp_server_id: "srv_compat_test".to_string(),
            passkey_user: "legacy_user_key_9999".to_string(),
            remote_port: Some(18500),
            tls_verify: Some(false),
            read_only: Some(true),
            allowed_models: vec!["llama3:8b".to_string(), "mistral:7b".to_string()],
            default_model: "llama3:8b".to_string(),
            max_num_ctx: 16384,
            max_num_predict: 2048,
            keep_alive_min: "1m".to_string(),
            keep_alive_max: "30m".to_string(),
            keys,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server_cfg, &connector, &mut rx).await;
    });

    let public_addr: SocketAddr = "127.0.0.1:18500".parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let laptop_auth = "Bearer laptop_inference_key_12345";
    let legacy_auth = "Bearer legacy_user_key_9999";

    // 1. ENDPOINT ALLOWLIST IN INFERENCE SCOPE
    // Allowed endpoints must succeed (200 OK)
    let allowed_endpoints = vec![
        (Method::GET, "/", None),
        (Method::GET, "/api", None),
        (Method::GET, "/api/version", None),
        (Method::GET, "/api/tags", None),
        (Method::GET, "/api/ps", None),
        (Method::GET, "/v1/models", None),
        (Method::GET, "/v1/models/llama3:8b", None),
        (
            Method::POST,
            "/api/generate",
            Some(serde_json::json!({"model": "llama3:8b", "prompt": "hi"})),
        ),
        (
            Method::POST,
            "/api/chat",
            Some(serde_json::json!({"model": "llama3:8b", "messages": []})),
        ),
        (
            Method::POST,
            "/api/embed",
            Some(serde_json::json!({"model": "llama3:8b", "input": "test"})),
        ),
        (
            Method::POST,
            "/api/embeddings",
            Some(serde_json::json!({"model": "llama3:8b", "prompt": "test"})),
        ),
        (
            Method::POST,
            "/api/show",
            Some(serde_json::json!({"name": "llama3:8b"})),
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "llama3:8b", "messages": []})),
        ),
        (
            Method::POST,
            "/v1/completions",
            Some(serde_json::json!({"model": "llama3:8b", "prompt": "hi"})),
        ),
        (
            Method::POST,
            "/v1/embeddings",
            Some(serde_json::json!({"model": "llama3:8b", "input": "test"})),
        ),
    ];

    for (meth, path, body) in allowed_endpoints {
        let (status, _, body_resp) =
            send_client_request(public_addr, meth.clone(), path, Some(laptop_auth), body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Endpoint {} {} must succeed in inference scope. Got: {} - Body: {}",
            meth,
            path,
            status,
            body_resp
        );
    }

    // 2. PROTOCOL-CORRECT 403 RESPONSES
    // Native Ollama mutating endpoint blocked -> Ollama error format + CORS
    let (pull_status, pull_headers, pull_body) = send_client_request(
        public_addr,
        Method::POST,
        "/api/pull",
        Some(laptop_auth),
        Some(serde_json::json!({"name": "gemma:2b"})),
    )
    .await;
    assert_eq!(pull_status, StatusCode::FORBIDDEN);
    assert_eq!(
        pull_headers
            .get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok()),
        Some("*")
    );
    assert!(pull_body.contains("model downloads are disabled on this server (read-only mode)"));
    let err_json: serde_json::Value = serde_json::from_str(&pull_body).unwrap();
    assert!(err_json.get("error").unwrap().is_string());

    // OpenAI mutating endpoint blocked -> OpenAI error format + CORS
    let (v1_status, v1_headers, v1_body) = send_client_request(
        public_addr,
        Method::POST,
        "/v1/models/create",
        Some(laptop_auth),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(v1_status, StatusCode::FORBIDDEN);
    assert_eq!(
        v1_headers
            .get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok()),
        Some("*")
    );
    let v1_json: serde_json::Value = serde_json::from_str(&v1_body).unwrap();
    assert_eq!(
        v1_json["error"]["type"].as_str().unwrap(),
        "permission_error"
    );
    assert_eq!(v1_json["error"]["code"].as_str().unwrap(), "forbidden");

    // 3. BODY NORMALIZATION UNDER INFERENCE SCOPE
    // Send request with keep_alive: 0, high num_ctx, num_predict: -1, and hardware options
    let test_body = serde_json::json!({
        "model": "llama3:8b",
        "prompt": "explain relativity",
        "keep_alive": 0,
        "options": {
            "num_ctx": 99999,
            "num_predict": -1,
            "num_gpu": 2,
            "main_gpu": 1,
            "num_thread": 16,
            "use_mmap": true,
            "use_mlock": true,
            "low_vram": true,
            "numa": true,
            "temperature": 0.8
        }
    });

    captured.requests.lock().await.clear();
    let (norm_status, _, _) = send_client_request(
        public_addr,
        Method::POST,
        "/api/generate",
        Some(laptop_auth),
        Some(test_body),
    )
    .await;
    assert_eq!(norm_status, StatusCode::OK);

    let recorded = captured.requests.lock().await.clone();
    assert_eq!(recorded.len(), 1);
    let (_, _, fwd_json) = &recorded[0];

    // keep_alive: 0 clamped to keep_alive_min ("1m" = 60s)
    assert_eq!(
        fwd_json.get("keep_alive").and_then(|v| v.as_i64()),
        Some(60)
    );
    // Hardware options stripped from options
    let opts = fwd_json.get("options").unwrap().as_object().unwrap();
    assert!(!opts.contains_key("num_gpu"));
    assert!(!opts.contains_key("main_gpu"));
    assert!(!opts.contains_key("num_thread"));
    assert!(!opts.contains_key("use_mmap"));
    assert!(!opts.contains_key("use_mlock"));
    assert!(!opts.contains_key("low_vram"));
    assert!(!opts.contains_key("numa"));
    // Context capped to max_num_ctx (16384)
    assert_eq!(opts.get("num_ctx").and_then(|v| v.as_u64()), Some(16384));
    // Predict capped to max_num_predict (2048)
    assert_eq!(opts.get("num_predict").and_then(|v| v.as_i64()), Some(2048));
    // Unknown/normal option passes through
    assert_eq!(opts.get("temperature").and_then(|v| v.as_f64()), Some(0.8));

    // Test keep_alive: -1 clamped to max (1800s)
    captured.requests.lock().await.clear();
    let _ = send_client_request(
        public_addr,
        Method::POST,
        "/api/generate",
        Some(laptop_auth),
        Some(serde_json::json!({"model": "llama3:8b", "keep_alive": -1})),
    )
    .await;
    let recorded2 = captured.requests.lock().await.clone();
    assert_eq!(
        recorded2[0].2.get("keep_alive").and_then(|v| v.as_i64()),
        Some(1800)
    );

    // Test /v1/chat/completions max_tokens capped to 2048
    captured.requests.lock().await.clear();
    let _ = send_client_request(
        public_addr,
        Method::POST,
        "/v1/chat/completions",
        Some(laptop_auth),
        Some(serde_json::json!({"model": "llama3:8b", "messages": [], "max_tokens": 10000})),
    )
    .await;
    let recorded3 = captured.requests.lock().await.clone();
    assert_eq!(
        recorded3[0].2.get("max_tokens").and_then(|v| v.as_i64()),
        Some(2048)
    );

    // 4. MODEL SELECTION & REWRITING
    // Request for disallowed model gets rewritten to default_model ("llama3:8b")
    captured.requests.lock().await.clear();
    let (rewrite_status, _, rewrite_resp) = send_client_request(
        public_addr,
        Method::POST,
        "/api/chat",
        Some(laptop_auth),
        Some(serde_json::json!({"model": "unapproved_gpt4", "messages": []})),
    )
    .await;
    assert_eq!(rewrite_status, StatusCode::OK);
    let recorded4 = captured.requests.lock().await.clone();
    assert_eq!(
        recorded4[0].2.get("model").and_then(|v| v.as_str()),
        Some("llama3:8b")
    );
    let resp_json: serde_json::Value = serde_json::from_str(&rewrite_resp).unwrap();
    assert_eq!(
        resp_json.get("model").and_then(|v| v.as_str()),
        Some("llama3:8b")
    );

    // 5. DISCOVERY FILTERING
    // /api/tags filters out secret-model:latest because it's not in allowed_models
    let (_, _, tags_resp) = send_client_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some(laptop_auth),
        None,
    )
    .await;
    assert!(tags_resp.contains("llama3:8b"));
    assert!(tags_resp.contains("mistral:7b"));
    assert!(!tags_resp.contains("secret-model:latest"));

    // /v1/models filters out secret-model:latest
    let (_, _, v1_models_resp) = send_client_request(
        public_addr,
        Method::GET,
        "/v1/models",
        Some(laptop_auth),
        None,
    )
    .await;
    assert!(v1_models_resp.contains("llama3:8b"));
    assert!(v1_models_resp.contains("mistral:7b"));
    assert!(!v1_models_resp.contains("secret-model:latest"));

    // /api/show clamps reported context_length to max_num_ctx (16384)
    let (_, _, show_resp) = send_client_request(
        public_addr,
        Method::POST,
        "/api/show",
        Some(laptop_auth),
        Some(serde_json::json!({"name": "llama3:8b"})),
    )
    .await;
    let show_json: serde_json::Value = serde_json::from_str(&show_resp).unwrap();
    assert_eq!(
        show_json["model_info"]["llama.context_length"].as_u64(),
        Some(16384)
    );
    assert_eq!(show_json["details"]["context_length"].as_u64(), Some(16384));

    // 6. BACKWARD COMPATIBILITY
    // Legacy passkey_user still works as an inference-scope key
    let (legacy_status, _, _) = send_client_request(
        public_addr,
        Method::GET,
        "/api/tags",
        Some(legacy_auth),
        None,
    )
    .await;
    assert_eq!(legacy_status, StatusCode::OK);

    let (legacy_pull_status, _, _) = send_client_request(
        public_addr,
        Method::POST,
        "/api/pull",
        Some(legacy_auth),
        Some(serde_json::json!({"name": "test"})),
    )
    .await;
    assert_eq!(legacy_pull_status, StatusCode::FORBIDDEN);

    let _ = std::fs::remove_file(&profile_path);
}

#[tokio::test]
async fn test_scoped_keys_manage_allows_mutations_when_proxy_allows() {
    let captured = CapturedRequests::default();
    let (ollama_addr, _mock_task) = start_mock_ollama_with_capture(captured.clone()).await;

    let olp_api_key = "user_manage_scope_test";
    let config_dir = olp::config::olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", olp_api_key));
    let _ = std::fs::remove_file(&profile_path);

    // Proxy read_only = false (allows manage if server allows)
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "18600-18700".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![olp_api_key.to_string()],
        },
        security: ProxySecuritySection {
            read_only: false,
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let mut keys = HashMap::new();
    keys.insert(
        "laptop".to_string(),
        ScopedKeyConfig {
            passkey: "laptop_inf_key_987654321".to_string(),
            hash: None,
            scope: KeyScope::Inference,
        },
    );
    keys.insert(
        "admin".to_string(),
        ScopedKeyConfig {
            passkey: "admin_man_key_987654321".to_string(),
            hash: None,
            scope: KeyScope::Manage,
        },
    );

    let mut server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: ollama_addr.to_string(),
            olp_api_key: olp_api_key.to_string(),
            olp_server_id: "srv_manage_test".to_string(),
            passkey_user: "legacy_user_key_1111".to_string(),
            remote_port: Some(18600),
            tls_verify: Some(false),
            read_only: Some(false),
            keys,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server_cfg, &connector, &mut rx).await;
    });

    let public_addr: SocketAddr = "127.0.0.1:18600".parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let laptop_auth = "Bearer laptop_inf_key_987654321";
    let admin_auth = "Bearer admin_man_key_987654321";

    // 1. Inference key cannot call POST /api/pull
    let (pull_status, _, _) = send_client_request(
        public_addr,
        Method::POST,
        "/api/pull",
        Some(laptop_auth),
        Some(serde_json::json!({"name": "llama3:8b"})),
    )
    .await;
    assert_eq!(pull_status, StatusCode::FORBIDDEN);

    // 2. Manage key CAN call POST /api/pull
    let (admin_pull_status, _, pull_resp) = send_client_request(
        public_addr,
        Method::POST,
        "/api/pull",
        Some(admin_auth),
        Some(serde_json::json!({"name": "llama3:8b"})),
    )
    .await;
    assert_eq!(
        admin_pull_status,
        StatusCode::OK,
        "Manage scope must allow /api/pull: {}",
        pull_resp
    );

    // 3. Manage key CAN call DELETE /api/delete
    let (admin_del_status, _, del_resp) = send_client_request(
        public_addr,
        Method::DELETE,
        "/api/delete",
        Some(admin_auth),
        Some(serde_json::json!({"name": "llama3:8b"})),
    )
    .await;
    assert_eq!(
        admin_del_status,
        StatusCode::OK,
        "Manage scope must allow /api/delete: {}",
        del_resp
    );

    let _ = std::fs::remove_file(&profile_path);
}

#[tokio::test]
async fn test_client_compat_simulated_flows() {
    let captured = CapturedRequests::default();
    let (ollama_addr, _mock_task) = start_mock_ollama_with_capture(captured.clone()).await;

    let olp_api_key = "user_sim_flows_test";
    let config_dir = olp::config::olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", olp_api_key));
    let _ = std::fs::remove_file(&profile_path);

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "18700-18800".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![olp_api_key.to_string()],
        },
        security: ProxySecuritySection {
            read_only: true, // Read-only enabled
            ..Default::default()
        },
        tls: test_proxy_tls(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let mut keys = HashMap::new();
    keys.insert(
        "app_client".to_string(),
        ScopedKeyConfig {
            passkey: "app_client_passkey_123".to_string(),
            hash: None,
            scope: KeyScope::Inference,
        },
    );

    let mut server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: ollama_addr.to_string(),
            olp_api_key: olp_api_key.to_string(),
            olp_server_id: "srv_sim_test".to_string(),
            passkey_user: "app_client_passkey_123".to_string(),
            remote_port: Some(18700),
            tls_verify: Some(false),
            read_only: Some(true),
            keys,
            ..Default::default()
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server_cfg, &connector, &mut rx).await;
    });

    let public_addr: SocketAddr = "127.0.0.1:18700".parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let auth = "Bearer app_client_passkey_123";

    // 1. Ollama CLI Flow:
    // a) `ollama list` -> GET /api/tags
    let (status, _, tags) =
        send_client_request(public_addr, Method::GET, "/api/tags", Some(auth), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(tags.contains("llama3:8b"));

    // b) `ollama show llama3:8b` -> POST /api/show
    let (status, _, show) = send_client_request(
        public_addr,
        Method::POST,
        "/api/show",
        Some(auth),
        Some(serde_json::json!({"name": "llama3:8b"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(show.contains("context_length"));

    // c) `ollama run llama3:8b` -> POST /api/chat
    let (status, _, chat) = send_client_request(
        public_addr,
        Method::POST,
        "/api/chat",
        Some(auth),
        Some(serde_json::json!({
            "model": "llama3:8b",
            "messages": [{"role": "user", "content": "What is 2+2?"}]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(chat.contains("Hello from mock Ollama"));

    // 2. OpenAI SDK Flow:
    // a) client.models.list() -> GET /v1/models
    let (status, _, models) =
        send_client_request(public_addr, Method::GET, "/v1/models", Some(auth), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(models.contains("llama3:8b"));

    // b) client.chat.completions.create(...) -> POST /v1/chat/completions
    let (status, _, oai_chat) = send_client_request(
        public_addr,
        Method::POST,
        "/v1/chat/completions",
        Some(auth),
        Some(serde_json::json!({
            "model": "llama3:8b",
            "messages": [{"role": "user", "content": "Write a haiku"}],
            "temperature": 0.7
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(oai_chat.contains("choices"));

    // 3. Open WebUI Flow:
    // a) GET /api/version
    let (status, _, ver) =
        send_client_request(public_addr, Method::GET, "/api/version", Some(auth), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ver.contains("version"));

    // b) POST /api/generate
    let (status, _, gen) = send_client_request(
        public_addr,
        Method::POST,
        "/api/generate",
        Some(auth),
        Some(serde_json::json!({
            "model": "llama3:8b",
            "prompt": "Hello",
            "stream": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(gen.contains("Hello from mock Ollama"));

    // 4. Cline / Roo Code Flow:
    // a) GET /v1/models
    let (status, _, _) =
        send_client_request(public_addr, Method::GET, "/v1/models", Some(auth), None).await;
    assert_eq!(status, StatusCode::OK);

    // b) POST /v1/chat/completions with stream=true
    let (status, _, sse_resp) = send_client_request(
        public_addr,
        Method::POST,
        "/v1/chat/completions",
        Some(auth),
        Some(serde_json::json!({
            "model": "llama3:8b",
            "messages": [{"role": "user", "content": "Refactor this code"}],
            "stream": true,
            "max_tokens": 1024
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(sse_resp.contains("choices"));

    let _ = std::fs::remove_file(&profile_path);
}
