use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use olp::cidr::{CidrBlock, IpFilter};
use olp::config::{
    olp_config_dir, ProxyAuthSection, ProxyConfig, ProxySection, ProxySecuritySection,
    ProxyTlsSection, ReconnectSection, ServerConfig, ServerSection, UserProfile, UserServerConfig,
};
use olp::keys::{enforce_private_file_permissions, IpRateLimiter, PasskeyVerifier};
use olp::protocol::{
    compute_server_auth_token, create_tunnel_tls_client_config, is_safe_identifier,
    verify_server_auth_token,
};
use olp::proxy::{
    extract_auth_token, extract_model, format_apache_timestamp, sanitize_for_log,
    start_proxy_server, verify_http_headers_auth,
};
use olp::server::run_single_tunnel_session;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;

fn create_temp_dir(suffix: &str) -> PathBuf {
    static ID: AtomicUsize = AtomicUsize::new(100);
    let id = ID.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("olp-sec-test-{}-{}", suffix, id));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

// ============================================================================
// 1. CREDENTIALS & AUTHENTICATION UNIT TESTS
// ============================================================================

#[test]
fn test_ip_rate_limiter_isolated() {
    let limiter = IpRateLimiter::new(3);
    let ip1: IpAddr = "192.168.1.50".parse().unwrap();
    let ip2: IpAddr = "10.0.0.99".parse().unwrap();

    assert!(limiter.is_locked_out(&ip1).is_none());
    assert!(limiter.is_locked_out(&ip2).is_none());

    // 1st failure
    limiter.record_failure(ip1);
    assert!(limiter.is_locked_out(&ip1).is_none());

    // 2nd failure
    limiter.record_failure(ip1);
    assert!(limiter.is_locked_out(&ip1).is_none());

    // 3rd failure -> trips threshold
    limiter.record_failure(ip1);
    assert!(limiter.is_locked_out(&ip1).is_some());

    // ip2 should still not be rate limited
    assert!(limiter.is_locked_out(&ip2).is_none());

    // Reset on success
    limiter.record_success(&ip1);
    // Note: lockout is time-based or cleared on success
}

#[test]
fn test_passkey_verifier_edge_cases() {
    let verifier = PasskeyVerifier::from_passkey("MyComplexPass#123!");
    assert!(verifier.verify("MyComplexPass#123!"));
    assert!(!verifier.verify("Mycomplexpass#123!"));
    assert!(!verifier.verify(""));

    let empty_verifier = PasskeyVerifier::from_passkey("");
    assert!(empty_verifier.verify(""));
    assert!(!empty_verifier.verify(" "));

    let unicode_verifier = PasskeyVerifier::from_passkey("🔑Secret_Пароль_测试_123");
    assert!(unicode_verifier.verify("🔑Secret_Пароль_测试_123"));
    assert!(!unicode_verifier.verify("🔑Secret_Пароль_测试_124"));

    let long_key: String = "a".repeat(1000);
    let long_verifier = PasskeyVerifier::from_passkey(&long_key);
    assert!(long_verifier.verify(&long_key));
    assert!(!long_verifier.verify(&format!("{}b", long_key)));
}

#[test]
fn test_verify_http_request_auth_schemes() {
    let pass = "super-secret-key-42!with:colons";
    let verifier = PasskeyVerifier::from_passkey(pass);

    let check = |auth: Option<&str>| {
        let mut headers = HeaderMap::new();
        if let Some(val) = auth {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(val).unwrap());
        }
        verify_http_headers_auth(&headers, &verifier)
    };

    assert!(!check(None));
    assert!(check(Some(&format!("Bearer {}", pass))));
    assert!(check(Some(&format!("bearer {}", pass))));
    assert!(check(Some(&format!("Bearer  {} ", pass))));
    assert!(!check(Some("Bearer wrong-pass")));
    assert!(!check(Some("Bearer")));
    assert!(!check(Some("Token something")));

    let creds1 = BASE64.encode(format!("ollama-user:{}", pass));
    assert!(check(Some(&format!("Basic {}", creds1))));
    assert!(check(Some(&format!("basic {}", creds1))));

    let creds_no_user = BASE64.encode(format!(":{}", pass));
    assert!(check(Some(&format!("Basic {}", creds_no_user))));

    let creds_wrong = BASE64.encode("user:badpassword");
    assert!(!check(Some(&format!("Basic {}", creds_wrong))));
    assert!(!check(Some("Basic ???not-base64???")));

    // Test custom API key headers
    for hdr in &["x-api-key", "api-key", "ollama-api-key", "x-auth-token"] {
        let mut headers = HeaderMap::new();
        headers.insert(*hdr, HeaderValue::from_str(pass).unwrap());
        assert!(verify_http_headers_auth(&headers, &verifier));

        let mut bad_headers = HeaderMap::new();
        bad_headers.insert(*hdr, HeaderValue::from_str("wrong-key").unwrap());
        assert!(!verify_http_headers_auth(&bad_headers, &verifier));
    }
}

// ============================================================================
// 2. CIDR IP FILTERING TESTS
// ============================================================================

#[test]
fn test_cidr_filter_matching_and_rejection() {
    let filter = IpFilter::new(&[
        "192.168.1.0/24".to_string(),
        "10.0.0.1/32".to_string(),
        "2001:db8::/32".to_string(),
    ])
    .unwrap();

    assert!(filter.is_allowed(&"192.168.1.1".parse().unwrap()));
    assert!(filter.is_allowed(&"192.168.1.254".parse().unwrap()));
    assert!(filter.is_allowed(&"10.0.0.1".parse().unwrap()));
    assert!(filter.is_allowed(&"2001:db8:1234::1".parse().unwrap()));

    assert!(!filter.is_allowed(&"192.168.2.1".parse().unwrap()));
    assert!(!filter.is_allowed(&"10.0.0.2".parse().unwrap()));
    assert!(!filter.is_allowed(&"172.16.0.1".parse().unwrap()));
    assert!(!filter.is_allowed(&"2001:db9::1".parse().unwrap()));

    let invalid = CidrBlock::parse("999.999.999.999/24");
    assert!(invalid.is_err());
    let invalid_mask = CidrBlock::parse("192.168.1.1/33");
    assert!(invalid_mask.is_err());
}

#[test]
fn test_olp_api_key_nonce_and_server_binding() {
    let nonce_a = [1u8; 32];
    let nonce_b = [2u8; 32];
    let api_key = "proxy-secret-123";
    let srv_id = "srv_alpha";

    let token_a = compute_server_auth_token(&nonce_a, srv_id, api_key);
    assert!(verify_server_auth_token(&token_a, &nonce_a, srv_id, api_key));

    // Replay on different session nonce fails
    assert!(!verify_server_auth_token(&token_a, &nonce_b, srv_id, api_key));

    // Wrong server_id fails
    assert!(!verify_server_auth_token(&token_a, &nonce_a, "srv_beta", api_key));

    // Wrong passkey fails
    assert!(!verify_server_auth_token(&token_a, &nonce_a, srv_id, "wrong-pass"));
}

// ============================================================================
// 3. FILESYSTEM & GIT SECURITY TESTS
// ============================================================================

#[cfg(unix)]
#[test]
fn test_filesystem_permissions_enforcement() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = create_temp_dir("perms");
    let secret_file = test_dir.join("proxy.toml");

    std::fs::write(&secret_file, "secret-data").unwrap();
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o666)).unwrap();

    let mode_before = std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_before, 0o666);

    enforce_private_file_permissions(&secret_file).unwrap();

    let mode_after = std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_after, 0o600);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[cfg(unix)]
#[test]
fn test_git_pre_commit_hook_blocks_sensitive_commits() {
    let test_dir = create_temp_dir("git_hook_test");
    let hook_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".githooks/pre-commit");

    let run = |cmd: &str| -> (bool, String) {
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(cmd)
            .current_dir(&test_dir)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        (output.status.success(), format!("{}\n{}", stdout, stderr))
    };

    run("git init -q");
    run("git config user.name 'Test Committer'");
    run("git config user.email 'test@example.com'");
    run("mkdir -p .githooks");

    let hook_dst = test_dir.join(".githooks/pre-commit");
    std::fs::copy(&hook_src, &hook_dst).unwrap();
    run("chmod +x .githooks/pre-commit");
    run("git config core.hooksPath .githooks");

    let gitignore_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".gitignore");
    std::fs::copy(&gitignore_src, test_dir.join(".gitignore")).unwrap();

    // 1. Verify .gitignore ignores sensitive files
    std::fs::write(test_dir.join("proxy.toml"), "secret=true").unwrap();
    let (ok_status, status_out) = run("git status --porcelain");
    assert!(ok_status);
    assert!(!status_out.contains("proxy.toml"));

    // 2. Test forbidden filename: Force-stage a forbidden file and attempt commit -> must be blocked
    run("git add -f proxy.toml");
    let (commit_ok, commit_err) = run("git commit -m 'Add secret file'");
    assert!(!commit_ok);
    assert!(commit_err.contains("COMMIT BLOCKED") || commit_err.contains("forbidden sensitive file"));
    run("git reset -q proxy.toml");
    let _ = std::fs::remove_file(test_dir.join("proxy.toml"));

    // 3. Test private key content: Stage a file containing a private key header -> must be blocked
    let leaked_key_file = test_dir.join("leaked.txt");
    std::fs::write(&leaked_key_file, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE...").unwrap();
    run("git add leaked.txt");
    let (commit_key_ok, commit_key_err) = run("git commit -m 'Commit private key'");
    assert!(!commit_key_ok);
    assert!(commit_key_err.contains("COMMIT BLOCKED") || commit_key_err.contains("Private"));
    run("git reset -q leaked.txt");
    let _ = std::fs::remove_file(leaked_key_file);

    // 4. Test clean file commit -> must succeed cleanly
    let clean_file = test_dir.join("clean.txt");
    std::fs::write(&clean_file, "This is safe documentation.\n").unwrap();
    run("git add clean.txt .gitignore");
    let (clean_ok, clean_out) = run("git commit -m 'Initial safe commit'");
    assert!(clean_ok, "Clean commit should succeed. Output: {}", clean_out);

    let _ = std::fs::remove_dir_all(&test_dir);
}

// ============================================================================
// 4. PORT GUARDRAIL TESTS
// ============================================================================

#[tokio::test]
async fn test_port_range_and_forbidden_port_rejection() {
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-16000".to_string(),
            listener_grace_period_sec: 60,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec!["legit-proxy-pass".to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Case 1: Requesting privileged port 80 -> proxy safely ignores invalid port and assigns safe port
    let mut server_cfg_priv = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "legit-proxy-pass".to_string(),
            olp_server_id: "srv_priv".to_string(),
            passkey_user: "user-pass".to_string(),
            remote_port: Some(80), // privileged port!
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx1, mut rx1) = watch::channel(false);
    let conn1 = connector.clone();
    let handle_priv = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server_cfg_priv, &conn1, &mut rx1).await;
        server_cfg_priv
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = tx1.send(true);
    let s_priv = handle_priv.await.unwrap();
    let assigned_priv = s_priv.server.remote_port.unwrap();
    assert_ne!(assigned_priv, 80, "Privileged port 80 must never be assigned");
    assert!(assigned_priv >= 15000 && assigned_priv <= 16000);

    // Case 2: Requesting port outside allowed range 15000-16000 (e.g. 25000) -> rejected or reassigned within allowed range
    let mut server_cfg_out = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "legit-proxy-pass".to_string(),
            olp_server_id: "srv_out".to_string(),
            passkey_user: "user-pass".to_string(),
            remote_port: Some(25000), // outside allowed 15000-16000
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx2, mut rx2) = watch::channel(false);
    let conn2 = connector.clone();
    // When an invalid recommended_port is requested, the proxy safely assigns a valid port in the range
    let handle = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server_cfg_out, &conn2, &mut rx2).await;
        server_cfg_out
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = tx2.send(true);
    let s_out = handle.await.unwrap();
    let assigned_out = s_out.server.remote_port.unwrap();
    assert!(assigned_out >= 15000 && assigned_out <= 16000);
}

#[tokio::test]
async fn test_multiple_simultaneous_olp_servers_on_different_ports() {
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17000-17999".to_string(),
            listener_grace_period_sec: 60,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec!["shared-proxy-pass".to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let mut server_cfg1 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "shared-proxy-pass".to_string(),
            olp_server_id: "srv_simul_1".to_string(),
            passkey_user: "user-pass-1".to_string(),
            remote_port: Some(17101),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let mut server_cfg2 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "shared-proxy-pass".to_string(),
            olp_server_id: "srv_simul_2".to_string(),
            passkey_user: "user-pass-2".to_string(),
            remote_port: Some(17102),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx1, mut rx1) = watch::channel(false);
    let (_tx2, mut rx2) = watch::channel(false);

    let connector_clone = connector.clone();
    let task1 = tokio::spawn(async move {
        run_single_tunnel_session(&mut server_cfg1, &connector_clone, &mut rx1).await
    });

    let connector_clone2 = connector.clone();
    let task2 = tokio::spawn(async move {
        run_single_tunnel_session(&mut server_cfg2, &connector_clone2, &mut rx2).await
    });

    for _ in 0..40 {
        let p1 = tokio::net::TcpStream::connect("127.0.0.1:17101").await;
        let p2 = tokio::net::TcpStream::connect("127.0.0.1:17102").await;
        if p1.is_ok() && p2.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(tokio::net::TcpStream::connect("127.0.0.1:17101").await.is_ok());
    assert!(tokio::net::TcpStream::connect("127.0.0.1:17102").await.is_ok());

    task1.abort();
    task2.abort();
}

#[tokio::test]
async fn test_ca_verification_rejects_untrusted_certificates() {
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "18000-18999".to_string(),
            listener_grace_period_sec: 60,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec!["ca-test-passkey".to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();

    // Client with WebPKI CA verification enabled:
    let tls_client_cfg = create_tunnel_tls_client_config(true).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let tcp_stream = tokio::net::TcpStream::connect(proxy_control_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("olp-tunnel.internal").unwrap();

    // The proxy uses a self-signed certificate, which WebPKI root certificates MUST reject
    let tls_result = connector.connect(server_name, tcp_stream).await;
    assert!(tls_result.is_err(), "WebPKI CA verification must reject self-signed proxy cert");

    // But with verify_ca = false, it succeeds:
    let tls_client_cfg_noverify = create_tunnel_tls_client_config(false).unwrap();
    let connector_noverify = TlsConnector::from(tls_client_cfg_noverify);
    let tcp_stream_ok = tokio::net::TcpStream::connect(proxy_control_addr).await.unwrap();
    let server_name_ok = rustls::pki_types::ServerName::try_from("olp-tunnel.internal").unwrap();
    let tls_ok = connector_noverify.connect(server_name_ok, tcp_stream_ok).await;
    assert!(tls_ok.is_ok(), "Self-signed certificate is accepted when verify_ca is false");
}

#[test]
fn test_path_traversal_identifier_rejection() {
    assert!(!is_safe_identifier("../bad"));
    assert!(!is_safe_identifier("../../etc/shadow"));
    assert!(!is_safe_identifier("user\0injection"));
    assert!(!is_safe_identifier("user/slash"));
    assert!(!is_safe_identifier("user\\backslash"));
    assert!(is_safe_identifier("normal_user-123"));
}

#[test]
fn test_server_should_verify_ca_auto_detection() {
    let mut s = ServerSection {
        proxy_addr: "127.0.0.1:4443".to_string(),
        ollama_addr: "127.0.0.1:11434".to_string(),
        olp_api_key: "pass".to_string(),
        olp_server_id: "srv_test".to_string(),
        passkey_user: "user_test".to_string(),
        remote_port: Some(18434),
        tls_verify: None,
    };
    assert!(!s.should_verify_ca());

    s.proxy_addr = "localhost:4443".to_string();
    assert!(!s.should_verify_ca());

    s.proxy_addr = "192.168.1.100:4443".to_string();
    assert!(!s.should_verify_ca());

    s.proxy_addr = "proxy.example.com:4443".to_string();
    assert!(s.should_verify_ca());

    // Explicit override
    s.tls_verify = Some(false);
    assert!(!s.should_verify_ca());

    s.tls_verify = Some(true);
    assert!(s.should_verify_ca());
}

#[test]
fn test_apache_access_log_helpers() {
    // 1. Timestamp formatting
    let now = std::time::SystemTime::now();
    let ts = format_apache_timestamp(now);
    assert!(ts.ends_with(" +0000"), "Must end with +0000: {}", ts);
    assert_eq!(ts.chars().filter(|&c| c == '/').count(), 2);
    assert_eq!(ts.chars().filter(|&c| c == ':').count(), 3);

    // 2. Sanitization
    let raw = "hello \"world\"\nnext line\r\t";
    let sanitized = sanitize_for_log(raw, 50);
    assert_eq!(sanitized, "hello \\\"world\\\"\\nnext line\\r\\t");

    let long_str = "a".repeat(150);
    let truncated = sanitize_for_log(&long_str, 20);
    assert!(truncated.ends_with("..."));
    assert!(truncated.len() <= 23);

    assert_eq!(sanitize_for_log("", 10), "-");

    // 3. Model extraction
    let body_json = br#"{"model":"llama3:8b","prompt":"hi"}"#;
    let dummy_uri: hyper::Uri = "/api/generate".parse().unwrap();
    assert_eq!(extract_model(body_json, &dummy_uri), "llama3:8b");

    let empty_body = b"";
    let query_uri: hyper::Uri = "/api/show?model=mistral".parse().unwrap();
    assert_eq!(extract_model(empty_body, &query_uri), "mistral");

    let no_model_uri: hyper::Uri = "/api/tags".parse().unwrap();
    assert_eq!(extract_model(empty_body, &no_model_uri), "-");

    // 4. Token extraction
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test-token-123"));
    assert_eq!(extract_auth_token(&headers), "Bearer:test-token-123");

    headers.clear();
    headers.insert(hyper::header::HeaderName::from_static("x-api-key"), HeaderValue::from_static("custom-api-key"));
    assert_eq!(extract_auth_token(&headers), "ApiKey:custom-api-key");

    headers.clear();
    assert_eq!(extract_auth_token(&headers), "-");
}

#[tokio::test]
async fn test_apache_access_log_file_logging() {
    let tmp = create_temp_dir("access-log");
    let log_path = tmp.join("access.log");

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "19100-19200".to_string(),
            listener_grace_period_sec: 60,
            access_log: Some(log_path.to_string_lossy().to_string()),
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec!["access-log-proxy-pass".to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();

    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let mut server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "access-log-proxy-pass".to_string(),
            olp_server_id: "srv_access_log".to_string(),
            passkey_user: "access-log-user-pass".to_string(),
            remote_port: Some(19150),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server_cfg, &connector, &mut rx).await;
    });

    // Wait for the public port to open
    for _ in 0..40 {
        if tokio::net::TcpStream::connect("127.0.0.1:19150").await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Send an unauthorized HTTP request (bad passkey_user)
    let mut bad_req = tokio::net::TcpStream::connect("127.0.0.1:19150").await.unwrap();
    let bad_payload = "POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1:19150\r\nAuthorization: Bearer bad-token\r\nContent-Length: 35\r\n\r\n{\"model\":\"llama3\",\"prompt\":\"hello\"}";
    tokio::io::AsyncWriteExt::write_all(&mut bad_req, bad_payload.as_bytes()).await.unwrap();
    let mut resp_buf = vec![0u8; 1024];
    let _ = tokio::io::AsyncReadExt::read(&mut bad_req, &mut resp_buf).await;

    // Send a CORS preflight OPTIONS request
    let mut options_req = tokio::net::TcpStream::connect("127.0.0.1:19150").await.unwrap();
    let options_payload = "OPTIONS /api/tags HTTP/1.1\r\nHost: 127.0.0.1:19150\r\n\r\n";
    tokio::io::AsyncWriteExt::write_all(&mut options_req, options_payload.as_bytes()).await.unwrap();
    let _ = tokio::io::AsyncReadExt::read(&mut options_req, &mut resp_buf).await;

    // Allow background logger to flush to disk
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(log_path.exists(), "access.log must be created");
    let content = std::fs::read_to_string(&log_path).unwrap();

    // Verify Apache log lines
    assert!(content.contains("127.0.0.1"));
    assert!(content.contains("401"));
    assert!(content.contains("Bearer:bad-token"));
    assert!(content.contains("model=\"llama3\""));
    assert!(content.contains("req=\"{\\\"model\\\":\\\"llama3\\\",\\\"prompt\\\":\\\"hello\\\"}\""));
    assert!(content.contains("OPTIONS /api/tags HTTP/1.1"));
    assert!(content.contains("204"));
}

// ============================================================================
// 6. MULTI-TENANT, ACL & BOUNDARY ATTACK TESTS
// ============================================================================

#[tokio::test]
async fn test_handshake_rejects_path_traversal_identifiers() {
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17200-17300".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec!["valid_user_key".to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Case A: Traversal in olp_api_key
    let mut server_traversal_key = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "../../../etc/shadow".to_string(),
            olp_server_id: "srv_valid".to_string(),
            passkey_user: "user_pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx1, mut rx1) = watch::channel(false);
    let res1 = run_single_tunnel_session(&mut server_traversal_key, &connector, &mut rx1).await;
    assert!(res1.is_err());
    let err1 = res1.unwrap_err().to_string();
    assert!(err1.contains("ERR_INVALID_IDENTIFIER"), "Expected ERR_INVALID_IDENTIFIER, got: {}", err1);

    // Case B: Traversal in olp_server_id
    let mut server_traversal_id = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: "valid_user_key".to_string(),
            olp_server_id: "srv/../../evil".to_string(),
            passkey_user: "user_pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx2, mut rx2) = watch::channel(false);
    let res2 = run_single_tunnel_session(&mut server_traversal_id, &connector, &mut rx2).await;
    assert!(res2.is_err());
    let err2 = res2.unwrap_err().to_string();
    assert!(err2.contains("ERR_INVALID_IDENTIFIER"), "Expected ERR_INVALID_IDENTIFIER, got: {}", err2);
}

#[tokio::test]
async fn test_user_disabled_account_rejection() {
    let user_key = "disabled_user_account";
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17300-17400".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![user_key.to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Manually create user profile with disabled = true
    let config_dir = olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", user_key));
    let mut profile = UserProfile::new(user_key);
    profile.user.disabled = true;
    profile.save_atomic(&profile_path).unwrap();

    let mut server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_disabled_test".to_string(),
            passkey_user: "user_pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    let res = run_single_tunnel_session(&mut server_cfg, &connector, &mut rx).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("ERR_USER_DISABLED"), "Expected ERR_USER_DISABLED, got: {}", err);

    let _ = std::fs::remove_file(&profile_path);
}

#[tokio::test]
async fn test_user_max_servers_limit_enforcement() {
    let user_key = "quota_limited_user";
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17400-17450".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![user_key.to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Set max_servers = 1
    let config_dir = olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", user_key));
    let mut profile = UserProfile::new(user_key);
    profile.user.max_servers = 1;
    profile.save_atomic(&profile_path).unwrap();

    // 1st server -> succeeds
    let mut server1 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_slot1".to_string(),
            passkey_user: "user_pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx1, mut rx1) = watch::channel(false);
    let conn1 = connector.clone();
    let handle1 = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut server1, &conn1, &mut rx1).await;
        server1
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2nd server -> exceeds max_servers (1), must be rejected with ERR_MAX_SERVERS_EXCEEDED
    let mut server2 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_slot2_overflow".to_string(),
            passkey_user: "user_pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx2, mut rx2) = watch::channel(false);
    let res2 = run_single_tunnel_session(&mut server2, &connector, &mut rx2).await;
    assert!(res2.is_err());
    let err2 = res2.unwrap_err().to_string();
    assert!(err2.contains("ERR_MAX_SERVERS_EXCEEDED"), "Expected ERR_MAX_SERVERS_EXCEEDED, got: {}", err2);

    let _ = tx1.send(true);
    let _ = handle1.await;
    let _ = std::fs::remove_file(&profile_path);
}

#[tokio::test]
async fn test_cross_user_port_stealing_prevention() {
    let alice_key = "cross_user_alice";
    let bob_key = "cross_user_bob";

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17500-17600".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![alice_key.to_string(), bob_key.to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Pre-allocate port 17500 to Alice
    let config_dir = olp_config_dir().unwrap();
    let alice_profile_path = config_dir.join(format!("{}.toml", alice_key));
    let mut alice_profile = UserProfile::new(alice_key);
    alice_profile.servers.insert(
        "srv_alice_box".to_string(),
        UserServerConfig {
            port: 17500,
            reserved: true,
            passkey_user: "alice_pass".to_string(),
            allowed_user_cidrs: vec!["0.0.0.0/0".to_string()],
            allowed_server_cidrs: vec!["0.0.0.0/0".to_string()],
            created_at: None,
        },
    );
    alice_profile.save_atomic(&alice_profile_path).unwrap();

    // Bob tries to connect recommending port 17500
    let mut bob_server = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: bob_key.to_string(),
            olp_server_id: "srv_bob_box".to_string(),
            passkey_user: "bob_pass".to_string(),
            remote_port: Some(17500), // recommending Alice's port!
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (tx_bob, mut rx_bob) = watch::channel(false);
    let conn_bob = connector.clone();
    let handle_bob = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut bob_server, &conn_bob, &mut rx_bob).await;
        bob_server
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = tx_bob.send(true);
    let res_bob = handle_bob.await.unwrap();

    // Verify Bob was assigned a free port that is NOT Alice's port (17500)
    let assigned = res_bob.server.remote_port.unwrap();
    assert_ne!(assigned, 17500, "Proxy must NOT assign another user's assigned port");
    assert!(assigned >= 17500 && assigned <= 17600);

    let _ = std::fs::remove_file(&alice_profile_path);
    let bob_profile_path = config_dir.join(format!("{}.toml", bob_key));
    let _ = std::fs::remove_file(&bob_profile_path);
}

#[tokio::test]
async fn test_port_exhaustion_returns_clean_error() {
    let user_key = "exhaustion_user";
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17700-17701".to_string(), // Only 2 ports available!
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![user_key.to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // 1st server -> gets 17700
    let mut srv1 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_ex1".to_string(),
            passkey_user: "pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };
    let (tx1, mut rx1) = watch::channel(false);
    let conn1 = connector.clone();
    let h1 = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut srv1, &conn1, &mut rx1).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2nd server -> gets 17701
    let mut srv2 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_ex2".to_string(),
            passkey_user: "pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };
    let (tx2, mut rx2) = watch::channel(false);
    let conn2 = connector.clone();
    let h2 = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&mut srv2, &conn2, &mut rx2).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3rd server -> range exhausted! Must fail with ERR_NO_PORTS_AVAILABLE
    let mut srv3 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_ex3".to_string(),
            passkey_user: "pass".to_string(),
            remote_port: None,
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };
    let (_tx3, mut rx3) = watch::channel(false);
    let res3 = run_single_tunnel_session(&mut srv3, &connector, &mut rx3).await;
    assert!(res3.is_err());
    let err3 = res3.unwrap_err().to_string();
    assert!(err3.contains("ERR_NO_PORTS_AVAILABLE"), "Expected ERR_NO_PORTS_AVAILABLE, got: {}", err3);

    let _ = tx1.send(true);
    let _ = tx2.send(true);
    let _ = h1.await;
    let _ = h2.await;

    let config_dir = olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", user_key));
    let _ = std::fs::remove_file(&profile_path);
}

#[tokio::test]
async fn test_server_specific_cidr_restrictions() {
    let user_key = "per_server_cidr_user";
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17800-17900".to_string(),
            listener_grace_period_sec: 10,
            access_log: None,
        },
        auth: ProxyAuthSection {
            olp_api_keys: vec![user_key.to_string()],
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
        maintenance: Default::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Save server profile where allowed_server_cidrs is restricted to an IP different from 127.0.0.1
    let config_dir = olp_config_dir().unwrap();
    let profile_path = config_dir.join(format!("{}.toml", user_key));
    let mut profile = UserProfile::new(user_key);
    profile.servers.insert(
        "srv_restricted_cidr".to_string(),
        UserServerConfig {
            port: 17850,
            reserved: false,
            passkey_user: "user_pass".to_string(),
            allowed_user_cidrs: vec!["0.0.0.0/0".to_string()],
            allowed_server_cidrs: vec!["192.168.254.1/32".to_string()], // 127.0.0.1 disallowed!
            created_at: None,
        },
    );
    profile.save_atomic(&profile_path).unwrap();

    let mut server = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            olp_api_key: user_key.to_string(),
            olp_server_id: "srv_restricted_cidr".to_string(),
            passkey_user: "user_pass".to_string(),
            remote_port: Some(17850),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
        maintenance: Default::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    let res = run_single_tunnel_session(&mut server, &connector, &mut rx).await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("ERR_SERVER_IP_FORBIDDEN"),
        "Expected ERR_SERVER_IP_FORBIDDEN, got: {}",
        err
    );

    let _ = std::fs::remove_file(&profile_path);
}
