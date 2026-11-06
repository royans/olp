use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use hyper::service::service_fn;
use hyper::Response;
use olp::config::{
    ProxyConfig, ProxyKeysSection, ProxySection, ProxySecuritySection, ProxyTlsSection,
    ReconnectSection, ServerConfig, ServerKeysSection, ServerSection,
};
use olp::keys::{
    add_authorized_key, enforce_private_file_permissions, format_pubkey,
    load_or_generate_keypair, verify_authorized_key, write_private_file, PasskeyVerifier,
};
use olp::protocol::{
    create_tunnel_tls_client_config, ProxyHelloChallenge, ServerAuthRegister,
};
use olp::proxy::{start_proxy_server, verify_http_headers_auth, IpRateLimiter};
use olp::server::run_single_tunnel_session;
use rand::rngs::OsRng;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
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

    assert!(!limiter.is_rate_limited(ip1));
    assert!(!limiter.is_rate_limited(ip2));

    // 1st failure
    limiter.record_failure(ip1);
    assert!(!limiter.is_rate_limited(ip1));

    // 2nd failure
    limiter.record_failure(ip1);
    assert!(!limiter.is_rate_limited(ip1));

    // 3rd failure -> trips threshold
    limiter.record_failure(ip1);
    assert!(limiter.is_rate_limited(ip1));

    // ip2 should still not be rate limited
    assert!(!limiter.is_rate_limited(ip2));

    // Clear IP
    limiter.clear_ip(ip1);
    assert!(!limiter.is_rate_limited(ip1));
}

#[test]
fn test_passkey_verifier_edge_cases() {
    // Normal passkey
    let verifier = PasskeyVerifier::from_passkey("MyComplexPass#123!");
    assert!(verifier.verify("MyComplexPass#123!"));
    assert!(!verifier.verify("Mycomplexpass#123!"));
    assert!(!verifier.verify(""));

    // Empty passkey
    let empty_verifier = PasskeyVerifier::from_passkey("");
    assert!(empty_verifier.verify(""));
    assert!(!empty_verifier.verify(" "));

    // Unicode and emoji passkey
    let unicode_verifier = PasskeyVerifier::from_passkey("🔑Secret_Пароль_测试_123");
    assert!(unicode_verifier.verify("🔑Secret_Пароль_测试_123"));
    assert!(!unicode_verifier.verify("🔑Secret_Пароль_测试_124"));

    // Long passkey (1000 characters)
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

    // 1. Missing header
    assert!(!check(None));

    // 2. Bearer token variations
    assert!(check(Some(&format!("Bearer {}", pass))));
    assert!(check(Some(&format!("bearer {}", pass))));
    assert!(check(Some(&format!("Bearer  {} ", pass)))); // leading/trailing spaces in token
    assert!(!check(Some("Bearer wrong-pass")));
    assert!(!check(Some("Bearer")));
    assert!(!check(Some("Token something")));

    // 3. Basic Auth variations
    // Standard username:password
    let creds1 = BASE64.encode(format!("ollama-user:{}", pass));
    assert!(check(Some(&format!("Basic {}", creds1))));
    assert!(check(Some(&format!("basic {}", creds1))));

    // Empty username :password (valid in RFC 7617)
    let creds_no_user = BASE64.encode(format!(":{}", pass));
    assert!(check(Some(&format!("Basic {}", creds_no_user))));

    // Custom username admin:password
    let creds_admin = BASE64.encode(format!("admin:{}", pass));
    assert!(check(Some(&format!("Basic {}", creds_admin))));

    // Bare passkey encoded without colon (only when passkey has no colons)
    let simple_pass = "simple-passkey-without-colons";
    let simple_verifier = PasskeyVerifier::from_passkey(simple_pass);
    let creds_bare = BASE64.encode(simple_pass);
    let mut bare_headers = HeaderMap::new();
    bare_headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Basic {}", creds_bare)).unwrap());
    assert!(verify_http_headers_auth(&bare_headers, &simple_verifier));

    // Wrong password in Basic Auth
    let creds_wrong = BASE64.encode("user:badpassword");
    assert!(!check(Some(&format!("Basic {}", creds_wrong))));

    // Malformed base64
    assert!(!check(Some("Basic ???not-base64???")));
}

#[test]
fn test_authorized_keys_parsing_and_port_pinning() {
    let key1 = SigningKey::generate(&mut OsRng);
    let pub1 = format_pubkey("olp-server-ed25519", &key1.verifying_key());

    let key2 = SigningKey::generate(&mut OsRng);
    let pub2 = format_pubkey("olp-server-ed25519", &key2.verifying_key());

    let content = format!(
        "# Authorized keys comment\n{} home-server ports=11434,11435\n{} work-server\n",
        pub1, pub2
    );

    let test_dir = create_temp_dir("auth_keys");
    let auth_file = test_dir.join("authorized_keys");
    write_private_file(&auth_file, &content).unwrap();

    // key1 is pinned to ports 11434, 11435
    assert!(verify_authorized_key(&auth_file, &key1.verifying_key(), 11434).unwrap());
    assert!(verify_authorized_key(&auth_file, &key1.verifying_key(), 11435).unwrap());
    assert!(!verify_authorized_key(&auth_file, &key1.verifying_key(), 11436).unwrap());

    // key2 has no port restriction (allowed on any port)
    assert!(verify_authorized_key(&auth_file, &key2.verifying_key(), 11434).unwrap());
    assert!(verify_authorized_key(&auth_file, &key2.verifying_key(), 19999).unwrap());

    // Unknown key
    let unknown_key = SigningKey::generate(&mut OsRng);
    assert!(!verify_authorized_key(&auth_file, &unknown_key.verifying_key(), 11434).unwrap());

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[cfg(unix)]
#[test]
fn test_git_pre_commit_hook_blocks_sensitive_commits() {
    let test_dir = create_temp_dir("git_hook_test");
    let hook_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".githooks/pre-commit");

    // Initialize temporary git repo
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

    // Copy hook and make it executable
    let hook_dst = test_dir.join(".githooks/pre-commit");
    std::fs::copy(&hook_src, &hook_dst).unwrap();
    run("chmod +x .githooks/pre-commit");
    run("git config core.hooksPath .githooks");

    // Copy .gitignore to test_dir
    let gitignore_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".gitignore");
    std::fs::copy(&gitignore_src, test_dir.join(".gitignore")).unwrap();

    // 1. Verify .gitignore ignores sensitive files
    std::fs::write(test_dir.join("proxy.toml"), "secret=true").unwrap();
    std::fs::write(test_dir.join("server_id_ed25519"), "secret_key").unwrap();
    let (ok_status, status_out) = run("git status --porcelain");
    assert!(ok_status);
    assert!(!status_out.contains("proxy.toml"), "proxy.toml should be ignored by .gitignore");
    assert!(!status_out.contains("server_id_ed25519"), "server_id_ed25519 should be ignored by .gitignore");

    // 2. Test forbidden filename: Force-stage a forbidden file and attempt commit -> must be blocked
    run("git add -f proxy.toml");
    let (commit_ok, commit_err) = run("git commit -m 'Add secret file'");
    assert!(!commit_ok, "Commit with forbidden filename must be blocked");
    assert!(commit_err.contains("COMMIT BLOCKED") || commit_err.contains("forbidden sensitive file"));
    run("git reset -q proxy.toml");
    let _ = std::fs::remove_file(test_dir.join("proxy.toml"));

    // 3. Test private key content: Stage a file containing a private key header -> must be blocked
    let leaked_key_file = test_dir.join("leaked.txt");
    std::fs::write(&leaked_key_file, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE...").unwrap();
    run("git add leaked.txt");
    let (commit_key_ok, commit_key_err) = run("git commit -m 'Commit private key'");
    assert!(!commit_key_ok, "Commit containing private key content must be blocked");
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

#[cfg(unix)]
#[test]
fn test_filesystem_permissions_enforcement() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = create_temp_dir("perms");
    let secret_file = test_dir.join("id_ed25519");

    // Write file with world-readable permissions 0666
    std::fs::write(&secret_file, "secret-data").unwrap();
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o666)).unwrap();

    // Verify it was 0666
    let mode_before = std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_before, 0o666);

    // Run enforce_private_file_permissions
    enforce_private_file_permissions(&secret_file).unwrap();

    // Verify it is tightened to 0600
    let mode_after = std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_after, 0o600);

    let _ = std::fs::remove_dir_all(&test_dir);
}

// ============================================================================
// 2. CRYPTOGRAPHIC & MITM CHANNEL BINDING TESTS
// ============================================================================

#[test]
fn test_tls_channel_binding_prevents_signature_replay() {
    let proxy_signing = SigningKey::generate(&mut OsRng);
    let server_signing = SigningKey::generate(&mut OsRng);

    let tls_exporter_session_a = [1u8; 32];
    let tls_exporter_session_b = [2u8; 32]; // Different TLS session!

    // Session A creates challenge & register
    let challenge_a = ProxyHelloChallenge::create(&proxy_signing, &tls_exporter_session_a);
    let verifier = PasskeyVerifier::from_passkey("test-passkey");
    let register_a = ServerAuthRegister::create(
        &server_signing,
        &tls_exporter_session_a,
        &challenge_a.proxy_nonce,
        11434,
        verifier.clone(),
    );

    // In Session A: Verification succeeds
    assert!(challenge_a
        .verify(&proxy_signing.verifying_key(), &tls_exporter_session_a)
        .is_ok());
    assert!(register_a
        .verify(&tls_exporter_session_a, &challenge_a.proxy_nonce)
        .is_ok());

    // ATTACK 1: Attacker captures register_a and attempts to replay it on Session B
    let replay_result = register_a.verify(&tls_exporter_session_b, &challenge_a.proxy_nonce);
    assert!(replay_result.is_err(), "Replayed signature must fail on different TLS session");

    // ATTACK 2: Attacker captures challenge_a and attempts to present it on Session B
    let fake_challenge_result =
        challenge_a.verify(&proxy_signing.verifying_key(), &tls_exporter_session_b);
    assert!(fake_challenge_result.is_err(), "Replayed challenge must fail on different TLS session");

    // ATTACK 3: Tampering with requested port in register_a
    let mut tampered_register = register_a.clone();
    tampered_register.remote_port = 11435;
    assert!(
        tampered_register
            .verify(&tls_exporter_session_a, &challenge_a.proxy_nonce)
            .is_err(),
        "Tampering with remote_port must break signature verification"
    );

    // ATTACK 4: Tampering with passkey verifier in register_a
    let mut tampered_verifier = register_a.clone();
    tampered_verifier.passkey_verifier = PasskeyVerifier::from_passkey("hacked");
    assert!(
        tampered_verifier
            .verify(&tls_exporter_session_a, &challenge_a.proxy_nonce)
            .is_err(),
        "Tampering with passkey_verifier must break signature verification"
    );
}

// ============================================================================
// 3. SECURITY INTEGRATION TESTS (PORT GUARDRAILS, CONFLICTS, FORBIDDEN METHODS)
// ============================================================================

#[tokio::test]
async fn test_port_range_and_forbidden_port_rejection() {
    let test_dir = create_temp_dir("port_sec");
    let proxy_priv = test_dir.join("proxy_id_ed25519");
    let auth_keys = test_dir.join("authorized_keys");
    let server_priv = test_dir.join("server_id_ed25519");
    let known_proxy = test_dir.join("known_proxy.pub");

    let proxy_signing = load_or_generate_keypair(&proxy_priv, "olp-proxy-ed25519").unwrap();
    let server_signing = Arc::new(load_or_generate_keypair(&server_priv, "olp-server-ed25519").unwrap());

    let proxy_pub_str = format_pubkey("olp-proxy-ed25519", &proxy_signing.verifying_key());
    let server_pub_str = format_pubkey("olp-server-ed25519", &server_signing.verifying_key());

    write_private_file(&known_proxy, &format!("{}\n", proxy_pub_str)).unwrap();
    add_authorized_key(&auth_keys, &server_pub_str).unwrap();

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-16000".to_string(),
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

    // Case 1: Requesting privileged port 80 -> rejected by proxy
    let mut server_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: 80, // privileged port!
            passkey: "secret".to_string(),
        },
        keys: ServerKeysSection {
            private_key: server_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    let res_priv = run_single_tunnel_session(
        &server_cfg,
        &server_signing,
        &proxy_signing.verifying_key(),
        &connector,
        &mut rx,
    )
    .await;
    assert!(res_priv.is_err());
    assert!(res_priv.unwrap_err().to_string().contains("ERR_PORT_FORBIDDEN"));

    // Case 2: Requesting port outside allowed range (e.g. 17000 > 16000)
    server_cfg.server.remote_port = 17000;
    let res_range = run_single_tunnel_session(
        &server_cfg,
        &server_signing,
        &proxy_signing.verifying_key(),
        &connector,
        &mut rx,
    )
    .await;
    assert!(res_range.is_err());
    assert!(res_range.unwrap_err().to_string().contains("ERR_PORT_FORBIDDEN"));

    // Case 3: Requesting proxy's own control port
    server_cfg.server.remote_port = proxy_control_addr.port();
    let res_ctrl = run_single_tunnel_session(
        &server_cfg,
        &server_signing,
        &proxy_signing.verifying_key(),
        &connector,
        &mut rx,
    )
    .await;
    assert!(res_ctrl.is_err());
    assert!(res_ctrl.unwrap_err().to_string().contains("ERR_PORT_FORBIDDEN"));

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_multiple_simultaneous_olp_servers_on_different_ports() {
    let test_dir = create_temp_dir("multi_server");
    let proxy_priv = test_dir.join("proxy_id_ed25519");
    let auth_keys = test_dir.join("authorized_keys");

    let server1_priv = test_dir.join("server1_id_ed25519");
    let server2_priv = test_dir.join("server2_id_ed25519");
    let known_proxy = test_dir.join("known_proxy.pub");

    let proxy_signing = load_or_generate_keypair(&proxy_priv, "olp-proxy-ed25519").unwrap();
    let server1_signing = Arc::new(load_or_generate_keypair(&server1_priv, "olp-server-ed25519").unwrap());
    let server2_signing = Arc::new(load_or_generate_keypair(&server2_priv, "olp-server-ed25519").unwrap());

    let proxy_pub_str = format_pubkey("olp-proxy-ed25519", &proxy_signing.verifying_key());
    write_private_file(&known_proxy, &format!("{}\n", proxy_pub_str)).unwrap();

    // Authorize BOTH servers in proxy's authorized_keys
    add_authorized_key(&auth_keys, &format_pubkey("olp-server-ed25519", &server1_signing.verifying_key())).unwrap();
    add_authorized_key(&auth_keys, &format_pubkey("olp-server-ed25519", &server2_signing.verifying_key())).unwrap();

    // Start two mock Ollama backends (one per server)
    let mock1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock1_addr = mock1.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = mock1.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_| async {
                    let body: http_body_util::combinators::BoxBody<Bytes, hyper::Error> =
                        http_body_util::Full::new(Bytes::from_static(b"{\"server\":\"gpu-cluster-1\"}"))
                            .map_err(|never| match never {})
                            .boxed();
                    Ok::<_, hyper::Error>(Response::new(body))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let mock2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock2_addr = mock2.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = mock2.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_| async {
                    let body: http_body_util::combinators::BoxBody<Bytes, hyper::Error> =
                        http_body_util::Full::new(Bytes::from_static(b"{\"server\":\"mac-studio-2\"}"))
                            .map_err(|never| match never {})
                            .boxed();
                    Ok::<_, hyper::Error>(Response::new(body))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-16000".to_string(),
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

    let port1 = 15601u16;
    let port2 = 15602u16;
    let passkey1 = "pass-server-1";
    let passkey2 = "pass-server-2";

    let server1_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: mock1_addr.to_string(),
            remote_port: port1,
            passkey: passkey1.to_string(),
        },
        keys: ServerKeysSection {
            private_key: server1_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection::default(),
    };

    let server2_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: mock2_addr.to_string(),
            remote_port: port2,
            passkey: passkey2.to_string(),
        },
        keys: ServerKeysSection {
            private_key: server2_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection::default(),
    };

    // Connect Server 1
    let (tx1, mut rx1) = watch::channel(false);
    let s1_signing = server1_signing.clone();
    let s1_proxy_key = proxy_signing.verifying_key();
    let s1_connector = connector.clone();
    let h1 = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&server1_cfg, &s1_signing, &s1_proxy_key, &s1_connector, &mut rx1).await;
    });

    // Connect Server 2 simultaneously
    let (tx2, mut rx2) = watch::channel(false);
    let s2_signing = server2_signing.clone();
    let s2_proxy_key = proxy_signing.verifying_key();
    let s2_connector = connector.clone();
    let h2 = tokio::spawn(async move {
        let _ = run_single_tunnel_session(&server2_cfg, &s2_signing, &s2_proxy_key, &s2_connector, &mut rx2).await;
    });

    // Wait for both public ports to open
    let addr1: std::net::SocketAddr = format!("127.0.0.1:{}", port1).parse().unwrap();
    let addr2: std::net::SocketAddr = format!("127.0.0.1:{}", port2).parse().unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Query Server 1 endpoint (port 15601) with passkey1
    let stream1 = tokio::net::TcpStream::connect(addr1).await.unwrap();
    let (mut sender1, conn1) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream1)).await.unwrap();
    tokio::spawn(async move { let _ = conn1.await; });
    let req1 = hyper::Request::builder()
        .uri("/api/tags")
        .header(hyper::header::AUTHORIZATION, format!("Bearer {}", passkey1))
        .body(http_body_util::Full::new(Bytes::new())).unwrap();
    let resp1 = sender1.send_request(req1).await.unwrap();
    assert_eq!(resp1.status(), hyper::StatusCode::OK);
    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body1).contains("gpu-cluster-1"));

    // Query Server 2 endpoint (port 15602) with passkey2
    let stream2 = tokio::net::TcpStream::connect(addr2).await.unwrap();
    let (mut sender2, conn2) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream2)).await.unwrap();
    tokio::spawn(async move { let _ = conn2.await; });
    let req2 = hyper::Request::builder()
        .uri("/api/tags")
        .header(hyper::header::AUTHORIZATION, format!("Bearer {}", passkey2))
        .body(http_body_util::Full::new(Bytes::new())).unwrap();
    let resp2 = sender2.send_request(req2).await.unwrap();
    assert_eq!(resp2.status(), hyper::StatusCode::OK);
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body2).contains("mac-studio-2"));

    // Cross-check: passkey1 fails on Server 2
    let stream_bad = tokio::net::TcpStream::connect(addr2).await.unwrap();
    let (mut sender_bad, conn_bad) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream_bad)).await.unwrap();
    tokio::spawn(async move { let _ = conn_bad.await; });
    let req_bad = hyper::Request::builder()
        .uri("/api/tags")
        .header(hyper::header::AUTHORIZATION, format!("Bearer {}", passkey1)) // wrong passkey!
        .body(http_body_util::Full::new(Bytes::new())).unwrap();
    let resp_bad = sender_bad.send_request(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), hyper::StatusCode::UNAUTHORIZED);

    let _ = tx1.send(true);
    let _ = tx2.send(true);
    let _ = h1.await;
    let _ = h2.await;
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_port_conflict_between_different_servers() {
    let test_dir = create_temp_dir("port_conflict");
    let proxy_priv = test_dir.join("proxy_id_ed25519");
    let auth_keys = test_dir.join("authorized_keys");

    let server1_priv = test_dir.join("server1_id_ed25519");
    let server2_priv = test_dir.join("server2_id_ed25519");
    let known_proxy = test_dir.join("known_proxy.pub");

    let proxy_signing = load_or_generate_keypair(&proxy_priv, "olp-proxy-ed25519").unwrap();
    let server1_signing = Arc::new(load_or_generate_keypair(&server1_priv, "olp-server-ed25519").unwrap());
    let server2_signing = Arc::new(load_or_generate_keypair(&server2_priv, "olp-server-ed25519").unwrap());

    let proxy_pub_str = format_pubkey("olp-proxy-ed25519", &proxy_signing.verifying_key());
    write_private_file(&known_proxy, &format!("{}\n", proxy_pub_str)).unwrap();

    // Authorize BOTH servers
    add_authorized_key(&auth_keys, &format_pubkey("olp-server-ed25519", &server1_signing.verifying_key())).unwrap();
    add_authorized_key(&auth_keys, &format_pubkey("olp-server-ed25519", &server2_signing.verifying_key())).unwrap();

    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "15000-16000".to_string(),
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

    let shared_port = 15555u16;

    let server1_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: shared_port,
            passkey: "secret1".to_string(),
        },
        keys: ServerKeysSection {
            private_key: server1_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection::default(),
    };

    let server2_cfg = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: shared_port, // SAME PORT!
            passkey: "secret2".to_string(),
        },
        keys: ServerKeysSection {
            private_key: server2_priv.to_string_lossy().to_string(),
            known_proxy_key: known_proxy.to_string_lossy().to_string(),
        },
        reconnect: ReconnectSection::default(),
    };

    // Server 1 establishes tunnel and binds port 15555
    let (shutdown_tx1, mut shutdown_rx1) = watch::channel(false);
    let s1_signing = server1_signing.clone();
    let s1_proxy_key = proxy_signing.verifying_key();
    let s1_connector = connector.clone();
    let server1_handle = tokio::spawn(async move {
        let _ = run_single_tunnel_session(
            &server1_cfg,
            &s1_signing,
            &s1_proxy_key,
            &s1_connector,
            &mut shutdown_rx1,
        )
        .await;
    });

    // Wait for port 15555 to open
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Server 2 (with different public key) tries to bind port 15555 -> must be rejected with ERR_PORT_CONFLICT
    let (_shutdown_tx2, mut shutdown_rx2) = watch::channel(false);
    let conflict_res = run_single_tunnel_session(
        &server2_cfg,
        &server2_signing,
        &proxy_signing.verifying_key(),
        &connector,
        &mut shutdown_rx2,
    )
    .await;

    assert!(conflict_res.is_err());
    assert!(conflict_res.unwrap_err().to_string().contains("ERR_PORT_CONFLICT"));

    let _ = shutdown_tx1.send(true);
    let _ = server1_handle.await;
    let _ = std::fs::remove_dir_all(&test_dir);
}
