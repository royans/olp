use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use olp::cidr::{CidrBlock, IpFilter};
use olp::config::{
    ProxyAuthSection, ProxyConfig, ProxySection, ProxySecuritySection, ProxyTlsSection,
    ReconnectSection, ServerConfig, ServerSection,
};
use olp::keys::{enforce_private_file_permissions, IpRateLimiter, PasskeyVerifier};
use olp::protocol::{
    compute_proxy_auth_token, create_tunnel_tls_client_config, verify_proxy_auth_token,
};
use olp::proxy::{start_proxy_server, verify_http_headers_auth};
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
fn test_passkey_proxy_nonce_binding() {
    let nonce_a = [1u8; 32];
    let nonce_b = [2u8; 32];
    let passkey = "proxy-secret-123";

    let token_a = compute_proxy_auth_token(passkey, &nonce_a);
    assert!(verify_proxy_auth_token(&token_a, passkey, &nonce_a));

    // Replay on different session nonce fails
    assert!(!verify_proxy_auth_token(&token_a, passkey, &nonce_b));

    // Wrong passkey fails
    assert!(!verify_proxy_auth_token(&token_a, "wrong-pass", &nonce_a));
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
        },
        auth: ProxyAuthSection {
            passkey_proxy: "legit-proxy-pass".to_string(),
            passkey_user: "legit-user-pass".to_string(),
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    // Case 1: Requesting privileged port 80 -> rejected by proxy
    let server_cfg_priv = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: 80, // privileged port!
            passkey_proxy: "legit-proxy-pass".to_string(),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
    };

    let (_tx, mut rx) = watch::channel(false);
    let res_priv = run_single_tunnel_session(&server_cfg_priv, &connector, &mut rx).await;
    assert!(res_priv.is_err());
    assert!(res_priv
        .unwrap_err()
        .to_string()
        .contains("ERR_PORT_FORBIDDEN"));

    // Case 2: Requesting port outside allowed range 15000-16000 (e.g. 25000) -> rejected
    let server_cfg_out = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: 25000, // outside allowed 15000-16000
            passkey_proxy: "legit-proxy-pass".to_string(),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
    };

    let (_tx, mut rx2) = watch::channel(false);
    let res_out = run_single_tunnel_session(&server_cfg_out, &connector, &mut rx2).await;
    assert!(res_out.is_err());
    assert!(res_out
        .unwrap_err()
        .to_string()
        .contains("ERR_PORT_FORBIDDEN"));
}

#[tokio::test]
async fn test_multiple_simultaneous_olp_servers_on_different_ports() {
    let proxy_cfg = ProxyConfig {
        proxy: ProxySection {
            listen_addr: "127.0.0.1:0".to_string(),
            allowed_ports: "17000-17999".to_string(),
            listener_grace_period_sec: 60,
        },
        auth: ProxyAuthSection {
            passkey_proxy: "shared-proxy-pass".to_string(),
            passkey_user: "shared-user-pass".to_string(),
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
    };

    let (proxy_control_addr, _proxy_handle) = start_proxy_server(proxy_cfg).await.unwrap();
    let tls_client_cfg = create_tunnel_tls_client_config(false).unwrap();
    let connector = TlsConnector::from(tls_client_cfg);

    let server_cfg1 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: 17101,
            passkey_proxy: "shared-proxy-pass".to_string(),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
    };

    let server_cfg2 = ServerConfig {
        server: ServerSection {
            proxy_addr: proxy_control_addr.to_string(),
            ollama_addr: "127.0.0.1:11434".to_string(),
            remote_port: 17102,
            passkey_proxy: "shared-proxy-pass".to_string(),
            tls_verify: None,
        },
        reconnect: ReconnectSection::default(),
    };

    let (_tx1, rx1) = watch::channel(false);
    let (_tx2, rx2) = watch::channel(false);

    let connector_clone = connector.clone();
    let task1 = tokio::spawn(async move {
        run_single_tunnel_session(&server_cfg1, &connector_clone, &mut { rx1 }).await
    });

    let connector_clone2 = connector.clone();
    let task2 = tokio::spawn(async move {
        run_single_tunnel_session(&server_cfg2, &connector_clone2, &mut { rx2 }).await
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
        },
        auth: ProxyAuthSection {
            passkey_proxy: "ca-test-passkey".to_string(),
            passkey_user: "ca-test-user".to_string(),
        },
        security: ProxySecuritySection::default(),
        tls: ProxyTlsSection::default(),
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
fn test_server_should_verify_ca_auto_detection() {
    let mut s = ServerSection {
        proxy_addr: "127.0.0.1:4443".to_string(),
        ollama_addr: "127.0.0.1:11434".to_string(),
        remote_port: 18434,
        passkey_proxy: "pass".to_string(),
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
