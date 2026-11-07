use anyhow::Result;
use clap::Parser;
use olp::config::{ensure_proxy_initialized, olp_home_dir, ProxyCliOverrides};
use olp::proxy::start_proxy_server;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "olp-proxy",
    version,
    about = "Ollama Proxy public gateway daemon (olp-proxy)"
)]
struct Args {
    /// Path to proxy configuration file (defaults to ~/.olp/proxy.toml)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Tunnel listen address for incoming olp-server connections (e.g. 0.0.0.0:4443)
    #[arg(long)]
    listen_addr: Option<String>,

    /// Allowed public port range for allocated servers (e.g. 10000-20000)
    #[arg(long)]
    allowed_ports: Option<String>,

    /// Initial olp_api_key (or comma-separated list of keys) for authenticating servers
    #[arg(long)]
    olp_api_key: Option<String>,

    /// Allowed CIDR blocks for tunnel connections (comma-separated, default: 0.0.0.0/0, ::/0)
    #[arg(long)]
    allowed_server_cidrs: Option<String>,

    /// Allowed CIDR blocks for user HTTP inference requests (comma-separated, default: 0.0.0.0/0, ::/0)
    #[arg(long)]
    allowed_user_cidrs: Option<String>,

    /// Public TLS encryption mode: "off", "self-signed", or "manual"
    #[arg(long)]
    tls_mode: Option<String>,

    /// Path to TLS certificate file (for "manual" TLS mode)
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key file (for "manual" TLS mode)
    #[arg(long)]
    tls_key: Option<String>,

    /// Apache-style access log path (or "off" to disable)
    #[arg(long)]
    access_log: Option<String>,

    /// Auto git pull on daily maintenance restart (true/false)
    #[arg(long)]
    auto_git_pull: Option<bool>,

    /// Enforce read-only mode (disable sensitive Ollama operations like pull/delete/create)
    #[arg(long)]
    read_only: bool,

    /// Allow sensitive Ollama operations (pull, delete, create, push, copy)
    #[arg(long, conflicts_with = "read_only")]
    allow_sensitive_ops: bool,

    /// Allow broken or ephemeral self-signed certificates on proxy (NOT RECOMMENDED)
    #[arg(long)]
    allow_broken_certs: bool,

    /// Disable TLS completely and run plaintext HTTP (NOT RECOMMENDED)
    #[arg(long)]
    insecure_no_tls: bool,

    /// Store passkeys in TOML profiles as salted BLAKE3 one-way hashes instead of editable plaintext
    #[arg(long)]
    hash_passkeys: bool,

    /// Initialize ~/.olp/proxy.toml with passkeys and settings, then exit without starting listener
    #[arg(long)]
    init_only: bool,

    /// Use default settings / flags without interactive prompts
    #[arg(long)]
    non_interactive: bool,
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config_path = match args.config {
        Some(p) => p,
        None => olp_home_dir()?.join("proxy.toml"),
    };

    let overrides = ProxyCliOverrides {
        listen_addr: args.listen_addr,
        allowed_ports: args.allowed_ports,
        olp_api_keys: args.olp_api_key.map(|k| {
            k.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }),
        allowed_server_cidrs: args.allowed_server_cidrs.map(|c| {
            c.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }),
        allowed_user_cidrs: args.allowed_user_cidrs.map(|c| {
            c.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }),
        tls_mode: args.tls_mode,
        tls_cert_path: args.tls_cert,
        tls_key_path: args.tls_key,
        allow_broken_certs: if args.allow_broken_certs {
            Some(true)
        } else {
            None
        },
        insecure_no_tls: args.insecure_no_tls,
        access_log: args.access_log,
        auto_git_pull: args.auto_git_pull,
        read_only: if args.read_only {
            Some(true)
        } else if args.allow_sensitive_ops {
            Some(false)
        } else {
            None
        },
        hash_passkeys: if args.hash_passkeys { Some(true) } else { None },
    };

    let cfg = ensure_proxy_initialized(&config_path, args.non_interactive, overrides)?;

    if args.init_only {
        println!("[olp-proxy] Initialization complete.");
        return Ok(());
    }

    println!("\n================================================================================");
    println!("  olp-proxy starting");
    println!("  Config               : {}", config_path.display());
    println!(
        "  Listen Addr (Tunnel) : {} (TLS 1.3 encrypted)",
        cfg.proxy.listen_addr
    );
    println!("  Public TLS Mode      : {}", cfg.tls.mode);
    println!(
        "  Allowed Server CIDRs : {:?}",
        cfg.security.allowed_server_cidrs
    );
    println!(
        "  Allowed User CIDRs   : {:?}",
        cfg.security.allowed_user_cidrs
    );
    println!("================================================================================\n");

    let pid_file = olp_home_dir()?.join("olp-proxy.pid");
    let _ = std::fs::write(&pid_file, std::process::id().to_string());

    let (_bound_addr, _server_task) = start_proxy_server(cfg).await?;

    wait_for_shutdown_signal().await;
    println!("\n[olp-proxy] Shutting down cleanly...");
    let _ = std::fs::remove_file(&pid_file);

    Ok(())
}
