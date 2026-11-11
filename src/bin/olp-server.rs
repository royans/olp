use anyhow::Result;
use clap::Parser;
use olp::config::{ensure_server_initialized, olp_home_dir, ServerCliOverrides};
use olp::server::run_server_with_shutdown;
use std::path::PathBuf;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "olp-server",
    version,
    about = "Ollama Proxy private server tunnel daemon (olp-server)"
)]
struct Args {
    /// Path to server configuration file (defaults to ~/.olp/server.toml)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Proxy server host:port (e.g. proxy.example.com:4443)
    #[arg(long)]
    proxy_addr: Option<String>,

    /// User API key (olp_api_key recognized by the proxy)
    #[arg(long)]
    olp_api_key: Option<String>,

    /// Client passkey_user required to query Ollama via this server
    #[arg(long)]
    passkey_user: Option<String>,

    /// Local Ollama daemon address (defaults to 127.0.0.1:11434)
    #[arg(long)]
    ollama_addr: Option<String>,

    /// Recommended or preferred public port on the proxy (e.g. 10000)
    #[arg(long)]
    remote_port: Option<u16>,

    /// Unique server identifier (defaults to random srv_xxxxxxxx)
    #[arg(long)]
    server_id: Option<String>,

    /// Enforce or skip TLS certificate CA root verification (true/false)
    #[arg(long)]
    tls_verify: Option<bool>,

    /// Auto git pull on daily maintenance restart (true/false)
    #[arg(long)]
    auto_git_pull: Option<bool>,

    /// Maximum context window (tokens) allowed per request; caps options.num_ctx and the
    /// context length reported by /api/show (default: 32768). Saved to server.toml.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    max_num_ctx: Option<u32>,

    /// Enforce read-only mode locally on olp-server (cannot coexist with proxy policy)
    #[arg(long)]
    read_only: bool,

    /// Explicitly allow sensitive Ollama operations locally on olp-server (cannot coexist with proxy policy)
    #[arg(long, conflicts_with = "read_only")]
    allow_sensitive_ops: bool,

    /// Skip TLS certificate verification (NOT RECOMMENDED: permits broken/untrusted certs)
    #[arg(long)]
    insecure_skip_tls_verify: bool,

    /// Initialize ~/.olp/server.toml, then exit without connecting
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
        None => olp_home_dir()?.join("server.toml"),
    };

    let overrides = ServerCliOverrides {
        proxy_addr: args.proxy_addr,
        ollama_addr: args.ollama_addr,
        remote_port: args.remote_port,
        olp_api_key: args.olp_api_key,
        olp_server_id: args.server_id,
        passkey_user: args.passkey_user,
        tls_verify: args.tls_verify,
        insecure_skip_tls_verify: args.insecure_skip_tls_verify,
        auto_git_pull: args.auto_git_pull,
        max_num_ctx: args.max_num_ctx.map(|n| n as usize),
        read_only: if args.read_only {
            Some(true)
        } else if args.allow_sensitive_ops {
            Some(false)
        } else {
            None
        },
    };

    let cfg = ensure_server_initialized(&config_path, args.non_interactive, overrides)?;

    if args.init_only {
        println!("[olp-server] Initialization complete.");
        return Ok(());
    }

    println!("\n================================================================================");
    println!("  olp-server starting");
    println!("  Config       : {}", config_path.display());
    println!("  Server ID    : {}", cfg.server.olp_server_id);
    println!(
        "  Proxy Target : {} (TLS 1.3 encrypted)",
        cfg.server.proxy_addr
    );
    println!("  Local Ollama : {}", cfg.server.ollama_addr);
    println!(
        "  Assigned Port: {}",
        cfg.server
            .remote_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "Dynamic (allocated by proxy)".to_string())
    );
    println!("================================================================================\n");

    let pid_file = olp_home_dir()?.join("olp-server.pid");
    let _ = std::fs::write(&pid_file, std::process::id().to_string());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let server_task = tokio::spawn(async move {
        if let Err(e) = run_server_with_shutdown(cfg, shutdown_rx).await {
            eprintln!("olp-server error: {}", e);
        }
    });

    wait_for_shutdown_signal().await;
    println!("\n[olp-server] Shutting down...");
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
    let _ = std::fs::remove_file(&pid_file);

    Ok(())
}
