use anyhow::Result;
use clap::Parser;
use olp::config::{ensure_proxy_initialized, olp_home_dir};
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

    /// Initialize ~/.olp/proxy.toml with random passkeys, then exit without starting the listener
    #[arg(long)]
    init_only: bool,

    /// Use default settings without interactive prompts if config is missing
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

    let cfg = ensure_proxy_initialized(&config_path, args.non_interactive)?;

    if args.init_only {
        println!("[olp-proxy] Initialization complete.");
        return Ok(());
    }

    println!("\n================================================================================");
    println!("  olp-proxy starting");
    println!("  Config               : {}", config_path.display());
    println!("  Listen Addr          : {}", cfg.proxy.listen_addr);
    println!("  Allowed Server CIDRs : {:?}", cfg.security.allowed_server_cidrs);
    println!("  Allowed User CIDRs   : {:?}", cfg.security.allowed_user_cidrs);
    println!("================================================================================\n");

    let pid_file = olp_home_dir()?.join("olp-proxy.pid");
    let _ = std::fs::write(&pid_file, std::process::id().to_string());

    let (_bound_addr, _server_task) = start_proxy_server(cfg).await?;

    wait_for_shutdown_signal().await;
    println!("\n[olp-proxy] Shutting down cleanly...");
    let _ = std::fs::remove_file(&pid_file);

    Ok(())
}
