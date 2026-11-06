use anyhow::Result;
use clap::Parser;
use olp::config::{ensure_server_initialized, olp_home_dir};
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

    /// Initialize ~/.olp/server.toml, then exit without connecting
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
        None => olp_home_dir()?.join("server.toml"),
    };

    let cfg = ensure_server_initialized(&config_path, args.non_interactive)?;

    if args.init_only {
        println!("[olp-server] Initialization complete.");
        return Ok(());
    }

    println!("\n================================================================================");
    println!("  olp-server starting");
    println!("  Config       : {}", config_path.display());
    println!("  Proxy Target : {} (TLS 1.3 encrypted)", cfg.server.proxy_addr);
    println!("  Local Ollama : {}", cfg.server.ollama_addr);
    println!("  Remote Port  : {}", cfg.server.remote_port);
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
