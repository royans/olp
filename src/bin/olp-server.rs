use anyhow::{Context, Result};
use clap::Parser;
use olp::config::{ensure_server_initialized, expand_path, olp_home_dir};
use olp::keys::{format_pubkey, load_or_generate_keypair, parse_pubkey, write_private_file};
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

    /// Print olp-server's public key and exit
    #[arg(long)]
    show_pubkey: bool,

    /// Set or update the pinned olp-proxy public key (~/.olp/keys/known_proxy.pub)
    #[arg(long)]
    set_proxy_key: Option<String>,

    /// Initialize ~/.olp/server.toml and keys, then exit without connecting
    #[arg(long)]
    init_only: bool,

    /// Use default settings without interactive prompts if config is missing
    #[arg(long)]
    non_interactive: bool,
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
    let priv_path = expand_path(&cfg.keys.private_key)?;
    let signing_key = load_or_generate_keypair(&priv_path, "olp-server-ed25519")?;
    let pubkey_str = format_pubkey("olp-server-ed25519", &signing_key.verifying_key());

    if args.show_pubkey {
        println!("{}", pubkey_str);
        return Ok(());
    }

    if let Some(ref proxy_key) = args.set_proxy_key {
        let parsed = parse_pubkey(proxy_key).context("Invalid olp-proxy public key")?;
        let known_path = expand_path(&cfg.keys.known_proxy_key)?;
        let formatted = format_pubkey("olp-proxy-ed25519", &parsed);
        write_private_file(&known_path, &format!("{}\n", formatted))?;
        println!(
            "[olp-server] Saved pinned olp-proxy public key to {}",
            known_path.display()
        );
        return Ok(());
    }

    if args.init_only {
        return Ok(());
    }

    println!("================================================================================");
    println!("  olp-server starting");
    println!("  Config       : {}", config_path.display());
    println!("  Proxy Target : {}", cfg.server.proxy_addr);
    println!("  Local Ollama : {}", cfg.server.ollama_addr);
    println!("  Remote Port  : {}", cfg.server.remote_port);
    println!("  Public Key   : {}", pubkey_str);
    println!("================================================================================");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\n[olp-server] Shutting down...");
            let _ = shutdown_tx.send(true);
        }
    });

    run_server_with_shutdown(cfg, shutdown_rx).await
}
