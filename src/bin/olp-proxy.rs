use anyhow::Result;
use clap::Parser;
use olp::config::{ensure_proxy_initialized, expand_path, olp_home_dir};
use olp::keys::{add_authorized_key, format_pubkey, load_or_generate_keypair};
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

    /// Print olp-proxy's public key and exit
    #[arg(long)]
    show_pubkey: bool,

    /// Authorize an olp-server public key (appends to ~/.olp/keys/authorized_keys) and exit
    #[arg(long)]
    add_key: Option<String>,

    /// Initialize ~/.olp/proxy.toml and keys, then exit without starting the listener
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
    let priv_path = expand_path(&cfg.keys.private_key)?;
    let signing_key = load_or_generate_keypair(&priv_path, "olp-proxy-ed25519")?;
    let pubkey_str = format_pubkey("olp-proxy-ed25519", &signing_key.verifying_key());

    if args.show_pubkey {
        println!("{}", pubkey_str);
        return Ok(());
    }

    if let Some(ref server_key) = args.add_key {
        let auth_path = expand_path(&cfg.keys.authorized_keys)?;
        add_authorized_key(&auth_path, server_key)?;
        println!(
            "[olp-proxy] Successfully authorized server key in {}",
            auth_path.display()
        );
        return Ok(());
    }

    if args.init_only {
        return Ok(());
    }

    println!("================================================================================");
    println!("  olp-proxy starting");
    println!("  Config      : {}", config_path.display());
    println!("  Listen Addr : {}", cfg.proxy.listen_addr);
    println!("  Public Key  : {}", pubkey_str);
    println!("================================================================================");

    let (_bound_addr, handle) = start_proxy_server(cfg).await?;

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            println!("\n[olp-proxy] Shutting down cleanly...");
        }
        _ = handle => {}
    }

    Ok(())
}
