use crate::keys::{
    add_authorized_key, enforce_private_file_permissions, ensure_secure_dir, format_pubkey,
    load_or_generate_keypair, parse_pubkey, write_private_file,
};
use anyhow::{anyhow, Context, Result};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

/// Returns the base `~/.olp` directory (or `$OLP_HOME` if set).
pub fn olp_home_dir() -> Result<PathBuf> {
    if let Ok(custom) = env::var("OLP_HOME") {
        if !custom.trim().is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine user home directory"))?;
    Ok(home.join(".olp"))
}

/// Expands leading `~/` using the current user's home directory (or maps `~/.olp` to `olp_home_dir()`).
pub fn expand_path(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/.olp/") {
        return Ok(olp_home_dir()?.join(rest));
    }
    if trimmed == "~/.olp" {
        return olp_home_dir();
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow!("Could not determine user home directory"))?;
        return Ok(home.join(rest));
    }
    Ok(PathBuf::from(trimmed))
}

// ============================================================================
// PROXY CONFIGURATION (`~/.olp/proxy.toml`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySection,
    pub keys: ProxyKeysSection,
    #[serde(default)]
    pub security: ProxySecuritySection,
    #[serde(default)]
    pub tls: ProxyTlsSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySection {
    pub listen_addr: String,
    #[serde(default = "default_allowed_ports")]
    pub allowed_ports: String,
    #[serde(default = "default_grace_period")]
    pub listener_grace_period_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyKeysSection {
    pub private_key: String,
    pub authorized_keys: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySecuritySection {
    #[serde(default = "default_max_auth_failures")]
    pub max_auth_failures_per_min: u32,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
}

impl Default for ProxySecuritySection {
    fn default() -> Self {
        Self {
            max_auth_failures_per_min: default_max_auth_failures(),
            max_concurrent_streams: default_max_concurrent_streams(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTlsSection {
    #[serde(default = "default_tls_mode")]
    pub mode: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl Default for ProxyTlsSection {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
            cert_path: None,
            key_path: None,
        }
    }
}

fn default_allowed_ports() -> String {
    "10000-20000".to_string()
}
fn default_grace_period() -> u64 {
    300
}
fn default_max_auth_failures() -> u32 {
    5
}
fn default_max_concurrent_streams() -> usize {
    128
}
fn default_tls_mode() -> String {
    "off".to_string()
}

impl ProxyConfig {
    pub fn default_config() -> Self {
        Self {
            proxy: ProxySection {
                listen_addr: "0.0.0.0:4443".to_string(),
                allowed_ports: default_allowed_ports(),
                listener_grace_period_sec: default_grace_period(),
            },
            keys: ProxyKeysSection {
                private_key: "~/.olp/keys/proxy_id_ed25519".to_string(),
                authorized_keys: "~/.olp/keys/authorized_keys".to_string(),
            },
            security: ProxySecuritySection::default(),
            tls: ProxyTlsSection::default(),
        }
    }

    pub fn parse_allowed_port_range(&self) -> Result<(u16, u16)> {
        let parts: Vec<&str> = self.proxy.allowed_ports.trim().split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid allowed_ports format '{}' (expected 'start-end', e.g. '10000-20000')",
                self.proxy.allowed_ports
            ));
        }
        let start: u16 = parts[0].trim().parse()?;
        let end: u16 = parts[1].trim().parse()?;
        if start < 1024 || start > end {
            return Err(anyhow!(
                "Invalid allowed_ports range {}-{} (must be >= 1024 and start <= end)",
                start,
                end
            ));
        }
        Ok((start, end))
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        enforce_private_file_permissions(path)?;
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read proxy config at {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("Failed to parse TOML in {}", path.display()))?;
        Ok(cfg)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let serialized = toml::to_string_pretty(self)?;
        write_private_file(path, &serialized)
    }
}

// ============================================================================
// SERVER CONFIGURATION (`~/.olp/server.toml`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub keys: ServerKeysSection,
    #[serde(default)]
    pub reconnect: ReconnectSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSection {
    pub proxy_addr: String,
    pub ollama_addr: String,
    pub remote_port: u16,
    pub passkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKeysSection {
    pub private_key: String,
    pub known_proxy_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectSection {
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default = "default_initial_delay")]
    pub initial_delay_sec: u64,
    #[serde(default = "default_max_delay")]
    pub max_delay_sec: u64,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_sec: u64,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_sec: u64,
}

impl Default for ReconnectSection {
    fn default() -> Self {
        Self {
            strategy: default_strategy(),
            initial_delay_sec: default_initial_delay(),
            max_delay_sec: default_max_delay(),
            heartbeat_interval_sec: default_heartbeat_interval(),
            heartbeat_timeout_sec: default_heartbeat_timeout(),
        }
    }
}

fn default_strategy() -> String {
    "fibonacci".to_string()
}
fn default_initial_delay() -> u64 {
    1
}
fn default_max_delay() -> u64 {
    300
}
fn default_heartbeat_interval() -> u64 {
    15
}
fn default_heartbeat_timeout() -> u64 {
    5
}

impl ServerConfig {
    pub fn default_config() -> Self {
        Self {
            server: ServerSection {
                proxy_addr: "127.0.0.1:4443".to_string(),
                ollama_addr: "127.0.0.1:11434".to_string(),
                remote_port: 11434,
                passkey: generate_random_passkey(),
            },
            keys: ServerKeysSection {
                private_key: "~/.olp/keys/server_id_ed25519".to_string(),
                known_proxy_key: "~/.olp/keys/known_proxy.pub".to_string(),
            },
            reconnect: ReconnectSection::default(),
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        enforce_private_file_permissions(path)?;
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read server config at {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("Failed to parse TOML in {}", path.display()))?;
        Ok(cfg)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let serialized = toml::to_string_pretty(self)?;
        write_private_file(path, &serialized)
    }
}

pub fn generate_random_passkey() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

// ============================================================================
// INTERACTIVE FIRST-RUN WIZARDS
// ============================================================================

fn prompt_line(question: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        print!("? {}: ", question);
    } else {
        print!("? {} [{}]: ", question, default);
    }
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Ensures `~/.olp/proxy.toml` and keys exist. If missing, runs the interactive setup wizard.
pub fn ensure_proxy_initialized(
    config_path: &Path,
    non_interactive: bool,
) -> Result<ProxyConfig> {
    let base_dir = olp_home_dir()?;
    let keys_dir = base_dir.join("keys");
    ensure_secure_dir(&base_dir)?;
    ensure_secure_dir(&keys_dir)?;

    if config_path.exists() {
        let cfg = ProxyConfig::load_from_path(config_path)?;
        let priv_path = expand_path(&cfg.keys.private_key)?;
        let _ = load_or_generate_keypair(&priv_path, "olp-proxy-ed25519")?;
        let auth_path = expand_path(&cfg.keys.authorized_keys)?;
        if !auth_path.exists() {
            write_private_file(
                &auth_path,
                "# Authorized olp-server public keys (one per line)\n",
            )?;
        }
        return Ok(cfg);
    }

    let mut cfg = ProxyConfig::default_config();
    let priv_path = expand_path(&cfg.keys.private_key)?;
    let signing_key = load_or_generate_keypair(&priv_path, "olp-proxy-ed25519")?;
    let pubkey_str = format_pubkey("olp-proxy-ed25519", &signing_key.verifying_key());

    let auth_path = expand_path(&cfg.keys.authorized_keys)?;
    if !auth_path.exists() {
        write_private_file(
            &auth_path,
            "# Authorized olp-server public keys (one per line)\n",
        )?;
    }

    println!("\n================================================================================");
    println!("  [olp-proxy] First-time setup initialized in {}", base_dir.display());
    println!("  YOUR OLP-PROXY PUBLIC KEY (Copy this to olp-server during its setup):");
    println!("  {}", pubkey_str);
    println!("================================================================================\n");

    if !non_interactive && io::stdin().is_terminal() {
        cfg.proxy.listen_addr = prompt_line(
            "Tunnel control listen address",
            &cfg.proxy.listen_addr,
        )?;
        cfg.proxy.allowed_ports = prompt_line(
            "Allowed public port range for servers",
            &cfg.proxy.allowed_ports,
        )?;
        let tls_choice = prompt_line(
            "Public TLS mode (off / self-signed / manual)",
            "off",
        )?;
        cfg.tls.mode = tls_choice.to_lowercase();
        if cfg.tls.mode == "manual" {
            let cert = prompt_line("Path to TLS certificate PEM", "~/.olp/keys/tls_cert.pem")?;
            let key = prompt_line("Path to TLS private key PEM", "~/.olp/keys/tls_key.pem")?;
            cfg.tls.cert_path = Some(cert);
            cfg.tls.key_path = Some(key);
        }

        let server_key = prompt_line(
            "Paste an authorized olp-server public key (or press Enter to add later)",
            "",
        )?;
        if !server_key.is_empty() {
            match add_authorized_key(&auth_path, &server_key) {
                Ok(_) => println!("[olp-proxy] Added server key to {}", auth_path.display()),
                Err(e) => eprintln!(
                    "[olp-proxy] Warning: could not parse server key ({}). You can add it later to {}",
                    e,
                    auth_path.display()
                ),
            }
        }
    }

    cfg.save_to_path(config_path)?;
    println!(
        "[olp-proxy] Configuration saved to {} (permissions 0600)\n",
        config_path.display()
    );
    Ok(cfg)
}

/// Ensures `~/.olp/server.toml` and keys exist. If missing, runs the interactive setup wizard.
pub fn ensure_server_initialized(
    config_path: &Path,
    non_interactive: bool,
) -> Result<ServerConfig> {
    let base_dir = olp_home_dir()?;
    let keys_dir = base_dir.join("keys");
    ensure_secure_dir(&base_dir)?;
    ensure_secure_dir(&keys_dir)?;

    if config_path.exists() {
        let cfg = ServerConfig::load_from_path(config_path)?;
        let priv_path = expand_path(&cfg.keys.private_key)?;
        let _ = load_or_generate_keypair(&priv_path, "olp-server-ed25519")?;
        return Ok(cfg);
    }

    let mut cfg = ServerConfig::default_config();
    let priv_path = expand_path(&cfg.keys.private_key)?;
    let signing_key = load_or_generate_keypair(&priv_path, "olp-server-ed25519")?;
    let pubkey_str = format_pubkey("olp-server-ed25519", &signing_key.verifying_key());

    println!("\n================================================================================");
    println!("  [olp-server] First-time setup initialized in {}", base_dir.display());
    println!("  YOUR OLP-SERVER PUBLIC KEY (Add this to ~/.olp/keys/authorized_keys on proxy):");
    println!("  {}", pubkey_str);
    println!("================================================================================\n");

    let known_proxy_path = expand_path(&cfg.keys.known_proxy_key)?;

    if !non_interactive && io::stdin().is_terminal() {
        cfg.server.proxy_addr = prompt_line(
            "Public olp-proxy address (host:port)",
            &cfg.server.proxy_addr,
        )?;

        let proxy_pub = prompt_line(
            "Paste olp-proxy's public key (from `olp-proxy` startup)",
            "",
        )?;
        if !proxy_pub.is_empty() {
            let parsed = parse_pubkey(&proxy_pub)
                .context("Invalid olp-proxy public key pasted")?;
            let formatted = format_pubkey("olp-proxy-ed25519", &parsed);
            write_private_file(&known_proxy_path, &format!("{}\n", formatted))?;
        }

        cfg.server.ollama_addr = prompt_line(
            "Local Ollama address",
            &cfg.server.ollama_addr,
        )?;

        let port_str = prompt_line(
            "External port to expose on olp-proxy",
            &cfg.server.remote_port.to_string(),
        )?;
        cfg.server.remote_port = port_str
            .parse::<u16>()
            .context("Remote port must be a valid port number (1024-65535)")?;

        let custom_passkey = prompt_line(
            "User passkey for Basic/Bearer Auth (press Enter to auto-generate)",
            "",
        )?;
        if custom_passkey.is_empty() {
            println!("  -> Generated strong passkey: {}", cfg.server.passkey);
        } else {
            cfg.server.passkey = custom_passkey;
        }
    }

    cfg.save_to_path(config_path)?;
    println!(
        "[olp-server] Configuration saved to {} (permissions 0600)\n",
        config_path.display()
    );
    Ok(cfg)
}

