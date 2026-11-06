use crate::keys::{enforce_private_file_permissions, ensure_secure_dir};
use anyhow::{anyhow, Context, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

// ============================================================================
// PROXY CONFIGURATION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySection,
    pub auth: ProxyAuthSection,
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
pub struct ProxyAuthSection {
    pub passkey_proxy: String,
    pub passkey_user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySecuritySection {
    #[serde(default = "default_allowed_cidrs")]
    pub allowed_server_cidrs: Vec<String>,
    #[serde(default = "default_allowed_cidrs")]
    pub allowed_user_cidrs: Vec<String>,
    #[serde(default = "default_max_auth_failures")]
    pub max_auth_failures_per_min: u32,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
}

impl Default for ProxySecuritySection {
    fn default() -> Self {
        Self {
            allowed_server_cidrs: default_allowed_cidrs(),
            allowed_user_cidrs: default_allowed_cidrs(),
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
fn default_allowed_cidrs() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}
fn default_max_auth_failures() -> u32 {
    60
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
            auth: ProxyAuthSection {
                passkey_proxy: generate_random_passkey(),
                passkey_user: generate_random_passkey(),
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
        let start: u16 = parts[0]
            .trim()
            .parse()
            .context("Invalid start port in allowed_ports")?;
        let end: u16 = parts[1]
            .trim()
            .parse()
            .context("Invalid end port in allowed_ports")?;
        if start > end {
            return Err(anyhow!("Start port cannot exceed end port in allowed_ports"));
        }
        Ok((start, end))
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read proxy config at {}", path.display()))?;
        let cfg: ProxyConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse proxy TOML at {}", path.display()))?;
        enforce_private_file_permissions(path)?;
        Ok(cfg)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let serialized = toml::to_string_pretty(self).context("Failed to serialize proxy config")?;
        if let Some(parent) = path.parent() {
            ensure_secure_dir(parent)?;
        }
        fs::write(path, serialized)
            .with_context(|| format!("Failed to write proxy config to {}", path.display()))?;
        enforce_private_file_permissions(path)?;
        Ok(())
    }
}

// ============================================================================
// SERVER CONFIGURATION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    #[serde(default)]
    pub reconnect: ReconnectSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerSection {
    pub proxy_addr: String,
    pub ollama_addr: String,
    pub remote_port: u16,
    pub passkey_proxy: String,
    #[serde(default)]
    pub tls_verify: Option<bool>,
}

impl ServerSection {
    /// Determines whether to verify the proxy's TLS certificate using Mozilla WebPKI root certificates.
    /// If explicitly set in server.toml (`tls_verify = true/false`), uses that value.
    /// Otherwise auto-detects: returns `true` for public domain names, and `false` for raw IP / 127.0.0.1 / localhost.
    pub fn should_verify_ca(&self) -> bool {
        if let Some(explicit) = self.tls_verify {
            return explicit;
        }

        let host = crate::protocol::extract_host(&self.proxy_addr);
        if host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host.parse::<std::net::IpAddr>().is_ok()
        {
            false
        } else {
            true
        }
    }
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
                passkey_proxy: String::new(),
                tls_verify: None,
            },
            reconnect: ReconnectSection::default(),
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read server config at {}", path.display()))?;
        let cfg: ServerConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse server TOML at {}", path.display()))?;
        enforce_private_file_permissions(path)?;
        Ok(cfg)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let serialized =
            toml::to_string_pretty(self).context("Failed to serialize server config")?;
        if let Some(parent) = path.parent() {
            ensure_secure_dir(parent)?;
        }
        fs::write(path, serialized)
            .with_context(|| format!("Failed to write server config to {}", path.display()))?;
        enforce_private_file_permissions(path)?;
        Ok(())
    }
}

// ============================================================================
// HELPER UTILITIES
// ============================================================================

pub fn olp_home_dir() -> Result<PathBuf> {
    if let Ok(val) = std::env::var("OLP_HOME") {
        let p = PathBuf::from(val);
        ensure_secure_dir(&p)?;
        return Ok(p);
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine user home directory"))?;
    let olp_dir = home.join(".olp");
    ensure_secure_dir(&olp_dir)?;
    Ok(olp_dir)
}

pub fn expand_path(input: &str) -> Result<PathBuf> {
    if let Some(stripped) = input.strip_prefix("~/") {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow!("Could not determine user home directory"))?;
        Ok(home.join(stripped))
    } else if input == "~" {
        dirs::home_dir().ok_or_else(|| anyhow!("Could not determine user home directory"))
    } else {
        Ok(PathBuf::from(input))
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
// FIRST-RUN INITIALIZATION
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

/// Ensures `~/.olp/proxy.toml` exists. If missing, initializes default settings with random passkeys.
pub fn ensure_proxy_initialized(
    config_path: &Path,
    non_interactive: bool,
) -> Result<ProxyConfig> {
    let base_dir = olp_home_dir()?;
    ensure_secure_dir(&base_dir)?;

    if config_path.exists() {
        return ProxyConfig::load_from_path(config_path);
    }

    let mut cfg = ProxyConfig::default_config();

    if !non_interactive && io::stdin().is_terminal() {
        println!("\n================================================================================");
        println!("  [olp-proxy] First-Time Configuration Setup");
        println!("================================================================================\n");

        cfg.proxy.listen_addr = prompt_line("Tunnel listen address", &cfg.proxy.listen_addr)?;
        cfg.proxy.allowed_ports = prompt_line(
            "Allowed public port range for servers",
            &cfg.proxy.allowed_ports,
        )?;

        let custom_proxy_key = prompt_line(
            "Passkey for server tunnel registration (press Enter to auto-generate)",
            "",
        )?;
        if !custom_proxy_key.is_empty() {
            cfg.auth.passkey_proxy = custom_proxy_key;
        }

        let custom_user_key = prompt_line(
            "Passkey for user HTTP authentication (press Enter to auto-generate)",
            "",
        )?;
        if !custom_user_key.is_empty() {
            cfg.auth.passkey_user = custom_user_key;
        }

        let server_cidr_str = prompt_line(
            "Allowed CIDR blocks for servers (comma-separated)",
            &cfg.security.allowed_server_cidrs.join(", "),
        )?;
        cfg.security.allowed_server_cidrs = server_cidr_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let user_cidr_str = prompt_line(
            "Allowed CIDR blocks for users (comma-separated)",
            &cfg.security.allowed_user_cidrs.join(", "),
        )?;
        cfg.security.allowed_user_cidrs = user_cidr_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    cfg.save_to_path(config_path)?;

    println!("\n================================================================================");
    println!("  [olp-proxy] Configuration saved to {}", config_path.display());
    println!("  ----------------------------------------------------------------------------");
    println!("  passkey_proxy : {}", cfg.auth.passkey_proxy);
    println!("  passkey_user  : {}", cfg.auth.passkey_user);
    println!("  ----------------------------------------------------------------------------");
    println!("  * passkey_proxy: Put this in your olp-server's server.toml");
    println!("  * passkey_user : Use this as the password for HTTP Basic Auth / Bearer token");
    println!("================================================================================\n");

    Ok(cfg)
}

/// Ensures `~/.olp/server.toml` exists. If missing, initializes default settings.
pub fn ensure_server_initialized(
    config_path: &Path,
    non_interactive: bool,
) -> Result<ServerConfig> {
    let base_dir = olp_home_dir()?;
    ensure_secure_dir(&base_dir)?;

    if config_path.exists() {
        return ServerConfig::load_from_path(config_path);
    }

    let mut cfg = ServerConfig::default_config();

    if !non_interactive && io::stdin().is_terminal() {
        println!("\n================================================================================");
        println!("  [olp-server] First-Time Configuration Setup");
        println!("================================================================================\n");

        // 1. Proxy Host & Port
        let proxy_host_input = prompt_line("Proxy server address/host", "proxy.example.com")?;
        let (host, default_port) = match proxy_host_input.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => {
                (h.to_string(), p.to_string())
            }
            _ => (proxy_host_input, "4443".to_string()),
        };

        let proxy_port = prompt_line("Proxy tunnel control port", &default_port)?;
        cfg.server.proxy_addr = format!("{}:{}", host.trim(), proxy_port.trim());

        // 2. Local Ollama address
        cfg.server.ollama_addr =
            prompt_line("Local Ollama address", &cfg.server.ollama_addr)?;

        // 3. Port to serve the service on via the proxy
        let port_str = prompt_line(
            "Port on the proxy to serve Ollama on (public port)",
            &cfg.server.remote_port.to_string(),
        )?;
        cfg.server.remote_port = port_str
            .trim()
            .parse::<u16>()
            .context("Public port must be a valid port number (1024-65535)")?;

        // 4. Passkey for proxy
        loop {
            let key = prompt_line(
                "Passkey for proxy (passkey_proxy from proxy.toml)",
                "",
            )?;
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                cfg.server.passkey_proxy = trimmed.to_string();
                break;
            } else {
                println!("  [!] passkey_proxy is required to connect to the proxy. Please enter it:");
            }
        }
    }

    if cfg.server.passkey_proxy.is_empty() {
        cfg.server.passkey_proxy = "change-me-to-match-proxy-toml".to_string();
    }

    cfg.save_to_path(config_path)?;

    println!("\n================================================================================");
    println!("  [olp-server] Configuration saved to {}", config_path.display());
    println!("================================================================================\n");

    Ok(cfg)
}
