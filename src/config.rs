use crate::keys::{enforce_private_file_permissions, ensure_secure_dir};
use anyhow::{anyhow, Context, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[serde(default = "default_maintenance_for_existing_deployments")]
    pub maintenance: MaintenanceSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySection {
    pub listen_addr: String,
    #[serde(default = "default_allowed_ports")]
    pub allowed_ports: String,
    #[serde(default = "default_grace_period")]
    pub listener_grace_period_sec: u64,
    #[serde(default = "default_access_log")]
    pub access_log: Option<String>,
}

fn default_access_log() -> Option<String> {
    Some("~/.olp/access.log".to_string())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyAuthSection {
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    pub olp_api_keys: Vec<String>,
}

/// Accepts either an array of strings `["key1", "key2"]` or a comma-delimited string `"key1, key2"`.
fn deserialize_string_or_seq<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrSeq {
        Seq(Vec<String>),
        Str(String),
    }
    match StringOrSeq::deserialize(deserializer)? {
        StringOrSeq::Seq(list) => Ok(list),
        StringOrSeq::Str(s) => Ok(s
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect()),
    }
}

// ============================================================================
// USER PROFILES & MULTI-SERVER MANAGEMENT (~/.olp/config/<olp_api_key>.toml)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user: UserSection,
    #[serde(default)]
    pub servers: HashMap<String, UserServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSection {
    pub api_key: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_max_servers")]
    pub max_servers: usize,
    #[serde(default)]
    pub disabled: bool,
}

fn default_max_servers() -> usize {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserServerConfig {
    pub port: u16,
    #[serde(default)]
    pub reserved: bool,
    #[serde(default)]
    pub passkey_user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_user_hash: Option<String>,
    #[serde(default = "default_allowed_cidrs")]
    pub allowed_user_cidrs: Vec<String>,
    #[serde(default = "default_allowed_cidrs")]
    pub allowed_server_cidrs: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub read_only: Option<bool>,
}

impl UserServerConfig {
    pub fn get_verifier(&self) -> crate::keys::PasskeyVerifier {
        // If passkey_user is set (user-editable plaintext mode), use it directly.
        // If passkey_user is empty and passkey_user_hash is present (salted hash mode), use the hash.
        if !self.passkey_user.is_empty() {
            return crate::keys::PasskeyVerifier::from_passkey(&self.passkey_user);
        }
        if let Some(ref h) = self.passkey_user_hash {
            if let Some(v) = crate::keys::PasskeyVerifier::from_encoded_hash(h) {
                return v;
            }
        }
        crate::keys::PasskeyVerifier::from_passkey(&self.passkey_user)
    }
}

impl UserProfile {
    pub fn new(api_key: &str) -> Self {
        Self {
            user: UserSection {
                api_key: api_key.to_string(),
                name: None,
                max_servers: default_max_servers(),
                disabled: false,
            },
            servers: HashMap::new(),
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read user profile at {}", path.display()))?;
        let profile: UserProfile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse user TOML at {}", path.display()))?;
        enforce_private_file_permissions(path)?;
        Ok(profile)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            ensure_secure_dir(parent)?;
        }
        let rand_suffix: u32 = rand::thread_rng().gen();
        let tmp_path = path.with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&tmp_path, content.as_bytes())?;
        enforce_private_file_permissions(&tmp_path)?;
        fs::rename(&tmp_path, path)?;
        enforce_private_file_permissions(path)?;
        Ok(())
    }
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
    #[serde(default = "default_read_only_true")]
    pub read_only: bool,
    #[serde(default = "default_policy_authority")]
    pub policy_authority: String,
    #[serde(default = "default_max_request_body_size_mb")]
    pub max_request_body_size_mb: usize,
    #[serde(default = "default_max_active_requests_per_server")]
    pub max_active_requests_per_server: usize,
    #[serde(default = "default_max_requests_per_min")]
    pub max_requests_per_min: u32,
    #[serde(default = "default_connection_timeout_sec")]
    pub connection_timeout_sec: u64,
    #[serde(default = "default_hash_passkeys_false")]
    pub hash_passkeys: bool,
}

fn default_read_only_true() -> bool {
    true
}

fn default_hash_passkeys_false() -> bool {
    false
}

fn default_policy_authority() -> String {
    "proxy".to_string()
}

fn default_max_request_body_size_mb() -> usize {
    32
}

fn default_max_active_requests_per_server() -> usize {
    4
}

fn default_max_requests_per_min() -> u32 {
    300
}

fn default_connection_timeout_sec() -> u64 {
    120
}

impl Default for ProxySecuritySection {
    fn default() -> Self {
        Self {
            allowed_server_cidrs: default_allowed_cidrs(),
            allowed_user_cidrs: default_allowed_cidrs(),
            max_auth_failures_per_min: default_max_auth_failures(),
            max_concurrent_streams: default_max_concurrent_streams(),
            read_only: true,
            policy_authority: "proxy".to_string(),
            max_request_body_size_mb: default_max_request_body_size_mb(),
            max_active_requests_per_server: default_max_active_requests_per_server(),
            max_requests_per_min: default_max_requests_per_min(),
            connection_timeout_sec: default_connection_timeout_sec(),
            hash_passkeys: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTlsSection {
    #[serde(default = "default_tls_mode")]
    pub mode: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    #[serde(default)]
    pub allow_broken_certs: bool,
}

impl Default for ProxyTlsSection {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
            cert_path: Some("~/.olp/tls/cert.pem".to_string()),
            key_path: Some("~/.olp/tls/key.pem".to_string()),
            allow_broken_certs: false,
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
    "manual".to_string()
}

impl ProxyConfig {
    pub fn default_config() -> Self {
        Self {
            proxy: ProxySection {
                listen_addr: "0.0.0.0:4443".to_string(),
                allowed_ports: default_allowed_ports(),
                listener_grace_period_sec: default_grace_period(),
                access_log: default_access_log(),
            },
            auth: ProxyAuthSection {
                olp_api_keys: Vec::new(),
            },
            security: ProxySecuritySection::default(),
            tls: ProxyTlsSection::default(),
            maintenance: MaintenanceSection::default(),
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
            return Err(anyhow!(
                "Start port cannot exceed end port in allowed_ports"
            ));
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
        let serialized =
            toml::to_string_pretty(self).context("Failed to serialize proxy config")?;
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
    #[serde(default = "default_maintenance_for_existing_deployments")]
    pub maintenance: MaintenanceSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerSection {
    pub proxy_addr: String,
    pub ollama_addr: String,
    pub olp_api_key: String,
    #[serde(default)]
    pub olp_server_id: String,
    pub passkey_user: String,
    #[serde(default)]
    pub remote_port: Option<u16>,
    #[serde(default)]
    pub tls_verify: Option<bool>,
    #[serde(default)]
    pub read_only: Option<bool>,
}

impl ServerSection {
    /// Determines whether to verify the proxy's TLS certificate using Mozilla WebPKI root certificates.
    /// Strict CA verification is ENABLED by default for all connections. Broken or self-signed certificates
    /// are rejected unless explicitly overridden by `tls_verify = false` (not recommended).
    pub fn should_verify_ca(&self) -> bool {
        self.tls_verify.unwrap_or(true)
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
                olp_api_key: String::new(),
                olp_server_id: String::new(),
                passkey_user: generate_random_passkey(),
                remote_port: None,
                tls_verify: None,
                read_only: None,
            },
            reconnect: ReconnectSection::default(),
            maintenance: MaintenanceSection::default(),
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
// MAINTENANCE (shared by proxy & server)
// ============================================================================

/// Settings consumed by `start-proxy.sh` / `start-server.sh` and their cron jobs.
///
/// ```toml
/// [maintenance]
/// auto_git_pull = true   # set to false (or "no") to stop the daily restart from running `git pull`
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MaintenanceSection {
    /// When the install directory is a git checkout, run `git pull --ff-only` (and rebuild if
    /// anything changed) on every scheduled/manual restart. Defaults to `true`.
    #[serde(
        default = "default_auto_git_pull",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub auto_git_pull: bool,
}

fn default_auto_git_pull() -> bool {
    true
}

fn default_maintenance_for_existing_deployments() -> MaintenanceSection {
    MaintenanceSection {
        auto_git_pull: true,
    }
}

/// Accepts TOML booleans as well as the strings "yes"/"no", "true"/"false", "on"/"off", "1"/"0".
fn deserialize_flexible_bool<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        Str(String),
    }
    match BoolOrString::deserialize(deserializer)? {
        BoolOrString::Bool(b) => Ok(b),
        BoolOrString::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
            "yes" | "y" | "true" | "on" | "1" => Ok(true),
            "no" | "n" | "false" | "off" | "0" => Ok(false),
            other => Err(serde::de::Error::custom(format!(
                "invalid boolean '{}' (expected yes/no or true/false)",
                other
            ))),
        },
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
    let home =
        dirs::home_dir().ok_or_else(|| anyhow!("Could not determine user home directory"))?;
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

pub fn olp_config_dir() -> Result<PathBuf> {
    let base = olp_home_dir()?;
    let config_dir = base.join("config");
    ensure_secure_dir(&config_dir)?;
    Ok(config_dir)
}

pub fn generate_random_server_id() -> String {
    let rand_str: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!("srv_{}", rand_str)
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

#[derive(Debug, Clone, Default)]
pub struct ProxyCliOverrides {
    pub listen_addr: Option<String>,
    pub allowed_ports: Option<String>,
    pub olp_api_keys: Option<Vec<String>>,
    pub allowed_server_cidrs: Option<Vec<String>>,
    pub allowed_user_cidrs: Option<Vec<String>>,
    pub tls_mode: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub allow_broken_certs: Option<bool>,
    pub insecure_no_tls: bool,
    pub access_log: Option<String>,
    pub auto_git_pull: Option<bool>,
    pub read_only: Option<bool>,
    pub hash_passkeys: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ServerCliOverrides {
    pub proxy_addr: Option<String>,
    pub ollama_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub olp_api_key: Option<String>,
    pub olp_server_id: Option<String>,
    pub passkey_user: Option<String>,
    pub tls_verify: Option<bool>,
    pub insecure_skip_tls_verify: bool,
    pub auto_git_pull: Option<bool>,
    pub read_only: Option<bool>,
}

/// Ensures `~/.olp/proxy.toml` and `~/.olp/config/` exist.
/// If missing, initializes default settings with a random admin API key and profile.
pub fn ensure_proxy_initialized(
    config_path: &Path,
    non_interactive: bool,
    overrides: ProxyCliOverrides,
) -> Result<ProxyConfig> {
    let base_dir = olp_home_dir()?;
    ensure_secure_dir(&base_dir)?;
    let config_dir = olp_config_dir()?;

    if config_path.exists() {
        let mut cfg = ProxyConfig::load_from_path(config_path)?;
        let mut modified = false;

        if let Some(val) = overrides.listen_addr {
            cfg.proxy.listen_addr = val;
            modified = true;
        }
        if let Some(val) = overrides.allowed_ports {
            cfg.proxy.allowed_ports = val;
            modified = true;
        }
        if let Some(keys) = overrides.olp_api_keys {
            for k in keys {
                if !cfg.auth.olp_api_keys.contains(&k) {
                    cfg.auth.olp_api_keys.push(k.clone());
                    let profile_path = config_dir.join(format!("{}.toml", k));
                    if !profile_path.exists() {
                        let mut prof = UserProfile::new(&k);
                        prof.user.name = Some("admin".to_string());
                        let _ = prof.save_atomic(&profile_path);
                    }
                }
            }
            modified = true;
        }
        if let Some(cidrs) = overrides.allowed_server_cidrs {
            cfg.security.allowed_server_cidrs = cidrs;
            modified = true;
        }
        if let Some(cidrs) = overrides.allowed_user_cidrs {
            cfg.security.allowed_user_cidrs = cidrs;
            modified = true;
        }
        if let Some(val) = overrides.tls_mode {
            cfg.tls.mode = val;
            modified = true;
        }
        if let Some(val) = overrides.tls_cert_path {
            cfg.tls.cert_path = Some(val);
            modified = true;
        }
        if let Some(val) = overrides.tls_key_path {
            cfg.tls.key_path = Some(val);
            modified = true;
        }
        if let Some(val) = overrides.access_log {
            cfg.proxy.access_log = if val == "off" { None } else { Some(val) };
            modified = true;
        }
        if let Some(val) = overrides.auto_git_pull {
            cfg.maintenance.auto_git_pull = val;
            modified = true;
        }
        if let Some(val) = overrides.read_only {
            cfg.security.read_only = val;
            modified = true;
        }
        if let Some(val) = overrides.hash_passkeys {
            cfg.security.hash_passkeys = val;
            modified = true;
        }
        if let Some(val) = overrides.allow_broken_certs {
            cfg.tls.allow_broken_certs = val;
            modified = true;
        }
        if overrides.insecure_no_tls {
            cfg.tls.mode = "off".to_string();
            modified = true;
        }

        if modified {
            cfg.save_to_path(config_path)?;
        }
        return Ok(cfg);
    }

    let mut cfg = ProxyConfig::default_config();
    let mut initial_api_key = overrides
        .olp_api_keys
        .as_ref()
        .and_then(|keys| keys.first().cloned())
        .unwrap_or_else(generate_random_passkey);

    let has_overrides = overrides.listen_addr.is_some()
        || overrides.allowed_ports.is_some()
        || overrides.olp_api_keys.is_some()
        || overrides.allowed_server_cidrs.is_some()
        || overrides.allowed_user_cidrs.is_some()
        || overrides.tls_mode.is_some();

    if !non_interactive && !has_overrides && io::stdin().is_terminal() {
        println!(
            "\n================================================================================"
        );
        println!("  [olp-proxy] First-Time Configuration Setup");
        println!(
            "================================================================================\n"
        );

        cfg.proxy.listen_addr = prompt_line("Tunnel listen address", &cfg.proxy.listen_addr)?;
        cfg.proxy.allowed_ports = prompt_line(
            "Allowed public port range for servers",
            &cfg.proxy.allowed_ports,
        )?;

        let custom_api_key = prompt_line(
            &format!(
                "Initial olp_api_key for first user (press Enter to auto-generate: {})",
                initial_api_key
            ),
            "",
        )?;
        if !custom_api_key.is_empty() {
            if crate::protocol::is_safe_identifier(&custom_api_key) {
                initial_api_key = custom_api_key;
            } else {
                println!("  [!] Invalid API key format; using generated key instead.");
            }
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

    if let Some(val) = overrides.listen_addr {
        cfg.proxy.listen_addr = val;
    }
    if let Some(val) = overrides.allowed_ports {
        cfg.proxy.allowed_ports = val;
    }
    if let Some(cidrs) = overrides.allowed_server_cidrs {
        cfg.security.allowed_server_cidrs = cidrs;
    }
    if let Some(cidrs) = overrides.allowed_user_cidrs {
        cfg.security.allowed_user_cidrs = cidrs;
    }
    if let Some(val) = overrides.tls_mode {
        cfg.tls.mode = val;
    }
    if let Some(val) = overrides.tls_cert_path {
        cfg.tls.cert_path = Some(val);
    }
    if let Some(val) = overrides.tls_key_path {
        cfg.tls.key_path = Some(val);
    }
    if let Some(val) = overrides.access_log {
        cfg.proxy.access_log = if val == "off" { None } else { Some(val) };
    }
    if let Some(val) = overrides.auto_git_pull {
        cfg.maintenance.auto_git_pull = val;
    }
    if let Some(val) = overrides.read_only {
        cfg.security.read_only = val;
    }
    if let Some(val) = overrides.hash_passkeys {
        cfg.security.hash_passkeys = val;
    }
    if let Some(val) = overrides.allow_broken_certs {
        cfg.tls.allow_broken_certs = val;
    }
    if overrides.insecure_no_tls {
        cfg.tls.mode = "off".to_string();
    }

    let all_keys = match overrides.olp_api_keys {
        Some(k) if !k.is_empty() => k,
        _ => vec![initial_api_key.clone()],
    };
    cfg.auth.olp_api_keys = all_keys.clone();
    cfg.save_to_path(config_path)?;

    // Create user profiles in ~/.olp/config/<key>.toml for each key
    for key in &all_keys {
        let profile_path = config_dir.join(format!("{}.toml", key));
        if !profile_path.exists() {
            let mut prof = UserProfile::new(key);
            prof.user.name = Some("admin".to_string());
            prof.save_atomic(&profile_path)?;
        }
    }

    let first_key = all_keys.first().cloned().unwrap_or(initial_api_key);
    let first_profile = config_dir.join(format!("{}.toml", first_key));

    println!("\n================================================================================");
    println!(
        "  [olp-proxy] Configuration saved to {}",
        config_path.display()
    );
    println!("  ----------------------------------------------------------------------------");
    println!("  olp_api_key  : {}", first_key);
    println!("  user profile : {}", first_profile.display());
    println!("  ----------------------------------------------------------------------------");
    println!("  * olp_api_key : Put this in your olp-server's server.toml");
    println!("  * You can create additional user keys at ~/.olp/config/<new_key>.toml");
    println!("================================================================================\n");

    Ok(cfg)
}

/// Ensures `~/.olp/server.toml` exists. If missing, initializes default settings.
pub fn ensure_server_initialized(
    config_path: &Path,
    non_interactive: bool,
    overrides: ServerCliOverrides,
) -> Result<ServerConfig> {
    let base_dir = olp_home_dir()?;
    ensure_secure_dir(&base_dir)?;

    if config_path.exists() {
        let mut cfg = ServerConfig::load_from_path(config_path)?;
        let mut modified = false;

        if let Some(val) = overrides.proxy_addr {
            cfg.server.proxy_addr = val;
            modified = true;
        }
        if let Some(val) = overrides.ollama_addr {
            cfg.server.ollama_addr = val;
            modified = true;
        }
        if let Some(val) = overrides.remote_port {
            cfg.server.remote_port = Some(val);
            modified = true;
        }
        if let Some(val) = overrides.olp_api_key {
            cfg.server.olp_api_key = val;
            modified = true;
        }
        if let Some(val) = overrides.olp_server_id {
            cfg.server.olp_server_id = val;
            modified = true;
        }
        if let Some(val) = overrides.passkey_user {
            cfg.server.passkey_user = val;
            modified = true;
        }
        if let Some(val) = overrides.tls_verify {
            cfg.server.tls_verify = Some(val);
            modified = true;
        }
        if let Some(val) = overrides.auto_git_pull {
            cfg.maintenance.auto_git_pull = val;
            modified = true;
        }
        if let Some(val) = overrides.read_only {
            cfg.server.read_only = Some(val);
            modified = true;
        }
        if overrides.insecure_skip_tls_verify {
            cfg.server.tls_verify = Some(false);
            modified = true;
        }

        if cfg.server.olp_server_id.is_empty() {
            cfg.server.olp_server_id = generate_random_server_id();
            modified = true;
        }
        if modified {
            cfg.save_to_path(config_path)?;
        }
        return Ok(cfg);
    }

    let mut cfg = ServerConfig::default_config();
    cfg.server.olp_server_id = overrides
        .olp_server_id
        .unwrap_or_else(generate_random_server_id);
    cfg.server.passkey_user = overrides
        .passkey_user
        .unwrap_or_else(generate_random_passkey);

    let has_overrides = overrides.proxy_addr.is_some()
        || overrides.olp_api_key.is_some()
        || overrides.ollama_addr.is_some()
        || overrides.remote_port.is_some();

    if !non_interactive && !has_overrides && io::stdin().is_terminal() {
        println!(
            "\n================================================================================"
        );
        println!("  [olp-server] First-Time Configuration Setup");
        println!(
            "================================================================================\n"
        );

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
        cfg.server.ollama_addr = prompt_line("Local Ollama address", &cfg.server.ollama_addr)?;

        // 3. Recommended port on proxy (optional)
        let rec_port_str = prompt_line(
            "Recommended port on proxy (optional, press Enter for dynamic assignment)",
            "",
        )?;
        if !rec_port_str.is_empty() {
            if let Ok(p) = rec_port_str.parse::<u16>() {
                cfg.server.remote_port = Some(p);
            }
        }

        // 4. olp_api_key for proxy
        loop {
            let key = prompt_line("User API key (olp_api_key from proxy)", "")?;
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                cfg.server.olp_api_key = trimmed.to_string();
                break;
            } else {
                println!("  [!] olp_api_key is required to connect to the proxy. Please enter it:");
            }
        }

        // 5. passkey_user
        let custom_passkey_user = prompt_line(
            &format!(
                "Passkey for client access to this server (press Enter to use generated: {})",
                cfg.server.passkey_user
            ),
            "",
        )?;
        if !custom_passkey_user.is_empty() {
            cfg.server.passkey_user = custom_passkey_user;
        }
    }

    if let Some(val) = overrides.proxy_addr {
        cfg.server.proxy_addr = val;
    }
    if let Some(val) = overrides.ollama_addr {
        cfg.server.ollama_addr = val;
    }
    if let Some(val) = overrides.remote_port {
        cfg.server.remote_port = Some(val);
    }
    if let Some(val) = overrides.olp_api_key {
        cfg.server.olp_api_key = val;
    }
    if let Some(val) = overrides.tls_verify {
        cfg.server.tls_verify = Some(val);
    }
    if let Some(val) = overrides.auto_git_pull {
        cfg.maintenance.auto_git_pull = val;
    }
    if let Some(val) = overrides.read_only {
        cfg.server.read_only = Some(val);
    }
    if overrides.insecure_skip_tls_verify {
        cfg.server.tls_verify = Some(false);
    }

    if cfg.server.olp_api_key.is_empty() {
        cfg.server.olp_api_key = "change-me-to-your-olp-api-key".to_string();
    }

    cfg.save_to_path(config_path)?;

    println!("\n================================================================================");
    println!(
        "  [olp-server] Configuration saved to {}",
        config_path.display()
    );
    println!("  ----------------------------------------------------------------------------");
    println!("  olp_server_id : {}", cfg.server.olp_server_id);
    println!("  passkey_user  : {}", cfg.server.passkey_user);
    println!("  ----------------------------------------------------------------------------");
    println!("  * passkey_user : Use this as your Bearer token / password when querying Ollama");
    println!("================================================================================\n");

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_defaults_to_git_pull_when_missing() {
        let cfg: ServerConfig = toml::from_str(
            "[server]\nproxy_addr = \"a:1\"\nollama_addr = \"b:2\"\nolp_api_key = \"x\"\npasskey_user = \"y\"\n",
        )
        .unwrap();
        assert!(cfg.maintenance.auto_git_pull);
    }

    #[test]
    fn test_olp_api_keys_deserialization() {
        // String format
        let toml_str = r#"
            olp_api_keys = "key1, key2, key3"
        "#;
        let auth: ProxyAuthSection = toml::from_str(toml_str).unwrap();
        assert_eq!(auth.olp_api_keys, vec!["key1", "key2", "key3"]);

        // Array format
        let toml_seq = r#"
            olp_api_keys = ["alpha", "beta"]
        "#;
        let auth2: ProxyAuthSection = toml::from_str(toml_seq).unwrap();
        assert_eq!(auth2.olp_api_keys, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_user_profile_atomic_save_and_load() {
        let dir =
            std::env::temp_dir().join(format!("olp_test_{}", rand::thread_rng().gen::<u64>()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_user.toml");

        let mut profile = UserProfile::new("test_user_key");
        profile.user.name = Some("Alice".to_string());
        profile.servers.insert(
            "srv_abc".to_string(),
            UserServerConfig {
                port: 12345,
                reserved: true,
                passkey_user: "user-pass-123".to_string(),
                passkey_user_hash: None,
                allowed_user_cidrs: vec!["0.0.0.0/0".to_string()],
                allowed_server_cidrs: vec!["0.0.0.0/0".to_string()],
                created_at: Some("2026-11-06T12:00:00Z".to_string()),
                read_only: Some(true),
            },
        );

        profile.save_atomic(&path).unwrap();
        let loaded = UserProfile::load_from_path(&path).unwrap();
        assert_eq!(loaded.user.api_key, "test_user_key");
        assert_eq!(loaded.user.name, Some("Alice".to_string()));
        let srv = loaded.servers.get("srv_abc").unwrap();
        assert_eq!(srv.port, 12345);
        assert!(srv.reserved);
        assert_eq!(srv.passkey_user, "user-pass-123");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn maintenance_accepts_yes_no_strings_and_bools() {
        for (val, expected) in [
            ("false", false),
            ("\"no\"", false),
            ("\"yes\"", true),
            ("true", true),
        ] {
            let m: MaintenanceSection =
                toml::from_str(&format!("auto_git_pull = {}", val)).unwrap();
            assert_eq!(m.auto_git_pull, expected, "value {}", val);
        }
        assert!(toml::from_str::<MaintenanceSection>("auto_git_pull = \"maybe\"").is_err());
    }

    #[test]
    fn new_configs_write_auto_git_pull_false() {
        let s = toml::to_string_pretty(&ProxyConfig::default_config()).unwrap();
        assert!(
            s.contains("[maintenance]") && s.contains("auto_git_pull = false"),
            "{}",
            s
        );
        let s = toml::to_string_pretty(&ServerConfig::default_config()).unwrap();
        assert!(
            s.contains("[maintenance]") && s.contains("auto_git_pull = false"),
            "{}",
            s
        );
    }
}
