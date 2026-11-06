use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use subtle::ConstantTimeEq;

/// Enforces `0700` permissions on a directory on Unix platforms.
pub fn ensure_secure_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory {}", path.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        let _ = fs::set_permissions(path, perms);
    }
    Ok(())
}

/// Enforces `0600` permissions on a sensitive file on Unix platforms.
pub fn enforce_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let metadata = fs::metadata(path)?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                let perms = fs::Permissions::from_mode(0o600);
                fs::set_permissions(path, perms).with_context(|| {
                    format!(
                        "Failed to tighten permissions to 0600 on {}",
                        path.display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Writes a sensitive file and immediately locks its permissions to `0600`.
pub fn write_private_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_secure_dir(parent)?;
    }
    fs::write(path, content)
        .with_context(|| format!("Failed to write file {}", path.display()))?;
    enforce_private_file_permissions(path)?;
    Ok(())
}

/// Formats an Ed25519 verifying key into a human-friendly single-line string.
pub fn format_pubkey(role_prefix: &str, key: &VerifyingKey) -> String {
    format!("{} {}", role_prefix, BASE64.encode(key.as_bytes()))
}

/// Parses an Ed25519 verifying key from either `<prefix> <base64>` or raw `<base64>`.
pub fn parse_pubkey(input: &str) -> Result<VerifyingKey> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Empty public key string"));
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let b64_part = if tokens.len() >= 2 && tokens[0].contains("ed25519") {
        tokens[1]
    } else {
        tokens[0]
    };

    let raw = BASE64
        .decode(b64_part)
        .context("Invalid base64 encoding in public key")?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must be exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("Invalid Ed25519 curve point in public key")
}

/// Loads an existing Ed25519 SigningKey from `priv_path`, or generates and saves a new keypair
/// (`priv_path` and `priv_path.pub`) if it does not exist yet.
pub fn load_or_generate_keypair(priv_path: &Path, role_prefix: &str) -> Result<SigningKey> {
    if priv_path.exists() {
        enforce_private_file_permissions(priv_path)?;
        let content = fs::read_to_string(priv_path)
            .with_context(|| format!("Failed to read private key {}", priv_path.display()))?;
        let raw = BASE64
            .decode(content.trim())
            .context("Failed to decode base64 private key")?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("Ed25519 private key must be 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&bytes);
        // Ensure .pub file exists as well
        let pub_path = priv_path.with_extension("pub");
        if !pub_path.exists() {
            let pub_str = format_pubkey(role_prefix, &signing_key.verifying_key());
            let _ = fs::write(&pub_path, format!("{}\n", pub_str));
        }
        return Ok(signing_key);
    }

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let priv_b64 = BASE64.encode(signing_key.to_bytes());
    write_private_file(priv_path, &format!("{}\n", priv_b64))?;

    let pub_path = priv_path.with_extension("pub");
    let pub_str = format_pubkey(role_prefix, &signing_key.verifying_key());
    fs::write(&pub_path, format!("{}\n", pub_str))
        .with_context(|| format!("Failed to write public key {}", pub_path.display()))?;

    Ok(signing_key)
}

/// Represents a single entry in `~/.olp/keys/authorized_keys`.
#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    pub pubkey: VerifyingKey,
    pub allowed_ports: Option<HashSet<u16>>,
    pub comment: Option<String>,
}

/// Parses an `authorized_keys` file and checks whether `candidate` is authorized
/// (and optionally whether it is allowed to bind `requested_port`).
pub fn verify_authorized_key(
    auth_keys_path: &Path,
    candidate: &VerifyingKey,
    requested_port: u16,
) -> Result<bool> {
    if !auth_keys_path.exists() {
        return Ok(false);
    }
    enforce_private_file_permissions(auth_keys_path)?;
    let content = fs::read_to_string(auth_keys_path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(entry) = parse_authorized_key_line(line) {
            if entry.pubkey.as_bytes() == candidate.as_bytes() {
                if let Some(ports) = entry.allowed_ports {
                    return Ok(ports.contains(&requested_port));
                }
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn parse_authorized_key_line(line: &str) -> Result<AuthorizedKeyEntry> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(anyhow!("Empty line"));
    }
    let (pubkey, rest_idx) = if tokens.len() >= 2 && tokens[0].contains("ed25519") {
        (
            parse_pubkey(&format!("{} {}", tokens[0], tokens[1]))?,
            2usize,
        )
    } else {
        (parse_pubkey(tokens[0])?, 1usize)
    };

    let mut allowed_ports: Option<HashSet<u16>> = None;
    let mut comments = Vec::new();

    for token in &tokens[rest_idx..] {
        if let Some(ports_str) = token.strip_prefix("ports=") {
            let mut set = HashSet::new();
            for p in ports_str.split(',') {
                if let Ok(port) = p.trim().parse::<u16>() {
                    set.insert(port);
                }
            }
            allowed_ports = Some(set);
        } else {
            comments.push(*token);
        }
    }

    Ok(AuthorizedKeyEntry {
        pubkey,
        allowed_ports,
        comment: if comments.is_empty() {
            None
        } else {
            Some(comments.join(" "))
        },
    })
}

/// Appends a public key line to `authorized_keys` if not already present.
pub fn add_authorized_key(auth_keys_path: &Path, pubkey_line: &str) -> Result<()> {
    let key = parse_pubkey(pubkey_line)?;
    let formatted = format_pubkey("olp-server-ed25519", &key);
    let mut existing = if auth_keys_path.exists() {
        fs::read_to_string(auth_keys_path)?
    } else {
        String::from("# Authorized olp-server public keys (one per line)\n")
    };

    for line in existing.lines() {
        if let Ok(entry) = parse_authorized_key_line(line) {
            if entry.pubkey.as_bytes() == key.as_bytes() {
                return Ok(());
            }
        }
    }

    if !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&formatted);
    existing.push('\n');
    write_private_file(auth_keys_path, &existing)
}

/// Salted BLAKE3 verifier for the user passkey so `olp-proxy` never stores plaintext passkeys
/// and verifies user credentials in constant time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyVerifier {
    pub salt: [u8; 32],
    pub hash: [u8; 32],
}

impl PasskeyVerifier {
    pub fn from_passkey(passkey: &str) -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let hash = Self::compute_hash(&salt, passkey);
        Self { salt, hash }
    }

    fn compute_hash(salt: &[u8; 32], passkey: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"olp-passkey-v1:");
        hasher.update(salt);
        hasher.update(passkey.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Constant-time verification of a candidate passkey.
    pub fn verify(&self, candidate: &str) -> bool {
        let candidate_hash = Self::compute_hash(&self.salt, candidate);
        self.hash.ct_eq(&candidate_hash).into()
    }
}

/// Signs arbitrary message bytes using an Ed25519 `SigningKey`.
pub fn sign_message(signing_key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    signing_key.sign(msg).to_bytes()
}

/// Verifies an Ed25519 signature over `msg`.
pub fn verify_signature(verifying_key: &VerifyingKey, msg: &[u8], sig_bytes: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(sig_bytes);
    verifying_key.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_verifier_constant_time() {
        let verifier = PasskeyVerifier::from_passkey("correct-horse-battery-staple");
        assert!(verifier.verify("correct-horse-battery-staple"));
        assert!(!verifier.verify("wrong-passkey"));
        assert!(!verifier.verify(""));
    }

    #[test]
    fn test_pubkey_parse_and_authorized_line() {
        let signing = SigningKey::generate(&mut OsRng);
        let pub_str = format_pubkey("olp-server-ed25519", &signing.verifying_key());
        let line = format!("{} home-gpu ports=11434,11435", pub_str);
        let entry = parse_authorized_key_line(&line).unwrap();
        assert_eq!(entry.pubkey, signing.verifying_key());
        let ports = entry.allowed_ports.unwrap();
        assert!(ports.contains(&11434));
        assert!(!ports.contains(&9999));
    }
}

