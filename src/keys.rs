use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
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

/// Salted BLAKE3 verifier for `passkey_user` so `olp-proxy` never stores plaintext passkeys
/// in memory and verifies user credentials in constant time.
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
        hasher.update(b"olp-user-passkey-v1:");
        hasher.update(salt);
        hasher.update(passkey.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Constant-time verification of a candidate passkey.
    pub fn verify(&self, candidate: &str) -> bool {
        let candidate_hash = Self::compute_hash(&self.salt, candidate);
        self.hash.ct_eq(&candidate_hash).into()
    }

    /// Serializes the salt and hash into a portable `$blake3$<salt_b64>$<hash_b64>` string.
    pub fn to_encoded_hash(&self) -> String {
        use base64::prelude::*;
        let s = BASE64_STANDARD.encode(self.salt);
        let h = BASE64_STANDARD.encode(self.hash);
        format!("$blake3${}${}", s, h)
    }

    /// Deserializes a `$blake3$<salt_b64>$<hash_b64>` encoded string.
    pub fn from_encoded_hash(encoded: &str) -> Option<Self> {
        use base64::prelude::*;
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() == 4 && parts[1] == "blake3" {
            let salt_bytes = BASE64_STANDARD.decode(parts[2]).ok()?;
            let hash_bytes = BASE64_STANDARD.decode(parts[3]).ok()?;
            if salt_bytes.len() == 32 && hash_bytes.len() == 32 {
                let mut salt = [0u8; 32];
                let mut hash = [0u8; 32];
                salt.copy_from_slice(&salt_bytes);
                hash.copy_from_slice(&hash_bytes);
                return Some(Self { salt, hash });
            }
        }
        None
    }
}

/// Tracks sliding-window request rates for authenticated requests per server/endpoint.
#[derive(Debug)]
pub struct RequestRateLimiter {
    max_requests_per_min: u32,
    window_duration: Duration,
    requests: Mutex<HashMap<u16, Vec<Instant>>>,
}

impl RequestRateLimiter {
    pub fn new(max_requests_per_min: u32) -> Self {
        Self {
            max_requests_per_min,
            window_duration: Duration::from_secs(60),
            requests: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a request on `port` is permitted. Returns true if allowed, false if limit exceeded.
    pub fn check_and_record(&self, port: u16) -> bool {
        if self.max_requests_per_min == 0 {
            return true;
        }
        let now = Instant::now();
        let window_start = now.checked_sub(self.window_duration).unwrap_or(now);

        let mut reqs = self.requests.lock().unwrap();
        let entry = reqs.entry(port).or_default();
        entry.retain(|&time| time > window_start);

        if entry.len() >= self.max_requests_per_min as usize {
            false
        } else {
            entry.push(now);
            true
        }
    }
}

/// Tracks per-IP authentication failures and applies temporary lockouts.
#[derive(Debug)]
pub struct IpRateLimiter {
    max_failures_per_min: u32,
    lockout_duration: Duration,
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    lockouts: Mutex<HashMap<IpAddr, Instant>>,
}

impl IpRateLimiter {
    pub fn new(max_failures_per_min: u32) -> Self {
        Self {
            max_failures_per_min,
            lockout_duration: Duration::from_secs(300),
            attempts: Mutex::new(HashMap::new()),
            lockouts: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_locked_out(&self, ip: &IpAddr) -> Option<Duration> {
        let mut lockouts = self.lockouts.lock().unwrap();
        if let Some(lockout_start) = lockouts.get(ip) {
            let elapsed = lockout_start.elapsed();
            if elapsed < self.lockout_duration {
                return Some(self.lockout_duration - elapsed);
            } else {
                lockouts.remove(ip);
            }
        }
        None
    }

    pub fn record_failure(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let one_min_ago = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);

        let mut attempts = self.attempts.lock().unwrap();
        let entry = attempts.entry(ip).or_default();
        entry.retain(|&time| time > one_min_ago);
        entry.push(now);

        if entry.len() >= self.max_failures_per_min as usize {
            let mut lockouts = self.lockouts.lock().unwrap();
            lockouts.insert(ip, now);
            entry.clear();
            return true;
        }
        false
    }

    pub fn record_success(&self, ip: &IpAddr) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(ip);
    }
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
    fn test_passkey_verifier_encoded_hash_roundtrip() {
        let verifier = PasskeyVerifier::from_passkey("my_secure_passkey_123");
        let encoded = verifier.to_encoded_hash();
        assert!(encoded.starts_with("$blake3$"));

        let restored = PasskeyVerifier::from_encoded_hash(&encoded).expect("must parse encoded hash");
        assert_eq!(verifier.salt, restored.salt);
        assert_eq!(verifier.hash, restored.hash);
        assert!(restored.verify("my_secure_passkey_123"));
        assert!(!restored.verify("wrong_passkey"));

        // Malformed hash strings must fail gracefully
        assert!(PasskeyVerifier::from_encoded_hash("invalid").is_none());
        assert!(PasskeyVerifier::from_encoded_hash("$unknown$aaa$bbb").is_none());
        assert!(PasskeyVerifier::from_encoded_hash("$blake3$short$short").is_none());
    }

    #[test]
    fn test_request_rate_limiter_window() {
        let limiter = RequestRateLimiter::new(3);
        assert!(limiter.check_and_record(10001));
        assert!(limiter.check_and_record(10001));
        assert!(limiter.check_and_record(10001));
        // 4th request in the same window must be rejected
        assert!(!limiter.check_and_record(10001));

        // Different port has independent limit
        assert!(limiter.check_and_record(10002));
    }
}
