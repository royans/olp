# Ollama Proxy (`olp-proxy` & `olp-server`)

[![Tests](https://img.shields.io/badge/tests-16%20passing-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Memory Footprint](https://img.shields.io/badge/memory-%3C5MB%20RAM-success.svg)]()

A lightweight, failure-resilient, mutually-authenticated reverse proxy and tunneling daemon in **Rust** designed to expose a private Ollama server (`olp-server` running behind NAT or restrictive firewalls) to a public gateway (`olp-proxy`).

```
 +----------------------------------+                   +----------------------------------+
 |  PRIVATE NETWORK A (Behind NAT)  |                   |  PUBLIC CLOUD SERVER / VPS       |
 |  [ollama-gpu-cluster]            |                   |                                  |
 |  [olp-server 1] -----------------+------------------>|  [olp-proxy]                     |
 +----------------------------------+ (Control :4443)   |    Control Port: :4443           |
                                                        |    Public Port 1: :11434 <-------+--- User A
 +----------------------------------+                   |    Public Port 2: :11435 <-------+--- User B
 |  PRIVATE NETWORK B (Behind NAT)  |                   |    Public Port 3: :11436 <-------+--- User C
 |  [ollama-mac-studio]             |                   |                                  |
 |  [olp-server 2] -----------------+------------------>|                                  |
 +----------------------------------+ (Control :4443)   +----------------------------------+
```

---

## Key Features

- **Zero Inbound NAT/Firewall Configuration**: `olp-server` makes an *outbound* connection to `olp-proxy` over a single TCP/TLS port (`:4443`). No port-forwarding or UPnP required on your private router.
- **Ultra-Low Resource Footprint**: Written in pure Rust (`tokio` + `yamux` + `rustls`) using **< 5 MB RAM** and near-zero idle CPU.
- **Zero-Friction Auto-Bootstrap**: `./start-proxy.sh` and `./start-server.sh` automatically detect your OS, silently install build tools and the minimal Rust toolchain if missing, compile the release binaries once, and launch an interactive first-run setup wizard.
- **Mutual Ed25519 & TLS Channel Binding**: Prevents Man-in-the-Middle (MITM) attacks using SSH-style keypairs and RFC 8446 TLS 1.3 Exporter binding (`EXPORTER-olp-tunnel-v1`).
- **Dual User Authentication**: End-users can authenticate using either **HTTP Basic Auth** (`username:passkey`) or **Bearer Tokens** (`Authorization: Bearer <passkey>`), making it compatible with the official Ollama CLI, Open WebUI, LibreChat, Python/JS SDKs, and IDE extensions (Continue, Cursor, Cline).
- **Salted BLAKE3 & Constant-Time Verification**: Plaintext passkeys are never stored on `olp-proxy`. Verification is performed using `subtle::ConstantTimeEq` to prevent timing side-channel attacks.
- **Edge IP Brute-Force Rate Limiting**: Automatic sliding-window rate limiter returns `429 Too Many Requests` on repeated bad authentication attempts before requests can reach the tunnel.
- **Fibonacci Reconnect Backoff**: Exponential reconnection sequence (`1s, 1s, 2s, 3s, 5s, 8s, 13s, 21s...` capped at 300s / 5 minutes) with $\pm 10\%$ jitter and automatic reset after 30 seconds of healthy connectivity.
- **Hot-Swappable Reconnection (Zero `EADDRINUSE`)**: If `olp-server` drops and reconnects, `olp-proxy` rebinds the active session atomically without restarting the listener, serving clean `503 Service Unavailable` (`Retry-After: 2`) during brief network interruptions.
- **Zero-Buffering Chunked Streaming**: Full support for real-time Server-Sent Events (SSE) and chunked token generation (`/api/generate`, `/api/chat`), embedding payloads (`/api/embed`), and multi-gigabyte model downloads (`/api/pull`).
- **Unified Runtime Isolation**: All keys, configs, and runtime state live exclusively in `~/.olp/` with strict `0700`/`0600` permissions.

---

## Multi-Server Support (Multiple `olp-server`s on One `olp-proxy`)

A single `olp-proxy` instance can simultaneously host any number of private `olp-server`s (e.g., an office GPU cluster, a home Mac Studio, and a cloud developer rig).

### How It Works:
1. All servers connect to the same tunnel control port (`:4443`) on `olp-proxy`.
2. Each server has its own Ed25519 keypair and registers an independent external public port:
   - Server 1 (Home GPU): declares remote port `11434` with `passkey-1`.
   - Server 2 (Office Mac Studio): declares remote port `11435` with `passkey-2`.
   - Server 3 (Cloud Dev Machine): declares remote port `11436` with `passkey-3`.
3. `olp-proxy` automatically spawns an isolated public listener for each server. Each endpoint has its own independent:
   - User authentication passkey (`passkey-1` cannot access Server 2).
   - Sliding-window brute-force rate limiter.
   - Bounded 256 KB Yamux flow control window.
4. In `~/.olp/keys/authorized_keys`, you can optionally restrict which server key is allowed to bind which port (e.g. `ports=11434`).

---

## Quick Start (3 Steps)

### Step 1: On the Public Server (`olp-proxy`)

Clone the repository and run the startup script:
```bash
git clone https://github.com/royans/olp.git
cd olp
./start-proxy.sh
```

> **Lifecycle Controls**:
> - `./start-proxy.sh restart` — Gracefully stops any running instance and starts a fresh one.
> - `./start-proxy.sh stop` — Gracefully terminates the running process (`SIGTERM` $\to$ clean socket release).
> - `./start-proxy.sh status` — Checks if the service is currently running and prints its PID.

On first launch:
1. It automatically generates `~/.olp/keys/proxy_id_ed25519` and displays your **Proxy Public Key**.
2. It prompts you for basic options (press `Enter` to accept the defaults: listen on `0.0.0.0:4443`, allowed port range `10000-20000`).
3. It saves `~/.olp/proxy.toml` and starts listening for tunnels.

---

### Step 2: On the Private Host (`olp-server`)

Clone the repository on the machine running Ollama (`127.0.0.1:11434`):
```bash
git clone https://github.com/royans/olp.git
cd olp
./start-server.sh
```

> **Lifecycle Controls**:
> - `./start-server.sh restart` — Gracefully stops any running instance and reconnects cleanly.
> - `./start-server.sh stop` — Gracefully terminates the running tunnel client (`SIGTERM`).
> - `./start-server.sh status` — Checks if the client is currently running and prints its PID.

On first launch:
1. It generates `~/.olp/keys/server_id_ed25519` and displays your **Server Public Key**.
2. Paste the **Proxy Public Key** copied from Step 1.
3. Enter your proxy host address (e.g. `your-proxy-domain.com:4443`).
4. Select the remote public port to expose (default: `11434`).
5. Choose or auto-generate your user passkey.
6. It saves `~/.olp/server.toml` and attempts to connect.

---

### Step 3: Authorize the Server on the Proxy (No Restart Needed)

On the proxy machine, run:
```bash
./start-proxy.sh --add-key "olp-server-ed25519 AAAAC3NzaC1..."
```

`olp-proxy` reads `~/.olp/keys/authorized_keys` dynamically on every handshake. The tunnel establishes immediately, and your Ollama endpoint is live on `http://YOUR_PROXY_HOST:11434`!

---

## Connecting Clients to Your Remote Ollama

### 1. Official Ollama CLI
Set `OLLAMA_HOST` with your credentials:
```bash
export OLLAMA_HOST="http://user:YOUR_PASSKEY@your-proxy-domain.com:11434"
ollama list
ollama run llama3
```

### 2. cURL (Basic Auth or Bearer Token)
```bash
# Using Basic Authentication:
curl -u user:YOUR_PASSKEY http://your-proxy-domain.com:11434/api/tags

# Using Bearer Token:
curl -H "Authorization: Bearer YOUR_PASSKEY" http://your-proxy-domain.com:11434/api/tags

# Real-time token streaming:
curl -N -u user:YOUR_PASSKEY http://your-proxy-domain.com:11434/api/generate \
  -d '{"model": "llama3", "prompt": "Why is the sky blue?"}'
```

### 3. Python SDK (`ollama-python`)
```python
import ollama

client = ollama.Client(
    host="http://your-proxy-domain.com:11434",
    headers={"Authorization": "Bearer YOUR_PASSKEY"}
)

response = client.chat(model="llama3", messages=[
    {"role": "user", "content": "Hello!"}
])
print(response["message"]["content"])
```

### 4. Open WebUI / LibreChat / Continue.dev / LangChain
Configure your remote endpoint as:
- **Base URL**: `http://your-proxy-domain.com:11434` (or `https://...`)
- **API Key / Bearer Token**: `YOUR_PASSKEY`

---

## Directory & File Layout (`~/.olp/`)

All sensitive files, keys, and configurations reside in `~/.olp/` with strict permissions enforced:

```
~/.olp/                         # Directory permissions: 0700 (drwx------)
├── proxy.toml                  # Configuration for olp-proxy (0600)
├── server.toml                 # Configuration for olp-server (0600)
├── keys/                       # Directory permissions: 0700 (drwx------)
│   ├── proxy_id_ed25519        # Proxy private key (0600)
│   ├── proxy_id_ed25519.pub    # Proxy public key (0644)
│   ├── server_id_ed25519       # Server private key (0600)
│   ├── server_id_ed25519.pub   # Server public key (0644)
│   ├── authorized_keys         # Allowed server public keys on proxy (0600)
│   └── known_proxy.pub         # Pinned proxy public key on server (0600)
```

### Port Pinning in `authorized_keys`
You can optionally restrict specific servers to specific public ports in `~/.olp/keys/authorized_keys`:
```text
# Allow this server key to bind any port:
olp-server-ed25519 AAAAC3NzaC1... home-mac-studio

# Restrict this server key strictly to port 11434:
olp-server-ed25519 AAAAC3NzaC1... home-gpu-server ports=11434
```

---

## Configuration Reference

Documented sample configuration templates are provided in the repo under `examples/`:
- [examples/proxy.toml.example](examples/proxy.toml.example) (deployed to `~/.olp/proxy.toml`)
- [examples/server.toml.example](examples/server.toml.example) (deployed to `~/.olp/server.toml`)

### `~/.olp/proxy.toml`:
```toml
[proxy]
listen_addr = "0.0.0.0:4443"        # Port for incoming tunnel connections
allowed_ports = "10000-20000"       # Allowed port range for public Ollama endpoints
listener_grace_period_sec = 300     # Grace period holding port open (503 Retry-After) during reconnects

[keys]
private_key = "~/.olp/keys/proxy_id_ed25519"
authorized_keys = "~/.olp/keys/authorized_keys"

[security]
max_auth_failures_per_min = 5      # Rate limiting threshold per IP
max_concurrent_streams = 128        # Maximum concurrent HTTP streams per tunnel

[tls]
mode = "off"                        # "off", "self-signed", or "manual"
# cert_path = "~/.olp/keys/tls_cert.pem"
# key_path = "~/.olp/keys/tls_key.pem"
```

### `~/.olp/server.toml`:
```toml
[server]
proxy_addr = "your-proxy-domain.com:4443"
ollama_addr = "127.0.0.1:11434"
remote_port = 11434
passkey = "your-strong-passkey"

[keys]
private_key = "~/.olp/keys/server_id_ed25519"
known_proxy_key = "~/.olp/keys/known_proxy.pub"

[reconnect]
strategy = "fibonacci"
initial_delay_sec = 1
max_delay_sec = 300
heartbeat_interval_sec = 15
heartbeat_timeout_sec = 5
```

---

## Production Deployment with Systemd

Systemd unit files are included under `examples/`:

### 1. Deploy `olp-proxy` as a System Service
```bash
sudo cp examples/olp-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now olp-proxy
sudo systemctl status olp-proxy
```

### 2. Deploy `olp-server` as a System Service
```bash
sudo cp examples/olp-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now olp-server
sudo systemctl status olp-server
```

---

## Security Model & Resilience Audit

| Threat / Vulnerability | Defense Mechanism |
|---|---|
| **Man-in-the-Middle (MITM)** | TLS 1.3 RFC 8446 Exporter Channel Binding (`EXPORTER-olp-tunnel-v1`). Signatures are bound to the TLS session keys; attacker cannot relay handshakes. |
| **Passkey Theft on Proxy Compromise** | Salted BLAKE3 hashing. `olp-proxy` only stores `(salt, hash)`—the plaintext passkey is never stored on the public server. |
| **Timing Side-Channel Attacks** | Constant-time passkey verification via `subtle::ConstantTimeEq`. |
| **Brute-Force Password Guessing** | Edge IP rate limiter blocks IPs after 5 failed attempts per minute with `429 Too Many Requests`. |
| **Silent NAT / Connection Drops** | Dual-layer detection: `yamux` ping/pong every 15s + OS `SO_KEEPALIVE` and Linux `TCP_USER_TIMEOUT` (20s). |
| **Port Scanner Floods on `:4443`** | Strict 10-second handshake timeout; unauthenticated sockets are dropped immediately. |
| **Port Conflicts & Hijacking** | Allowed port range enforcement (`10000-20000`), privileged port blocking (`< 1024`), and atomic session ownership checks. |
| **Local SSRF / Request Smuggling** | `CONNECT` method rejected (`405 Method Not Allowed`), URI normalized to path-and-query, external `Authorization` header stripped before reaching local Ollama, and `Host` header rewritten. |
| **Unbounded Memory Buffering** | Zero full-body buffering. Streams are forwarded chunk-by-chunk through 16 KB buffers with a 256 KB `yamux` backpressure window. |

---

## Security Protections Against Leaked Secrets & Checkins

To ensure that private keys, credentials, or runtime configurations can never be accidentally committed to source control:

1. **Bulletproof `.gitignore`**:
   - Automatically ignores `proxy.toml`, `server.toml`, `.env*`, `*.secret`, `*.passkey`.
   - Automatically ignores all key formats: `*id_ed25519*`, `*id_rsa*`, `authorized_keys`, `known_proxy*`, `*.pem`, `*.key`, `*.der`, `*.pfx`.
   - Ignores `.olp/` runtime data directories and `acme_cache/`.
   - Only documented template files under `examples/` (`*.toml.example`) are permitted in version control.

2. **Automated Git Pre-Commit Security Hook (`.githooks/pre-commit`)**:
   - Automatically installed via `./install-git-hooks.sh` or auto-configured on launch of `./start-proxy.sh` / `./start-server.sh`.
   - Scans all staged files before every commit:
     - Blocks forbidden sensitive filenames.
     - Scans staged diffs for private key headers (`BEGIN OPENSSH PRIVATE KEY`, `BEGIN PRIVATE KEY`).
     - Scans for hardcoded passkeys or secrets in non-example code.
     - Aborts the commit with an error code and diagnostics if any secret is detected.
   - Verified by an automated test suite ([`test_git_pre_commit_hook_blocks_sensitive_commits`](file:///home/royans/c/olp/tests/security_test.rs)).

---

## Running the Test Suite

The test suite includes comprehensive unit and end-to-end integration tests:
```bash
cargo test
```

### Included Tests:
- `test_fibonacci_sequence_and_cap`: Verifies progression from 1s to 300s cap.
- `test_fibonacci_jitter_range`: Verifies $\pm 10\%$ uniform jitter application.
- `test_passkey_verifier_constant_time`: Verifies BLAKE3 salted verification and mismatch rejection.
- `test_passkey_verifier_edge_cases`: Tests empty keys, Unicode, emojis, colons, and long keys.
- `test_verify_http_request_auth_schemes`: Tests Basic Auth (with and without username) and Bearer tokens.
- `test_filesystem_permissions_enforcement`: Tests automatic tightening of file permissions to `0600`.
- `test_tls_channel_binding_prevents_signature_replay`: Tests replay attack rejection across distinct TLS sessions and payload tampering.
- `test_port_range_and_forbidden_port_rejection`: Tests rejection of privileged ports (<1024) and out-of-range ports.
- `test_port_conflict_between_different_servers`: Tests rejection of port hijacking attempts between different server keys.
- `test_ip_rate_limiter_isolated`: Tests token bucket sliding-window rate limiting per IP.
- `test_end_to_end_tunnel_auth_streaming_and_hotswap`: Full end-to-end integration test covering real-time token streaming, hot-swap reconnection (`503` during drop $\to$ `200 OK` on rebind), CONNECT method rejection, and rate limiting.
- `test_mitm_and_unauthorized_key_rejection`: End-to-end rejection of untrusted proxies and unauthorized server keys.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
