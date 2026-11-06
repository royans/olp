# Ollama Proxy (`olp-proxy` & `olp-server`)

[![Tests](https://img.shields.io/badge/tests-20%20passing-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Memory Footprint](https://img.shields.io/badge/memory-%3C5MB%20RAM-success.svg)]()

A lightweight, failure-resilient reverse proxy and reverse-tunneling daemon in **Rust** designed to expose a private Ollama server (`olp-server` running behind NAT or restrictive firewalls) through a public gateway (`olp-proxy`).

```
 +----------------------------------+                   +----------------------------------+
 |  PRIVATE NETWORK (Behind NAT)    |                   |  PUBLIC CLOUD SERVER / VPS       |
 |  [ollama-gpu-host]               |                   |  [olp-proxy]                     |
 |  [olp-server] -------------------+------------------>|    Control Port: :4443           |
 |    (Reverse TLS 1.3 Tunnel)      | (passkey_proxy)   |    Public Port:  :11434          |
 +----------------------------------+                   +------------------+---------------+
                                                                           |
                                                      (passkey_user)       | Basic / Bearer Auth
                                                                           v
                                                                +--------------------+
                                                                | Users & Ollama App |
                                                                +--------------------+
```

---

## Simple Passkey & Security Model

`olp` uses a streamlined, two-passkey architecture with granular CIDR IP filtering:

1. **`passkey_proxy`**:
   - Shared between `olp-proxy` and `olp-server`.
   - Authorizes `olp-server` to connect to `olp-proxy:4443` and register a reverse tunnel.
   - Defined in `proxy.toml` and specified in `server.toml`.
2. **`passkey_user`**:
   - Shared between `olp-proxy` and end users querying Ollama.
   - Used for **HTTP Basic Auth** (`username:passkey_user`) or **Bearer Token** (`Authorization: Bearer <passkey_user>`).
   - Handled directly by `olp-proxy`.
3. **CIDR IP Filtering**:
   - **`allowed_server_cidrs`**: Restricts which IP addresses / subnets can connect to the tunnel control port (`:4443`).
   - **`allowed_user_cidrs`**: Restricts which IP addresses / subnets can query the public Ollama HTTP port (`:11434`).
   - Defaults to `["0.0.0.0/0", "::/0"]` (allow all), or configure specific subnets (e.g. `["67.180.155.0/24"]`).

---

## Key Features

- **Zero Inbound Port Forwarding on NAT**: `olp-server` initiates an *outbound* connection to `olp-proxy` over a single TLS 1.3 port (`:4443`).
- **Encrypted TLS 1.3 Reverse Tunnel**: All multiplexed traffic is end-to-end encrypted with forward secrecy over TLS 1.3 using Yamux.
- **Constant-Time Verification**: Plaintext passkeys are never verified with naive string equality; verification uses constant-time comparisons (`subtle::ConstantTimeEq`) and salted BLAKE3 hashing.
- **CIDR Block IP Filtering**: IPv4 and IPv6 subnet filtering on both tunnel and user HTTP connections.
- **Dual User Authentication**: Supports both HTTP Basic Auth and Bearer Tokens, compatible with the official Ollama CLI, Open WebUI, LibreChat, and IDE extensions (Continue, Cursor, Cline).
- **Fibonacci Reconnect Backoff**: Smart reconnect sequence (`1s, 1s, 2s, 3s, 5s, 8s, 13s, 21s...` capped at 300s) with $\pm 10\%$ jitter.
- **Zero-Buffering Chunked Streaming**: Full support for real-time Server-Sent Events (SSE) and token streaming (`/api/generate`, `/api/chat`).
- **Edge IP Brute-Force Rate Limiting**: Automatic sliding-window rate limiter returns `429 Too Many Requests` on repeated failed authentications.
- **Single-Directory Isolation**: Configuration files live exclusively in `~/.olp/` with strict `0600`/`0700` permissions.

---

## Quick Start (2 Steps)

### Step 1: On the Public Server (`olp-proxy`)

Clone and launch `olp-proxy`:
```bash
git clone https://github.com/royans/olp.git
cd olp
./start-proxy.sh
```

On first run, `olp-proxy` auto-generates two strong passkeys and displays:
```text
================================================================================
  [olp-proxy] Configuration saved to ~/.olp/proxy.toml
  ----------------------------------------------------------------------------
  passkey_proxy : <random-passkey-proxy>
  passkey_user  : <random-passkey-user>
  ----------------------------------------------------------------------------
  * passkey_proxy: Put this in your olp-server's server.toml
  * passkey_user : Use this as the password for HTTP Basic Auth / Bearer token
================================================================================
```

> **Lifecycle Commands**:
> - `./start-proxy.sh restart` — Gracefully restarts and pulls latest updates.
> - `./start-proxy.sh stop` — Stops the proxy cleanly (`SIGTERM`).
> - `./start-proxy.sh status` — Shows process status.

---

### Step 2: On the Private Ollama Machine (`olp-server`)

On your GPU machine or Mac running Ollama (`127.0.0.1:11434`):
```bash
git clone https://github.com/royans/olp.git
cd olp
./start-server.sh
```

When prompted:
1. Enter your proxy host (e.g. `ssh3.blogofy.com:4443`).
2. Paste `passkey_proxy` from Step 1.

The tunnel connects immediately:
```text
Tunnel established! Exposing local Ollama (127.0.0.1:11434) on remote port :11434
```

---

## Configuration Reference

### `~/.olp/proxy.toml`
```toml
[proxy]
listen_addr = "0.0.0.0:4443"
allowed_ports = "10000-20000"
listener_grace_period_sec = 60

[auth]
# Passkey required by olp-server to register a reverse tunnel
passkey_proxy = "your-secret-proxy-passkey"

# Passkey required by end users for HTTP Basic Auth / Bearer token
passkey_user = "your-secret-user-passkey"

[security]
# Allowed CIDR blocks for olp-server tunnel connections
allowed_server_cidrs = ["0.0.0.0/0", "::/0"]

# Allowed CIDR blocks for user HTTP connections to Ollama
allowed_user_cidrs = ["0.0.0.0/0", "::/0"]

max_auth_failures_per_min = 60
max_concurrent_streams = 128

[tls]
mode = "off" # "off", "self-signed", or "manual"
```

### `~/.olp/server.toml`
```toml
[server]
proxy_addr = "ssh3.blogofy.com:4443"
ollama_addr = "127.0.0.1:11434"
remote_port = 11434
passkey_proxy = "your-secret-proxy-passkey"

[reconnect]
strategy = "fibonacci"
initial_delay_sec = 1
max_delay_sec = 300
heartbeat_interval_sec = 15
heartbeat_timeout_sec = 5
```

---

## Querying the Proxied Ollama

### Using curl with Bearer Token
```bash
curl -X POST http://ssh3.blogofy.com:11434/api/generate \
  -H "Authorization: Bearer <passkey_user>" \
  -d '{"model": "llama3", "prompt": "Why is the sky blue?"}'
```

### Using curl with HTTP Basic Auth
```bash
curl -u "user:<passkey_user>" http://ssh3.blogofy.com:11434/api/tags
```

### Using Official Ollama CLI
```bash
export OLLAMA_HOST="http://user:<passkey_user>@ssh3.blogofy.com:11434"
ollama list
ollama run llama3
```

---

## Running in Background via Systemd

Systemd unit files are provided in `examples/`:

```bash
# On the proxy host:
sudo cp examples/olp-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now olp-proxy

# On the Ollama server host:
sudo cp examples/olp-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now olp-server
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
