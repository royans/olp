# Ollama Proxy (`olp-proxy` & `olp-server`)

[![Tests](https://img.shields.io/badge/tests-21%20passing-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Memory Footprint](https://img.shields.io/badge/memory-%3C5MB%20RAM-success.svg)]()

A lightweight, failure-resilient reverse proxy and reverse-tunneling daemon in **Rust** designed to expose a private Ollama server (`olp-server` running behind NAT or restrictive firewalls) through a public gateway (`olp-proxy`).

```
 +----------------------------------+                   +----------------------------------+
 |  PRIVATE NETWORK (Behind NAT)    |                   |  PUBLIC CLOUD SERVER / VPS       |
 |  [ollama-gpu-host]               |                   |  [olp-proxy]                     |
 |  [olp-server] -------------------+------------------>|    Control Port: :4443           |
 |    (Reverse TLS 1.3 Tunnel)      | (olp_api_key)     |    Public Port:  :11434          |
 +----------------------------------+                   +------------------+---------------+
                                                                           |
                                                      (passkey_user)       | Basic / Bearer / API Key
                                                                           v
                                                                +--------------------+
                                                                | Users & Ollama App |
                                                                | (Cline, WebUI, CLI)|
                                                                +--------------------+
```

---

## Multi-User & Multi-Server Architecture

`olp` is designed for multi-tenancy where a single `olp-proxy` serves multiple users, and each user can host multiple `olp-server` instances:

1. **`olp_api_key`**:
   - Alphanumeric user API key authorizing `olp-server` instances to register reverse tunnels.
   - Listed in `proxy.toml` (`olp_api_keys = ["ABcd123"]`) or discovered via `~/.olp/config/<olp_api_key>.toml`.
   - Server authenticates using a cryptographically bound BLAKE3 token over TLS 1.3 with session nonces.
2. **`olp_server_id` & Dynamic Port Allocation**:
   - Each `olp-server` generates or defines an alphanumeric server ID (e.g. `srv_8aBcD123`).
   - The server may optionally recommend a public port; the proxy safely checks availability and assigns an unused port from `allowed_ports`.
   - The proxy atomically saves the allocated port into `~/.olp/config/<olp_api_key>.toml` and returns the assigned port in the handshake.
3. **`passkey_user` (Per-Server)**:
   - Defined individually per server.
   - Accepted via **Bearer Token** (`Authorization: Bearer <passkey_user>`), **HTTP Basic Auth** (`username:passkey_user`), or **API Key headers** (`x-api-key`, `api-key`, `ollama-api-key`).
   - Verified directly by `olp-proxy` on that server's assigned public port in constant time.
4. **CIDR IP Filtering**:
   - **`allowed_server_cidrs`**: Restricts which IP addresses / subnets can connect to the tunnel control port (`:4443`) or specific server tunnels.
   - **`allowed_user_cidrs`**: Restricts which IP addresses / subnets can query the public Ollama HTTP ports.
   - Defaults to `["0.0.0.0/0", "::/0"]` (allow all), or configure specific subnets.

---

## Key Features

- **Automatic Model Dynamic Mapping ("Serve Whatever is Loaded")**:
  - `olp-server` automatically detects whichever model is actively running in Ollama's memory (`/api/ps`) or installed on disk (`/api/tags`).
  - **The model name requested by the client does not matter.** Whether Cline, Open WebUI, or curl requests `llama3.1`, `auto`, `default`, or anything else, `olp-server` transparently rewrites the request to whatever model is loaded (e.g., `hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M`).
  - Automatically rewrites model parameters in `/api/show` so agent context windows, capabilities, and templates work out of the box without manual configuration.
- **Zero Inbound Port Forwarding on NAT**: `olp-server` initiates an *outbound* connection to `olp-proxy` over a single TLS 1.3 port (`:4443`).
- **Encrypted TLS 1.3 Reverse Tunnel**: All multiplexed traffic is end-to-end encrypted with forward secrecy over TLS 1.3 using Yamux.
- **Strict Multi-User Session Isolation & PII Safety**:
  - Independent Yamux substreams and ephemeral local TCP connections per request guarantee zero session bleed or data mixing between concurrent users.
  - Completely stateless architecture: no prompt logging, disk caching, or cross-request memory.
  - Compatible with Ollama's isolated parallel slots (`OLLAMA_NUM_PARALLEL`).
- **Built-in CORS & Webview Compatibility**: Full CORS preflight (`OPTIONS`) handling without authentication, enabling seamless integration with VS Code extensions (Cline, Roo Code) and browser web interfaces (Open WebUI).
- **Flexible Client Authentication**: Supports Bearer tokens, HTTP Basic Auth, and custom `x-api-key` / `ollama-api-key` headers.
- **Constant-Time Verification**: Plaintext passkeys are never verified with naive string equality; verification uses constant-time comparisons (`subtle::ConstantTimeEq`) and salted BLAKE3 hashing.
- **CIDR Block IP Filtering**: IPv4 and IPv6 subnet filtering on both tunnel and user HTTP connections.
- **Fibonacci Reconnect Backoff**: Smart reconnect sequence (`1s, 1s, 2s, 3s, 5s, 8s, 13s, 21s...` capped at 300s) with $\pm 10\%$ jitter.
- **Zero-Buffering Chunked Streaming**: Full support for real-time Server-Sent Events (SSE) and token streaming (`/api/generate`, `/api/chat`).
- **Cron & Daemon Friendly**: Built-in PID tracking and auto-cleanup terminates previous instances cleanly upon re-execution; supports `--daemon` / `-d` for background crontab jobs, plus a 15-minute watchdog and a randomized daily restart with optional `git pull`.
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

On first run, `olp-proxy` auto-generates your initial user API key and profile:
```text
================================================================================
  [olp-proxy] Configuration saved to ~/.olp/proxy.toml
  ----------------------------------------------------------------------------
  olp_api_key  : <random-user-api-key>
  user profile : ~/.olp/config/<random-user-api-key>.toml
  ----------------------------------------------------------------------------
  * olp_api_key : Put this in your olp-server's server.toml
  * You can create additional user keys at ~/.olp/config/<new_key>.toml
================================================================================
```

> **Lifecycle & Cron Commands**:
> - `./start-proxy.sh restart` — Gracefully restarts and pulls latest updates from git.
> - `./start-proxy.sh install-cron` — Installs automated 24h git auto-update + 15-min watchdog into crontab.
> - `./start-proxy.sh uninstall-cron` — Removes managed cronjobs from crontab.
> - `./start-proxy.sh stop` — Stops the proxy cleanly (`SIGTERM`).
> - `./start-proxy.sh status` — Shows process status.

#### Automated / Headless Setup for `olp-proxy`:
Brand new instances can be completely scripted via CLI without interactive prompts:
```bash
./start-proxy.sh --daemon \
  --listen-addr 0.0.0.0:4443 \
  --allowed-ports 10000-20000 \
  --olp-api-key "my-user-api-key" \
  --non-interactive
```

---

### Step 2: On the Private Ollama Machine (`olp-server`)

On your GPU machine or Mac running Ollama (`127.0.0.1:11434`):
```bash
git clone https://github.com/royans/olp.git
cd olp
./start-server.sh
```

When prompted:
1. Enter your proxy host (e.g. `proxy.example.com:4443`).
2. Enter your `olp_api_key` from Step 1.
3. Keep or customize your server's `passkey_user` for client HTTP queries.

The tunnel connects immediately and receives an assigned port:
```text
TLS 1.3 tunnel established! Exposing local Ollama (127.0.0.1:11434) on remote port :11434 (server_id: srv_aBcd1234)
```

> **Lifecycle & Cron Commands**:
> - `./start-server.sh restart` — Gracefully restarts and pulls latest updates from git.
> - `./start-server.sh install-cron` — Installs automated 24h git auto-update + 15-min watchdog into crontab.
> - `./start-server.sh uninstall-cron` — Removes managed cronjobs from crontab.
> - `./start-server.sh stop` — Stops the server cleanly (`SIGTERM`).
> - `./start-server.sh status` — Shows process status.

#### Automated / Headless Setup for `olp-server`:
Brand new instances can be completely scripted via CLI without interactive prompts:
```bash
./start-server.sh --daemon \
  --proxy-addr proxy.example.com:4443 \
  --olp-api-key "my-user-api-key" \
  --passkey-user "my-client-passkey" \
  --remote-port 10000 \
  --non-interactive
```

---

## Configuration Reference

### `~/.olp/proxy.toml`
```toml
[proxy]
listen_addr = "0.0.0.0:4443"
allowed_ports = "10000-20000"
listener_grace_period_sec = 60
access_log = "~/.olp/access.log" # Apache-style access log (set to "off" to disable)

[auth]
# User API keys: accepts an array of strings or a comma-delimited string
# Each key has its individual config at ~/.olp/config/<olp_api_key>.toml
olp_api_keys = ["admin_key_abc123"]

[security]
allowed_server_cidrs = ["0.0.0.0/0", "::/0"]
allowed_user_cidrs = ["0.0.0.0/0", "::/0"]
max_auth_failures_per_min = 60
max_concurrent_streams = 128

[tls]
mode = "off" # Set to "manual" when using Let's Encrypt / custom certs
# cert_path = "~/.olp/tls/fullchain.pem"
# key_path = "~/.olp/tls/privkey.pem"
```

### `~/.olp/server.toml`
```toml
[server]
proxy_addr = "proxy.example.com:4443"
ollama_addr = "127.0.0.1:11434"
olp_api_key = "your-user-api-key"
olp_server_id = "srv_my_ollama_box"
passkey_user = "your-client-passkey-for-this-server"
# remote_port = 11434 # optional recommended port; proxy allocates dynamically if omitted

# TLS CA Certificate Verification (optional, auto-detected)
# Defaults to true for public domain names, false for localhost / 127.0.0.1.
# Enforces Mozilla WebPKI root verification (e.g. Let's Encrypt) to protect against MITM.
# tls_verify = true

[reconnect]
strategy = "fibonacci"
initial_delay_sec = 1
max_delay_sec = 300
heartbeat_interval_sec = 15
heartbeat_timeout_sec = 5

[maintenance]
# Daily scheduled restart runs `git pull --ff-only` (+ rebuild) when installed from a git checkout.
# Set to false (or "no") to pin the current version. Applies to proxy.toml as well.
auto_git_pull = true
```

---

## Connecting from Cline / VS Code Extension

Cline connects cleanly through `olp-proxy`:

1. In Cline Settings, select **API Provider**: `Ollama`.
2. Check **Use custom base URL**:
   - `http://proxy.example.com:11434`
3. Enter **Ollama API Key**: `<passkey_user>` (your `passkey_user` from `proxy.toml`).
4. In **Model**, enter **any model name** (or `default`, `llama3.1`, etc.).
   - `olp-server` automatically routes to whatever model is loaded in Ollama (e.g. `hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M`).
5. Click **Done** and start chatting!

---

## Querying the Proxied Ollama

### Using curl with Bearer Token (or custom API Key)
```bash
# Model name can be anything: olp-server automatically rewrites it to whatever is loaded!
curl -X POST http://proxy.example.com:11434/api/generate \
  -H "Authorization: Bearer <passkey_user>" \
  -d '{"model": "auto", "prompt": "Why is the sky blue?"}'

# Or using x-api-key header:
curl -X POST http://proxy.example.com:11434/api/generate \
  -H "x-api-key: <passkey_user>" \
  -d '{"model": "default", "prompt": "Hello!"}'
```

### Using curl with HTTP Basic Auth
```bash
curl -u "user:<passkey_user>" http://proxy.example.com:11434/api/tags
```

### Using Official Ollama CLI
```bash
export OLLAMA_HOST="http://user:<passkey_user>@proxy.example.com:11434"
ollama list
ollama run default
```

---

## Multi-User Concurrency & Privacy Guarantees

When multiple users query the same proxied Ollama instance:

* **No Shared Sessions or Cross-Talk**: Each client request travels across an isolated Yamux substream with its own unique channel ID and triggers a distinct ephemeral TCP connection to local Ollama.
* **No Cache Pollution or PII Leakage**: `olp` is strictly stateless. It does not cache prompts, conversation histories, or response bodies. Ollama's attention KV cache evaluates token prefixes strictly per sequence; attention tensors from one user are never injected into another user's generation.
* **Independent IP Rate Limiting**: Brute-force protection tracks failures per IP address. One user's authentication mistakes will never lock out another user.
* **Parallel Processing**: To allow Ollama to generate responses for multiple users concurrently (rather than queuing sequentially), set `OLLAMA_NUM_PARALLEL` on the Ollama host before starting Ollama:
  ```bash
  export OLLAMA_NUM_PARALLEL=2  # or 4, depending on GPU VRAM
  ```

---

## Running in Background via Cron or Systemd

### Running via Cron (`--daemon` mode)

`start-proxy.sh` and `start-server.sh` include built-in PID tracking. If re-executed, they safely terminate the previous instance and start fresh. On the first interactive run they offer to install three cronjobs (and they automatically upgrade a previously installed `@reboot`-only entry):

```cron
# Start on boot
@reboot cd "/path/to/olp" && ./start-proxy.sh --daemon >> "~/.olp/proxy.log" 2>&1 # olp-proxy-managed:/path/to/olp

# Watchdog every 15 minutes: start it only if it is not running (no git pull)
7,22,37,52 * * * * cd "/path/to/olp" && ./start-proxy.sh ensure >> "~/.olp/proxy.log" 2>&1 # olp-proxy-managed:/path/to/olp

# Daily full restart (git pull + rebuild if auto_git_pull = true)
41 3 * * * cd "/path/to/olp" && ./start-proxy.sh restart --daemon >> "~/.olp/proxy.log" 2>&1 # olp-proxy-managed:/path/to/olp
```

The same set is installed for `start-server.sh`. The watchdog minute offset and the daily restart time (between 01:00 and 05:59 local time) are randomized per host at install time, so a fleet doesn't restart or pull all at once. The chosen times are kept on later runs. A lock file (`~/.olp/olp-<proxy|server>.lock`, requires `flock`) stops the watchdog from starting a second copy while a restart is pulling or compiling.

To stop the daily restart from pulling new code, set `auto_git_pull = false` under `[maintenance]` in `~/.olp/proxy.toml` / `~/.olp/server.toml`. Running `./start-proxy.sh update` explicitly always pulls.

Logs are written automatically to `~/.olp/proxy.log` and `~/.olp/server.log`.

### Running via Systemd

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
