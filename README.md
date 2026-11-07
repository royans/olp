# Ollama Proxy (`olp-proxy` & `olp-server`)

[![Tests](https://img.shields.io/badge/tests-56%20passing-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Memory Footprint](https://img.shields.io/badge/memory-%3C5MB%20RAM-success.svg)]()

A lightweight, failure-resilient reverse proxy and reverse-tunneling daemon in **Rust** designed to expose a private Ollama server (`olp-server` running behind NAT or restrictive firewalls) through a publicly accessible gateway (`olp-proxy`).

```
 +----------------------------------+                   +----------------------------------+
 |  PRIVATE NETWORK (Behind NAT)    |                   |  PUBLICLY ACCESSIBLE SERVER / VPS|
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

## Quick Start (2 Steps)

### Step 1: On the Publicly Accessible Server (`olp-proxy`)

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
- **Encrypted TLS 1.3 Reverse Tunnel**: All multiplexed tunnel traffic between olp-server and olp-proxy is encrypted in transit with forward secrecy over TLS 1.3 using Yamux.
- **Strict Multi-User Session Isolation & PII Safety**:
  - Independent Yamux substreams and ephemeral local TCP connections per request guarantee zero session bleed or data mixing between concurrent users.
  - Prompts pass through the gateway encrypted in transit and are never logged or stored on disk; for zero trust, you can run your own self-hosted `olp-proxy`.
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

## Configuration Reference

### `~/.olp/proxy.toml`
```toml
[proxy]
listen_addr = "0.0.0.0:4443"
allowed_ports = "10000-20000"
listener_grace_period_sec = 60
access_log = "~/.olp/access.log" # Apache-style access log (set to "off" to disable)

[auth]
# Multi-tenant API keys: accepts an array of strings or a comma-delimited string
# Each key has its individual config at ~/.olp/config/<olp_api_key>.toml
olp_api_keys = ["admin_key_abc123"]

[security]
# Read-only mode disallows sensitive mutating Ollama operations:
# (POST /api/pull, DELETE /api/delete, POST /api/create, POST /api/push, POST /api/copy, raw blobs)
# Safe inference and read operations are permitted (native /api/generate, /api/chat, /api/tags, /api/show,
# and OpenAI-compatible /v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models).
# Defaults to false (not enforced as RO by default). Set to true to enforce read-only from proxy.
read_only = false

# Policy Authority and Stricter-Setting-Wins Resolution:
# - "proxy" (default): olp-proxy policy applies by default.
#   * Both sides can set policy as long as they are aligned.
#   * A server can always restrict itself further (if proxy has read_only = false, server can set read_only = true; stricter wins).
#   * Only an attempt by a server to loosen a proxy's stricter policy (proxy RO=true, server RO=false) is rejected.
# - "server": olp-proxy delegates full policy control to individual connecting olp-servers.
policy_authority = "proxy"

allowed_server_cidrs = ["0.0.0.0/0", "::/0"]
allowed_user_cidrs = ["0.0.0.0/0", "::/0"]
max_auth_failures_per_min = 60
max_concurrent_streams = 128
max_request_body_size_mb = 32         # Cap incoming requests to 32MB (413 if exceeded)
max_active_requests_per_server = 4   # GPU VRAM throttle: max concurrent inference requests (429 if busy)
max_requests_per_min = 300           # Authenticated request rate limiter (429 if exceeded)
connection_timeout_sec = 120         # Slowloris connection timeout

[tls]
mode = "manual" # "manual" (default), "self-signed", or "off"
# cert_path = "~/.olp/tls/cert.pem"
# key_path = "~/.olp/tls/key.pem"
allow_broken_certs = false # default: false (refuses startup if certificates are missing or invalid)

[maintenance]
# Automatic git updates on daily restart / startup.
# Defaults to false (disabled). When false or omitted, olp-proxy does not automatically pull from git.
# If your version is out of sync with remote, it checks updates and displays a prominent warning banner
# with a 15-second delayed start so you are always notified of updates.
auto_git_pull = false
```

### `~/.olp/config/<olp_api_key>.toml` (Per-User Profile)
```toml
[user]
api_key = "TXEVKeIG11rFUhekNvK64qBn"
name = "admin"
max_servers = 10
disabled = false

[servers.srv_Bc9bOUPj]
port = 10000
reserved = false
# By default, passkey_user is stored in plaintext (protected by 0600 file permissions)
# so users and admins can easily view and modify passwords manually in any text editor.
passkey_user = "your-client-passkey"
# When hash_passkeys = true is enabled in proxy.toml, salted BLAKE3 one-way hashes are stored instead:
# passkey_user_hash = "$blake3$zl77O1CIXmtaaXJ9X200Blf6A258Fe467ZSYgyCPFyk=$6YWrxHckT0ezytY2DpD0Q+ETerdIWSbDx8PAgP055FE="
allowed_user_cidrs = ["0.0.0.0/0", "::/0"]
allowed_server_cidrs = ["0.0.0.0/0", "::/0"]
created_at = "07/Nov/2026:04:25:24 +0000"
```

### `~/.olp/server.toml`
```toml
[server]
proxy_addr = "proxy.example.com:4443"
ollama_addr = "127.0.0.1:11434"
olp_api_key = "your-user-api-key"
olp_server_id = "srv_my_ollama_box"
passkey_user = "your-client-passkey-for-this-server"
# remote_port = 10000 # optional recommended port; proxy allocates dynamically if omitted

# Read-Only Policy (optional):
# Stricter setting wins! A GPU server can always restrict itself to read-only mode (read_only = true)
# even if connected to a proxy with read_only = false. Mutating operations (pull/delete/create/push/copy/blobs)
# will be blocked both on the proxy's worker port and locally on the server.
# read_only = true

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
# Automatic git updates on daily restart / startup.
# Defaults to false (disabled). When false or omitted, olp-server does not automatically pull from git.
# If your version is out of sync with remote, it checks updates and displays a prominent warning banner
# with a 15-second delayed start so you are always notified of updates.
auto_git_pull = false
```

---

## Connecting from Cline / VS Code Extension

Cline connects cleanly through `olp-proxy`:

1. In Cline Settings, select **API Provider**: `Ollama`.
2. Check **Use custom base URL**:
   - When TLS is enabled on proxy (`tls.mode = "manual"` or `"self-signed"`):
     **`https://proxy.example.com:10000`** *(must use `https://`)*
   - When TLS is disabled (`tls.mode = "off"`):
     **`http://proxy.example.com:10000`**
3. Enter **Ollama API Key**: `<passkey_user>` (your server's `passkey_user`).
4. In **Model**, enter **any model name** (or `default`, `llama3.1`, etc.).
   - `olp-server` automatically routes to whatever model is loaded in Ollama (e.g. `hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M`).
5. Click **Done** and start chatting!

> **Plaintext HTTP on HTTPS Port Protection**: If a client accidentally sends an unencrypted `http://` request to an HTTPS-secured port, `olp-proxy` automatically intercepts the request and responds with a friendly JSON HTTP 400 error: `{"error":"The plain HTTP request was sent to HTTPS port. Please use https:// instead of http://"}`.

---

## Apache-Style Access Logging (`~/.olp/access.log`)

`olp-proxy` features built-in high-performance asynchronous HTTP access logging for auditability and abuse analysis.

### Log Format & Privacy Sanitization
Logs are strictly sanitized to prevent credential and prompt/response leakage:
- Passkeys and bearer tokens are **never logged** (only the authorization scheme is recorded: `auth=bearer`, `auth=basic`, `auth=api_key`, or `auth=-`).
- Request and response body text snippets are **never logged**, ensuring zero exposure of private prompt inputs, personal data, or AI-generated output.

```text
<Client_IP> - auth=<Scheme> [<Timestamp>] "<Method> <Path> <Proto>" <Status> <Resp_Bytes> <Duration_ms>ms model="<Model>" req_bytes=<Req_Size>
```

### Example Log Lines
```text
127.0.0.1 - auth=bearer [07/Nov/2026:04:43:23 +0000] "GET /api/tags HTTP/1.1" 200 20 4ms model="-" req_bytes=0
67.180.155.189 - auth=bearer [07/Nov/2026:04:45:10 +0000] "POST /api/chat HTTP/1.1" 200 3421 842ms model="qwen3.5" req_bytes=128
67.180.155.189 - auth=basic [07/Nov/2026:04:46:02 +0000] "POST /api/pull HTTP/1.1" 403 98 1ms model="-" req_bytes=34
```

Set `access_log = "off"` under `[proxy]` in `proxy.toml` if you wish to disable request logging.

---

## Querying the Proxied Ollama

### Using curl with Bearer Token (HTTPS or HTTP)
```bash
# Model name can be anything: olp-server automatically rewrites it to whatever is loaded!
curl -X POST https://proxy.example.com:10000/api/generate \
  -H "Authorization: Bearer <passkey_user>" \
  -d '{"model": "auto", "prompt": "Why is the sky blue?"}'

# Or using x-api-key header:
curl -X POST https://proxy.example.com:10000/api/generate \
  -H "x-api-key: <passkey_user>" \
  -d '{"model": "default", "prompt": "Hello!"}'
```

### Using curl with HTTP Basic Auth
```bash
curl -u "user:<passkey_user>" https://proxy.example.com:10000/api/tags
```

### Using Official Ollama CLI
```bash
export OLLAMA_HOST="https://user:<passkey_user>@proxy.example.com:10000"
ollama list
ollama run default
```

---

## Multi-User Concurrency & Privacy Guarantees

When multiple users query the same proxied Ollama instance:

* **Privacy in Transit & Zero Prompt Logging**: Prompts pass through the gateway encrypted in transit (TLS 1.3) and are never logged or stored on disk. The proxy only inspects HTTP headers in memory to verify authentication and route requests. For zero trust, you can easily run your own self-hosted `olp-proxy` on your own VPS.
* **No Cache Pollution or PII Leakage**: `olp` is strictly stateless. It does not cache prompts, conversation histories, or response bodies. Ollama's attention KV cache evaluates token prefixes strictly per sequence; attention tensors from one user are never injected into another user's generation.
* **Independent IP Rate Limiting**: Brute-force protection tracks failures per IP address. One user's authentication mistakes will never lock out another user.
* **Parallel Processing**: To allow Ollama to generate responses for multiple users concurrently (rather than queuing sequentially), set `OLLAMA_NUM_PARALLEL` on the Ollama host before starting Ollama:
  ```bash
  export OLLAMA_NUM_PARALLEL=2  # or 4, depending on GPU VRAM
  ```

---

## Security Architecture & Policy Enforcement

### 1. Read-Only Mode & Sensitive Operations Filter
When read-only mode is active, only safe inference and inspection endpoints are permitted:
- **Permitted Safe Operations**:
  - Native Ollama: `POST /api/generate`, `POST /api/chat`, `POST /api/embeddings`, `POST /api/embed`, `GET /api/tags`, `GET /api/version`, `GET /api/ps`, `POST /api/show`
  - OpenAI-Compatible: `POST /v1/chat/completions`, `POST /v1/completions`, `POST /v1/embeddings`, `GET /v1/models` (and `GET /v1/models/*`)
- **Blocked Sensitive Mutating Operations** (rejected with `403 Forbidden`):
  - Model pulling: `POST /api/pull`
  - Model deletion: `DELETE /api/delete`
  - Model creation / customization: `POST /api/create`
  - Model pushing: `POST /api/push`
  - Model copying: `POST /api/copy`
  - Raw blob uploads / inspections: `POST /api/blobs/*`, `HEAD /api/blobs/*`

### 2. Policy Alignment & Stricter-Setting-Wins Resolution
To protect both the public proxy and private GPU owners without split-brain security policies:
- **Default (Not Enforced as RO by Default)**: By default, `read_only = false` in `proxy.toml`.
- **Policy Alignment**: Both proxy and server are permitted to set policy as long as they are aligned (e.g., both set `read_only = true` or both set `read_only = false`).
- **GPU Owners Can Restrict Themselves (Stricter Setting Wins)**: A connecting `olp-server` is **always** allowed to restrict itself further. If `olp-proxy` has `read_only = false`, an `olp-server` setting `read_only = true` in `server.toml` is accepted immediately, and the proxy enforces `read_only = true` on that server's port. The GPU owner remains protected even when connecting to a public or hosted proxy.
- **Loosening Restrictions Prohibited**: A connecting `olp-server` cannot loosen the proxy's stricter policy. If `olp-proxy` is configured with `read_only = true` and a server attempts to connect with `read_only = false`, registration is rejected with `CRITICAL CONFIG CONFLICT`.
- **Server Delegation Authority**: If `policy_authority = "server"` is configured in `proxy.toml`, the proxy explicitly delegates policy to individual connecting servers.

### 3. Strict TLS & Broken Certificate Defense
- **TLS by Default**: Unencrypted plain HTTP public endpoints are disabled by default (`tls.mode = "manual"`).
- **Broken Certificates Rejected**: Startup aborts with `CRITICAL TLS ERROR` if certificates are missing, unreadable, or invalid.
- **Strict WebPKI CA Verification**: `olp-server` strictly verifies proxy certificates against Mozilla WebPKI CA roots by default, preventing active Man-in-the-Middle (MITM) attacks.
- **Insecure Bypass Flags (Optional, Not Recommended)**:
  - `--allow-broken-certs`: Permit self-signed or broken certificates on `olp-proxy`.
  - `--insecure-no-tls`: Run `olp-proxy` with plain HTTP.
  - `--insecure-skip-tls-verify`: Bypass CA verification on `olp-server`.

### 4. Log Privacy & Sanitization
Access logs strictly omit sensitive data:
- Passkeys, bearer tokens, and API keys are **never** logged (`auth=bearer`, `auth=basic`, `auth=api_key`, or `auth=-`).
- Request and response body text snippets are **never** logged, completely eliminating prompt, PII, and output leakage. Prompts pass through the gateway encrypted in transit and are never stored on disk.

### 5. Pre-Auth Body Defense & Memory Exhaustion Protection
- **Pre-Auth Validation**: Client IP CIDR, HTTP method (`CONNECT`), and passkey authentication headers are validated **before** any request body bytes are read into memory. Unauthenticated or malformed requests are rejected immediately with zero body buffering.
- **Request Body Limits (`max_request_body_size_mb`)**: Incoming request bodies are capped (default: 32 MB). Requests exceeding this limit receive `413 Payload Too Large` immediately.

### 6. Backend GPU Concurrency Throttling & Rate Limiting
- **Concurrency Throttling (`max_active_requests_per_server`)**: Caps concurrent inference requests per backend Ollama worker (default: 4) to protect GPU VRAM from saturation and out-of-memory crashes. Excess concurrent requests receive `429 Too Many Requests` with a `Retry-After: 5` header.
- **Authenticated Request Rate Limiting (`max_requests_per_min`)**: Limits inference requests from authorized clients (default: 300 req/min) to prevent accidental loops or resource hogging.
- **Connection Timeout (`connection_timeout_sec`)**: Idle and slowloris connections are closed after 120 seconds.

### 7. User Profile Storage & Optional Salted Passkey Hashing
- **Default User-Editable Storage**: In `~/.olp/config/<olp_api_key>.toml`, passkeys are stored as `passkey_user = "..."` with strict `0600` private file permissions. This allows users and administrators to easily inspect, hand-edit, and update client passkeys in any text editor. Changes take effect dynamically without restarting `olp-proxy`.
- **Opt-In Salted One-Way Hashing (`hash_passkeys = true`)**: For environments requiring zero-plaintext credential persistence, administrators can enable `hash_passkeys = true` in `proxy.toml` under `[security]` (or pass `--hash-passkeys` CLI flag). When enabled, passkeys are saved exclusively as salted BLAKE3 one-way hashes (`passkey_user_hash = "$blake3$<salt>$<hash>"`).

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

Automated git updates are disabled by default (`auto_git_pull = false`). When false or omitted, the daily restart does not pull code. To enable automated updates, set `auto_git_pull = true` under `[maintenance]` in `~/.olp/proxy.toml` / `~/.olp/server.toml`. Running `./start-proxy.sh update` explicitly always pulls.

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
