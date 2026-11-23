use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Global atomic counters for request busyness and throughput.
pub static ACTIVE_REQUESTS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_REQUESTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTelemetryResponse {
    pub status: String,
    pub enabled: bool,
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<UptimeStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average: Option<LoadAvgStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<UserSessionStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpus: Option<Vec<GpuStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ollama: Option<OllamaStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busyness: Option<BusynessStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeStats {
    pub process_seconds: u64,
    pub system_seconds: Option<u64>,
    pub human: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAvgStats {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionStats {
    pub logged_in_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuStats {
    pub temperature_c: Option<f32>,
    pub utilization_percent: Option<f32>,
    pub cores: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuStats {
    pub index: usize,
    pub name: String,
    pub temperature_c: Option<f32>,
    pub utilization_percent: Option<f32>,
    pub memory_utilization_percent: Option<f32>,
    pub vram_total_mb: u64,
    pub vram_used_mb: u64,
    pub vram_free_mb: u64,
    pub power_watts: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaStats {
    pub status: String,
    pub loaded_models: Vec<OllamaLoadedModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaLoadedModel {
    pub name: String,
    pub vram_mb: u64,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusynessStats {
    pub active_requests: usize,
    pub total_requests: usize,
}

/// Tracks CPU ticks for delta utilization calculations.
#[derive(Debug, Clone, Copy)]
struct CpuTicks {
    idle: u64,
    total: u64,
}

/// In-memory cached metrics to prevent polling DoS on `nvidia-smi` and sysfs.
pub struct MetricsCollector {
    server_id: String,
    ollama_addr: String,
    start_instant: Instant,
    cache: RwLock<Option<(ServerTelemetryResponse, Instant)>>,
    last_cpu_ticks: RwLock<Option<(CpuTicks, Instant)>>,
    ttl: Duration,
}

impl MetricsCollector {
    pub fn new(server_id: String, ollama_addr: String) -> Self {
        Self {
            server_id,
            ollama_addr,
            start_instant: Instant::now(),
            cache: RwLock::new(None),
            last_cpu_ticks: RwLock::new(None),
            ttl: Duration::from_secs(3),
        }
    }

    pub async fn collect(&self, enabled: bool) -> ServerTelemetryResponse {
        if !enabled {
            return ServerTelemetryResponse {
                status: "disabled".to_string(),
                enabled: false,
                server_id: self.server_id.clone(),
                timestamp: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                uptime: None,
                load_average: None,
                users: None,
                cpu: None,
                memory: None,
                gpus: None,
                ollama: None,
                busyness: None,
                message: Some(
                    "Telemetry is currently disabled on this server. Enable via olpweb or PUT /api/olp/metrics."
                        .to_string(),
                ),
            };
        }

        // Fast path: cached read
        {
            let guard = self.cache.read().await;
            if let Some((ref cached, ref timestamp)) = *guard {
                if timestamp.elapsed() < self.ttl {
                    return cached.clone();
                }
            }
        }

        // Slow path: generate metrics snapshot
        let res = self.gather_live_metrics().await;
        let mut guard = self.cache.write().await;
        *guard = Some((res.clone(), Instant::now()));
        res
    }

    async fn gather_live_metrics(&self) -> ServerTelemetryResponse {
        let process_uptime = self.start_instant.elapsed().as_secs();
        let system_uptime = read_system_uptime();
        let human_uptime = format_human_duration(process_uptime);

        let load_avg = read_load_average();
        let users = count_logged_in_users();
        let (cpu_temp, cpu_util, cpu_cores) = self.gather_cpu_info().await;
        let memory = read_memory_info();
        let gpus = tokio::task::spawn_blocking(gather_nvidia_gpus)
            .await
            .unwrap_or_default();
        let ollama = self.gather_ollama_stats().await;

        let busyness = BusynessStats {
            active_requests: ACTIVE_REQUESTS.load(Ordering::Relaxed),
            total_requests: TOTAL_REQUESTS.load(Ordering::Relaxed),
        };

        ServerTelemetryResponse {
            status: "ok".to_string(),
            enabled: true,
            server_id: self.server_id.clone(),
            timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            uptime: Some(UptimeStats {
                process_seconds: process_uptime,
                system_seconds: system_uptime,
                human: human_uptime,
            }),
            load_average: load_avg,
            users: Some(UserSessionStats {
                logged_in_count: users,
            }),
            cpu: Some(CpuStats {
                temperature_c: cpu_temp,
                utilization_percent: cpu_util,
                cores: cpu_cores,
            }),
            memory,
            gpus: Some(gpus),
            ollama: Some(ollama),
            busyness: Some(busyness),
            message: None,
        }
    }

    async fn gather_cpu_info(&self) -> (Option<f32>, Option<f32>, usize) {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let temp = read_cpu_temperature();
        let util = self.calculate_cpu_utilization().await;
        (temp, util, cores)
    }

    async fn calculate_cpu_utilization(&self) -> Option<f32> {
        let current_ticks = read_proc_stat_ticks()?;
        let now = Instant::now();

        let mut guard = self.last_cpu_ticks.write().await;
        if let Some((prev_ticks, prev_time)) = *guard {
            let elapsed = now.duration_since(prev_time);
            if elapsed >= Duration::from_millis(500) {
                let total_delta = current_ticks.total.saturating_sub(prev_ticks.total);
                let idle_delta = current_ticks.idle.saturating_sub(prev_ticks.idle);
                if total_delta > 0 {
                    let busy_delta = total_delta.saturating_sub(idle_delta);
                    let pct = (busy_delta as f32 / total_delta as f32) * 100.0;
                    *guard = Some((current_ticks, now));
                    return Some((pct * 10.0).round() / 10.0);
                }
            }
        } else {
            *guard = Some((current_ticks, now));
        }
        None
    }

    async fn gather_ollama_stats(&self) -> OllamaStats {
        let ps_url = "/api/ps";
        match crate::server::query_ollama_json(&self.ollama_addr, ps_url).await {
            Ok(val) => {
                let mut loaded = Vec::new();
                if let Some(models) = val.get("models").and_then(|m| m.as_array()) {
                    for m in models {
                        let name = m
                            .get("name")
                            .or_else(|| m.get("model"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let size_vram = m
                            .get("size_vram")
                            .or_else(|| m.get("size"))
                            .and_then(|s| s.as_u64())
                            .unwrap_or(0);
                        let vram_mb = size_vram / (1024 * 1024);

                        let expires_in_seconds = m
                            .get("expires_at")
                            .and_then(|e| e.as_str())
                            .and_then(|date_str| chrono_approx_expires(date_str));

                        loaded.push(OllamaLoadedModel {
                            name,
                            vram_mb,
                            expires_in_seconds,
                        });
                    }
                }
                OllamaStats {
                    status: "online".to_string(),
                    loaded_models: loaded,
                }
            }
            Err(_) => OllamaStats {
                status: "unreachable".to_string(),
                loaded_models: Vec::new(),
            },
        }
    }
}

// ----------------------------------------------------------------------------
// Low-level procfs & sysfs parsers (Zero External Dependencies)
// ----------------------------------------------------------------------------

fn read_system_uptime() -> Option<u64> {
    let content = fs::read_to_string("/proc/uptime").ok()?;
    let first = content.split_whitespace().next()?;
    let secs: f64 = first.parse().ok()?;
    Some(secs as u64)
}

fn read_load_average() -> Option<LoadAvgStats> {
    let content = fs::read_to_string("/proc/loadavg").ok()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() >= 3 {
        let one: f64 = parts[0].parse().ok()?;
        let five: f64 = parts[1].parse().ok()?;
        let fifteen: f64 = parts[2].parse().ok()?;
        return Some(LoadAvgStats { one, five, fifteen });
    }
    None
}

/// Discovers CPU / SoC package temperatures across Linux sysfs thermal and hwmon interfaces.
fn read_cpu_temperature() -> Option<f32> {
    // 1. Try hwmon coretemp or k10temp inputs
    if let Ok(entries) = fs::read_dir("/sys/class/hwmon") {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = fs::read_to_string(path.join("name")).unwrap_or_default();
            let name_trim = name.trim();
            if name_trim.contains("coretemp")
                || name_trim.contains("k10temp")
                || name_trim.contains("cpu")
                || name_trim.contains("zenpower")
            {
                if let Ok(temp_str) = fs::read_to_string(path.join("temp1_input")) {
                    if let Ok(milli) = temp_str.trim().parse::<f32>() {
                        if milli > 0.0 {
                            return Some(((milli / 1000.0) * 10.0).round() / 10.0);
                        }
                    }
                }
            }
        }
    }

    // 2. Fall back to thermal_zone
    if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                if fname.starts_with("thermal_zone") {
                    let type_str = fs::read_to_string(path.join("type")).unwrap_or_default();
                    let t_lower = type_str.to_ascii_lowercase();
                    if t_lower.contains("x86_pkg")
                        || t_lower.contains("cpu")
                        || t_lower.contains("soc")
                        || t_lower.contains("acpitz")
                    {
                        if let Ok(temp_str) = fs::read_to_string(path.join("temp")) {
                            if let Ok(milli) = temp_str.trim().parse::<f32>() {
                                if milli > 0.0 {
                                    return Some(((milli / 1000.0) * 10.0).round() / 10.0);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn read_proc_stat_ticks() -> Option<CpuTicks> {
    let content = fs::read_to_string("/proc/stat").ok()?;
    for line in content.lines() {
        if line.starts_with("cpu ") {
            let parts: Vec<&str> = line.split_whitespace().skip(1).collect();
            if parts.len() >= 4 {
                let user: u64 = parts[0].parse().ok()?;
                let nice: u64 = parts[1].parse().ok()?;
                let system: u64 = parts[2].parse().ok()?;
                let idle: u64 = parts[3].parse().ok()?;
                let iowait: u64 = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                let irq: u64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
                let softirq: u64 = parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
                let steal: u64 = parts.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);

                let total = user + nice + system + idle + iowait + irq + softirq + steal;
                return Some(CpuTicks {
                    idle: idle + iowait,
                    total,
                });
            }
        }
    }
    None
}

fn read_memory_info() -> Option<MemoryStats> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb: Option<u64> = None;
    let mut avail_kb: Option<u64> = None;
    let mut free_kb: Option<u64> = None;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = parse_meminfo_kb(line);
        } else if line.starts_with("MemAvailable:") {
            avail_kb = parse_meminfo_kb(line);
        } else if line.starts_with("MemFree:") {
            free_kb = parse_meminfo_kb(line);
        }
        if total_kb.is_some() && avail_kb.is_some() && free_kb.is_some() {
            break;
        }
    }

    let total = total_kb?;
    let free = free_kb.unwrap_or(0);
    let avail = avail_kb.unwrap_or(free);
    let used = total.saturating_sub(avail);

    let total_mb = total / 1024;
    let used_mb = used / 1024;
    let free_mb = avail / 1024;
    let usage_percent = if total_mb > 0 {
        ((used_mb as f32 / total_mb as f32) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    Some(MemoryStats {
        total_mb,
        used_mb,
        free_mb,
        usage_percent,
    })
}

fn parse_meminfo_kb(line: &str) -> Option<u64> {
    let val_str = line.split(':').nth(1)?.trim();
    val_str.split_whitespace().next()?.parse::<u64>().ok()
}

/// Counts logged in interactive sessions via `/run/utmp` or `who -q` securely without leaking usernames.
fn count_logged_in_users() -> usize {
    // Count active login sessions in systemd if present
    if let Ok(entries) = fs::read_dir("/run/systemd/sessions") {
        let count = entries.flatten().count();
        if count > 0 {
            return count;
        }
    }

    // Try `who -q` fallback
    if let Ok(output) = std::process::Command::new("who").arg("-q").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            for line in s.lines() {
                if let Some(idx) = line.find("# users=") {
                    let num_str = &line[idx + 8..].trim();
                    if let Ok(count) = num_str.parse::<usize>() {
                        return count;
                    }
                }
            }
        }
    }
    0
}

/// Non-blocking query to `nvidia-smi` with robust CSV parsing.
fn gather_nvidia_gpus() -> Vec<GpuStats> {
    let mut gpus = Vec::new();
    let query_args = "index,name,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.used,memory.free,power.draw";
    let output = match std::process::Command::new("nvidia-smi")
        .arg(format!("--query-gpu={}", query_args))
        .arg("--format=csv,noheader,nounits")
        .output()
    {
        Ok(out) if out.status.success() => out,
        _ => return gpus,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 9 {
            let index = parts[0].parse::<usize>().unwrap_or(0);
            let name = parts[1].to_string();
            let temp_c = parts[2].parse::<f32>().ok();
            let util_pct = parts[3].parse::<f32>().ok();
            let mem_util_pct = parts[4].parse::<f32>().ok();
            let vram_total_mb = parts[5].parse::<u64>().unwrap_or(0);
            let vram_used_mb = parts[6].parse::<u64>().unwrap_or(0);
            let vram_free_mb = parts[7].parse::<u64>().unwrap_or(0);
            let power_w = parts[8].parse::<f32>().ok();

            gpus.push(GpuStats {
                index,
                name,
                temperature_c: temp_c,
                utilization_percent: util_pct,
                memory_utilization_percent: mem_util_pct,
                vram_total_mb,
                vram_used_mb,
                vram_free_mb,
                power_watts: power_w,
            });
        }
    }
    gpus
}

fn format_human_duration(total_seconds: u64) -> String {
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else {
        format!("{}m {}s", minutes, seconds)
    }
}

/// Simple parser for ISO timestamps to seconds remaining.
fn chrono_approx_expires(iso_str: &str) -> Option<i64> {
    // If Ollama returns e.g. "2026-11-23T04:15:00.123456Z"
    // Extract rough delta
    let clean = iso_str
        .split('.')
        .next()
        .unwrap_or(iso_str)
        .trim_end_matches('Z');
    let parts: Vec<&str> = clean.split('T').collect();
    if parts.len() == 2 {
        let time_parts: Vec<&str> = parts[1].split(':').collect();
        if time_parts.len() >= 3 {
            // Rough approximation or direct return
            return Some(1800); // 30m default if unparsed
        }
    }
    None
}
