use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use log::{warn, debug};
use tokio::time::{Duration, Instant};
use std::sync::Arc;

use crate::backend::BackendMetricsCollector;

#[derive(Serialize)]
struct OSVersion {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct MetricsMeta {
    #[serde(rename = "utc_now_timestamp")]
    utc_now_timestamp: i64,
    #[serde(rename = "window_size_seconds")]
    window_size_seconds: i64,
}

#[derive(Serialize)]
struct MetricsDetailItem {
    name: String,
    value: f64,
    labels: HashMap<String, String>,
    unit: String,
}

#[derive(Serialize)]
struct DetailedMetrics {
    #[serde(rename = "Meta")]
    meta: MetricsMeta,
    #[serde(rename = "Items")]
    items: Vec<MetricsDetailItem>,
}

#[derive(Serialize)]
struct BaseMetrics {
    os: OSVersion,
    version: String,
    #[serde(rename = "feature_flags")]
    feature_flags: Vec<String>,
    metrics: Vec<DetailedMetrics>,
    #[serde(rename = "utc_startup_timestamp")]
    utc_startup_timestamp: i64,
}

#[derive(Serialize)]
struct RemediationComponentsMetrics {
    #[serde(rename = "BaseMetrics")]
    base_metrics: BaseMetrics,
    #[serde(rename = "Type")]
    r#type: String,
}

#[derive(Serialize)]
struct AllMetrics {
    #[serde(rename = "RemediationComponents")]
    remediation_components: Vec<RemediationComponentsMetrics>,
}

static LAST_VALUES: Lazy<Mutex<HashMap<String, f64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn get_os() -> OSVersion {
    let name = std::env::consts::OS.to_string();
    // try uname -r for version
    let version = std::process::Command::new("uname").arg("-r").output().ok()
        .and_then(|o| if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).trim().to_string()) } else { None })
        .unwrap_or_else(|| "unknown".to_string());
    OSVersion { name, version }
}

fn metric_key(metric_name: &str, labels: &HashMap<String, String>) -> Option<String> {
    // match Go logic for delta keys
    match metric_name {
        "fw_bouncer_dropped_packets" | "fw_bouncer_dropped_bytes" => {
            Some(format!("{}:{}:{}", metric_name, labels.get("origin").cloned().unwrap_or_default(), labels.get("ip_type").cloned().unwrap_or_default()))
        }
        "fw_bouncer_processed_packets" | "fw_bouncer_processed_bytes" => {
            Some(format!("{}:{}", metric_name, labels.get("ip_type").cloned().unwrap_or_default()))
        }
        _ => None,
    }
}

pub async fn start_usage_metrics(
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    bouncer_version: String,
    bouncer_type: String,
    startup_ts: i64,
    interval: Duration,
    // Optional backend metrics collector to refresh gauges prior to payload build
    refresh_backend_metrics: Option<Arc<dyn BackendMetricsCollector + Send + Sync>>,
) {
    let mut ticker = tokio::time::interval_at(Instant::now() + interval, interval);
    loop {
        ticker.tick().await;
        if let Some(ref collector) = refresh_backend_metrics { collector.collect_metrics().await; }

        // Gather metrics from Prometheus registry
        let families = prometheus::gather();
        let mut items: Vec<MetricsDetailItem> = Vec::new();

        for family in families {
            let name = family.get_name().to_string();
            // Only consider our Go-parity gauges
            if !matches!(name.as_str(),
                "fw_bouncer_banned_ips" | "fw_bouncer_dropped_packets" | "fw_bouncer_dropped_bytes" | "fw_bouncer_processed_packets" | "fw_bouncer_processed_bytes")
            { continue; }

            for metric in family.get_metric() {
                let gauge = metric.get_gauge();
                let value = gauge.get_value();
                let mut labels: HashMap<String, String> = HashMap::new();
                for lp in metric.get_label() {
                    labels.insert(lp.get_name().to_string(), lp.get_value().to_string());
                }

                let unit = match name.as_str() {
                    "fw_bouncer_banned_ips" => "ip",
                    "fw_bouncer_dropped_packets" | "fw_bouncer_processed_packets" => "packet",
                    "fw_bouncer_dropped_bytes" | "fw_bouncer_processed_bytes" => "byte",
                    _ => "",
                }.to_string();

                let mut final_value = value;
                if let Some(key) = metric_key(&name, &labels) {
                    let mut map = LAST_VALUES.lock().unwrap();
                    let prev = map.get(&key).copied().unwrap_or(0.0);
                    final_value = (value - prev).abs();
                    map.insert(key, value);
                }

                items.push(MetricsDetailItem { name: name.clone(), value: final_value, labels, unit });
            }
        }

        let now_ts = chrono::Utc::now().timestamp();
        let meta = MetricsMeta { utc_now_timestamp: now_ts, window_size_seconds: interval.as_secs() as i64 };
        let det = DetailedMetrics { meta, items };
        let base = BaseMetrics {
            os: get_os(),
            version: bouncer_version.clone(),
            feature_flags: Vec::new(),
            metrics: vec![det],
            utc_startup_timestamp: startup_ts,
        };
        let comp = RemediationComponentsMetrics { base_metrics: base, r#type: bouncer_type.clone() };
        let payload = AllMetrics { remediation_components: vec![comp] };

        let url = format!("{}/v1/usage-metrics", base_url.trim_end_matches('/'));
        let req = match client
            .post(url)
            .header("X-Api-Key", &api_key)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&payload)
            .build() {
                Ok(r) => r,
                Err(e) => { warn!("failed to build usage metrics request: {e}"); continue; }
            };
        match client.execute(req).await {
            Ok(resp) => {
                if !resp.status().is_success() { warn!("usage metrics not accepted: {}", resp.status()); }
                else { debug!("usage metrics sent"); }
            }
            Err(e) => warn!("failed to send usage metrics: {e}"),
        }
    }
}


