use once_cell::sync::Lazy;
use prometheus::{register_int_counter, register_int_counter_vec, register_gauge_vec, IntCounter, IntCounterVec, GaugeVec};
use log::{error, warn};
use hyper::server::conn::http1;
use hyper::{service::service_fn, Request, Response};
use http_body_util::Full;
use bytes::Bytes;
use prometheus::{Encoder, TextEncoder};
use std::net::SocketAddr;
use hyper_util::rt::tokio::TokioIo;

pub static API_CALLS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_api_calls_total", "Total CrowdSec API calls").unwrap()
});

pub static API_ERRORS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_api_errors_total", "CrowdSec API errors").unwrap()
});

pub static DECISIONS_NEW_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_decisions_new_total", "New decisions received").unwrap()
});

pub static DECISIONS_DELETED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_decisions_deleted_total", "Deleted decisions received").unwrap()
});

pub static BATCHES_PROCESSED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_batches_processed_total", "Number of decision batches processed").unwrap()
});

pub static DECISIONS_APPLIED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_decisions_applied_total", "Decisions applied to backend").unwrap()
});

pub static DECISIONS_REMOVED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("csfb_decisions_removed_total", "Decisions removed from backend").unwrap()
});

#[allow(dead_code)]
pub static DECISIONS_BY_ORIGIN: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "csfb_decisions_by_origin_total",
        "Decisions grouped by origin",
        &["origin", "op"]
    ).unwrap()
});

// Go-parity metrics (gauges)
#[allow(dead_code)]
pub static FW_BOUNCER_DROPPED_PACKETS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "fw_bouncer_dropped_packets",
        "Total dropped packets due to crowdsec rules",
        &["origin", "ip_type"]
    ).unwrap()
});

#[allow(dead_code)]
pub static FW_BOUNCER_DROPPED_BYTES: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "fw_bouncer_dropped_bytes",
        "Total dropped bytes due to crowdsec rules",
        &["origin", "ip_type"]
    ).unwrap()
});

#[allow(dead_code)]
pub static FW_BOUNCER_PROCESSED_PACKETS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "fw_bouncer_processed_packets",
        "Total processed packets by crowdsec chain",
        &["ip_type"]
    ).unwrap()
});

#[allow(dead_code)]
pub static FW_BOUNCER_PROCESSED_BYTES: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "fw_bouncer_processed_bytes",
        "Total processed bytes by crowdsec chain",
        &["ip_type"]
    ).unwrap()
});

#[allow(dead_code)]
pub static FW_BOUNCER_BANNED_IPS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "fw_bouncer_banned_ips",
        "Number of IPs currently banned",
        &["origin", "ip_type"]
    ).unwrap()
});

pub async fn serve_metrics(
    listen_addr: String,
    backend_collector: Option<std::sync::Arc<dyn crate::backend::BackendMetricsCollector + Send + Sync>>,
) {
    let addr: SocketAddr = match listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("invalid metrics listen addr: {e}");
            return;
        }
    };

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("metrics bind failed: {e}");
            return;
        }
    };

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("metrics accept error: {e}");
                continue;
            }
        };
        let collector_clone = backend_collector.clone();
        tokio::spawn(async move {
            // Best-effort: refresh backend metrics before serving
            if let Some(ref collector) = collector_clone { collector.collect_metrics().await; }
            let io = TokioIo::new(stream);
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(handle_metrics))
                .await;
        });
    }
}

async fn handle_metrics(_req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    let _ = encoder.encode(&metric_families, &mut buffer);
    Ok(Response::new(Full::new(Bytes::from(buffer))))
}



