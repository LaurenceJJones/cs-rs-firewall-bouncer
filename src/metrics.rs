use once_cell::sync::Lazy;
use prometheus::{register_int_counter, register_int_counter_vec, IntCounter, IntCounterVec};
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

pub static DECISIONS_BY_ORIGIN: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "csfb_decisions_by_origin_total",
        "Decisions grouped by origin",
        &["origin", "op"]
    ).unwrap()
});

pub async fn serve_metrics(listen_addr: String) {
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
        tokio::spawn(async move {
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


