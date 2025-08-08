use once_cell::sync::Lazy;
use prometheus::{register_int_counter, register_int_counter_vec, IntCounter, IntCounterVec};

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


