use std::sync::Arc;
use std::time::Duration;
use reqwest::header::USER_AGENT;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::canonical_registry::ExchangeLogManager;
use crate::config::{NEPTUN_THREATS_POLL_INTERVAL_SEC, TARGETS_PRIMARY_FAILOVER_TIMEOUT_SEC};
use crate::crypto_decoder::RawExtractedTarget;
use crate::geo_math::calculate_bearing;
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, ThreatState};

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

pub async fn run_failover_neptun_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    http_client: reqwest::Client,
) {
    loop {
        sleep(Duration::from_secs(NEPTUN_THREATS_POLL_INTERVAL_SEC)).await;

        let needs_failover = {
            let state = threat_state.read().await;
            (now_sec() - state.last_primary_targets_ts) > TARGETS_PRIMARY_FAILOVER_TIMEOUT_SEC
        };

        if !needs_failover {
            continue;
        }

        warn!("All UkraineAlarm streams (WebSocket & HTTP Fallback) silent >{:.0}s. Triggering Tier 3 Neptun disaster recovery poller...", TARGETS_PRIMARY_FAILOVER_TIMEOUT_SEC);

        // 1. Резервний збір повітряних цілей
        let threats_url = "https://neptun.in.ua/api/v1/threats";
        if let Ok(resp) = http_client.get(threats_url)
            .header(USER_AGENT, BROWSER_UA)
            .header(reqwest::header::REFERER, "https://neptun.in.ua/")
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<Value>().await {
                    let threats_opt = val.get("threats").and_then(|t| t.as_array())
                        .or_else(|| val.get("data").and_then(|t| t.as_array()))
                        .or_else(|| val.get("targets").and_then(|t| t.as_array()))
                        .or_else(|| val.as_array());
                    if let Some(threats_raw) = threats_opt {
                    let mut extracted = Vec::new();
                    for t in threats_raw {
                        let lat = t.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let lon = t.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let heading_raw = t.get("heading").and_then(|v| v.as_f64());
                        let mut heading = heading_raw.unwrap_or(0.0);

                        // Якщо курс відсутній (null) або 0.0, спробувати обчислити за останніми двома точками треку
                        if heading <= 0.0 {
                            if let Some(trail) = t.get("trail").and_then(|tr| tr.as_array()) {
                                if trail.len() >= 2 {
                                    let p_prev = &trail[trail.len() - 2];
                                    let p_curr = &trail[trail.len() - 1];
                                    if let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = (
                                        p_prev.get("lat").and_then(|v| v.as_f64()),
                                        p_prev.get("lon").and_then(|v| v.as_f64()),
                                        p_curr.get("lat").and_then(|v| v.as_f64()),
                                        p_curr.get("lon").and_then(|v| v.as_f64()),
                                    ) {
                                        heading = calculate_bearing(lat1, lon1, lat2, lon2);
                                    }
                                }
                            }
                        }

                        let raw_type = t.get("type").and_then(|v| v.as_str()).unwrap_or("uav");
                        let title = t.get("title").and_then(|v| v.as_str()).unwrap_or("");
                        let expl = t.get("explanationShort").and_then(|v| v.as_str()).unwrap_or("");
                        let raw_combined = format!("{} {} {}", raw_type, title, expl);

                        let raw_code = match raw_type {
                            "uav" => 8,
                            "missile" | "ballistic" => 3,
                            _ => 0,
                        };

                        // Нептун реєструє цілі незалежно без об'єднання з UkraineAlarm
                        let id = t.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
                            .unwrap_or_else(|| format!("nep_{:.2}_{:.2}", lat, lon));

                        extracted.push(RawExtractedTarget {
                            id,
                            lat,
                            lon,
                            raw_name: raw_combined,
                            raw_type_code: raw_code,
                            heading_deg: heading,
                            speed_kmh: None,
                            confidence: None,
                            time_offset_ms: None,
                            trail_points: Vec::new(),
                            upstream_status: "active".to_string(),
                        });
                    }

                    let extracted_count = extracted.len();
                    let mut state = threat_state.write().await;
                    let lost_tracks = state.tracker.update_batch(&extracted, &*detector, Some(&*exchange_mgr), "Neptun Failover");
                    state.recompute_oblast_alerts(&detector);
                    state.last_targets_update_ts = now_sec();
                    state.last_update_ts = now_sec();
                    state.update_seq += 1;
                    state.upstream_provider = "Neptun (Резервний)".to_string();
                    state.targets_provider = "Neptun (Резервний)".to_string();
                    state.last_targets_provider_status = "failover".to_string();

                    if storage.is_history_recording_enabled() {
                        for trk in state.tracker.tracks.values_mut() {
                            let is_new = trk.trajectory.len() <= 1;
                            let time_since_hist = now_sec() - trk.last_history_sync_ts;
                            if is_new || time_since_hist >= 15.0 {
                                history_mgr.record_track(trk, "active");
                                trk.last_history_sync_ts = now_sec();
                            }
                        }
                        for trk in &lost_tracks {
                            history_mgr.record_track(trk, "lost");
                        }
                    }
                    if extracted_count > 0 {
                        info!("Neptun failover: updated {} active targets from backup feed", extracted_count);
                    }
                }
            }
        }
    }
}
}
