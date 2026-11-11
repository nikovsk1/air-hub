use std::sync::Arc;
use std::time::Duration;
use reqwest::header::USER_AGENT;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::canonical_registry::ExchangeLogManager;
use crate::config::{NEPTUN_THREATS_POLL_INTERVAL_SEC, TARGETS_PRIMARY_FAILOVER_TIMEOUT_SEC, TARGETS_STARTUP_GRACE_PERIOD_SEC};
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
    let process_start_ts = now_sec();
    let mut was_in_failover = false;
    let mut last_logged_count: Option<usize> = None;

    loop {
        sleep(Duration::from_secs(NEPTUN_THREATS_POLL_INTERVAL_SEC)).await;

        // Стартовий Grace Period (25 секунд): не перевіряти таймаут тиші на старті, дати сокету спокійно підключитися
        let uptime = now_sec() - process_start_ts;
        if uptime < TARGETS_STARTUP_GRACE_PERIOD_SEC {
            debug!(
                "Neptun failover: startup grace period active ({:.1}s / {:.0}s), awaiting primary WebSocket stabilization",
                uptime, TARGETS_STARTUP_GRACE_PERIOD_SEC
            );
            continue;
        }

        let needs_failover = {
            let state = threat_state.read().await;
            (now_sec() - state.last_primary_targets_ts) > TARGETS_PRIMARY_FAILOVER_TIMEOUT_SEC
        };

        if !needs_failover {
            if was_in_failover {
                info!("Primary UkraineAlarm stream resumed. Neptun failover deactivated.");
                was_in_failover = false;
                last_logged_count = None;
            }
            continue;
        }

        if !was_in_failover {
            warn!(
                "Primary UkraineAlarm streams (WebSocket & HTTP Fallback) silent >{:.0}s. Switching to Tier 3 Neptun disaster recovery...",
                TARGETS_PRIMARY_FAILOVER_TIMEOUT_SEC
            );
            was_in_failover = true;
        }

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
                        let lat = t.get("lat").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0.0);
                        let lon = t.get("lon").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0.0);
                        let heading_raw = t.get("heading").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
                        let mut heading = heading_raw.unwrap_or(0.0);

                        let mut trail_pts = Vec::new();
                        if let Some(trail) = t.get("trail").and_then(|tr| tr.as_array()) {
                            for pt in trail {
                                if let (Some(p_lat), Some(p_lon)) = (
                                    pt.get("lat").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))),
                                    pt.get("lon").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))),
                                ) {
                                    trail_pts.push((p_lat, p_lon));
                                }
                            }
                        }

                        // Якщо курс відсутній (null) або 0.0, спробувати обчислити за останніми двома точками треку
                        if heading <= 0.0 && trail_pts.len() >= 2 {
                            let p_prev = trail_pts[trail_pts.len() - 2];
                            let p_curr = trail_pts[trail_pts.len() - 1];
                            heading = calculate_bearing(p_prev.0, p_prev.1, p_curr.0, p_curr.1);
                        } else if heading <= 0.0 && !trail_pts.is_empty() && (lat != 0.0 || lon != 0.0) {
                            let p_last = trail_pts[trail_pts.len() - 1];
                            if (p_last.0 - lat).abs() > 0.001 || (p_last.1 - lon).abs() > 0.001 {
                                heading = calculate_bearing(p_last.0, p_last.1, lat, lon);
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
                            .unwrap_or_else(|| format!("nep_{:.4}_{:.4}", lat, lon));

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
                            trail_points: trail_pts,
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
                    if extracted_count > 0 && last_logged_count != Some(extracted_count) {
                        info!("Neptun failover: tracking {} active targets from backup feed", extracted_count);
                        last_logged_count = Some(extracted_count);
                    }
                }
            }
        }
    }
}
}
