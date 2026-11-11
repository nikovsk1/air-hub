use std::sync::Arc;
use std::time::Duration;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::canonical_registry::ExchangeLogManager;
use crate::config::TARGETS_STARTUP_GRACE_PERIOD_SEC;
use crate::crypto_decoder::RawExtractedTarget;
use crate::geo_math::calculate_bearing;
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, ThreatState};

const MAPA_API_URL: &str = "https://mapa.ua/api/v1/current";
const MAPA_UA: &str = "AirAlertHub-Backend/1.0 (MAPA.UA OpenData Integration)";

pub fn parse_mapa_objects(val: &Value) -> Vec<RawExtractedTarget> {
    let mut extracted = Vec::new();
    let objects_opt = val.get("objects").and_then(|o| o.as_array());
    let Some(objects) = objects_opt else {
        return extracted;
    };

    for obj in objects {
        // 1. Парсимо та нормалізуємо статус цілі за канонічною матрицею хаба
        let raw_status = obj.get("status").and_then(|s| s.as_str()).unwrap_or("active");
        let upstream_status = match raw_status {
            "active" => "active",
            "lost" | "disappeared" => "lost",
            "eliminated" | "destroyed" | "shot_down" => "eliminated",
            "hit_target" | "hit" | "impact" => "hit_target",
            "remove" | "cancelled" | "deleted" => "remove",
            _ => "active",
        }.to_string();

        let lat = obj.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let lon = obj.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if lat == 0.0 && lon == 0.0 {
            continue;
        }

        let id_val = obj.get("id")
            .and_then(|v| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string())))
            .unwrap_or_else(|| format!("{:.4}_{:.4}", lat, lon));
        let id = format!("mapa_{}", id_val);

        let mut heading = obj.get("heading").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let speed_kmh = obj.get("speed_kmh").and_then(|v| v.as_f64());

        // 2. Витягуємо траєкторію (trail): у mapa.ua точки зберігаються як [lon, lat, ts]
        let mut trail_pts = Vec::new();
        if let Some(trail_arr) = obj.get("trail").and_then(|t| t.as_array()) {
            for pt in trail_arr {
                if let Some(coords) = pt.as_array() {
                    if coords.len() >= 2 {
                        let p_lon = coords[0].as_f64().unwrap_or(0.0);
                        let p_lat = coords[1].as_f64().unwrap_or(0.0);
                        if p_lat != 0.0 || p_lon != 0.0 {
                            trail_pts.push((p_lat, p_lon)); // зберігаємо як (lat, lon)
                        }
                    }
                }
            }
        }

        // Якщо курс відсутній або 0.0 — рахуємо bearing за останніми точками траєкторії
        if heading <= 0.0 && trail_pts.len() >= 2 {
            let p_prev = trail_pts[trail_pts.len() - 2];
            let p_curr = trail_pts[trail_pts.len() - 1];
            heading = calculate_bearing(p_prev.0, p_prev.1, p_curr.0, p_curr.1);
        } else if heading <= 0.0 && !trail_pts.is_empty() {
            let p_last = trail_pts[trail_pts.len() - 1];
            if (p_last.0 - lat).abs() > 0.001 || (p_last.1 - lon).abs() > 0.001 {
                heading = calculate_bearing(p_last.0, p_last.1, lat, lon);
            }
        }

        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("drone_piston");
        let subkind = obj.get("subkind").and_then(|v| v.as_str()).unwrap_or("");
        let title = obj.get("title").and_then(|v| v.as_str()).unwrap_or("");
        let raw_combined = format!("{} {} {}", kind, subkind, title);

        let raw_code = match kind {
            "drone_piston" => 8,
            "drone_jet" => 9,
            "drone_fpv" => 7,
            "missile_cruise" => 3,
            "missile_ballistic" => 4,
            "bomb" => 5,
            _ => 0,
        };

        extracted.push(RawExtractedTarget {
            id,
            lat,
            lon,
            raw_name: raw_combined,
            raw_type_code: raw_code,
            heading_deg: heading,
            speed_kmh,
            confidence: Some(95),
            time_offset_ms: None,
            trail_points: trail_pts,
            upstream_status,
        });
    }

    extracted
}

pub async fn run_mapa_targets_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    http_client: reqwest::Client,
) {
    let process_start_ts = now_sec();
    let mut was_active = false;
    let mut last_logged_count: Option<usize> = None;

    loop {
        let mapa_cfg = storage.get_stream("mapa_targets");
        let ua_ws_cfg = storage.get_stream("ukrainealarm_ws");
        let neptun_cfg = storage.get_stream("neptun_targets");

        let mapa_enabled = mapa_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);
        let poll_interval_sec = mapa_cfg.as_ref().map(|s| s.poll_interval_sec).unwrap_or(10).max(3);
        let failover_timeout_sec = mapa_cfg.as_ref().map(|s| s.failover_timeout_sec).unwrap_or(20.0).max(5.0);
        let mapa_priority = mapa_cfg.as_ref().map(|s| s.priority).unwrap_or(3);

        sleep(Duration::from_secs(poll_interval_sec)).await;

        if !mapa_enabled {
            if was_active {
                info!("MAPA.UA Targets stream disabled by admin configuration. Deactivating collector.");
                was_active = false;
            }
            continue;
        }

        // Перевіряємо, чи є вищі за пріоритетом джерела, які активні та не мовчать
        let ua_enabled = ua_ws_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);
        let ua_priority = ua_ws_cfg.as_ref().map(|s| s.priority).unwrap_or(1);
        let ua_failover_timeout = ua_ws_cfg.as_ref().map(|s| s.failover_timeout_sec).unwrap_or(15.0).max(5.0);

        let neptun_enabled = neptun_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);
        let neptun_priority = neptun_cfg.as_ref().map(|s| s.priority).unwrap_or(2);
        let neptun_failover_timeout = neptun_cfg.as_ref().map(|s| s.failover_timeout_sec).unwrap_or(15.0).max(5.0);

        let is_mapa_primary = (!ua_enabled || mapa_priority < ua_priority)
            && (!neptun_enabled || mapa_priority < neptun_priority);

        if !is_mapa_primary {
            let uptime = now_sec() - process_start_ts;
            if uptime < TARGETS_STARTUP_GRACE_PERIOD_SEC {
                debug!(
                    "MAPA.UA collector: startup grace period active ({:.1}s / {:.0}s), waiting for higher-priority streams",
                    uptime, TARGETS_STARTUP_GRACE_PERIOD_SEC
                );
                continue;
            }

            let state_read = threat_state.read().await;
            let now = now_sec();

            // Чи активне UkraineAlarm WS?
            let ua_alive = ua_enabled && ua_priority < mapa_priority && (now - state_read.last_primary_targets_ts) <= ua_failover_timeout;
            // Чи активне Neptun?
            let neptun_alive = neptun_enabled && neptun_priority < mapa_priority
                && state_read.targets_provider.contains("Neptun")
                && (now - state_read.last_targets_update_ts) <= neptun_failover_timeout;

            drop(state_read);

            if ua_alive || neptun_alive {
                if was_active {
                    info!("Higher priority targets stream active. MAPA.UA standby.");
                    was_active = false;
                    last_logged_count = None;
                }
                continue;
            }

            if !was_active {
                warn!(
                    "Higher priority target streams silent >{:.0}s. Engaging MAPA.UA (mapa.ua) as active targets provider...",
                    failover_timeout_sec
                );
                was_active = true;
            }
        } else if !was_active {
            info!("MAPA.UA configured as PRIMARY targets stream (Priority #{}). Starting direct radar polling.", mapa_priority);
            was_active = true;
        }

        // Опитування MAPA.UA API
        match http_client
            .get(MAPA_API_URL)
            .header(USER_AGENT, MAPA_UA)
            .header(ACCEPT, "application/json")
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(val) = resp.json::<Value>().await {
                    let extracted = parse_mapa_objects(&val);
                    let extracted_count = extracted.len();

                    let mut state = threat_state.write().await;
                    let provider_name = if is_mapa_primary {
                        "MAPA.UA (Основний)"
                    } else {
                        "MAPA.UA (Резервний)"
                    };
                    let status_str = if is_mapa_primary { "primary" } else { "failover" };

                    state.targets_provider = provider_name.to_string();
                    state.last_targets_provider_status = status_str.to_string();
                    state.last_targets_update_ts = now_sec();
                    state.update_seq += 1;

                    let lost = state.tracker.update_batch(
                        &extracted,
                        &detector,
                        Some(&exchange_mgr),
                        provider_name,
                    );

                    if storage.is_history_recording_enabled() {
                        for trk in state.tracker.tracks.values_mut() {
                            let is_new = trk.trajectory.len() <= 1;
                            let time_since_hist = now_sec() - trk.last_history_sync_ts;
                            if is_new || time_since_hist >= 15.0 {
                                history_mgr.record_track(trk, "active");
                                trk.last_history_sync_ts = now_sec();
                            }
                        }
                        for trk in &lost {
                            let hist_status = match trk.status.as_str() {
                                "eliminated" => "eliminated",
                                "hit_target" => "hit_target",
                                _ => "lost",
                            };
                            history_mgr.record_track(trk, hist_status);
                        }
                    }

                    state.recompute_oblast_alerts(&detector);
                    drop(state);

                    if last_logged_count != Some(extracted_count) {
                        info!(
                            "MAPA.UA collector: updated {} active targets from feed (source={})",
                            extracted_count, provider_name
                        );
                        last_logged_count = Some(extracted_count);
                    }
                }
            }
            Ok(resp) => {
                warn!("MAPA.UA API returned non-success HTTP status: {}", resp.status());
            }
            Err(e) => {
                warn!("MAPA.UA API request failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_mapa_objects_active_filtering_and_conversion() {
        let sample = json!({
            "attack": { "id": 42, "status": "active" },
            "objects": [
                {
                    "id": 1001,
                    "kind": "drone_jet",
                    "subkind": "banderol",
                    "title": "Реактивний БпЛА на Харків",
                    "status": "active",
                    "lat": 50.0,
                    "lon": 36.25,
                    "heading": 180.0,
                    "speed_kmh": 450.0,
                    "trail": [
                        [36.30, 50.10, 1710000000],
                        [36.25, 50.00, 1710000060]
                    ]
                },
                {
                    "id": 1002,
                    "kind": "drone_piston",
                    "subkind": "drone_piston",
                    "title": "Шахед на Полтаву",
                    "status": "eliminated", // повинен бути відфільтрований!
                    "lat": 49.58,
                    "lon": 34.55,
                    "heading": 270.0,
                    "speed_kmh": 165.0
                }
            ],
            "ts": 1710000060
        });

        let targets = parse_mapa_objects(&sample);
        assert_eq!(targets.len(), 2, "Both active and eliminated targets must be parsed");
        let t0 = &targets[0];
        assert_eq!(t0.id, "mapa_1001");
        assert_eq!(t0.upstream_status, "active");
        assert_eq!(t0.lat, 50.0);
        assert_eq!(t0.lon, 36.25);
        assert_eq!(t0.heading_deg, 180.0);
        assert_eq!(t0.speed_kmh, Some(450.0));
        assert_eq!(t0.raw_type_code, 9);
        assert!(t0.raw_name.contains("drone_jet"));
        assert!(t0.raw_name.contains("Реактивний"));
        assert_eq!(t0.trail_points.len(), 2);
        // trail_points повинен бути (lat, lon)
        assert_eq!(t0.trail_points[0], (50.10, 36.30));
        assert_eq!(t0.trail_points[1], (50.00, 36.25));

        let t1 = &targets[1];
        assert_eq!(t1.id, "mapa_1002");
        assert_eq!(t1.upstream_status, "eliminated");
        assert_eq!(t1.raw_type_code, 8);
    }
}
