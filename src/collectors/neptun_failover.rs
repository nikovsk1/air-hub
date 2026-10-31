use std::sync::Arc;
use std::time::Duration;
use reqwest::header::USER_AGENT;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::canonical_registry::ExchangeLogManager;
use crate::crypto_decoder::RawExtractedTarget;
use crate::geo_math::{calculate_bearing, calculate_haversine_distance};
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::tracker::{now_sec, OfficialAlert, ThreatState};

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

pub async fn run_failover_neptun_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    http_client: reqwest::Client,
) {
    loop {
        sleep(Duration::from_secs(6)).await;

        let needs_failover = {
            let state = threat_state.read().await;
            (now_sec() - state.last_primary_targets_ts) > 45.0
        };

        if !needs_failover {
            continue;
        }

        warn!("All UkraineAlarm streams (WebSocket & HTTP Fallback) silent >45s. Triggering Tier 3 Neptun disaster recovery poller...");

        // 1. Резервний збір повітряних цілей
        let threats_url = "https://neptun.in.ua/api/v1/threats";
        if let Ok(resp) = http_client.get(threats_url)
            .header(USER_AGENT, BROWSER_UA)
            .header(reqwest::header::REFERER, "https://neptun.in.ua/")
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            if let Ok(val) = resp.json::<Value>().await {
                if let Some(threats_raw) = val.get("threats").and_then(|t| t.as_array()) {
                    let mut extracted = Vec::new();
                    for t in threats_raw {
                        let lat = t.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let lon = t.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let mut heading = t.get("heading").and_then(|v| v.as_f64()).unwrap_or(0.0);

                        if heading == 0.0 {
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

                        // Точкова Естафета (Failover Handover):
                        // Якщо поруч (<15 км) є активна ціль від основного джерела UkraineAlarm зі схожим вектором руху,
                        // успадковуємо її оригінальний ID, щоб не плодити дублікатів і не створювати хибних маркерів збиттів
                        let candidate_id = {
                            let state = threat_state.read().await;
                            let mut best_match: Option<(String, f64)> = None;
                            for (existing_id, trk) in &state.tracker.tracks {
                                if !existing_id.starts_with("nep_") {
                                    let d = calculate_haversine_distance(trk.lat, trk.lon, lat, lon);
                                    let mut h_diff = (trk.heading - heading).abs();
                                    if h_diff > 180.0 { h_diff = 360.0 - h_diff; }
                                    if d <= 15.0 && (h_diff <= 40.0 || heading == 0.0 || trk.heading == 0.0) {
                                        if best_match.as_ref().map_or(true, |(_, best_d)| d < *best_d) {
                                            best_match = Some((existing_id.clone(), d));
                                        }
                                    }
                                }
                            }
                            best_match.map(|(id, _)| id)
                        };

                        let id = candidate_id.unwrap_or_else(|| {
                            t.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
                                .unwrap_or_else(|| format!("nep_{:.2}_{:.2}", lat, lon))
                        });

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
                        });
                    }

                    let extracted_count = extracted.len();
                    let mut state = threat_state.write().await;
                    let lost_tracks = state.tracker.update_batch(&extracted, &*detector, Some(&*exchange_mgr), "Neptun Failover");
                    state.recompute_oblast_alerts(&detector);
                    state.last_targets_update_ts = now_sec();
                    state.last_update_ts = now_sec();
                    state.update_seq += 1;
                    state.upstream_provider = "Neptun Failover REST API".to_string();

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
                    if extracted_count > 0 {
                        info!("Neptun failover: updated {} active targets from backup feed", extracted_count);
                    }
                }
            }
        }

        // 2. Резервний збір офіційних сирен
        let alerts_url = "https://neptun.in.ua/api/v1/alerts";
        if let Ok(resp) = http_client.get(alerts_url)
            .header(USER_AGENT, BROWSER_UA)
            .header(reqwest::header::REFERER, "https://neptun.in.ua/")
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            if let Ok(val) = resp.json::<Value>().await {
                let mut state = threat_state.write().await;
                let mut updated_any = false;
                let mut active_neptun_ids = std::collections::HashSet::new();

                // 2.1 Області з neptun
                if let Some(ob_arr) = val.get("oblasts").and_then(|o| o.as_array()) {
                    for ob_item in ob_arr {
                        let ob_name = ob_item.get("oblast")
                            .or_else(|| ob_item.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("");
                        let ob_id = detector.get_oblast_id_by_name(ob_name);
                        if !ob_id.is_empty() && ob_id != "0" {
                            let color = if ob_item.get("level").and_then(|l| l.as_str()).unwrap_or("").to_lowercase() == "yellow" {
                                "yellow".to_string()
                            } else {
                                "red".to_string()
                            };

                            active_neptun_ids.insert(ob_id.clone());
                            state.official_alerts.insert(
                                ob_id.clone(),
                                OfficialAlert {
                                    id: ob_id,
                                    name: ob_name.to_string(),
                                    alert: true,
                                    alert_type: "missile".to_string(),
                                    color,
                                    level: "State".to_string(),
                                    updated_at: chrono::Utc::now().to_rfc3339(),
                                },
                            );
                            updated_any = true;
                        } else if !ob_name.is_empty() {
                            exchange_mgr.record_unmapped(
                                "region",
                                ob_name,
                                None,
                                "unmapped",
                                "Neptun",
                                Some(&format!("Область '{}' не знайдена в словнику детектору", ob_name)),
                            );
                        }
                    }
                }

                // 2.2 Райони з neptun
                if let Some(ra_arr) = val.get("raions").and_then(|r| r.as_array()) {
                    for r_item in ra_arr {
                        let r_name = r_item.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let r_id = detector.get_raion_id_by_name(r_name);
                        if !r_id.is_empty() && r_id != "0" {
                            let color = if r_item.get("level").and_then(|l| l.as_str()).unwrap_or("").to_lowercase() == "yellow" {
                                "yellow".to_string()
                            } else {
                                "red".to_string()
                            };

                            active_neptun_ids.insert(r_id.clone());
                            state.official_alerts.insert(
                                r_id.clone(),
                                OfficialAlert {
                                    id: r_id,
                                    name: r_name.to_string(),
                                    alert: true,
                                    alert_type: "missile".to_string(),
                                    color,
                                    level: "Raion".to_string(),
                                    updated_at: chrono::Utc::now().to_rfc3339(),
                                },
                            );
                            updated_any = true;
                        } else if !r_name.is_empty() {
                            exchange_mgr.record_unmapped(
                                "region",
                                r_name,
                                None,
                                "unmapped",
                                "Neptun",
                                Some(&format!("Район '{}' не знайдений в словнику детектору", r_name)),
                            );
                        }
                    }
                }

                // 2.3 Fallback на стандартний масив alerts
                if let Some(alerts_arr) = val.get("alerts").and_then(|a| a.as_array()) {
                    for item in alerts_arr {
                        let reg_id = item.get("regionId")
                            .or_else(|| item.get("id"))
                            .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                            .unwrap_or_default();

                        let name = item.get("regionName").and_then(|n| n.as_str()).unwrap_or("").to_string();
                        let alert = item.get("alert").and_then(|b| b.as_bool()).unwrap_or(true);
                        let alert_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("missile").to_string();
                        let color = item.get("color").and_then(|c| c.as_str()).unwrap_or("red").to_string();

                        if !reg_id.is_empty() {
                            if alert {
                                active_neptun_ids.insert(reg_id.clone());
                            }
                            let level = if crate::oblast_detector::get_canonical_raion_to_oblast().contains_key(reg_id.as_str()) {
                                "Raion".to_string()
                            } else {
                                "State".to_string()
                            };

                            state.official_alerts.insert(
                                reg_id.clone(),
                                OfficialAlert {
                                    id: reg_id,
                                    name,
                                    alert,
                                    alert_type,
                                    color,
                                    level,
                                    updated_at: chrono::Utc::now().to_rfc3339(),
                                },
                            );
                            updated_any = true;
                        }
                    }
                }

                // 2.4 Скидання відбоїв (Neptun повертає лише активні тривоги: регіони, яких немає у відповіді, вимикаємо)
                let has_neptun_data = val.get("oblasts").is_some() || val.get("raions").is_some() || val.get("alerts").is_some();
                if has_neptun_data {
                    let now_iso = chrono::Utc::now().to_rfc3339();
                    for alert in state.official_alerts.values_mut() {
                        if !alert.alert {
                            continue;
                        }

                        let should_clear = if alert.level == "State" {
                            // Якщо це область і її немає в active_neptun_ids -> знімаємо тривогу
                            !active_neptun_ids.contains(&alert.id)
                        } else {
                            // Якщо це район чи громада: якщо в її області немає тривоги -> знімаємо і в громаді
                            let parent_ob_id = detector.get_oblast_id_by_region(&alert.id);
                            if parent_ob_id != "0" {
                                !active_neptun_ids.contains(&parent_ob_id)
                            } else {
                                !active_neptun_ids.contains(&alert.id)
                            }
                        };

                        if should_clear {
                            alert.alert = false;
                            alert.color = "none".to_string();
                            alert.alert_type = "none".to_string();
                            alert.updated_at = now_iso.clone();
                            updated_any = true;
                        }
                    }
                }

                if updated_any {
                    state.recompute_oblast_alerts(&detector);
                    state.last_alerts_update_ts = now_sec();
                    state.update_seq += 1;
                }
            }
        }
    }
}
