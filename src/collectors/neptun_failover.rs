use std::sync::Arc;
use std::time::Duration;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::crypto_decoder::RawExtractedTarget;
use crate::geo_math::calculate_bearing;
use crate::oblast_detector::OblastDetector;
use crate::tracker::{now_sec, OfficialAlert, ThreatState};

pub async fn run_failover_neptun_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    http_client: reqwest::Client,
) {
    loop {
        sleep(Duration::from_secs(6)).await;

        let needs_failover = {
            let state = threat_state.read().await;
            (now_sec() - state.last_targets_update_ts) > 45.0
        };

        if !needs_failover {
            continue;
        }

        warn!("Centrifugo WebSocket targets silent >45s. Triggering Neptun failover poller...");

        // 1. Резервний збір повітряних цілей
        let threats_url = "https://neptun.in.ua/api/v1/threats";
        if let Ok(resp) = http_client.get(threats_url).timeout(Duration::from_secs(8)).send().await {
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

                        let id = t.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
                            .unwrap_or_else(|| format!("nep_{:.2}", lat));

                        extracted.push(RawExtractedTarget {
                            id,
                            lat,
                            lon,
                            raw_name: raw_combined,
                            raw_type_code: raw_code,
                            heading_deg: heading,
                        });
                    }

                    let mut state = threat_state.write().await;
                    state.tracker.update_batch(&extracted, &detector);
                    state.last_targets_update_ts = now_sec();
                    state.last_update_ts = now_sec();
                    state.update_seq += 1;
                    state.upstream_provider = "Neptun Failover REST API".to_string();
                }
            }
        }

        // 2. Резервний збір офіційних сирен
        let alerts_url = "https://neptun.in.ua/api/v1/alerts";
        if let Ok(resp) = http_client.get(alerts_url).timeout(Duration::from_secs(8)).send().await {
            if let Ok(val) = resp.json::<Value>().await {
                let mut state = threat_state.write().await;
                let mut updated_any = false;

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
                            state.official_alerts.insert(
                                reg_id.clone(),
                                OfficialAlert {
                                    id: reg_id,
                                    name,
                                    alert,
                                    alert_type,
                                    color,
                                    level: "State".to_string(),
                                    updated_at: chrono::Utc::now().to_rfc3339(),
                                },
                            );
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
