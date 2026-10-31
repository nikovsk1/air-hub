use std::sync::Arc;
use std::time::Duration;
use reqwest::header::{ORIGIN, REFERER, USER_AGENT};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::debug;

use crate::canonical_registry::ExchangeLogManager;
use crate::oblast_detector::OblastDetector;
use crate::tracker::{now_sec, OfficialAlert, ThreatState};

const MAP_UPDATE_URL: &str = "https://map.ukrainealarm.com/api/v2/data/mapUpdate";
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36";

pub async fn run_official_alerts_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    exchange_mgr: Arc<ExchangeLogManager>,
    http_client: reqwest::Client,
) {
    loop {
        match http_client
            .get(MAP_UPDATE_URL)
            .header(USER_AGENT, BROWSER_UA)
            .header(ORIGIN, "https://map.ukrainealarm.com")
            .header(REFERER, "https://map.ukrainealarm.com/")
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(data) = resp.json::<Value>().await {
                    let mut state = threat_state.write().await;
                    state.official_alerts.clear();

                    // 1. migAlerts
                    let mig_active = data.get("migAlerts")
                        .and_then(|m| m.as_array())
                        .map(|arr| !arr.is_empty())
                        .unwrap_or(false);
                    let mut mig_detected = mig_active;

                    // 2. artillery regions set
                    let mut artillery_regions = std::collections::HashSet::new();
                    if let Some(art_arr) = data.get("artillery").and_then(|a| a.as_array()) {
                        for a in art_arr {
                            let rid = a.get("regionId")
                                .or_else(|| a.get("id"))
                                .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                                .unwrap_or_default();
                            if !rid.is_empty() {
                                artillery_regions.insert(rid);
                            }
                        }
                    }

                    // 3. alert_reasons
                    let mut reasons = Vec::new();
                    if let Some(r_arr) = data.get("reasons").and_then(|r| r.as_array()) {
                        for r in r_arr {
                            if let Some(s) = r.as_str() {
                                if !reasons.contains(&s.to_string()) {
                                    reasons.push(s.to_string());
                                }
                            }
                        }
                    }

                    // 4. alerts
                    if let Some(alerts_arr) = data.get("alerts").and_then(|a| a.as_array()) {
                        for item in alerts_arr {
                            let reg_id = item.get("regionId")
                                .or_else(|| item.get("id"))
                                .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                                .unwrap_or_default();
                            if reg_id.is_empty() {
                                continue;
                            }

                            let name = item.get("regionName")
                                .or_else(|| item.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();

                            let reg_type = item.get("regionType")
                                .or_else(|| item.get("type"))
                                .and_then(|t| t.as_str())
                                .unwrap_or("State")
                                .to_string();

                            // Фіксація нерозпізнаних регіонів у журналі обміну
                            if reg_type != "Community" && !detector.is_known_region(&reg_id) && !detector.is_known_region_name(&name) {
                                exchange_mgr.record_unmapped(
                                    "region",
                                    &format!("id={}, name={}", reg_id, name),
                                    None,
                                    "unmapped",
                                    "UkraineAlarm",
                                    Some(&format!("Регіон '{}' (ID {}) відсутній у канонічному списку областей/районів", name, reg_id)),
                                );
                            }

                            let mut is_alert = false;
                            let mut alert_type = "none".to_string();
                            let mut color = "none".to_string();
                            let level = reg_type;

                            if let Some(active_alerts) = item.get("activeAlerts").and_then(|a| a.as_array()) {
                                if !active_alerts.is_empty() {
                                    is_alert = true;
                                    for a in active_alerts {
                                        let a_type = a.get("type").and_then(|t| t.as_str()).unwrap_or("").to_uppercase();
                                        if a_type == "ARTILLERY" || artillery_regions.contains(&reg_id) {
                                            alert_type = "artillery".to_string();
                                            color = "red".to_string();
                                        } else if a_type == "AIR" || a_type == "MISSILE" {
                                            if alert_type != "artillery" {
                                                alert_type = "missile".to_string();
                                            }
                                        }

                                        if let Some(levels) = a.get("activeAlertLevels").and_then(|l| l.as_array()) {
                                            for lvl_obj in levels {
                                                if let Some(lvl_str) = lvl_obj.get("alertLevel").and_then(|s| s.as_str()) {
                                                    if lvl_str.to_lowercase() == "yellow" || lvl_str.to_lowercase() == "community" {
                                                        if color != "red" {
                                                            color = "yellow".to_string();
                                                        }
                                                    } else {
                                                        color = "red".to_string();
                                                    }
                                                }
                                                if let Some(rsn) = lvl_obj.get("reason").and_then(|s| s.as_str()) {
                                                    if rsn.to_lowercase().contains("міг-31") || rsn.to_lowercase().contains("mig-31") {
                                                        mig_detected = true;
                                                    }
                                                    if !reasons.contains(&rsn.to_string()) {
                                                        reasons.push(rsn.to_string());
                                                    }
                                                }
                                            }
                                        } else if let Some(lvl_str) = a.get("alertLevel").and_then(|s| s.as_str()) {
                                            if lvl_str.to_lowercase() == "yellow" || lvl_str.to_lowercase() == "community" {
                                                if color != "red" {
                                                    color = "yellow".to_string();
                                                }
                                            } else {
                                                color = "red".to_string();
                                            }
                                        }
                                    }

                                    if color == "none" {
                                        color = "red".to_string();
                                    }
                                    if alert_type == "none" {
                                        alert_type = "missile".to_string();
                                    }
                                }
                            } else if let Some(alert_bool) = item.get("alert").and_then(|b| b.as_bool()) {
                                is_alert = alert_bool;
                                if is_alert {
                                    color = item.get("color").and_then(|c| c.as_str()).unwrap_or("red").to_string();
                                    alert_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("missile").to_string();
                                }
                            }

                            if artillery_regions.contains(&reg_id) {
                                is_alert = true;
                                alert_type = "artillery".to_string();
                                color = "red".to_string();
                            }

                            if is_alert {
                                state.official_alerts.insert(
                                    reg_id.clone(),
                                    OfficialAlert {
                                        id: reg_id,
                                        name,
                                        alert: true,
                                        alert_type,
                                        color,
                                        level,
                                        updated_at: chrono::Utc::now().to_rfc3339(),
                                    },
                                );
                            }
                        }
                    }

                    state.mig_active = mig_detected;
                    state.alert_reasons = reasons;
                    state.recompute_oblast_alerts(&detector);
                    state.last_alerts_update_ts = now_sec();
                    state.update_seq += 1;
                }
            }
            Err(e) => {
                debug!("Error updating official mapUpdate: {}", e);
            }
        }

        sleep(Duration::from_secs(12)).await;
    }
}
