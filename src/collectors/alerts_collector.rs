use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use reqwest::header::{HeaderValue, AUTHORIZATION, USER_AGENT};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::canonical_registry::{classify_neptun_alert, classify_official_alert, ExchangeLogManager};
use crate::config::{NEPTUN_ALERTS_POLL_INTERVAL_SEC, UKRAINEALARM_STATUS_POLL_INTERVAL_SEC};
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, OfficialAlert, ThreatState};

const UKRAINEALARM_STATUS_URL: &str = "https://api.ukrainealarm.com/api/v3/alerts/status";
const UKRAINEALARM_ALERTS_URL: &str = "https://api.ukrainealarm.com/api/v3/alerts";
const NEPTUN_ALERTS_URL: &str = "https://neptun.in.ua/api/v1/alerts";
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36";

/// Уніфікований фоновий сервіс збору офіційних тривог:
/// 1. Основний рушій: Офіційний REST API api.ukrainealarm.com (API v3 з токеном, Smart Polling)
/// 2. Альтернативний рушій: Neptun API (neptun.in.ua/api/v1/alerts, якщо токен не задано або API v3 недоступне)
pub async fn run_alerts_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    storage: Arc<StorageManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    http_client: reqwest::Client,
) {
    let mut last_action_index: Option<u64> = None;
    let mut consecutive_ua_failures: u32 = 0;
    let mut ua_cooldown_until: f64 = 0.0;
    let mut last_provider_log = String::new();

    // Офіційний регламент UkraineAlarm API v3: запити раз на 12-15 секунд (4-5 запитів на хвилину)
    // За замовчуванням 12 секунд (допустимий діапазон 10..60 сек)
    let poll_interval_secs: u64 = std::env::var("ALERTS_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(12)
        .clamp(10, 60);

    info!(
        "Alerts collector initialized: polling interval = {}s (UkraineAlarm API v3 rate-limit compliant)",
        poll_interval_secs
    );

    loop {
        let service_keys = storage.get_service_keys();
        let ua_token = service_keys
            .ukrainealarm_api_token
            .filter(|t| !t.trim().is_empty());

        let now = now_sec();
        let mut used_primary = false;

        if let Some(token) = ua_token {
            let should_try_ua = if consecutive_ua_failures < 5 {
                now >= ua_cooldown_until
            } else {
                // Відновлювальне зондування (Recovery Probing): кожні 60с повторна спроба
                now >= ua_cooldown_until
            };

            if should_try_ua {
                // =========================================================================
                // ОСНОВНИЙ РУШІЙ: Офіційний API v3 (api.ukrainealarm.com)
                // =========================================================================
                if last_provider_log != "UkraineAlarm API v3" {
                    info!("Alerts collector: using primary engine UkraineAlarm Official API v3");
                    last_provider_log = "UkraineAlarm API v3".to_string();
                }

                let mut auth_val = HeaderValue::from_str(&token).unwrap_or_else(|_| HeaderValue::from_static(""));
                if auth_val.is_empty() {
                    // Fallback to empty if invalid chars
                    auth_val = HeaderValue::from_static("");
                }

                let status_res = http_client
                    .get(UKRAINEALARM_STATUS_URL)
                    .header(AUTHORIZATION, auth_val.clone())
                    .header(USER_AGENT, BROWSER_UA)
                    .timeout(Duration::from_secs(6))
                    .send()
                    .await;

                match status_res {
                    Ok(resp) if resp.status().is_success() => {
                        consecutive_ua_failures = 0;
                        ua_cooldown_until = 0.0;
                        used_primary = true;

                        if let Ok(status_json) = resp.json::<Value>().await {
                            let curr_idx = status_json
                                .get("lastActionIndex")
                                .and_then(|v| v.as_u64());

                            let should_fetch = match (last_action_index, curr_idx) {
                                (None, _) => true,
                                (Some(prev), Some(curr)) => curr != prev,
                                _ => true,
                            };

                            if should_fetch {
                                // Запобігання мікро-спайкам (burst protection): 800мс між запитами
                                sleep(Duration::from_millis(800)).await;

                                if let Ok(alerts_resp) = http_client
                                    .get(UKRAINEALARM_ALERTS_URL)
                                    .header(AUTHORIZATION, auth_val)
                                    .header(USER_AGENT, BROWSER_UA)
                                    .timeout(Duration::from_secs(8))
                                    .send()
                                    .await
                                {
                                    if let Ok(alerts_val) = alerts_resp.json::<Value>().await {
                                        if let Some(regions_arr) = alerts_val.as_array() {
                                            process_ukrainealarm_v3_alerts(
                                                regions_arr,
                                                &threat_state,
                                                &detector,
                                                &exchange_mgr,
                                            )
                                            .await;
                                            last_action_index = curr_idx;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(resp) if resp.status().as_u16() == 429 => {
                        // Отримано HTTP 429 Too Many Requests: читаємо Retry-After або бекофф 60 сек
                        let retry_after = resp
                            .headers()
                            .get(reqwest::header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(60);

                        warn!(
                            "UkraineAlarm API v3 returned HTTP 429 Too Many Requests. Rate limit triggered! Pausing requests for {}s (failures={})",
                            retry_after,
                            consecutive_ua_failures + 1
                        );
                        consecutive_ua_failures += 1;
                        ua_cooldown_until = now_sec() + (retry_after as f64);
                    }
                    Ok(resp) => {
                        warn!(
                            "UkraineAlarm API v3 returned HTTP status: {} (failures={})",
                            resp.status(),
                            consecutive_ua_failures + 1
                        );
                        consecutive_ua_failures += 1;
                        let backoff = (consecutive_ua_failures as f64).min(5.0) * 15.0;
                        ua_cooldown_until = now_sec() + backoff;
                    }
                    Err(e) => {
                        warn!(
                            "UkraineAlarm API v3 request failed: {} (failures={})",
                            e,
                            consecutive_ua_failures + 1
                        );
                        consecutive_ua_failures += 1;
                        let backoff = (consecutive_ua_failures as f64).min(5.0) * 15.0;
                        ua_cooldown_until = now_sec() + backoff;
                    }
                }
            } else if now < ua_cooldown_until {
                debug!(
                    "UkraineAlarm API v3 in cooldown for next {:.0}s, routing through fallback",
                    ua_cooldown_until - now
                );
            }
        }

        // =========================================================================
        // АЛЬТЕРНАТИВНИЙ РУШІЙ: Neptun API (neptun.in.ua/api/v1/alerts)
        // Спрацьовує, якщо токен UkraineAlarm не налаштований або запити зазнали збою / cooldown
        // =========================================================================
        if !used_primary {
            if last_provider_log != "Neptun Alerts" {
                info!("Alerts collector: using failover/alternative engine Neptun Alerts (neptun.in.ua)");
                last_provider_log = "Neptun Alerts".to_string();
            }

            match http_client
                .get(NEPTUN_ALERTS_URL)
                .header(USER_AGENT, BROWSER_UA)
                .header(reqwest::header::REFERER, "https://neptun.in.ua/")
                .timeout(Duration::from_secs(8))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(val) = resp.json::<Value>().await {
                        process_neptun_alerts(&val, &threat_state, &detector, &exchange_mgr).await;
                    }
                }
                Ok(resp) => {
                    debug!("Neptun alerts HTTP error: {}", resp.status());
                }
                Err(e) => {
                    debug!("Neptun alerts request failed: {}", e);
                }
            }
            // Резервний цикл опитування: суворе дотримання ліміту Cloudflare CDN (>= 5с)
            sleep(Duration::from_secs(NEPTUN_ALERTS_POLL_INTERVAL_SEC)).await;
            continue;
        }

        // Штатний режим Smart Polling UkraineAlarm API v3 (/status кожні 4с)
        sleep(Duration::from_secs(UKRAINEALARM_STATUS_POLL_INTERVAL_SEC)).await;
    }
}

/// Обробка даних офіційного API v3 (api.ukrainealarm.com)
async fn process_ukrainealarm_v3_alerts(
    regions_arr: &[Value],
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    exchange_mgr: &Arc<ExchangeLogManager>,
) {
    let mut state = threat_state.write().await;
    let mut active_ids = HashSet::new();
    let mut mig_detected = false;
    let mut reasons = Vec::new();
    let now_iso = Utc::now().to_rfc3339();

    for item in regions_arr {
        let reg_id = item
            .get("regionId")
            .or_else(|| item.get("id"))
            .map(|v| {
                if let Some(s) = v.as_str() {
                    s.to_string()
                } else {
                    v.to_string()
                }
            })
            .unwrap_or_default();

        if reg_id.is_empty() {
            continue;
        }

        let name = item
            .get("regionName")
            .or_else(|| item.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let reg_type = item
            .get("regionType")
            .or_else(|| item.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("State")
            .to_string();

        // Фіксація нерозпізнаних регіонів
        if reg_type != "Community"
            && !detector.is_known_region(&reg_id)
            && !detector.is_known_region_name(&name)
        {
            exchange_mgr.record_unmapped(
                "region",
                &format!("id={}, name={}", reg_id, name),
                None,
                "unmapped",
                "UkraineAlarm v3",
                Some(&format!("Регіон '{}' (ID {}) не знайдено у словнику областей/районів", name, reg_id)),
            );
        }

        let mut is_alert = false;
        let mut alert_type = "none".to_string();
        let mut color = "none".to_string();

        if let Some(active_alerts) = item.get("activeAlerts").and_then(|a| a.as_array()) {
            if !active_alerts.is_empty() {
                is_alert = true;
                for a in active_alerts {
                    let raw_type = a.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    let raw_level = a.get("level").and_then(|l| l.as_str());

                    let (mapped_cat, mapped_color, _) = classify_official_alert(raw_type, raw_level);
                    if mapped_color == "red" || color != "red" {
                        color = mapped_color.to_string();
                        alert_type = mapped_cat.to_string();
                    }

                    // Перевірка причини тривоги (МіГ-31К тощо)
                    if let Some(rsn) = a.get("reason").and_then(|s| s.as_str()) {
                        let lower_r = rsn.to_lowercase();
                        if lower_r.contains("міг-31") || lower_r.contains("mig-31") {
                            mig_detected = true;
                        }
                        if !reasons.contains(&rsn.to_string()) {
                            reasons.push(rsn.to_string());
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
        }

        if is_alert {
            active_ids.insert(reg_id.clone());
            state.official_alerts.insert(
                reg_id.clone(),
                OfficialAlert {
                    id: reg_id,
                    name,
                    alert: true,
                    alert_type,
                    color,
                    level: reg_type,
                    updated_at: now_iso.clone(),
                },
            );
        }
    }

    // Скидання відбоїв для регіонів, яких немає в active_ids
    for alert in state.official_alerts.values_mut() {
        if alert.alert && !active_ids.contains(&alert.id) {
            alert.alert = false;
            alert.color = "none".to_string();
            alert.alert_type = "none".to_string();
            alert.updated_at = now_iso.clone();
        }
    }

    state.mig_active = mig_detected;
    state.alert_reasons = reasons;
    state.recompute_oblast_alerts(detector);
    state.last_alerts_update_ts = now_sec();
    state.alarms_provider = "UkraineAlarm (API v3)".to_string();
    state.last_alarms_provider_status = "primary".to_string();
    state.update_seq += 1;
}

/// Обробка даних альтернативного API Neptun (neptun.in.ua)
async fn process_neptun_alerts(
    val: &Value,
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    exchange_mgr: &Arc<ExchangeLogManager>,
) {
    let mut state = threat_state.write().await;
    let mut active_neptun_ids = HashSet::new();
    let now_iso = Utc::now().to_rfc3339();

    // 1. Області
    if let Some(ob_arr) = val.get("oblasts").and_then(|o| o.as_array()) {
        for ob_item in ob_arr {
            let ob_name = ob_item
                .get("name")
                .or_else(|| ob_item.get("oblast"))
                .and_then(|n| n.as_str())
                .unwrap_or("");

            let level = ob_item.get("level").and_then(|l| l.as_str()).unwrap_or("red");
            let (cat, color, _) = classify_neptun_alert(level);

            let ob_id = detector.get_oblast_id_by_name(ob_name);
            if !ob_id.is_empty() && ob_id != "0" {
                active_neptun_ids.insert(ob_id.clone());
                state.official_alerts.insert(
                    ob_id.clone(),
                    OfficialAlert {
                        id: ob_id,
                        name: ob_name.to_string(),
                        alert: true,
                        alert_type: cat.to_string(),
                        color: color.to_string(),
                        level: "State".to_string(),
                        updated_at: now_iso.clone(),
                    },
                );
            } else if !ob_name.is_empty() {
                exchange_mgr.record_unmapped(
                    "region",
                    ob_name,
                    None,
                    "unmapped",
                    "Neptun Alerts",
                    Some(&format!("Область '{}' не знайдена в словнику детектора", ob_name)),
                );
            }
        }
    }

    // 2. Райони
    if let Some(ra_arr) = val.get("raions").and_then(|r| r.as_array()) {
        for r_item in ra_arr {
            let r_name = r_item.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let level = r_item.get("level").and_then(|l| l.as_str()).unwrap_or("yellow");
            let (cat, color, _) = classify_neptun_alert(level);

            let r_id = detector.get_raion_id_by_name(r_name);
            if !r_id.is_empty() && r_id != "0" {
                active_neptun_ids.insert(r_id.clone());
                state.official_alerts.insert(
                    r_id.clone(),
                    OfficialAlert {
                        id: r_id,
                        name: r_name.to_string(),
                        alert: true,
                        alert_type: cat.to_string(),
                        color: color.to_string(),
                        level: "Raion".to_string(),
                        updated_at: now_iso.clone(),
                    },
                );
            } else if !r_name.is_empty() {
                exchange_mgr.record_unmapped(
                    "region",
                    r_name,
                    None,
                    "unmapped",
                    "Neptun Alerts",
                    Some(&format!("Район '{}' не знайдений в словнику детектора", r_name)),
                );
            }
        }
    }

    // 3. Скидання відбоїв
    for alert in state.official_alerts.values_mut() {
        if !alert.alert {
            continue;
        }

        let should_clear = if alert.level == "State" {
            !active_neptun_ids.contains(&alert.id)
        } else {
            let parent_ob_id = detector.get_oblast_id_by_region(&alert.id);
            if parent_ob_id != "0" {
                !active_neptun_ids.contains(&parent_ob_id) && !active_neptun_ids.contains(&alert.id)
            } else {
                !active_neptun_ids.contains(&alert.id)
            }
        };

        if should_clear {
            alert.alert = false;
            alert.color = "none".to_string();
            alert.alert_type = "none".to_string();
            alert.updated_at = now_iso.clone();
        }
    }

    state.recompute_oblast_alerts(detector);
    state.last_alerts_update_ts = now_sec();
    state.alarms_provider = "Neptun (Резервний)".to_string();
    state.last_alarms_provider_status = "failover".to_string();
    state.update_seq += 1;
}
