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
use crate::config::{NEPTUN_ALERTS_POLL_INTERVAL_SEC, UKRAINEALARM_ALERTS_POLL_INTERVAL_SEC};
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, OfficialAlert, ThreatState};

const UKRAINEALARM_ALERTS_URL: &str = "https://api.ukrainealarm.com/api/v3/alerts";
const API_UA: &str = "AirAlertHub-Backend/1.0 (Commercial Partner Integration)";

/// Уніфікований фоновий сервіс збору офіційних тривог:
/// 1. Головне джерело (за замовчуванням): Офіційний REST API api.ukrainealarm.com/api/v3/alerts
///    - Комерційний/партнерський токен
///    - ОДИН прямий запит кожні 15 секунд (без проміжних викликів /status та без mapUpdate)
///    - Чесний заголовок User-Agent: AirAlertHub-Backend/1.0
/// 2. Резервне джерело / Альтернативний первинний потік: Neptun Alerts
///    - Працює ВИКЛЮЧНО через чистий WebSocket stream (wss://neptun.in.ua/api/v1/stream) в neptun_failover
///    - Жодного REST до neptun.in.ua/api/v1/alerts!
pub async fn run_alerts_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    storage: Arc<StorageManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    http_client: reqwest::Client,
) {
    let mut consecutive_ua_failures: u32 = 0;
    let mut ua_cooldown_until: f64 = 0.0;
    let mut last_provider_log = String::new();

    let mut poll_interval_secs: u64 = std::env::var("ALERTS_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(UKRAINEALARM_ALERTS_POLL_INTERVAL_SEC)
        .clamp(10, 300);

    info!(
        "Alerts collector initialized: primary interval = {}s (UkraineAlarm API v3 direct poll), fallback interval = {}s (Neptun Alerts)",
        poll_interval_secs, NEPTUN_ALERTS_POLL_INTERVAL_SEC
    );

    loop {
        let ua_stream = storage.get_stream("ukrainealarm_alerts");
        let neptun_stream = storage.get_stream("neptun_alerts");

        let ua_enabled = ua_stream.as_ref().map(|s| s.enabled).unwrap_or(true);
        let neptun_enabled = neptun_stream.as_ref().map(|s| s.enabled).unwrap_or(true);

        let ua_priority = ua_stream.as_ref().map(|s| s.priority).unwrap_or(1);
        let neptun_priority = neptun_stream.as_ref().map(|s| s.priority).unwrap_or(2);

        let configured_ua_interval = ua_stream.as_ref().map(|s| s.poll_interval_sec).unwrap_or(15).max(10);
        let neptun_poll_interval = neptun_stream.as_ref().map(|s| s.poll_interval_sec).unwrap_or(6).max(3);

        if poll_interval_secs < configured_ua_interval && poll_interval_secs < 60 {
            poll_interval_secs = configured_ua_interval;
        }

        if !ua_enabled && !neptun_enabled {
            debug!("Alerts collector: all alert streams are disabled by admin configuration");
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let is_neptun_primary = neptun_enabled && (!ua_enabled || neptun_priority < ua_priority);

        let service_keys = storage.get_service_keys();
        let ua_token = service_keys
            .ukrainealarm_api_token
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                std::env::var("UKRAINEALARM_API_TOKEN")
                    .or_else(|_| std::env::var("UKRAINEALARM_API_KEY"))
                    .ok()
                    .filter(|t| !t.trim().is_empty())
            });

        let now = now_sec();
        let mut used_primary = false;

        // ЯКЩО NEPTUN ПРИЗНАЧЕНО ОСНОВНИМ ПОТОКОМ ТРИВОГ (Пріоритет #1)
        if is_neptun_primary {
            let (neptun_active, neptun_timeout) = {
                let st = threat_state.read().await;
                let to = neptun_stream.as_ref().map(|s| s.failover_timeout_sec).unwrap_or(15.0).max(5.0);
                let alive = st.alarms_provider.contains("Neptun") && (now - st.last_alerts_update_ts) <= to;
                (alive, to)
            };

            if neptun_active {
                if last_provider_log != "Neptun Alerts (Primary)" {
                    info!("Alerts collector: Neptun Alerts is PRIMARY engine (pure WebSocket). UkraineAlarm API v3 in standby.");
                    last_provider_log = "Neptun Alerts (Primary)".to_string();
                }
                sleep(Duration::from_secs(neptun_poll_interval)).await;
                continue;
            } else {
                debug!("Neptun primary WebSocket alerts silent > {:.0}s. Engaging UkraineAlarm API v3 as failover...", neptun_timeout);
            }
        }

        // ЯКЩО UKRAINEALARM УВІМКНЕНО
        if ua_enabled {
            if let Some(token) = ua_token {
                let should_try_ua = now >= ua_cooldown_until;

                if should_try_ua {
                    // =========================================================================
                    // ОСНОВНИЙ РУШІЙ: Офіційний API v3 (api.ukrainealarm.com/api/v3/alerts)
                    // Прямий запит (квота: 1 req/60s для стандартного токена, 1 req/15s для комерційного)
                    // =========================================================================
                    if last_provider_log != "UkraineAlarm API v3" {
                        info!("Alerts collector: using UkraineAlarm Official API v3 ({}s direct poll)", poll_interval_secs);
                        last_provider_log = "UkraineAlarm API v3".to_string();
                    }

                    let auth_val = HeaderValue::from_str(&token).unwrap_or_else(|_| HeaderValue::from_static(""));

                    let alerts_res = http_client
                        .get(UKRAINEALARM_ALERTS_URL)
                        .header(AUTHORIZATION, auth_val)
                        .header(USER_AGENT, API_UA)
                        .header(reqwest::header::ACCEPT, "application/json")
                        .timeout(Duration::from_secs(8))
                        .send()
                        .await;

                    match alerts_res {
                        Ok(resp) if resp.status().is_success() => {
                            if consecutive_ua_failures > 0 {
                                info!("UkraineAlarm API v3 connection restored successfully");
                            }
                            consecutive_ua_failures = 0;
                            ua_cooldown_until = 0.0;
                            {
                                let mut st = threat_state.write().await;
                                st.ua_alerts_cooldown_until = 0.0;
                            }
                            used_primary = true;

                            if let Ok(alerts_val) = resp.json::<Value>().await {
                                if let Some(regions_arr) = alerts_val.as_array() {
                                    process_ukrainealarm_v3_alerts(
                                        regions_arr,
                                        &threat_state,
                                        &detector,
                                        &exchange_mgr,
                                        "UkraineAlarm (API v3)",
                                    )
                                    .await;
                                }
                            }
                        }
                        Ok(resp) if resp.status().as_u16() == 429 => {
                            // Отримано HTTP 429 Too Many Requests: читаємо Retry-After (+2с буфер)
                            let retry_after = resp
                                .headers()
                                .get(reqwest::header::RETRY_AFTER)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(60);

                            let total_cooldown = retry_after + 2;
                            if poll_interval_secs < 60 {
                                warn!(
                                    "UkraineAlarm API v3 returned HTTP 429 (token quota is 1 req/60s). Auto-adjusting poll interval from {}s to 60s to prevent lockouts. Cooling down for {}s",
                                    poll_interval_secs, total_cooldown
                                );
                                poll_interval_secs = 60;
                            } else {
                                warn!(
                                    "UkraineAlarm API v3 returned HTTP 429 Too Many Requests. Cooling down for {}s (failures={})",
                                    total_cooldown,
                                    consecutive_ua_failures + 1
                                );
                            }
                            consecutive_ua_failures += 1;
                            ua_cooldown_until = now_sec() + (total_cooldown as f64);
                            {
                                let mut st = threat_state.write().await;
                                st.ua_alerts_cooldown_until = ua_cooldown_until;
                            }
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
                            {
                                let mut st = threat_state.write().await;
                                st.ua_alerts_cooldown_until = ua_cooldown_until;
                            }
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
                            {
                                let mut st = threat_state.write().await;
                                st.ua_alerts_cooldown_until = ua_cooldown_until;
                            }
                        }
                    }
                } else {
                    debug!(
                        "UkraineAlarm API v3 in cooldown for next {:.0}s, checking backup stream",
                        ua_cooldown_until - now
                    );
                }
            }
        }

        // =========================================================================
        // РЕЗЕРВНЕ ОЧІКУВАННЯ: Якщо UkraineAlarm не спрацював (cooldown / помилка мережі)
        // Neptun Alerts обробляється автономним арбітром neptun_alerts через чистий WebSocket!
        // Жодних HTTP REST викликів не виконується!
        // =========================================================================
        if !used_primary {
            if neptun_enabled {
                if last_provider_log != "Neptun Alerts Failover Standby" {
                    info!("Alerts collector: UkraineAlarm silent/cooldown. Failover active via Neptun pure WebSocket stream.");
                    last_provider_log = "Neptun Alerts Failover Standby".to_string();
                }
            } else {
                debug!("Alerts collector: UkraineAlarm unavailable and Neptun backup is disabled. Waiting for retry...");
            }
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        // Штатний інтервал опитування основного джерела (15 секунд)
        sleep(Duration::from_secs(poll_interval_secs)).await;
    }
}

/// Обробка даних офіційного API v3 (api.ukrainealarm.com)
async fn process_ukrainealarm_v3_alerts(
    regions_arr: &[Value],
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    exchange_mgr: &Arc<ExchangeLogManager>,
    provider_name: &str,
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
                    let raw_level = a.get("level").and_then(|l| l.as_str())
                        .or_else(|| a.get("alertLevel").and_then(|l| l.as_str()))
                        .or_else(|| a.pointer("/activeAlertLevels/0/alertLevel").and_then(|l| l.as_str()));

                    let (mapped_cat, mapped_color, _) = classify_official_alert(raw_type, raw_level);
                    if mapped_color == "red" || color != "red" {
                        color = mapped_color.to_string();
                        alert_type = mapped_cat.to_string();
                    }

                    // Перевірка причини тривоги (МіГ-31К тощо)
                    let rsn_opt = a.get("reason").and_then(|s| s.as_str())
                        .or_else(|| a.pointer("/activeAlertLevels/0/reason").and_then(|s| s.as_str()));
                    if let Some(rsn) = rsn_opt {
                        let lower_r = rsn.to_lowercase();
                        if lower_r.contains("міг-31") || lower_r.contains("mig-31") {
                            mig_detected = true;
                        }
                        if !rsn.is_empty() && !reasons.contains(&rsn.to_string()) {
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
    state.alarms_provider = provider_name.to_string();
    state.last_alarms_provider_status = "primary".to_string();
    state.update_seq += 1;
}

/// Обробка даних альтернативного API Neptun (neptun.in.ua) - підтримує як REST, так і WebSocket фрейми
pub async fn process_neptun_alerts(
    val: &Value,
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    exchange_mgr: &Arc<ExchangeLogManager>,
    provider_name: &str,
    status_str: &str,
) {
    let mut state = threat_state.write().await;
    let mut active_neptun_ids = HashSet::new();
    let now_iso = Utc::now().to_rfc3339();

    let alerts_data = val.get("data").unwrap_or(val);

    // 1. Області
    if let Some(ob_arr) = alerts_data.get("oblasts").and_then(|o| o.as_array()) {
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
    if let Some(ra_arr) = alerts_data.get("raions").and_then(|r| r.as_array()) {
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
    state.alarms_provider = provider_name.to_string();
    state.last_alarms_provider_status = status_str.to_string();
    state.update_seq += 1;
}
