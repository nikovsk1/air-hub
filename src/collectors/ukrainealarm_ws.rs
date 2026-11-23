use std::sync::{Arc, OnceLock};
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use regex::Regex;
use reqwest::header::{HeaderValue, ORIGIN, REFERER, USER_AGENT};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::canonical_registry::ExchangeLogManager;
use crate::crypto_decoder::{decode_payload_native, decode_surface_v2_payload, extract_targets, extract_taxonomy, RawExtractedTarget};
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, ThreatState};

const PAGE_URL: &str = "https://map.ukrainealarm.com/onlyMap";

static RE_TOKEN: OnceLock<Regex> = OnceLock::new();
static RE_CHANNEL: OnceLock<Regex> = OnceLock::new();
static RE_WS_URL: OnceLock<Regex> = OnceLock::new();
static RE_SUB_EP: OnceLock<Regex> = OnceLock::new();

/// Уніфікована обробка корисного навантаження (як з Centrifugo WebSocket, так і з REST Fallback)
pub async fn process_ukrainealarm_payload(
    payload: &str,
    source_label: &str,
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    history_mgr: &Arc<HistoryManager>,
    exchange_mgr: &Arc<ExchangeLogManager>,
    storage: &Arc<StorageManager>,
) -> bool {
    process_ukrainealarm_payload_inner(
        payload,
        None,
        source_label,
        threat_state,
        detector,
        history_mgr,
        exchange_mgr,
        storage,
    ).await
}

/// Варіант із підтримкою попередньо розкодованого AST для уникнення повторного ChaCha20-розкодування
#[allow(dead_code)]
pub async fn process_ukrainealarm_payload_decoded(
    payload: &str,
    pre_decoded: Option<Value>,
    source_label: &str,
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    history_mgr: &Arc<HistoryManager>,
    exchange_mgr: &Arc<ExchangeLogManager>,
    storage: &Arc<StorageManager>,
) -> bool {
    process_ukrainealarm_payload_inner(
        payload,
        pre_decoded,
        source_label,
        threat_state,
        detector,
        history_mgr,
        exchange_mgr,
        storage,
    ).await
}

async fn process_ukrainealarm_payload_inner(
    payload: &str,
    pre_decoded: Option<Value>,
    source_label: &str,
    threat_state: &Arc<RwLock<ThreatState>>,
    detector: &Arc<OblastDetector>,
    history_mgr: &Arc<HistoryManager>,
    exchange_mgr: &Arc<ExchangeLogManager>,
    storage: &Arc<StorageManager>,
) -> bool {
    let colon_pos = payload.find(':');
    let prefix = match colon_pos {
        Some(pos) => &payload[..pos + 1],
        None => "",
    };

    // Стратегія адаптивного розпізнавання потоків:
    // 1) Префікс "~s" (~s2:, ~s3:, ~s4: ...) -> Surface SVG-компресований потік
    // 2) Префікс "~" (~5:, ~6:, ~7: ...) -> AST ChaCha20 потік
    // 3) Взаємний fallback: якщо визначений декодер дав збій, тестується альтернативний
    let mut extracted_targets: Option<(Vec<RawExtractedTarget>, &'static str)> = None;

    if prefix.starts_with("~s") {
        match decode_surface_v2_payload(payload) {
            Ok(targets) => {
                extracted_targets = Some((targets, "Surface"));
            }
            Err(e) => {
                debug!("Surface decode failed for {}: {}. Trying AST fallback...", prefix, e);
                let decoded_res = match pre_decoded {
                    Some(d) => Ok(d),
                    None => decode_payload_native(payload),
                };
                if let Ok(decoded) = decoded_res {
                    let targets = extract_targets(&decoded);
                    extracted_targets = Some((targets, "AST (fallback)"));
                } else {
                    warn!("Surface payload decode error for {}: {}", prefix, e);
                }
            }
        }
    } else if prefix.starts_with('~') {
        let decoded_res = match pre_decoded {
            Some(d) => Ok(d),
            None => decode_payload_native(payload),
        };
        match decoded_res {
            Ok(decoded) => {
                let targets = extract_targets(&decoded);
                extracted_targets = Some((targets, "AST"));
                let tax = extract_taxonomy(&decoded);
                static REGISTERED_TAX: OnceLock<parking_lot::RwLock<std::collections::HashSet<i64>>> = OnceLock::new();
                let tax_set = REGISTERED_TAX.get_or_init(|| parking_lot::RwLock::new(std::collections::HashSet::new()));
                for item in tax {
                    let is_new_code = {
                        let r = tax_set.read();
                        !r.contains(&item.code)
                    };
                    if is_new_code {
                        let mut w = tax_set.write();
                        if w.insert(item.code) {
                            let (cat, _) = crate::canonical_registry::classify_target(&item.name_ua, item.code);
                            if cat == "unknown" {
                                exchange_mgr.record_unmapped(
                                    "taxonomy",
                                    &item.name_ua,
                                    Some(item.code),
                                    &item.name_en,
                                    "UkraineAlarm Taxonomy",
                                    Some(&format!("Dynamic taxonomy: code={}, icon={}", item.code, item.icon)),
                                );
                            } else {
                                info!(
                                    "Discovered dynamic taxonomy: code={}, name_ua='{}', icon='{}' -> mapped to '{}'",
                                    item.code, item.name_ua, item.icon, cat
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("AST decode failed for {}: {}. Trying Surface fallback...", prefix, e);
                match decode_surface_v2_payload(payload) {
                    Ok(targets) => {
                        extracted_targets = Some((targets, "Surface (fallback)"));
                    }
                    Err(_) => {
                        warn!("AST payload decode error for {}: {}", prefix, e);
                    }
                }
            }
        }
    } else {
        // Невідомий/новий префікс: евристичний автотест обох декодерів
        if let Ok(targets) = decode_surface_v2_payload(payload) {
            extracted_targets = Some((targets, "Surface (Auto)"));
        } else {
            let decoded_res = match pre_decoded {
                Some(d) => Ok(d),
                None => decode_payload_native(payload),
            };
            if let Ok(decoded) = decoded_res {
                let targets = extract_targets(&decoded);
                extracted_targets = Some((targets, "AST (Auto)"));
            }
        }
    }

    if let Some((extracted, stream_type)) = extracted_targets {
        let ua_stream = storage.get_stream("ukrainealarm_ws");
        let neptun_stream = storage.get_stream("neptun_targets");

        let ua_enabled = ua_stream.as_ref().map(|s| s.enabled).unwrap_or(true);
        if !ua_enabled {
            debug!("WS UkraineAlarm: stream is disabled by admin configuration. Skipping payload commit.");
            return false;
        }

        let neptun_enabled = neptun_stream.as_ref().map(|s| s.enabled).unwrap_or(true);
        let neptun_priority = neptun_stream.as_ref().map(|s| s.priority).unwrap_or(2);
        let ua_priority = ua_stream.as_ref().map(|s| s.priority).unwrap_or(1);

        let mapa_stream = storage.get_stream("mapa_targets");
        let mapa_enabled = mapa_stream.as_ref().map(|s| s.enabled).unwrap_or(true);
        let mapa_priority = mapa_stream.as_ref().map(|s| s.priority).unwrap_or(3);

        // Якщо Neptun Targets або MAPA.UA призначено вищим за пріоритетом потоком
        if (neptun_enabled && neptun_priority < ua_priority) || (mapa_enabled && mapa_priority < ua_priority) {
            debug!("WS UkraineAlarm: Alternative target stream has higher priority. Ignoring secondary WS stream.");
            return false;
        }

        let mut state = threat_state.write().await;
        let provider_name = format!("{} ({})", source_label, stream_type);
        let lost_tracks = state.tracker.update_batch(&extracted, detector, Some(exchange_mgr), &provider_name);
        state.recompute_oblast_alerts(detector);
        let now = now_sec();
        state.last_update_ts = now;
        state.last_targets_update_ts = now;
        state.last_primary_targets_ts = now;
        if source_label.contains("WS") {
            state.last_ws_targets_ts = now;
        }
        state.bump_seq();
        state.upstream_provider = format!("{} ({})", source_label, stream_type);
        state.targets_provider = "WS UkraineAlarm".to_string();
        state.last_targets_provider_status = "active".to_string();
        info!("Updated radar snapshot via {} ({} active targets)", state.upstream_provider, extracted.len());

        // Перевірка прапорця history_recording: уникати зайвих операцій диск/пам'ять при вимкненій історії
        if storage.is_history_recording_enabled() {
            // Синхронізація активних траєкторій в історію з дроселюванням (раз на 15 с для стабільних цілей)
            for trk in state.tracker.tracks.values_mut() {
                let is_new = trk.trajectory.len() <= 1;
                let time_since_hist = now - trk.last_history_sync_ts;
                if is_new || time_since_hist >= 15.0 {
                    history_mgr.record_track(trk, "active");
                    trk.last_history_sync_ts = now;
                }
            }
            // Фіксація завершення польоту зі збереженням повної траєкторії та точного статусу (збито/приліт/втрачено)!
            for trk in &lost_tracks {
                let hist_status = match trk.status.as_str() {
                    "eliminated" => "eliminated",
                    "hit_target" => "hit_target",
                    "superseded" => "superseded",
                    _ => "lost",
                };
                history_mgr.record_track(trk, hist_status);
            }
        }
        true
    } else {
        // Жоден декодер не зміг розпарсити пакет
        let prefix_display = if prefix.is_empty() {
            &payload[..payload.len().min(8)]
        } else {
            prefix
        };

        warn!(
            "{}: unhandled payload format detected! Prefix: '{}', length: {}, preview: '{}'",
            source_label,
            prefix_display,
            payload.len(),
            &payload[..payload.len().min(50)]
        );

        exchange_mgr.record_unmapped(
            "protocol",
            prefix_display,
            None,
            "unsupported_payload_format",
            source_label,
            Some(&format!(
                "Отримано непідтримуваний формат корисного навантаження: '{}' (розмір: {} байт).",
                prefix_display,
                payload.len()
            )),
        );

        false
    }
}

pub async fn run_ukrainealarm_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    http_client: reqwest::Client,
    diia_bridge: Arc<parking_lot::RwLock<crate::diia_relay::DiiaBridgeState>>,
) {
    let re_token = RE_TOKEN.get_or_init(|| Regex::new(r#"id=["']centrifugo-token["'][^>]*value=["']([^"']+)["']"#).unwrap());
    let re_channel = RE_CHANNEL.get_or_init(|| Regex::new(r#"data-target-centrifugo-channel=["']([^"']+)["']"#).unwrap());
    let re_ws_url = RE_WS_URL.get_or_init(|| Regex::new(r#"id=["']centrifugo-url["'][^>]*value=["']([^"']+)["']"#).unwrap());
    let re_sub_ep = RE_SUB_EP.get_or_init(|| Regex::new(r#"data-target-subscribe-endpoint=["']([^"']+)["']"#).unwrap());

    loop {
        let ua_stream = storage.get_stream("ukrainealarm_ws");
        if !ua_stream.as_ref().map(|s| s.enabled).unwrap_or(true) {
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let can_probe = {
            let st = threat_state.read().await;
            st.can_probe_stream("ukrainealarm_ws")
        };
        if !can_probe {
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let configured_diia_cookie = storage.get_service_keys().ukrainealarm_diia_cookie
            .or_else(|| std::env::var("UKRAINEALARM_DIIA_COOKIE").ok())
            .filter(|s| !s.trim().is_empty());

        if configured_diia_cookie.is_none() {
            {
                let mut state = threat_state.write().await;
                state.report_stream_failure("ukrainealarm_ws", "Немає авторизаційної куки Дії");
                let all_streams = storage.get_streams();
                state.recompute_all_stream_statuses(&all_streams);
            }
            sleep(Duration::from_secs(10)).await;
            continue;
        }

        info!("Connecting to UkraineAlarm Centrifugo WebSocket upstream...");

        let browser_ua = crate::diia_relay::get_browser_ua();
        let page_resp = match http_client
            .get(PAGE_URL)
            .header(USER_AGENT, &browser_ua)
            .header(ORIGIN, "https://map.ukrainealarm.com")
            .header(REFERER, "https://map.ukrainealarm.com/")
            .header("sec-ch-ua", crate::diia_relay::SEC_CH_UA)
            .header("sec-ch-ua-mobile", crate::diia_relay::SEC_CH_UA_MOBILE)
            .header("sec-ch-ua-platform", crate::diia_relay::SEC_CH_UA_PLATFORM)
            .header("sec-ch-ua-arch", crate::diia_relay::SEC_CH_UA_ARCH)
            .header("sec-ch-ua-bitness", crate::diia_relay::SEC_CH_UA_BITNESS)
            .header("sec-ch-ua-full-version", crate::diia_relay::SEC_CH_UA_FULL_VERSION)
            .header("sec-ch-ua-platform-version", crate::diia_relay::SEC_CH_UA_PLATFORM_VERSION)
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "none")
            .header("sec-fetch-user", "?1")
            .header("upgrade-insecure-requests", "1")
            .timeout(Duration::from_secs(12))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to fetch onlyMap page: {}. Retrying in 6s...", e);
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };

        // Витяг сесійних кук та комбінування з авторизаційною кукою Дії (DiiaMapAccess)
        let configured_diia_cookie = storage.get_service_keys().ukrainealarm_diia_cookie
            .or_else(|| std::env::var("UKRAINEALARM_DIIA_COOKIE").ok())
            .filter(|s| !s.trim().is_empty());
        let initial_diia_cookie = configured_diia_cookie.clone();

        let mut session_cookies = Vec::new();
        if let Some(ref diia) = configured_diia_cookie {
            session_cookies.push(diia.clone());
        }
        for cookie_header in page_resp.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(s) = cookie_header.to_str() {
                if let Some(c) = s.split(';').next() {
                    let trimmed = c.trim();
                    let prefix = trimmed.split('=').next().unwrap_or("");
                    if !trimmed.is_empty() && !session_cookies.iter().any(|existing| existing.contains(prefix)) {
                        session_cookies.push(trimmed.to_string());
                    }
                }
            }
        }
        let cookie_header_val = if !session_cookies.is_empty() {
            HeaderValue::from_str(&session_cookies.join("; ")).ok()
        } else {
            None
        };

        let html = match page_resp.text().await {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to read onlyMap body: {}. Retrying in 6s...", e);
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };

        let auth_token = match re_token.captures(&html).and_then(|c| c.get(1)) {
            Some(m) => m.as_str().to_string(),
            None => {
                warn!("No centrifugo-token found on page. Retrying in 6s...");
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };

        let channel = re_channel
            .captures(&html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "$r_09f4c276b81de5a3".to_string());

        let ws_url = re_ws_url
            .captures(&html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "wss://ws.ukrainealarm.com/connection/websocket".to_string());

        let sub_ep = re_sub_ep
            .captures(&html)
            .and_then(|c| c.get(1))
            .map(|m| format!("https://map.ukrainealarm.com{}", m.as_str()))
            .unwrap_or_else(|| "https://map.ukrainealarm.com/api/centrifuge/map/diia/subscribe".to_string());

        let mut req = match ws_url.into_client_request() {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid WS URL: {}. Retrying in 6s...", e);
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };
        req.headers_mut().insert(ORIGIN, HeaderValue::from_static("https://map.ukrainealarm.com"));
        if let Some(ref c_val) = cookie_header_val {
            req.headers_mut().insert(reqwest::header::COOKIE, c_val.clone());
        }

        let (ws_stream, _) = match connect_async(req).await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("WebSocket connect failed: {}. Retrying in 6s...", e);
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };

        let (mut write, mut read) = ws_stream.split();

        // 1. Handshake
        let connect_msg = json!({
            "params": {
                "token": auth_token,
                "name": "js"
            },
            "id": 1
        });

        if let Err(e) = write.send(Message::Text(connect_msg.to_string())).await {
            warn!("Failed to send connect message: {}", e);
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        info!("Connected to Centrifugo WebSocket. Awaiting client ID...");
        // Do NOT refresh last_primary_targets_ts on raw TCP connection before Diia authentication succeeds.

        loop {
            let ua_stream = storage.get_stream("ukrainealarm_ws");
            if !ua_stream.as_ref().map(|s| s.enabled).unwrap_or(true) {
                info!("UkraineAlarm WS disabled in admin config. Disconnecting WebSocket.");
                break;
            }

            // Миттєве виявлення оновлення сесії Дії через адмінку
            let current_diia_cookie = storage.get_service_keys().ukrainealarm_diia_cookie
                .or_else(|| std::env::var("UKRAINEALARM_DIIA_COOKIE").ok())
                .filter(|s| !s.trim().is_empty());
            if current_diia_cookie != initial_diia_cookie {
                info!("UkraineAlarm WS: detected updated Diia session cookie in configuration. Reconnecting to Centrifugo...");
                break;
            }

            let msg_res = match tokio::time::timeout(Duration::from_secs(45), read.next()).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    warn!("UkraineAlarm Centrifugo WS connection closed by server. Reconnecting in 5s...");
                    break;
                }
                Err(_) => {
                    warn!("UkraineAlarm Centrifugo WS silent >45s (ping/heartbeat timeout). Reconnecting...");
                    break;
                }
            };

            let msg = match msg_res {
                Ok(m) => m,
                Err(e) => {
                    warn!("WebSocket error: {}. Reconnecting...", e);
                    break;
                }
            };

            let text = match msg {
                Message::Text(t) => t,
                Message::Ping(p) => {
                    let _ = write.send(Message::Pong(p)).await;
                    continue;
                }
                _ => continue,
            };

            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed == r#"{"id":0}"# {
                    continue;
                }
                // Відповідь на Centrifugo heartbeat ping для запобігання обриву з'єднання кожні 25с
                if trimmed == "{}" {
                    let _ = write.send(Message::Text("{}".to_string())).await;
                    continue;
                }

                let val: Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // Відповідь на підключення: отримано client_id -> підписка на канал
                if val.get("id").and_then(|id| id.as_i64()) == Some(1) {
                    let client_id = val.get("result")
                        .and_then(|r| r.get("client"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("");

                    if !client_id.is_empty() {
                        let mut sub_builder = crate::diia_relay::apply_browser_headers(http_client.post(&sub_ep))
                            .timeout(Duration::from_secs(6))
                            .header(REFERER, "https://map.ukrainealarm.com/onlyMap");

                        if let Some(ref c_val) = cookie_header_val {
                            sub_builder = sub_builder.header(reqwest::header::COOKIE, c_val.clone());
                        }

                        let sub_res = sub_builder
                            .json(&json!({
                                "client": client_id,
                                "channels": [channel]
                            }))
                            .send()
                            .await;

                        match sub_res {
                            Ok(resp) => {
                                let status = resp.status();
                                if !status.is_success() {
                                    warn!("Centrifugo subscription rejected on {}: HTTP {}", sub_ep, status);
                                    if status.as_u16() == 401 || status.as_u16() == 403 {
                                        warn!("Diia authorization session expired or rejected on {}. Please re-authorize via Admin Panel.", sub_ep);
                                        {
                                            let mut d_guard = diia_bridge.write();
                                            // Не затирати статус, якщо прямо зараз користувач сканує новий QR-код (pending)!
                                            if d_guard.status != "pending" {
                                                d_guard.status = "expired".to_string();
                                                d_guard.last_error = Some(format!("Сесію Дії вичерпано або відхилено сервером (HTTP {})", status));
                                            }
                                        }
                                        {
                                            let mut state = threat_state.write().await;
                                            state.last_targets_provider_status = "offline".to_string();
                                            state.last_primary_targets_ts = 0.0;
                                            state.last_ws_targets_ts = 0.0;
                                            state.report_stream_failure("ukrainealarm_ws", &format!("Сесію Дії вичерпано або відхилено (HTTP {})", status));
                                            let all_streams = storage.get_streams();
                                            state.recompute_all_stream_statuses(&all_streams);
                                        }
                                        let sleep_secs = {
                                            let state = threat_state.read().await;
                                            state.get_stream_runtime_status("ukrainealarm_ws")
                                                .map(|s| (s.next_probe_ts - now_sec()).max(5.0) as u64)
                                                .unwrap_or(60)
                                        };
                                        sleep(Duration::from_secs(sleep_secs)).await;
                                    }
                                } else if let Ok(sub_data) = resp.json::<Value>().await {
                                    {
                                        let mut d_guard = diia_bridge.write();
                                        d_guard.status = "authorized".to_string();
                                        d_guard.last_error = None;
                                    }
                                    let mut stoken = None;
                                    if let Some(chs) = sub_data.get("channels").and_then(|c| c.as_array()) {
                                        for ch in chs {
                                            if ch.get("channel").and_then(|s| s.as_str()) == Some(&channel) {
                                                stoken = ch.get("token").and_then(|t| t.as_str()).map(|s| s.to_string());
                                            }
                                        }
                                    }
                                    if stoken.is_none() {
                                        if let Some(ch_obj) = sub_data.get(&channel).and_then(|o| o.as_object()) {
                                            stoken = ch_obj.get("token").and_then(|t| t.as_str()).map(|s| s.to_string());
                                        }
                                    }

                                    if let Some(token) = stoken {
                                        let sub_frame = json!({
                                            "method": 1,
                                            "params": {
                                                "channel": channel,
                                                "token": token
                                            },
                                            "id": 4
                                        });
                                        let _ = write.send(Message::Text(sub_frame.to_string())).await;
                                        info!("Successfully subscribed to Centrifugo channel: {}", channel);
                                        let is_ua_primary = {
                                            let ua_s = storage.get_stream("ukrainealarm_ws");
                                            let nep_s = storage.get_stream("neptun_targets");
                                            let map_s = storage.get_stream("mapa_targets");
                                            let ua_en = ua_s.as_ref().map(|s| s.enabled).unwrap_or(true);
                                            let nep_en = nep_s.as_ref().map(|s| s.enabled).unwrap_or(true);
                                            let map_en = map_s.as_ref().map(|s| s.enabled).unwrap_or(true);
                                            let ua_p = ua_s.as_ref().map(|s| s.priority).unwrap_or(1);
                                            let nep_p = nep_s.as_ref().map(|s| s.priority).unwrap_or(2);
                                            let map_p = map_s.as_ref().map(|s| s.priority).unwrap_or(3);
                                            ua_en && (!nep_en || ua_p <= nep_p) && (!map_en || ua_p <= map_p)
                                        };
                                        {
                                            let mut state = threat_state.write().await;
                                            state.last_primary_targets_ts = now_sec();
                                            state.last_ws_targets_ts = now_sec();
                                            state.report_stream_success("ukrainealarm_ws");
                                            let all_streams = storage.get_streams();
                                            state.recompute_all_stream_statuses(&all_streams);
                                            if is_ua_primary {
                                                state.targets_provider = "WS UkraineAlarm".to_string();
                                            }
                                        }
                                    } else {
                                        warn!("Could not extract subscription token from response: {:?}", sub_data);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("HTTP error during Centrifugo subscription: {}", e);
                            }
                        }
                    }
                    continue;
                }

                // Універсальний витяг корисного навантаження (~5:...) через JSON-pointer
                let payload = val.pointer("/result/data/data/n")
                    .or_else(|| val.pointer("/result/data/n"))
                    .or_else(|| val.pointer("/result/n"))
                    .or_else(|| val.pointer("/push/pub/data/data/n"))
                    .or_else(|| val.pointer("/push/pub/data/n"))
                    .or_else(|| val.pointer("/push/pub/n"))
                    .or_else(|| val.pointer("/pub/data/n"))
                    .or_else(|| val.pointer("/data/n"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if !payload.is_empty() {
                    process_ukrainealarm_payload(
                        payload,
                        "UkraineAlarm WS",
                        &threat_state,
                        &detector,
                        &history_mgr,
                        &exchange_mgr,
                        &storage,
                    ).await;
                }
            }
        }

        {
            let mut state = threat_state.write().await;
            state.report_stream_failure("ukrainealarm_ws", "З'єднання розірвано");
            let all_streams = storage.get_streams();
            state.recompute_all_stream_statuses(&all_streams);
        }
        let sleep_secs = {
            let state = threat_state.read().await;
            state.get_stream_runtime_status("ukrainealarm_ws")
                .map(|s| (s.next_probe_ts - now_sec()).max(5.0) as u64)
                .unwrap_or(60)
        };
        sleep(Duration::from_secs(sleep_secs)).await;
    }
}
