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
use crate::crypto_decoder::{decode_payload_native, decode_surface_v2_payload, extract_snapshot_meta, extract_targets, extract_taxonomy, RawExtractedTarget};
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, ThreatState};

const PAGE_URL: &str = "https://map.ukrainealarm.com/onlyMap";
const FALLBACK_URL: &str = "https://map.ukrainealarm.com/api/centrifuge/map/fallback";
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36";

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
                            exchange_mgr.record_unmapped(
                                "taxonomy",
                                &item.name_ua,
                                Some(item.code),
                                &item.name_en,
                                "UkraineAlarm Taxonomy",
                                Some(&format!("Dynamic taxonomy: code={}, icon={}", item.code, item.icon)),
                            );
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
        state.update_seq += 1;
        state.upstream_provider = format!("{} ({})", source_label, stream_type);
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
            // Фіксація завершення польоту зі збереженням повної траєкторії!
            for trk in &lost_tracks {
                history_mgr.record_track(trk, "lost");
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
) {
    let re_token = Regex::new(r#"id=["']centrifugo-token["'][^>]*value=["']([^"']+)["']"#).unwrap();
    let re_channel = Regex::new(r#"data-target-centrifugo-channel=["']([^"']+)["']"#).unwrap();
    let re_ws_url = Regex::new(r#"id=["']centrifugo-url["'][^>]*value=["']([^"']+)["']"#).unwrap();
    let re_sub_ep = Regex::new(r#"data-target-subscribe-endpoint=["']([^"']+)["']"#).unwrap();

    loop {
        info!("Connecting to UkraineAlarm Centrifugo WebSocket upstream...");

        let page_resp = match http_client
            .get(PAGE_URL)
            .header(USER_AGENT, BROWSER_UA)
            .header(ORIGIN, "https://map.ukrainealarm.com")
            .header(REFERER, "https://map.ukrainealarm.com/")
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
            .unwrap_or_else(|| "https://map.ukrainealarm.com/api/centrifuge/map/subscribe".to_string());

        let mut req = match ws_url.into_client_request() {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid WS URL: {}. Retrying in 6s...", e);
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };
        req.headers_mut().insert(ORIGIN, HeaderValue::from_static("https://map.ukrainealarm.com"));

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

        while let Some(msg_res) = read.next().await {
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
                        let sub_res = http_client
                            .post(&sub_ep)
                            .timeout(Duration::from_secs(6))
                            .header(USER_AGENT, BROWSER_UA)
                            .header(ORIGIN, "https://map.ukrainealarm.com")
                            .header(REFERER, "https://map.ukrainealarm.com/onlyMap")
                            .header("X-Requested-With", "XMLHttpRequest")
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
                                } else if let Ok(sub_data) = resp.json::<Value>().await {
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

        sleep(Duration::from_secs(5)).await;
    }
}

/// Фоновий збирач Tier 2 REST Fallback для UkraineAlarm:
/// Активується, якщо Centrifugo WebSocket мовчить понад 8 секунд.
/// Опитує https://map.ukrainealarm.com/api/centrifuge/map/fallback кожні 8-10 секунд
/// та декодує знімок цілей без повторних ChaCha20 операцій.
pub async fn run_ukrainealarm_http_fallback(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    http_client: reqwest::Client,
) {
    info!("Starting Cold Start bootstrap from UkraineAlarm Fallback...");
    let mut last_hash: Option<String> = None;
    let mut last_raw_payload: Option<String> = None;
    let mut last_fetch_instant = std::time::Instant::now() - Duration::from_secs(20);

    // 1. Cold Start Bootstrap: негайно отримуємо повний знімок активних цілей та їхніх хвостів
    {
        let req = http_client
            .get(FALLBACK_URL)
            .header(USER_AGENT, BROWSER_UA)
            .header(ORIGIN, "https://map.ukrainealarm.com")
            .header(REFERER, "https://map.ukrainealarm.com/")
            .header("X-Requested-With", "XMLHttpRequest")
            .timeout(Duration::from_secs(8));

        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<Value>().await {
                    if let Some(payload) = data.get("n").and_then(|v| v.as_str()) {
                        if !payload.is_empty() {
                            last_raw_payload = Some(payload.to_string());
                            let mut pre_decoded = None;
                            if payload.starts_with('~') && !payload.starts_with("~s") {
                                if let Ok(decoded) = decode_payload_native(payload) {
                                    let meta = extract_snapshot_meta(&decoded);
                                    last_hash = meta.revision_hash;
                                    pre_decoded = Some(decoded);
                                }
                            }
                            let ok = process_ukrainealarm_payload_decoded(
                                payload,
                                pre_decoded,
                                "UkraineAlarm Fallback (Cold Start)",
                                &threat_state,
                                &detector,
                                &history_mgr,
                                &exchange_mgr,
                                &storage,
                            ).await;
                            if ok {
                                info!("Cold Start bootstrap successfully initialized active radar targets and historical trails");
                            }
                        }
                    }
                }
            }
            last_fetch_instant = std::time::Instant::now();
        }
    }

    // 2. Dual-Stack Smart Fusion Engine
    loop {
        let ws_silence_sec = {
            let state = threat_state.read().await;
            now_sec() - state.last_ws_targets_ts
        };

        // Якщо WebSocket стабільно постачає дані (мовчання <= 8.0 сек), Fallback не втручається
        if ws_silence_sec <= 8.0 {
            sleep(Duration::from_millis(2000)).await;
            continue;
        }

        // Якщо WebSocket мовчить > 8.0 сек: Fallback стає основним джерелом і опитує кожні 8.0 сек
        let elapsed = last_fetch_instant.elapsed();
        if elapsed < Duration::from_millis(8000) {
            sleep(Duration::from_millis(8000) - elapsed).await;
        }

        debug!(
            "Polling UkraineAlarm Fallback (WS silence: {:.1}s, last_hash: {:?})...",
            ws_silence_sec, last_hash
        );

        let req = http_client
            .get(FALLBACK_URL)
            .header(USER_AGENT, BROWSER_UA)
            .header(ORIGIN, "https://map.ukrainealarm.com")
            .header(REFERER, "https://map.ukrainealarm.com/")
            .header("X-Requested-With", "XMLHttpRequest")
            .timeout(Duration::from_secs(8));

        last_fetch_instant = std::time::Instant::now();

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    match resp.json::<Value>().await {
                        Ok(data) => {
                            let payload = data.get("n").and_then(|v| v.as_str()).unwrap_or("");
                            if !payload.is_empty() {
                                // 1. Швидка перевірка сирого тексту: якщо payload ідентичний, пропускаємо розбір (0% CPU)
                                if last_raw_payload.as_deref() == Some(payload) {
                                    debug!("Fallback snapshot raw payload identical, skipping redundant update");
                                    sleep(Duration::from_millis(1000)).await;
                                    continue;
                                }

                                // 2. Якщо це AST потік, декодуємо один раз і перевіряємо revision_hash
                                let mut skip_reprocessing = false;
                                let mut pre_decoded = None;
                                if payload.starts_with('~') && !payload.starts_with("~s") {
                                    if let Ok(decoded) = decode_payload_native(payload) {
                                        let meta = extract_snapshot_meta(&decoded);
                                        if let Some(ref h) = meta.revision_hash {
                                            if last_hash.as_ref() == Some(h) {
                                                debug!("Fallback snapshot hash {:?} unchanged, skipping redundant update", h);
                                                skip_reprocessing = true;
                                            } else {
                                                last_hash = Some(h.clone());
                                            }
                                        }
                                        pre_decoded = Some(decoded);
                                    }
                                }

                                last_raw_payload = Some(payload.to_string());

                                if !skip_reprocessing {
                                    let _success = process_ukrainealarm_payload_decoded(
                                        payload,
                                        pre_decoded,
                                        "UkraineAlarm HTTP Fallback",
                                        &threat_state,
                                        &detector,
                                        &history_mgr,
                                        &exchange_mgr,
                                        &storage,
                                    ).await;
                                }
                            } else {
                                warn!("HTTP fallback response has empty 'n' payload field");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse HTTP fallback JSON: {}", e);
                        }
                    }
                } else if status.as_u16() == 429 {
                    warn!("HTTP 429 Too Many Requests from Fallback endpoint. Backing off for 20s...");
                    sleep(Duration::from_secs(20)).await;
                } else {
                    warn!("HTTP fallback endpoint returned HTTP {}", status);
                }
            }
            Err(e) => {
                debug!("HTTP fallback request error: {}", e);
            }
        }

        sleep(Duration::from_millis(1000)).await;
    }
}
