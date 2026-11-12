use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use reqwest::header::{HeaderValue, ORIGIN, REFERER, USER_AGENT};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::canonical_registry::ExchangeLogManager;
use crate::collectors::alerts_collector::process_neptun_alerts;
use crate::config::TARGETS_STARTUP_GRACE_PERIOD_SEC;
use crate::crypto_decoder::RawExtractedTarget;
use crate::geo_math::calculate_bearing;
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::storage::StorageManager;
use crate::tracker::{now_sec, ThreatState};

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

#[derive(Default, Debug)]
pub struct NeptunAlertsBuffer {
    pub raw_data: Option<Value>,
    pub last_received_ts: f64,
}

#[derive(Default, Debug)]
pub struct NeptunTargetsBuffer {
    pub targets: HashMap<String, RawExtractedTarget>,
    pub pending_removals: Vec<String>,
    pub last_received_ts: f64,
}

pub fn parse_single_neptun_threat(t: &Value) -> Option<RawExtractedTarget> {
    let lat = t.get("lat")
        .or_else(|| t.get("latitude"))
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0.0);
    let lon = t.get("lon")
        .or_else(|| t.get("lng"))
        .or_else(|| t.get("longitude"))
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0.0);

    if lat == 0.0 && lon == 0.0 {
        return None;
    }

    let mut heading = t.get("heading")
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0.0);

    let mut trail_pts = Vec::new();
    if let Some(trail) = t.get("trail").and_then(|tr| tr.as_array()) {
        for pt in trail {
            if let Some(coords) = pt.as_array() {
                if coords.len() >= 2 {
                    let c0 = coords[0].as_f64().unwrap_or(0.0);
                    let c1 = coords[1].as_f64().unwrap_or(0.0);
                    if c0 > 40.0 && c0 < 55.0 {
                        trail_pts.push((c0, c1));
                    } else if c1 > 40.0 && c1 < 55.0 {
                        trail_pts.push((c1, c0));
                    }
                }
            } else if let (Some(p_lat), Some(p_lon)) = (
                pt.get("lat").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))),
                pt.get("lon").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))),
            ) {
                trail_pts.push((p_lat, p_lon));
            }
        }
    }

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

    let raw_type = t.get("type").and_then(|v| v.as_str()).unwrap_or("uav");
    let title = t.get("title").and_then(|v| v.as_str()).unwrap_or("");
    let expl = t.get("explanationShort").and_then(|v| v.as_str()).unwrap_or("");
    let raw_combined = format!("{} {} {}", raw_type, title, expl);

    let raw_code = match raw_type {
        "uav" => 8,
        "missile" | "ballistic" => 3,
        _ => 0,
    };

    let id = t.get("id")
        .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string())))
        .unwrap_or_else(|| format!("nep_{:.4}_{:.4}", lat, lon));

    let speed_kmh = t.get("speed_kmh").or_else(|| t.get("speed")).and_then(|v| v.as_f64());

    let raw_status = t.get("status")
        .or_else(|| t.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("active");
    let upstream_status = match raw_status {
        "active" => "active",
        "lost" | "disappeared" => "lost",
        "eliminated" | "destroyed" | "shot_down" | "downed" => "eliminated",
        "hit" | "impact" | "hit_target" => "hit_target",
        "remove" | "removed" | "cancelled" | "deleted" => "remove",
        _ => "active",
    }.to_string();

    Some(RawExtractedTarget {
        id,
        lat,
        lon,
        raw_name: raw_combined,
        raw_type_code: raw_code,
        heading_deg: heading,
        speed_kmh,
        confidence: Some(90),
        time_offset_ms: None,
        trail_points: trail_pts,
        upstream_status,
    })
}

pub fn parse_neptun_threats_list(val: &Value) -> Vec<RawExtractedTarget> {
    let threats_opt = val.get("threats").and_then(|t| t.as_array())
        .or_else(|| val.get("data").and_then(|t| t.as_array()))
        .or_else(|| val.get("targets").and_then(|t| t.as_array()))
        .or_else(|| val.as_array());

    let mut extracted = Vec::new();
    if let Some(arr) = threats_opt {
        for t in arr {
            if let Some(target) = parse_single_neptun_threat(t) {
                extracted.push(target);
            }
        }
    }
    extracted
}

/// Фрейм-диспетчер єдиного WebSocket з'єднання Neptun (Split-Stream Arbiter)
async fn run_neptun_ws_dispatcher(
    alerts_buf: Arc<RwLock<NeptunAlertsBuffer>>,
    targets_buf: Arc<RwLock<NeptunTargetsBuffer>>,
) {
    let ws_url = "wss://neptun.in.ua/api/v1/stream";
    info!("Neptun Split-Stream Arbiter: initializing WebSocket stream dispatcher ({})", ws_url);

    loop {
        let mut req = match ws_url.into_client_request() {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid Neptun WS URL: {}. Retrying in 6s...", e);
                sleep(Duration::from_secs(6)).await;
                continue;
            }
        };
        req.headers_mut().insert(ORIGIN, HeaderValue::from_static("https://neptun.in.ua"));
        req.headers_mut().insert(REFERER, HeaderValue::from_static("https://neptun.in.ua/"));
        req.headers_mut().insert(USER_AGENT, HeaderValue::from_static(BROWSER_UA));

        let ws_stream = match connect_async(req).await {
            Ok((stream, _)) => {
                info!("Neptun Split-Stream Arbiter: successfully connected to wss://neptun.in.ua/api/v1/stream");
                stream
            }
            Err(e) => {
                debug!("Neptun WS connect failed (REST Fallback active): {}. Reconnecting in 10s...", e);
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let (mut write, mut read) = ws_stream.split();

        while let Some(msg_res) = read.next().await {
            let msg = match msg_res {
                Ok(m) => m,
                Err(e) => {
                    warn!("Neptun WS connection closed: {}. Reconnecting...", e);
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

            let trimmed = text.trim();
            if trimmed.is_empty() {
                continue;
            }

            let val: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let env_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

            // 1. Потік тривог (neptun_alerts): type == "alerts" або наявні поля raions/oblasts
            if env_type == "alerts" || val.get("raions").is_some() || val.get("oblasts").is_some()
                || val.get("data").and_then(|d| d.get("raions").or_else(|| d.get("oblasts"))).is_some()
            {
                let mut ab = alerts_buf.write().await;
                ab.raw_data = Some(val.get("data").unwrap_or(&val).clone());
                ab.last_received_ts = now_sec();
                debug!("Neptun WS: dispatched live alerts frame to alerts buffer");
                continue;
            }

            // 2. Потік цілей (neptun_targets): snapshot / threats / upsert / remove
            if env_type == "snapshot" || env_type == "threats" || val.get("threats").is_some() || val.is_array() {
                let threats = parse_neptun_threats_list(&val);
                let mut tb = targets_buf.write().await;
                tb.targets.clear();
                for t in threats {
                    tb.targets.insert(t.id.clone(), t);
                }
                tb.last_received_ts = now_sec();
                debug!("Neptun WS: dispatched snapshot to targets buffer ({} threats)", tb.targets.len());
            } else if env_type == "upsert" {
                let threat_val = val.get("threat").or_else(|| val.get("data")).unwrap_or(&val);
                if let Some(t) = parse_single_neptun_threat(threat_val) {
                    let mut tb = targets_buf.write().await;
                    tb.targets.insert(t.id.clone(), t);
                    tb.last_received_ts = now_sec();
                    // Захист оперативної пам'яті: якщо буфер розростається понад 500 цілей — залишаємо останні 300
                    if tb.targets.len() > 500 {
                        let excess = tb.targets.len() - 300;
                        let keys_to_remove: Vec<String> = tb.targets.keys().take(excess).cloned().collect();
                        for k in keys_to_remove {
                            tb.targets.remove(&k);
                        }
                    }
                }
            } else if env_type == "remove" {
                let id_opt = val.get("id").and_then(|v| v.as_str())
                    .or_else(|| val.get("data").and_then(|d| d.get("id")).and_then(|v| v.as_str()));
                if let Some(id) = id_opt {
                    let mut tb = targets_buf.write().await;
                    tb.targets.remove(id);
                    tb.pending_removals.push(id.to_string());
                    tb.last_received_ts = now_sec();
                }
            } else if env_type == "ping" || trimmed == "{}" {
                let _ = write.send(Message::Text(r#"{"type":"pong"}"#.to_string())).await;
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}

/// Автономний арбітр тривог (neptun_alerts)
async fn run_neptun_alerts_arbiter(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    _http_client: reqwest::Client,
    alerts_buf: Arc<RwLock<NeptunAlertsBuffer>>,
) {
    let mut was_active = false;
    let process_start_ts = now_sec();

    loop {
        let neptun_alerts_cfg = storage.get_stream("neptun_alerts");
        let ua_alerts_cfg = storage.get_stream("ukrainealarm_alerts");

        let neptun_enabled = neptun_alerts_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);
        let ua_enabled = ua_alerts_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);

        let neptun_priority = neptun_alerts_cfg.as_ref().map(|s| s.priority).unwrap_or(2);
        let ua_priority = ua_alerts_cfg.as_ref().map(|s| s.priority).unwrap_or(1);

        let poll_interval_sec = neptun_alerts_cfg.as_ref().map(|s| s.poll_interval_sec).unwrap_or(6).max(3);
        let failover_timeout_sec = neptun_alerts_cfg.as_ref().map(|s| s.failover_timeout_sec).unwrap_or(15.0).max(5.0);

        sleep(Duration::from_secs(poll_interval_sec)).await;

        if !neptun_enabled {
            if was_active {
                info!("Neptun Alerts stream disabled by admin. Deactivating alerts arbiter.");
                was_active = false;
            }
            continue;
        }

        let is_neptun_primary = !ua_enabled || neptun_priority < ua_priority;
        let now = now_sec();

        let should_run = if is_neptun_primary {
            true
        } else {
            let state_read = threat_state.read().await;
            let in_cooldown = now < state_read.ua_alerts_cooldown_until;
            let is_silent = (now - process_start_ts) > TARGETS_STARTUP_GRACE_PERIOD_SEC
                && (now - state_read.last_alerts_update_ts) > failover_timeout_sec;
            let service_keys = storage.get_service_keys();
            let has_token = service_keys.ukrainealarm_api_token.as_ref().map(|t| !t.trim().is_empty()).unwrap_or(false)
                || std::env::var("UKRAINEALARM_API_TOKEN").is_ok()
                || std::env::var("UKRAINEALARM_API_KEY").is_ok();

            in_cooldown || is_silent || !has_token
        };

        if !should_run {
            if was_active {
                info!("Primary UkraineAlarm alerts stream active. Neptun alerts arbiter in standby.");
                was_active = false;
            }
            continue;
        }

        if !was_active {
            if is_neptun_primary {
                info!("Neptun Alerts configured as PRIMARY stream (Priority #{}). Starting arbiter.", neptun_priority);
            } else {
                warn!("UkraineAlarm alerts inactive / cooling down. Activating Neptun Alerts arbiter...");
            }
            was_active = true;
        }

        let provider_name = if is_neptun_primary { "Neptun Alerts (Primary)" } else { "Neptun (Резервний)" };
        let status_str = if is_neptun_primary { "primary" } else { "failover" };

        // 1. Спроба застосувати свіжі тривоги з буфера WebSocket (вік <= 25 секунд)
        let ws_alerts_opt = {
            let ab = alerts_buf.read().await;
            if (now - ab.last_received_ts) <= 25.0 && ab.raw_data.is_some() {
                ab.raw_data.clone()
            } else {
                None
            }
        };

        if let Some(val) = ws_alerts_opt {
            process_neptun_alerts(&val, &threat_state, &detector, &exchange_mgr, provider_name, status_str).await;
        } else {
            debug!("Neptun alerts: WebSocket buffer silent (>25s). Pure WebSocket mode — no REST fallback.");
        }
    }
}

/// Автономний арбітр цілей (neptun_targets)
async fn run_neptun_targets_arbiter(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    _http_client: reqwest::Client,
    targets_buf: Arc<RwLock<NeptunTargetsBuffer>>,
) {
    let mut was_active = false;
    let mut last_logged_count: Option<usize> = None;
    let process_start_ts = now_sec();

    loop {
        let neptun_tgt_cfg = storage.get_stream("neptun_targets");
        let ua_ws_cfg = storage.get_stream("ukrainealarm_ws");
        let mapa_cfg = storage.get_stream("mapa_targets");

        let neptun_enabled = neptun_tgt_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);
        let ua_enabled = ua_ws_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);
        let mapa_enabled = mapa_cfg.as_ref().map(|s| s.enabled).unwrap_or(true);

        let neptun_priority = neptun_tgt_cfg.as_ref().map(|s| s.priority).unwrap_or(2);
        let ua_priority = ua_ws_cfg.as_ref().map(|s| s.priority).unwrap_or(1);
        let mapa_priority = mapa_cfg.as_ref().map(|s| s.priority).unwrap_or(3);

        let poll_interval_sec = neptun_tgt_cfg.as_ref().map(|s| s.poll_interval_sec).unwrap_or(5).max(3);
        let failover_timeout_sec = neptun_tgt_cfg.as_ref().map(|s| s.failover_timeout_sec).unwrap_or(15.0).max(5.0);

        sleep(Duration::from_secs(poll_interval_sec)).await;

        if !neptun_enabled {
            if was_active {
                info!("Neptun Targets stream disabled by admin configuration. Deactivating targets arbiter.");
                was_active = false;
            }
            continue;
        }

        let is_neptun_primary = (!ua_enabled || neptun_priority < ua_priority)
            && (!mapa_enabled || neptun_priority < mapa_priority);
        let now = now_sec();

        if !is_neptun_primary {
            let uptime = now - process_start_ts;
            if uptime < TARGETS_STARTUP_GRACE_PERIOD_SEC {
                debug!(
                    "Neptun failover: startup grace period active ({:.1}s / {:.0}s), awaiting higher-priority targets stream stabilization",
                    uptime, TARGETS_STARTUP_GRACE_PERIOD_SEC
                );
                continue;
            }

            let state_read = threat_state.read().await;
            let ua_alive = ua_enabled && ua_priority < neptun_priority
                && (now - state_read.last_primary_targets_ts) <= failover_timeout_sec;
            let mapa_alive = mapa_enabled && mapa_priority < neptun_priority
                && state_read.targets_provider.contains("MAPA")
                && (now - state_read.last_targets_update_ts) <= failover_timeout_sec;
            drop(state_read);

            if ua_alive || mapa_alive {
                if was_active {
                    info!("Higher priority targets stream active. Neptun targets arbiter in standby.");
                    was_active = false;
                    last_logged_count = None;
                }
                continue;
            }

            if !was_active {
                warn!(
                    "Higher priority target streams silent >{:.0}s. Switching to Neptun pure WebSocket stream...",
                    failover_timeout_sec
                );
                was_active = true;
            }
        } else if !was_active {
            info!("Neptun Targets configured as PRIMARY stream (Priority #{}). Starting direct radar polling.", neptun_priority);
            was_active = true;
        }

        let provider_name = if is_neptun_primary { "Neptun (Основний)" } else { "Neptun (Резервний)" };
        let status_str = if is_neptun_primary { "primary" } else { "failover" };

        // 1. Спроба взяти цілі з буфера WebSocket (вік <= 25 секунд)
        let (ws_extracted_opt, pending_removals) = {
            let mut tb = targets_buf.write().await;
            let removals = std::mem::take(&mut tb.pending_removals);
            let targets_vec = if (now - tb.last_received_ts) <= 25.0 {
                Some(tb.targets.values().cloned().collect::<Vec<_>>())
            } else {
                None
            };
            (targets_vec, removals)
        };

        let extracted = if let Some(ws_targets) = ws_extracted_opt {
            ws_targets
        } else {
            debug!("Neptun targets: WebSocket buffer silent (>25s). Pure WebSocket mode — no REST fallback.");
            Vec::new()
        };

        let extracted_count = extracted.len();
        let mut state = threat_state.write().await;

        // Безслідне видалення цілей, надісланих у подіях remove (без хрестиків на мапі)
        for r_id in pending_removals {
            state.tracker.silent_remove(&r_id);
        }

        let lost_tracks = state.tracker.update_batch(&extracted, &*detector, Some(&*exchange_mgr), provider_name);
        state.recompute_oblast_alerts(&detector);
        state.last_targets_update_ts = now_sec();
        state.last_update_ts = now_sec();
        state.update_seq += 1;
        state.upstream_provider = provider_name.to_string();
        state.targets_provider = provider_name.to_string();
        state.last_targets_provider_status = status_str.to_string();

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
                let hist_status = match trk.status.as_str() {
                    "eliminated" => "eliminated",
                    "hit_target" => "hit_target",
                    _ => "lost",
                };
                history_mgr.record_track(trk, hist_status);
            }
        }
        if extracted_count > 0 && last_logged_count != Some(extracted_count) {
            info!("Neptun failover: tracking {} active targets from backup feed", extracted_count);
            last_logged_count = Some(extracted_count);
        }
    }
}

/// Точка входу: запуск Split-Stream Arbiter для Neptun (WebSocket + REST Fallback для тривог і цілей)
pub async fn run_failover_neptun_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
    exchange_mgr: Arc<ExchangeLogManager>,
    storage: Arc<StorageManager>,
    http_client: reqwest::Client,
) {
    let alerts_buf = Arc::new(RwLock::new(NeptunAlertsBuffer::default()));
    let targets_buf = Arc::new(RwLock::new(NeptunTargetsBuffer::default()));

    // 1. Запуск єдиного диспетчера WebSocket-з'єднання wss://neptun.in.ua/api/v1/stream
    {
        let ab = alerts_buf.clone();
        let tb = targets_buf.clone();
        tokio::spawn(async move {
            run_neptun_ws_dispatcher(ab, tb).await;
        });
    }

    // 2. Запуск автономного арбітра тривог (neptun_alerts)
    {
        let ts = threat_state.clone();
        let det = detector.clone();
        let exch = exchange_mgr.clone();
        let stor = storage.clone();
        let client = http_client.clone();
        let ab = alerts_buf.clone();
        tokio::spawn(async move {
            run_neptun_alerts_arbiter(ts, det, exch, stor, client, ab).await;
        });
    }

    // 3. Запуск автономного арбітра цілей (neptun_targets)
    run_neptun_targets_arbiter(
        threat_state,
        detector,
        history_mgr,
        exchange_mgr,
        storage,
        http_client,
        targets_buf,
    ).await;
}
