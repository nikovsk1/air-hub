use std::sync::Arc;
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
use tracing::{info, warn};

use crate::crypto_decoder::{decode_payload_native, extract_targets};
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::tracker::{now_sec, ThreatState};

const PAGE_URL: &str = "https://map.ukrainealarm.com/onlyMap";
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36";

pub async fn run_ukrainealarm_collector(
    threat_state: Arc<RwLock<ThreatState>>,
    detector: Arc<OblastDetector>,
    history_mgr: Arc<HistoryManager>,
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
                if trimmed.is_empty() || trimmed == "{}" || trimmed == r#"{"id":0}"# {
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

                // Витяг корисного навантаження (~5:...)
                let mut payload = "";
                if let Some(push) = val.get("push").and_then(|p| p.get("pub")).and_then(|pb| pb.get("data")) {
                    if let Some(n) = push.get("data").and_then(|d| d.get("n")).and_then(|s| s.as_str()) {
                        payload = n;
                    } else if let Some(n) = push.get("n").and_then(|s| s.as_str()) {
                        payload = n;
                    }
                } else if let Some(res) = val.get("result").and_then(|r| r.get("data")).and_then(|d| d.get("data")) {
                    if let Some(n) = res.get("n").and_then(|s| s.as_str()) {
                        payload = n;
                    }
                }

                if !payload.is_empty() && payload.starts_with("~5:") {
                    match decode_payload_native(payload) {
                        Ok(decoded) => {
                            let extracted = extract_targets(&decoded);
                            let mut state = threat_state.write().await;
                            let lost_tracks = state.tracker.update_batch(&extracted, &detector);
                            state.recompute_oblast_alerts(&detector);
                            let now = now_sec();
                            state.last_update_ts = now;
                            state.last_targets_update_ts = now;
                            state.update_seq += 1;
                            state.upstream_provider = "Centrifugo (ws.ukrainealarm.com)".to_string();

                            // Синхронізація активних траєкторій в історію
                            for trk in state.tracker.tracks.values() {
                                history_mgr.record_track(trk, "active");
                            }
                            // Фіксація завершення польоту зі збереженням повної траєкторії!
                            for trk in &lost_tracks {
                                history_mgr.record_track(trk, "lost");
                            }
                        }
                        Err(e) => {
                            warn!("Payload decode error: {}", e);
                        }
                    }
                }
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}
