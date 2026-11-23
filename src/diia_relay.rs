use std::sync::Arc;
use parking_lot::RwLock;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, COOKIE, ORIGIN, REFERER, SET_COOKIE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::storage::{now_ts, StorageManager};

pub const DIIA_START_URL: &str = "https://map.ukrainealarm.com/api/diia/auth/start";
pub const DIIA_STATUS_URL: &str = "https://map.ukrainealarm.com/api/diia/auth/status";

pub const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Динамічний або налаштовуваний через DIIA_BROWSER_UA заголовок User-Agent
pub fn get_browser_ua() -> String {
    std::env::var("DIIA_BROWSER_UA").unwrap_or_else(|_| BROWSER_UA.to_string())
}

/// Нормалізація часових міток: якщо мітка в мілісекундах (> 10^10), конвертуємо в секунди
pub fn normalize_timestamp_secs(ts: i64) -> i64 {
    if ts > 10_000_000_000 {
        ts / 1000
    } else {
        ts
    }
}

pub const SEC_CH_UA: &str = "\"Not-A.Brand\";v=\"99\", \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\"";
pub const SEC_CH_UA_MOBILE: &str = "?0";
pub const SEC_CH_UA_PLATFORM: &str = "\"Windows\"";
pub const SEC_CH_UA_FULL_VERSION: &str = "\"131.0.6778.86\"";
pub const SEC_CH_UA_ARCH: &str = "\"x86\"";
pub const SEC_CH_UA_BITNESS: &str = "\"64\"";
pub const SEC_CH_UA_PLATFORM_VERSION: &str = "\"19.0.0\"";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiiaBridgeState {
    pub status: String, // "idle" | "pending" | "authorized" | "failed" | "expired"
    pub deep_link: Option<String>,
    pub request_id: Option<String>,
    pub flow_cookie: Option<String>,
    pub expires_at: Option<i64>,
    pub session_expires_at: Option<i64>,
    pub last_error: Option<String>,
    pub last_updated_ts: i64,
}

impl Default for DiiaBridgeState {
    fn default() -> Self {
        Self {
            status: "idle".to_string(),
            deep_link: None,
            request_id: None,
            flow_cookie: None,
            expires_at: None,
            session_expires_at: None,
            last_error: None,
            last_updated_ts: 0,
        }
    }
}

pub fn apply_browser_headers(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let ua = get_browser_ua();
    builder
        .header(USER_AGENT, ua)
        .header(ORIGIN, "https://map.ukrainealarm.com")
        .header(REFERER, "https://map.ukrainealarm.com/")
        .header("sec-ch-ua", SEC_CH_UA)
        .header("sec-ch-ua-mobile", SEC_CH_UA_MOBILE)
        .header("sec-ch-ua-platform", SEC_CH_UA_PLATFORM)
        .header("sec-ch-ua-arch", SEC_CH_UA_ARCH)
        .header("sec-ch-ua-bitness", SEC_CH_UA_BITNESS)
        .header("sec-ch-ua-full-version", SEC_CH_UA_FULL_VERSION)
        .header("sec-ch-ua-platform-version", SEC_CH_UA_PLATFORM_VERSION)
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-origin")
        .header(ACCEPT, "application/json")
}

pub fn extract_flow_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    for cookie_header in headers.get_all(SET_COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let trimmed = part.trim();
                let lower = trimmed.to_ascii_lowercase();
                if lower.starts_with("diiaauthflow=") {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

pub fn extract_deep_link_from_json(body_json: &Value) -> Option<String> {
    body_json.get("deepLink")
        .or_else(|| body_json.get("deep_link"))
        .or_else(|| body_json.get("url"))
        .or_else(|| body_json.get("link"))
        .or_else(|| body_json.get("qrCode"))
        .or_else(|| body_json.get("data").and_then(|d| d.get("deepLink").or_else(|| d.get("url"))))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub async fn start_diia_session(
    client: &reqwest::Client,
    state: &Arc<RwLock<DiiaBridgeState>>,
) -> Result<Value, String> {
    info!("DiiaBridge: requesting new auth session from UkraineAlarm...");

    let req = apply_browser_headers(client.post(DIIA_START_URL))
        .header(CONTENT_TYPE, "application/json")
        .json(&json!({ "returnPath": "/" }));

    let resp = req.send().await.map_err(|e| format!("Failed to connect to Diia start endpoint: {}", e))?;
    let status = resp.status();
    let resp_headers = resp.headers().clone();

    if !status.is_success() {
        let err_text = resp.text().await.unwrap_or_default();
        let msg = format!("Diia start rejected: HTTP {} - {}", status, err_text);
        warn!("{}", msg);
        let mut guard = state.write();
        guard.status = "failed".to_string();
        guard.last_error = Some(msg.clone());
        return Err(msg);
    }

    let mut flow_cookie_opt = extract_flow_cookie_from_headers(&resp_headers);

    // Fallback: If not found in Set-Cookie headers, reuse active flow_cookie from state
    if flow_cookie_opt.is_none() {
        let guard = state.read();
        if let Some(ref prev_cookie) = guard.flow_cookie {
            flow_cookie_opt = Some(prev_cookie.clone());
        }
    }

    let body_json: Value = resp.json().await.map_err(|e| format!("Invalid JSON from Diia start: {}", e))?;
    let deep_link = extract_deep_link_from_json(&body_json);

    let request_id = body_json.get("requestId")
        .or_else(|| body_json.get("request_id"))
        .or_else(|| body_json.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let expires_at = body_json.get("expiresAt")
        .or_else(|| body_json.get("expires_at"))
        .and_then(|v| v.as_i64())
        .map(normalize_timestamp_secs);

    if deep_link.is_none() || flow_cookie_opt.is_none() {
        let upstream_error = body_json.get("error")
            .or_else(|| body_json.get("message"))
            .or_else(|| body_json.get("code"))
            .and_then(|v| v.as_str());

        let msg = if let Some(err) = upstream_error {
            format!("UkraineAlarm відхилив сесію Дії: {}", err)
        } else if deep_link.is_none() && flow_cookie_opt.is_none() {
            "UkraineAlarm повернув відповідь без посилання deepLink та без куки DiiaAuthFlow".to_string()
        } else if deep_link.is_none() {
            "UkraineAlarm не надав посилання для відкриття в Дії (deepLink)".to_string()
        } else {
            "UkraineAlarm не надав сесійну куку DiiaAuthFlow".to_string()
        };

        warn!(
            "Diia start response incomplete: msg={}, deep_link={}, has_cookie={}, body={:?}, headers={:?}",
            msg,
            deep_link.is_some(),
            flow_cookie_opt.is_some(),
            body_json,
            resp_headers
        );
        let mut guard = state.write();
        guard.status = "failed".to_string();
        guard.last_error = Some(msg.clone());
        return Err(msg);
    }

    {
        let mut guard = state.write();
        guard.status = "pending".to_string();
        guard.deep_link = deep_link.clone();
        guard.request_id = request_id.clone();
        guard.flow_cookie = flow_cookie_opt;
        guard.expires_at = expires_at;
        guard.last_error = None;
        guard.last_updated_ts = now_ts();
    }

    info!("DiiaBridge: auth session started, awaiting user scan in Diia app");
    Ok(json!({
        "status": "pending",
        "deepLink": deep_link,
        "requestId": request_id,
        "expiresAt": expires_at,
        "remainingMs": body_json.get("remainingMs"),
    }))
}

pub async fn poll_diia_status(
    client: &reqwest::Client,
    state: &Arc<RwLock<DiiaBridgeState>>,
    storage: &StorageManager,
) -> Result<Value, String> {
    let (flow_cookie, expires_at) = {
        let guard = state.read();
        if guard.status != "pending" {
            return Ok(json!({
                "status": guard.status,
                "deepLink": guard.deep_link,
                "last_error": guard.last_error,
                "session_expires_at": guard.session_expires_at,
            }));
        }
        (guard.flow_cookie.clone(), guard.expires_at)
    };

    let Some(cookie_str) = flow_cookie else {
        return Ok(json!({ "status": "idle" }));
    };

    // Перевірка таймауту на стороні клієнта
    if let Some(exp) = expires_at {
        let exp_sec = normalize_timestamp_secs(exp);
        if now_ts() >= exp_sec {
            let mut guard = state.write();
            guard.status = "expired".to_string();
            guard.last_error = Some("Час очікування сканування QR-коду вичерпано".to_string());
            return Ok(json!({ "status": "expired" }));
        }
    }

    let cookie_val = HeaderValue::from_str(&cookie_str).map_err(|e| format!("Invalid cookie header: {}", e))?;
    let req = apply_browser_headers(client.post(DIIA_STATUS_URL))
        .header(COOKIE, cookie_val);

    let resp = req.send().await.map_err(|e| format!("Failed to poll Diia status: {}", e))?;
    let status_code = resp.status();
    if !status_code.is_success() {
        return Ok(json!({ "status": "pending" }));
    }

    let headers = resp.headers().clone();
    let body_json: Value = resp.json().await.map_err(|e| format!("Invalid JSON from Diia status: {}", e))?;
    let resp_status = body_json.get("status").and_then(|v| v.as_str()).unwrap_or("pending");

    if resp_status == "authorized" {
        info!("DiiaBridge: user authorized via Diia! Extracting issued session cookies...");

        let mut issued_cookies = Vec::new();
        for cookie_header in headers.get_all(SET_COOKIE) {
            if let Ok(s) = cookie_header.to_str() {
                for part in s.split(';') {
                    let trimmed = part.trim();
                    let lower = trimmed.to_ascii_lowercase();
                    if lower.starts_with("diiamapaccess=") || lower.starts_with("maptargetsession=") {
                        issued_cookies.push(trimmed.to_string());
                    } else if !trimmed.is_empty()
                        && trimmed.contains('=')
                        && !lower.starts_with("path=")
                        && !lower.starts_with("expires=")
                        && !lower.starts_with("max-age=")
                        && !lower.starts_with("domain=")
                        && !lower.starts_with("samesite=")
                        && !lower.eq("secure")
                        && !lower.eq("httponly")
                    {
                        issued_cookies.push(trimmed.to_string());
                    }
                }
            }
        }

        let cookie_full = issued_cookies.join("; ");
        let session_expires = body_json.get("expiresAt").and_then(|v| v.as_i64()).map(normalize_timestamp_secs);

        if !cookie_full.is_empty() && cookie_full.to_ascii_lowercase().contains("diiamapaccess") {
            let _ = storage.set_service_key("diia", "Загальна мапа", Some(cookie_full.clone()));
            info!("DiiaBridge: successfully saved fresh DiiaMapAccess to hub configuration!");
        } else if !cookie_full.is_empty() {
            // Even if named differently, save to ensure UkraineAlarm WS has access
            let _ = storage.set_service_key("diia", "Загальна мапа", Some(cookie_full.clone()));
            info!("DiiaBridge: saved session cookie to hub configuration: {}", cookie_full);
        }

        {
            let mut guard = state.write();
            guard.status = "authorized".to_string();
            guard.session_expires_at = session_expires;
            guard.last_error = None;
            guard.last_updated_ts = now_ts();
        }

        return Ok(json!({
            "status": "authorized",
            "expiresAt": session_expires,
            "message": "Авторизація успішна"
        }));
    }

    Ok(json!({
        "status": resp_status,
        "expiresAt": body_json.get("expiresAt"),
        "remainingMs": body_json.get("remainingMs"),
    }))
}

pub fn get_diia_session_info(
    storage: &StorageManager,
    state: &Arc<RwLock<DiiaBridgeState>>,
    last_provider_status: &str,
) -> Value {
    let service_keys = storage.get_service_keys();
    let cookie_opt = service_keys.ukrainealarm_diia_cookie;
    let bridge_state = state.read().clone();

    let is_configured = cookie_opt.as_ref().map(|c| c.contains("DiiaMapAccess")).unwrap_or(false);
    let is_unauth = last_provider_status == "unauthorized"
        || bridge_state.status == "expired"
        || bridge_state.status == "failed";

    let display_status = if !is_configured {
        "not_configured"
    } else if is_unauth {
        "expired"
    } else {
        "active"
    };

    json!({
        "configured": is_configured,
        "status": display_status,
        "bridge_status": bridge_state.status,
        "last_error": bridge_state.last_error,
        "session_expires_at": bridge_state.session_expires_at,
        "has_active_qr": bridge_state.status == "pending",
        "deep_link": if bridge_state.status == "pending" { bridge_state.deep_link } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_flow_cookie_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("DiiaAuthFlow=token_xyz_123; path=/api; secure; httponly"),
        );
        let cookie = extract_flow_cookie_from_headers(&headers);
        assert_eq!(cookie, Some("DiiaAuthFlow=token_xyz_123".to_string()));

        // Case-insensitivity check
        let mut headers_lower = HeaderMap::new();
        headers_lower.insert(
            SET_COOKIE,
            HeaderValue::from_static("diiaauthflow=token_abc_456; Max-Age=900"),
        );
        let cookie_lower = extract_flow_cookie_from_headers(&headers_lower);
        assert_eq!(cookie_lower, Some("diiaauthflow=token_abc_456".to_string()));
    }

    #[test]
    fn test_extract_deep_link_from_json() {
        // Standard format
        let v1 = json!({ "deepLink": "https://diia.app/offer/123" });
        assert_eq!(extract_deep_link_from_json(&v1), Some("https://diia.app/offer/123".to_string()));

        // Alternative snake_case
        let v2 = json!({ "deep_link": "https://diia.app/offer/456" });
        assert_eq!(extract_deep_link_from_json(&v2), Some("https://diia.app/offer/456".to_string()));

        // Nested data object
        let v3 = json!({ "data": { "url": "https://diia.app/offer/789" } });
        assert_eq!(extract_deep_link_from_json(&v3), Some("https://diia.app/offer/789".to_string()));

        // Missing
        let v4 = json!({ "status": "failed", "error": "rate_limited" });
        assert_eq!(extract_deep_link_from_json(&v4), None);
    }
}


