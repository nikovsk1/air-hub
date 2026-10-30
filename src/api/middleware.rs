use std::net::IpAddr;
use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // Unique Local Address fc00::/7
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
        }
    }
}

/// Перевірка чи запит надійшов із зовнішньої мережі або через Cloudflare
pub fn is_external_request<B>(headers: &HeaderMap, peer_ip: Option<IpAddr>) -> bool {
    // 1. Якщо присутні заголовки Cloudflare -> зовнішній запит
    if headers.contains_key("cf-connecting-ip") || headers.contains_key("cf-ray") {
        return true;
    }

    // 2. Перевірка X-Forwarded-For
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        for ip_str in xff.split(',') {
            let clean = ip_str.trim();
            if let Ok(ip) = clean.parse::<IpAddr>() {
                if !is_private_ip(ip) {
                    return true;
                }
            } else {
                return true;
            }
        }
    }

    // 3. Перевірка X-Real-IP
    if let Some(x_real) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if let Ok(ip) = x_real.trim().parse::<IpAddr>() {
            if !is_private_ip(ip) {
                return true;
            }
        } else {
            return true;
        }
    }

    // 4. Перевірка прямої IP-адреси сокета
    if let Some(ip) = peer_ip {
        if !is_private_ip(ip) {
            return true;
        }
    }

    false
}

/// Перевірка прав адміністратора за допомогою порівняння за сталий час (constant-time)
pub fn is_admin(
    headers: &HeaderMap,
    query_key: Option<&str>,
    peer_ip: Option<IpAddr>,
    secret_key: &str,
) -> bool {
    // Зовнішні запити категорично відсікаються
    if is_external_request::<()>(headers, peer_ip) {
        return false;
    }

    let provided = query_key
        .or_else(|| headers.get("x-admin-key").and_then(|h| h.to_str().ok()))
        .unwrap_or("");

    if provided.is_empty() {
        return false;
    }

    let prov_bytes = provided.as_bytes();
    let sec_bytes = secret_key.as_bytes();

    if prov_bytes.len() != sec_bytes.len() {
        return false;
    }

    prov_bytes.ct_eq(sec_bytes).into()
}

/// Отримання API-ключа клієнта з Query (?token= або ?api_key=), заголовка X-API-Key або Authorization: Bearer
pub fn extract_client_api_key(headers: &HeaderMap, query_token: Option<&str>) -> Option<String> {
    if let Some(tok) = query_token {
        if !tok.trim().is_empty() {
            return Some(tok.trim().to_string());
        }
    }

    if let Some(h) = headers.get("x-api-key").and_then(|h| h.to_str().ok()) {
        if !h.trim().is_empty() {
            return Some(h.trim().to_string());
        }
    }

    if let Some(auth) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        if auth.starts_with("Bearer ") {
            let tok = auth.trim_start_matches("Bearer ").trim();
            if !tok.is_empty() {
                return Some(tok.to_string());
            }
        }
    }

    None
}
