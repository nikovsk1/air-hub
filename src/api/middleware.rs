use std::net::IpAddr;
use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // Carrier Grade NAT (CGNAT) 100.64.0.0/10: 100.64.0.0 – 100.127.255.255
            let is_cgnat = octets[0] == 100 && (octets[1] & 0xc0) == 64;
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || is_cgnat
        }
        IpAddr::V6(ipv6) => {
            // Підтримка IPv4-mapped IPv6 адрес (::ffff:x.x.x.x)
            if let Some(v4) = ipv6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            ipv6.is_loopback()
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // Unique Local Address fc00::/7
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
        }
    }
}

/// Перевірка чи запит надійшов із зовнішньої мережі або через Cloudflare
pub fn is_external_request<B>(headers: &HeaderMap, peer_ip: Option<IpAddr>) -> bool {
    // 1. Пряма перевірка сокета: якщо фізичний peer_ip публічний -> це безумовно зовнішній запит
    if let Some(ip) = peer_ip {
        if !is_private_ip(ip) {
            return true;
        }
    }

    // 2. Якщо присутні заголовки Cloudflare -> зовнішній запит через тунель/проксі
    if headers.contains_key("cf-connecting-ip") || headers.contains_key("cf-ray") {
        return true;
    }

    // 3. Перевірка X-Forwarded-For від довіреного локального проксі (Home Assistant / Nginx)
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

    // 4. Перевірка X-Real-IP
    if let Some(x_real) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if let Ok(ip) = x_real.trim().parse::<IpAddr>() {
            if !is_private_ip(ip) {
                return true;
            }
        } else {
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

    let header_key = headers.get("x-admin-key").and_then(|h| h.to_str().ok());
    let bearer_key = headers.get("authorization").and_then(|h| h.to_str().ok()).and_then(|auth| {
        if auth.starts_with("Bearer ") {
            Some(auth.trim_start_matches("Bearer ").trim())
        } else {
            None
        }
    });

    let provided = header_key
        .or(bearer_key)
        .or_else(|| {
            if let Some(qk) = query_key {
                if !qk.trim().is_empty() {
                    tracing::warn!("⚠️ Admin request authenticated via deprecated query parameter ?admin_key=...; please transition to X-Admin-Key header");
                    return Some(qk);
                }
            }
            None
        })
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

/// Middleware безпеки для встановлення базових заголовків (CSP, X-Frame-Options, X-Content-Type-Options)
pub async fn security_headers_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' ws: wss: https: blob:; worker-src 'self' blob:; object-src 'none';",
        ),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_is_private_ip_ipv4_and_cgnat() {
        assert!(is_private_ip(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("10.10.0.5").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("192.168.1.100").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("172.16.5.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("169.254.1.1").unwrap())); // link-local
        assert!(is_private_ip(IpAddr::from_str("100.64.0.1").unwrap())); // CGNAT start
        assert!(is_private_ip(IpAddr::from_str("100.100.50.2").unwrap())); // CGNAT mid
        assert!(is_private_ip(IpAddr::from_str("100.127.255.254").unwrap())); // CGNAT end

        // Public IPs must return false
        assert!(!is_private_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("100.128.0.1").unwrap())); // Above CGNAT
    }

    #[test]
    fn test_is_private_ip_ipv6_and_mapped() {
        assert!(is_private_ip(IpAddr::from_str("::1").unwrap())); // loopback
        assert!(is_private_ip(IpAddr::from_str("fc00::1").unwrap())); // ULA
        assert!(is_private_ip(IpAddr::from_str("fd12:3456:789a::1").unwrap())); // ULA
        assert!(is_private_ip(IpAddr::from_str("fe80::1").unwrap())); // link-local
        // IPv4-mapped IPv6
        assert!(is_private_ip(IpAddr::from_str("::ffff:192.168.1.5").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("::ffff:10.0.0.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("::ffff:8.8.8.8").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("2001:4860:4860::8888").unwrap())); // Google DNS IPv6
    }

    #[test]
    fn test_is_admin_constant_time_verification() {
        let secret = "super_secret_test_key_xyz";

        // 1. Header auth
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", secret.parse().unwrap());
        assert!(is_admin(&headers, None, Some(IpAddr::from_str("127.0.0.1").unwrap()), secret));

        // 2. Bearer auth
        let mut headers_bearer = HeaderMap::new();
        headers_bearer.insert("authorization", format!("Bearer {}", secret).parse().unwrap());
        assert!(is_admin(&headers_bearer, None, Some(IpAddr::from_str("192.168.0.2").unwrap()), secret));

        // 3. Invalid key rejected
        assert!(!is_admin(&headers, None, Some(IpAddr::from_str("127.0.0.1").unwrap()), "wrong_key"));

        // 4. External request rejected even with valid key
        assert!(!is_admin(&headers, None, Some(IpAddr::from_str("8.8.8.8").unwrap()), secret));
    }
}
