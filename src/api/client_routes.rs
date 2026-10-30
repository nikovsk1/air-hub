use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::sleep;

use crate::api::admin_routes::AppState;
use crate::api::middleware::{extract_client_api_key, is_admin, is_external_request};
use crate::canonical_registry::*;
use crate::geo_math::{approach_angle, bearing_to_compass, calculate_bearing, calculate_haversine_distance, format_eta_ua, project_radar_point};
use crate::storage::User;

#[derive(Deserialize)]
pub struct ClientQuery {
    pub token: Option<String>,
    pub api_key: Option<String>,
    pub slot: Option<String>,
    pub slot_id: Option<String>,
    pub radius: Option<f64>,
    pub radius_km: Option<f64>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub month: Option<String>,
    pub date: Option<String>,
}

pub fn client_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_root))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/unknown_types", get(handle_unknown_types))
        .route("/api/v1/directory", get(handle_directory))
        .route("/api/v1/reference", get(handle_directory))
        .route("/api/v1/regions/geojson", get(handle_regions_geojson))
        .route("/api/v1/slots", get(handle_get_slots).post(handle_create_slot))
        .route("/api/v1/slots/:slot_id", put(handle_update_slot).delete(handle_delete_slot))
        .route("/api/v1/locations/dynamic", post(handle_dynamic_location))
        .route("/api/v1/settings", get(handle_get_settings).put(handle_update_settings).post(handle_update_settings))
        .route("/api/v1/threats", get(handle_get_threats))
        .route("/api/v1/radar", get(handle_get_radar))
        .route("/api/v1/map", get(handle_get_map))
        .route("/api/v1/stream", get(handle_ws_stream))
        .route("/api/v1/history/months", get(handle_history_months))
        .route("/api/v1/history", get(handle_get_history))
        .route("/api/v1/history/upload", post(handle_upload_history))
        .route("/api/ukraine_alarm_plus/map", get(handle_radar_map_html))
        .route("/map", get(handle_radar_map_html))
        .route("/radar-map", get(handle_radar_map_html))
        .route("/replay", get(handle_timeline_map_html))
        .route("/history/replay", get(handle_timeline_map_html))
        .route("/timeline", get(handle_timeline_map_html))
}

async fn authenticate_user(
    headers: &HeaderMap,
    query: &ClientQuery,
    state: &AppState,
    addr: Option<SocketAddr>,
) -> Option<User> {
    let header_key = extract_client_api_key(headers, None);
    let key_opt = query.token.as_deref()
        .or_else(|| query.api_key.as_deref())
        .or_else(|| header_key.as_deref());

    if let Some(key) = key_opt {
        if let Some(user) = state.storage.get_user_by_key(key) {
            if user.enabled {
                state.storage.update_user_last_seen(key);
                return Some(user);
            }
        }
    }

    // Якщо це адмін у локальній мережі -> повертаємо першого доступного користувача або віртуального адміна
    let peer_ip = addr.map(|a| a.ip());
    if is_admin(headers, query.token.as_deref(), peer_ip, &state.config.admin_secret_key) {
        let users = state.storage.get_all_users();
        if let Some(first) = users.into_iter().next() {
            return Some(first);
        }
    }

    None
}

async fn handle_root(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if is_external_request::<()>(&headers, Some(addr.ip())) {
        StatusCode::NOT_FOUND.into_response()
    } else {
        Redirect::to("/admin").into_response()
    }
}

async fn handle_health(
    State(state): State<AppState>,
) -> Response {
    let st = state.threat_state.read().await;
    Json(json!({
        "status": "online",
        "app": "Air Alert Radar Hub (Rust)",
        "version": "1.0.0",
        "upstream_provider": st.upstream_provider,
        "active_threats": st.tracker.tracks.len(),
        "recent_lost_2min": st.tracker.recent_lost.len(),
        "total_official_sirens": st.official_alerts.len(),
        "mig31k_active": st.mig_active,
        "last_update_ts": st.last_update_ts,
        "update_seq": st.update_seq,
        "registered_users": state.storage.get_all_users().len()
    })).into_response()
}

async fn handle_unknown_types(
    State(state): State<AppState>,
) -> Response {
    let summary = state.exchange_mgr.get_summary();
    Json(summary).into_response()
}

async fn handle_directory() -> Response {
    let threats_list: Vec<&ThreatMeta> = vec![
        &THREAT_SHAHED, &THREAT_SHAHED_JET, &THREAT_MISSILE, &THREAT_BALLISTIC,
        &THREAT_KAB, &THREAT_LANCET, &THREAT_RECON, &THREAT_FPV,
        &THREAT_AVIATION, &THREAT_BANDEROL, &THREAT_ARTILLERY, &THREAT_UNKNOWN
    ];

    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(json!({
            "status": "ok",
            "threats": threats_list,
            "total_categories": threats_list.len()
        }))
    ).into_response()
}

async fn handle_regions_geojson(
    State(state): State<AppState>,
) -> Response {
    let path = state.config.data_dir.join("regions.geojson");
    if let Ok(content) = fs::read_to_string(&path) {
        (
            [
                (header::CONTENT_TYPE, "application/geo+json"),
                (header::CACHE_CONTROL, "public, max-age=86400")
            ],
            content
        ).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn handle_get_slots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let total = user.slots.len();
    Json(json!({
        "status": "ok",
        "slots": user.slots,
        "total_slots": total,
        "max_slots": 5,
        "can_add": total < 5
    })).into_response()
}

#[derive(Deserialize)]
pub struct CreateSlotPayload {
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub danger_zone: Option<f64>,
}

async fn handle_create_slot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<CreateSlotPayload>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state.storage.create_slot(&user.api_key, &payload.name, payload.lat, payload.lon, payload.danger_zone, &state.detector) {
        Ok(slot) => (StatusCode::CREATED, Json(json!({"status": "created", "slot": slot}))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateSlotPayload {
    pub name: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub active: Option<bool>,
    #[serde(alias = "danger_radius_km")]
    pub danger_zone: Option<f64>,
    pub alert_threat: Option<bool>,
    #[serde(alias = "react_threat_types")]
    pub react_threats: Option<Vec<String>>,
    pub alert_siren: Option<bool>,
    pub alert_mig: Option<bool>,
    pub alert_artillery: Option<bool>,
}

async fn handle_update_slot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(slot_id): AxumPath<String>,
    Json(payload): Json<UpdateSlotPayload>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state.storage.update_slot(
        &user.api_key, &slot_id, payload.name, payload.lat, payload.lon, payload.active,
        payload.danger_zone, payload.alert_threat, payload.react_threats, payload.alert_siren,
        payload.alert_mig, payload.alert_artillery, &state.detector,
    ) {
        Ok(slot) => Json(json!({"status": "updated", "slot": slot})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

async fn handle_delete_slot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(slot_id): AxumPath<String>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state.storage.delete_slot(&user.api_key, &slot_id) {
        Ok(true) => Json(json!({"status": "deleted"})).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct DynamicLocationPayload {
    pub lat: Option<f64>,
    pub latitude: Option<f64>,
    pub lon: Option<f64>,
    pub longitude: Option<f64>,
    pub accuracy_m: Option<f64>,
    pub accuracy: Option<f64>,
}

async fn handle_dynamic_location(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<DynamicLocationPayload>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let lat = payload.lat.or(payload.latitude).unwrap_or(0.0);
    let lon = payload.lon.or(payload.longitude).unwrap_or(0.0);
    let acc = payload.accuracy_m.or(payload.accuracy);

    match state.storage.update_dynamic_location(&user.api_key, lat, lon, acc, &state.detector) {
        Ok(slot) => Json(json!({"status": "updated", "slot": slot})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

async fn handle_get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    Json(json!({
        "status": "ok",
        "danger_radius_km": user.default_danger_zone,
        "alert_threat": user.target_alert_threat,
        "react_threats": user.target_react_threats,
        "alert_siren": user.alert_siren,
        "alert_mig": user.alert_mig,
        "alert_artillery": user.alert_artillery
    })).into_response()
}

#[derive(Deserialize)]
pub struct UpdateSettingsPayload {
    pub danger_radius_km: Option<f64>,
    pub apply_to_all_slots: Option<bool>,
    pub alert_threat: Option<bool>,
    pub react_threats: Option<Vec<String>>,
    pub alert_siren: Option<bool>,
    pub alert_mig: Option<bool>,
    pub alert_artillery: Option<bool>,
}

async fn handle_update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<UpdateSettingsPayload>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state.storage.update_user_settings(
        &user.api_key,
        payload.danger_radius_km,
        payload.alert_threat,
        payload.react_threats,
        payload.alert_siren,
        payload.alert_mig,
        payload.alert_artillery,
        payload.apply_to_all_slots.unwrap_or(false),
    ) {
        Ok(updated_user) => Json(json!({"status": "updated", "user": updated_user})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

pub fn build_user_snapshot(user: &User, st: &crate::tracker::ThreatState, slot_id: &str) -> Value {
    let selected_slot = user.slots.get(slot_id);

    let (center_lat, center_lon, eff_danger_km, slot_name, slot_active, slot_alert_threat, slot_alert_siren, slot_alert_mig) = match selected_slot {
        Some(s) => (s.lat, s.lon, s.danger_zone, s.name.clone(), s.active, s.alert_threat, s.alert_siren, s.alert_mig),
        None => (50.4501, 30.5234, user.default_danger_zone, "Точка".to_string(), true, user.target_alert_threat, user.alert_siren, user.alert_mig),
    };
    let allowed_categories: Vec<String> = selected_slot
        .map(|s| s.react_threats.clone())
        .unwrap_or_else(|| user.target_react_threats.clone());

    let mut processed_threats = Vec::new();
    let mut closest_threat_obj: Option<Value> = None;
    let mut min_distance = f64::INFINITY;

    for trk in st.tracker.tracks.values() {
        let dist = calculate_haversine_distance(center_lat, center_lon, trk.lat, trk.lon);
        let bearing = calculate_bearing(center_lat, center_lon, trk.lat, trk.lon);
        let app_angle = approach_angle(trk.lat, trk.lon, trk.heading, center_lat, center_lon);
        let in_danger = dist <= eff_danger_km;

        let eta_minutes = if (app_angle <= 85.0 || in_danger) && trk.speed_kmh > 10.0 {
            Some((dist / trk.speed_kmh) * 60.0)
        } else {
            None
        };

        let compass = bearing_to_compass(bearing);
        let approach_status = if app_angle <= 45.0 {
            "direct"
        } else if app_angle <= 85.0 {
            "approaching"
        } else {
            "passing"
        };

        let approach_desc = if app_angle <= 45.0 {
            "Прямий курс на точку"
        } else if app_angle <= 85.0 {
            "Наближається"
        } else {
            "Рухається повз / віддаляється"
        };

        let corridor = trk.get_extrapolated_corridor();

        let threat_val = json!({
            "id": trk.id,
            "type": trk.type_ua,
            "type_ua": trk.type_ua,
            "type_en": trk.type_en,
            "category": trk.category,
            "ha_icon": trk.ha_icon,
            "esp_code": trk.esp_code,
            "color_hex": trk.color_hex,
            "raw_code": trk.raw_code,
            "lat": trk.lat,
            "lon": trk.lon,
            "heading": trk.heading,
            "heading_deg": trk.heading,
            "speed_kmh": trk.speed_kmh,
            "oblast": trk.oblast,
            "oblast_id": trk.oblast_id,
            "distance_km": (dist * 10.0).round() / 10.0,
            "bearing_deg": (bearing * 10.0).round() / 10.0,
            "compass": compass,
            "bearing_sector": compass,
            "approach_angle": (app_angle * 10.0).round() / 10.0,
            "approach_status": approach_status,
            "approach_desc": approach_desc,
            "eta_minutes": eta_minutes.map(|v| (v * 10.0).round() / 10.0),
            "eta_formatted": format_eta_ua(eta_minutes),
            "in_danger_zone": in_danger,
            "trajectory": trk.trajectory,
            "extrapolated": corridor,
            "extrapolated_path": corridor
        });

        if allowed_categories.contains(&trk.category) {
            if dist < min_distance {
                min_distance = dist;
                closest_threat_obj = Some(threat_val.clone());
            }
        }

        processed_threats.push(threat_val);
    }

    let mut slots_stats = HashMap::new();
    for (s_id, s) in &user.slots {
        let mut s_min_dist = f64::INFINITY;
        let mut s_closest_trk = None;

        for trk in st.tracker.tracks.values() {
            if s.react_threats.contains(&trk.category) {
                let dist = calculate_haversine_distance(s.lat, s.lon, trk.lat, trk.lon);
                if dist < s_min_dist {
                    s_min_dist = dist;
                    let app_ang = approach_angle(trk.lat, trk.lon, trk.heading, s.lat, s.lon);
                    let eta = if (app_ang <= 85.0 || dist <= s.danger_zone) && trk.speed_kmh > 10.0 {
                        Some((dist / trk.speed_kmh) * 60.0)
                    } else {
                        None
                    };
                    s_closest_trk = Some((trk, dist, eta));
                }
            }
        }

        let is_danger = s.active && s.alert_threat && s_min_dist <= s.danger_zone;
        let (c_type, c_id, c_eta, c_eta_f) = match s_closest_trk {
            Some((trk, _, eta)) => (
                Some(trk.type_ua.clone()),
                Some(trk.id.clone()),
                eta.map(|v| (v * 10.0).round() / 10.0),
                format_eta_ua(eta),
            ),
            None => (None, None, None, "--".to_string()),
        };

        slots_stats.insert(s_id.clone(), json!({
            "slot_id": s_id,
            "name": s.name,
            "lat": s.lat,
            "lon": s.lon,
            "active": s.active,
            "danger_zone": s.danger_zone,
            "danger_radius_km": s.danger_zone,
            "danger_zone_active": is_danger,
            "closest_target_id": c_id,
            "closest_distance_km": if s_min_dist.is_finite() { Some((s_min_dist * 10.0).round() / 10.0) } else { None },
            "closest_type": c_type,
            "closest_eta_minutes": c_eta,
            "closest_eta_formatted": c_eta_f,
            "siren_active": s.active && s.alert_siren && st.oblast_alerts.get(s.oblast_id.as_deref().unwrap_or("0")).map(|o| o.alert).unwrap_or(false)
        }));
    }

    let closest_threat = closest_threat_obj;
    let closest_target_id = closest_threat.as_ref().and_then(|t| t.get("id")).and_then(|v| v.as_str());
    let closest_dist_km = closest_threat.as_ref().and_then(|t| t.get("distance_km")).and_then(|v| v.as_f64());
    let closest_type = closest_threat.as_ref().and_then(|t| t.get("type")).and_then(|v| v.as_str());
    let closest_eta_min = closest_threat.as_ref().and_then(|t| t.get("eta_minutes")).and_then(|v| v.as_f64());
    let closest_eta_fmt = closest_threat.as_ref().and_then(|t| t.get("eta_formatted")).and_then(|v| v.as_str()).unwrap_or("--");

    // Fallback if user has no slots configured yet: ensure at least Slot 1 is present in slots_stats
    if slots_stats.is_empty() {
        slots_stats.insert("1".to_string(), json!({
            "slot_id": "1",
            "name": "Точка 1",
            "lat": center_lat,
            "lon": center_lon,
            "active": slot_active,
            "danger_zone": eff_danger_km,
            "danger_radius_km": eff_danger_km,
            "danger_zone_active": slot_active && slot_alert_threat && min_distance <= eff_danger_km,
            "closest_target_id": closest_target_id,
            "closest_distance_km": if min_distance.is_finite() { Some((min_distance * 10.0).round() / 10.0) } else { None },
            "closest_type": closest_type,
            "closest_eta_minutes": closest_eta_min,
            "closest_eta_formatted": closest_eta_fmt,
            "siren_active": slot_active && slot_alert_siren
        }));
    }

    json!({
        "timestamp": (st.last_update_ts * 1000.0) as i64,
        "owner": user.owner,
        "upstream_provider": st.upstream_provider,
        "active_threats_total": st.tracker.tracks.len(),
        "total_threats_in_country": st.tracker.tracks.len(),
        "general_alerts": {
            "mig31k_active": st.mig_active,
            "total_official_sirens": st.official_alerts.len(),
            "active_oblasts_count": st.oblast_alerts.values().filter(|o| o.alert).count(),
            "active_raions_count": st.raion_alerts.values().filter(|r| r.alert).count(),
            "reasons": st.alert_reasons
        },
        "current_point": {
            "slot_id": slot_id,
            "name": slot_name,
            "lat": center_lat,
            "lon": center_lon,
            "danger_radius_km": eff_danger_km
        },
        "settings": {
            "danger_radius_km": eff_danger_km,
            "alert_threat": user.target_alert_threat,
            "alert_siren": user.alert_siren,
            "alert_mig": user.alert_mig,
            "alert_artillery": user.alert_artillery
        },
        "audio_alert_active": slot_active && ((slot_alert_siren && min_distance <= eff_danger_km) || (slot_alert_mig && st.mig_active)),
        "audio_alert_reasons": st.alert_reasons,
        "danger_zone": {
            "active": slot_active && slot_alert_threat && min_distance <= eff_danger_km,
            "status": if slot_active && slot_alert_threat && min_distance <= eff_danger_km { "DANGER" } else { "CALM" },
            "radius_km": eff_danger_km,
            "closest_target_id": closest_target_id,
            "closest_distance_km": closest_dist_km,
            "closest_type": closest_type,
            "closest_eta_minutes": closest_eta_min,
            "closest_eta_formatted": closest_eta_fmt
        },
        "closest_threat": closest_threat,
        "slots": slots_stats,
        "threats": processed_threats,
        "recent_lost": st.tracker.recent_lost.values().collect::<Vec<_>>(),
        "version": format!("{}_{}", st.update_seq, st.tracker.tracks.len()),
        "map_oblasts": st.oblast_alerts.values().collect::<Vec<_>>(),
        "oblasts": st.oblast_alerts.values().collect::<Vec<_>>(),
        "raions": st.raion_alerts.values().collect::<Vec<_>>()
    })
}

/// GET /api/v1/threats: головний клієнтський ендпоінт для Home Assistant з підтримкою ETag 304
async fn handle_get_threats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let st = state.threat_state.read().await;
    let etag = st.get_etag();

    if let Some(client_etag) = headers.get(header::IF_NONE_MATCH).and_then(|h| h.to_str().ok()) {
        if client_etag.trim() == etag.trim() {
            return (
                StatusCode::NOT_MODIFIED,
                [(header::ETAG, etag.clone())],
                ""
            ).into_response();
        }
    }

    let selected_slot_id = query.slot.or(query.slot_id).unwrap_or_else(|| "1".to_string());
    let resp_payload = build_user_snapshot(&user, &st, &selected_slot_id);

    (
        [
            (header::ETAG, etag),
            (header::CONTENT_TYPE, "application/json".to_string())
        ],
        Json(resp_payload)
    ).into_response()
}

/// GET /api/v1/radar: полярна проекція 368x448 для Waveshare ESP32-S3 AMOLED
async fn handle_get_radar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let st = state.threat_state.read().await;
    let selected_slot_id = query.slot.or(query.slot_id).unwrap_or_else(|| "1".to_string());
    let selected_slot = user.slots.get(&selected_slot_id);

    let (center_lat, center_lon, eff_danger_km, loc_name) = match selected_slot {
        Some(s) => (s.lat, s.lon, s.danger_zone, s.name.clone()),
        None => (query.lat.unwrap_or(50.4501), query.lon.unwrap_or(30.5234), user.default_danger_zone, "Radar".to_string()),
    };

    let radius_km = query.radius.or(query.radius_km).unwrap_or(100.0);
    const SCREEN_W: f64 = 368.0;
    const SCREEN_H: f64 = 448.0;
    let center_x = SCREEN_W / 2.0;
    let center_y = SCREEN_H / 2.0;
    let max_px = center_x.min(center_y) * 0.92;

    let mut radar_targets = Vec::new();
    let mut min_dist = f64::INFINITY;
    let mut closest_eta = None;
    let mut closest_eta_f = "--".to_string();

    for trk in st.tracker.tracks.values() {
        let (px_x, px_y, dist, bearing) = project_radar_point(
            center_x, center_y, max_px, radius_km, center_lat, center_lon, trk.lat, trk.lon
        );

        let mut screen_trail = Vec::new();
        for p in &trk.trajectory {
            let (tx, ty, _, _) = project_radar_point(
                center_x, center_y, max_px, radius_km, center_lat, center_lon, p.lat, p.lon
            );
            screen_trail.push([tx, ty]);
        }

        let in_danger = dist <= eff_danger_km;
        let app_ang = approach_angle(trk.lat, trk.lon, trk.heading, center_lat, center_lon);
        let eta = if (app_ang <= 85.0 || in_danger) && trk.speed_kmh > 10.0 {
            Some((dist / trk.speed_kmh) * 60.0)
        } else {
            None
        };

        if dist < min_dist {
            min_dist = dist;
            closest_eta = eta;
            closest_eta_f = format_eta_ua(eta);
        }

        radar_targets.push(json!({
            "id": trk.id,
            "type": trk.type_ua,
            "category": trk.category,
            "ha_icon": trk.ha_icon,
            "esp_code": trk.esp_code,
            "color_hex": trk.color_hex,
            "code": trk.raw_code,
            "dist_km": (dist * 10.0).round() / 10.0,
            "bearing": (bearing * 10.0).round() / 10.0,
            "x": px_x,
            "y": px_y,
            "heading": trk.heading,
            "eta_min": eta.map(|v| (v * 10.0).round() / 10.0),
            "danger": in_danger,
            "screen_trail": screen_trail
        }));
    }

    let danger_circle_px = ((eff_danger_km / radius_km).min(1.0) * max_px).round() as i32;

    Json(json!({
        "timestamp": (st.last_update_ts * 1000.0) as i64,
        "owner": user.owner,
        "slot_id": selected_slot_id,
        "location_name": loc_name,
        "radius_km": radius_km,
        "danger_radius_km": eff_danger_km,
        "danger_circle_px": danger_circle_px,
        "threats_count": radar_targets.len(),
        "siren_active": st.oblast_alerts.values().any(|o| o.alert),
        "mig_active": st.mig_active,
        "closest_km": if min_dist.is_finite() { Some((min_dist * 10.0).round() / 10.0) } else { None },
        "closest_eta": closest_eta.map(|v| (v * 10.0).round() / 10.0),
        "closest_eta_formatted": closest_eta_f,
        "danger_active": min_dist <= eff_danger_km,
        "audio_alert_active": min_dist <= eff_danger_km || st.mig_active,
        "audio_alert_reasons": st.alert_reasons,
        "targets": radar_targets
    })).into_response()
}

async fn handle_get_map(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if authenticate_user(&headers, &query, &state, Some(addr)).await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let st = state.threat_state.read().await;
    Json(json!({
        "timestamp": (st.last_update_ts * 1000.0) as i64,
        "active_threats": st.tracker.tracks.values().collect::<Vec<_>>(),
        "recent_lost": st.tracker.recent_lost.values().collect::<Vec<_>>(),
        "oblasts": st.oblast_alerts.values().collect::<Vec<_>>(),
        "raions": st.raion_alerts.values().collect::<Vec<_>>(),
        "mig31k_active": st.mig_active
    })).into_response()
}

/// WebSocket стрім телеметрії для клієнтів Home Assistant та ESP32
async fn handle_ws_stream(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws_client(socket, state, query, addr))
}

async fn handle_ws_client(
    mut socket: WebSocket,
    state: AppState,
    query: ClientQuery,
    addr: SocketAddr,
) {
    let dummy_headers = HeaderMap::new();
    let user = match authenticate_user(&dummy_headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => {
            let _ = socket.send(Message::Text(json!({"error": "Unauthorized"}).to_string())).await;
            return;
        }
    };

    let mut selected_slot = query.slot.or(query.slot_id).unwrap_or_else(|| "1".to_string());
    let mut last_seq = 0u64;

    loop {
        let current_user = state.storage.get_user_by_key(&user.api_key).unwrap_or_else(|| user.clone());

        let (_current_seq, update_json) = {
            let st = state.threat_state.read().await;
            let seq = st.update_seq;
            if seq != last_seq {
                last_seq = seq;
                let snapshot = build_user_snapshot(&current_user, &st, &selected_slot);
                (seq, Some(snapshot))
            } else {
                (seq, None)
            }
        };

        if let Some(msg) = update_json {
            if socket.send(Message::Text(msg.to_string())).await.is_err() {
                break;
            }
        }

        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(cmd) = serde_json::from_str::<Value>(&text) {
                            if cmd.get("action").and_then(|a| a.as_str()) == Some("switch_slot") {
                                if let Some(new_slot) = cmd.get("slot").and_then(|s| s.as_str()) {
                                    selected_slot = new_slot.to_string();
                                    last_seq = 0; // Force push
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            _ = sleep(Duration::from_millis(500)) => {}
        }
    }
}

async fn handle_history_months(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if authenticate_user(&headers, &query, &state, Some(addr)).await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (months_map, sources) = state.history_mgr.get_available_months_map();
    Json(json!({
        "status": "ok",
        "months": months_map,
        "sources": sources
    })).into_response()
}

async fn handle_get_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if authenticate_user(&headers, &query, &state, Some(addr)).await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let date_filter = query.date.as_deref();
    let month = if let Some(ref m) = query.month {
        m.clone()
    } else if let Some(ref d) = query.date {
        if d.len() >= 7 { d[..7].to_string() } else { crate::history::HistoryManager::current_month() }
    } else {
        crate::history::HistoryManager::current_month()
    };

    if let Some(data) = state.history_mgr.get_month_history_filtered(&month, date_filter) {
        return Json(data).into_response();
    }

    // Спроба автоматичного підтягування з Google Drive
    let cfg = state.storage.get_gdrive_config();
    if let Some(ref webhook) = cfg.gdrive_webhook_url {
        if !webhook.is_empty() {
            if let Ok(data) = state.history_mgr.fetch_month_from_gdrive(&month, webhook, &state.http_client).await {
                return Json(data).into_response();
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn handle_upload_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<Value>,
) -> Response {
    if authenticate_user(&headers, &query, &state, Some(addr)).await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let count = state.history_mgr.import_external_history(&payload);
    Json(json!({
        "status": "imported",
        "imported_targets": count
    })).into_response()
}

async fn handle_radar_map_html(
    State(state): State<AppState>,
) -> Response {
    let map_file = state.config.static_dir.join("radar_map.html");
    if let Ok(content) = fs::read_to_string(&map_file) {
        Html(content).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "radar_map.html not found").into_response()
    }
}

async fn handle_timeline_map_html(
    State(state): State<AppState>,
) -> Response {
    let timeline_file = state.config.static_dir.join("timeline_map.html");
    if let Ok(content) = fs::read_to_string(&timeline_file) {
        Html(content).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "timeline_map.html not found").into_response()
    }
}
