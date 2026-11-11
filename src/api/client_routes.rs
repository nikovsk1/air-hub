use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

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
    pub full_regions: Option<bool>,
    #[allow(dead_code)]
    pub compact: Option<bool>,
}

pub fn client_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_root))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/unknown_types", get(handle_unknown_types))
        .route("/api/v1/directory", get(handle_directory))
        .route("/api/v1/reference", get(handle_directory))
        .route("/api/v1/regions/geojson", get(handle_regions_geojson))
        .route("/api/v1/poi", get(handle_get_poi))
        .route("/api/v1/client/poi", get(handle_get_poi))
        .route("/api/v1/client/regions.geojson", get(handle_regions_geojson))
        .route("/api/v1/client/regions/geojson", get(handle_regions_geojson))
        .route("/api/v1/slots", get(handle_get_slots).post(handle_create_slot))
        .route("/api/v1/slots/:slot_id", put(handle_update_slot).delete(handle_delete_slot))
        .route("/api/v1/client/slots", get(handle_get_slots).post(handle_create_slot))
        .route("/api/v1/client/slots/:slot_id", put(handle_update_slot).delete(handle_delete_slot))
        .route("/api/v1/location", post(handle_dynamic_location).get(handle_get_location_slots))
        .route("/api/v1/locations/dynamic", post(handle_dynamic_location))
        .route("/api/v1/settings", get(handle_get_settings).put(handle_update_settings).post(handle_update_settings))
        .route("/api/v1/threats", get(handle_get_threats))
        .route("/api/v1/client/threats", get(handle_get_threats))
        .route("/api/v1/radar", get(handle_get_radar))
        .route("/api/v1/radar/live", get(handle_get_radar))
        .route("/api/v1/map", get(handle_get_map))
        .route("/api/v1/stream", get(handle_ws_stream))
        .route("/api/v1/history/months", get(handle_history_months))
        .route("/api/v1/history/summary", get(handle_get_history_summary))
        .route("/api/v1/client/history/summary", get(handle_get_history_summary))
        .route("/api/v1/history", get(handle_get_history))
        .route("/api/v1/client/history", get(handle_get_history))
        .route("/api/v1/history/upload", post(handle_upload_history))
        .route("/api/v1/client/map/settings", get(handle_get_map_settings).post(handle_save_map_settings))
        .route("/api/v1/client/map_settings", get(handle_get_map_settings).post(handle_save_map_settings))
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
    _addr: Option<SocketAddr>,
) -> Option<User> {
    let header_key = extract_client_api_key(headers, None);
    let cookie_key = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).and_then(|cookies| {
        for part in cookies.split(';') {
            let mut kv = part.splitn(2, '=');
            let k = kv.next()?.trim();
            let v = kv.next()?.trim();
            if k == "radar_client_token" || k == "air_alert_token" {
                return Some(v.to_string());
            }
        }
        None
    });

    let key_opt = query.token.as_deref()
        .or_else(|| query.api_key.as_deref())
        .or_else(|| header_key.as_deref())
        .or_else(|| cookie_key.as_deref());

    if let Some(key) = key_opt {
        if let Some(user) = state.storage.get_user_by_key(key) {
            if user.enabled {
                state.storage.update_user_last_seen(key);
                return Some(user);
            }
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
    let obl_count = st.official_alerts.values().filter(|a| a.alert && a.level == "State").count();
    let raion_count = st.official_alerts.values().filter(|a| a.alert && a.level != "State").count();
    let total_sirens = st.official_alerts.values().filter(|a| a.alert).count();
    let active_threats = st.tracker.tracks.len();

    let sk = state.storage.get_service_keys();
    let ua_configured = sk.ukrainealarm_api_token.as_ref().map(|t| !t.trim().is_empty()).unwrap_or(false)
        || std::env::var("UKRAINEALARM_API_TOKEN").map(|t| !t.trim().is_empty()).unwrap_or(false)
        || std::env::var("UKRAINEALARM_API_KEY").map(|t| !t.trim().is_empty()).unwrap_or(false);

    let ex_summary = state.exchange_mgr.get_summary();
    let unmapped_threats = ex_summary.get("unmapped_threats_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let recent_unmapped_threats: Vec<_> = ex_summary.get("recent_entries")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|e| e.get("category").and_then(|c| c.as_str()) == Some("threat"))
                .map(|e| json!({
                    "type_identifier": e.get("raw_value").and_then(|r| r.as_str()).unwrap_or("unknown"),
                    "raw_code": e.get("raw_code").and_then(|c| c.as_i64()).unwrap_or(0),
                    "count": 1
                }))
                .collect()
        })
        .unwrap_or_default();

    Json(json!({
        "status": "online",
        "app": "Air Alert Radar Hub (Rust)",
        "version": "1.0.0",
        "ukrainealarm_configured": ua_configured,
        "upstream_provider": st.upstream_provider,
        "alarms_provider": st.alarms_provider,
        "targets_provider": st.targets_provider,
        "alarms_status": st.last_alarms_provider_status,
        "targets_status": st.last_targets_provider_status,
        "last_alarms_ts": st.last_alerts_update_ts,
        "last_targets_ts": st.last_targets_update_ts,
        "sources": {
            "alarms": st.alarms_provider,
            "targets": st.targets_provider,
            "alarms_status": st.last_alarms_provider_status,
            "targets_status": st.last_targets_provider_status,
            "last_alarms_ts": st.last_alerts_update_ts,
            "last_targets_ts": st.last_targets_update_ts
        },
        "active_threats": active_threats,
        "active_threats_count": active_threats,
        "active_oblasts_count": obl_count,
        "active_raions_count": raion_count,
        "official_sirens_count": total_sirens,
        "total_official_sirens": total_sirens,
        "recent_lost_2min": st.tracker.recent_lost.len(),
        "mig31k_active": st.mig_active,
        "last_update_ts": st.last_update_ts,
        "update_seq": st.update_seq,
        "registered_users": state.storage.get_all_users().len(),
        "unknown_target_types_count": unmapped_threats,
        "unknown_target_types": recent_unmapped_threats
    })).into_response()
}

async fn handle_unknown_types(
    State(state): State<AppState>,
) -> Response {
    let summary = state.exchange_mgr.get_summary();
    Json(summary).into_response()
}

async fn handle_directory(
    State(state): State<AppState>,
) -> Response {
    let threats_list: Vec<&ThreatMeta> = vec![
        &THREAT_SHAHED, &THREAT_SHAHED_JET, &THREAT_MISSILE, &THREAT_BALLISTIC,
        &THREAT_KAB, &THREAT_LANCET, &THREAT_RECON, &THREAT_FPV,
        &THREAT_AVIATION, &THREAT_BANDEROL, &THREAT_ARTILLERY, &THREAT_UNKNOWN
    ];

    let alerts_list = vec![
        &ALERT_MISSILE, &ALERT_DRONE, &ALERT_ARTILLERY, &ALERT_CLEAR
    ];

    let oblasts: Vec<_> = state.detector.regions.iter().map(|o| {
        json!({
            "id": o.id,
            "name": o.name,
            "center": o.center,
        })
    }).collect();

    let raions: Vec<_> = state.detector.raion_regions.iter().map(|r| {
        json!({
            "id": r.id,
            "name": r.name,
            "oblast_id": r.oblast_id,
            "center": r.center,
        })
    }).collect();

    let summary = state.exchange_mgr.get_summary();

    (
        [(header::CACHE_CONTROL, "public, max-age=1800")],
        Json(json!({
            "status": "ok",
            "version": "1.0.0",
            "updated_at": chrono::Utc::now().to_rfc3339(),
            "threats": threats_list,
            "total_threat_categories": threats_list.len(),
            "alerts": alerts_list,
            "regions": {
                "total_oblasts": oblasts.len(),
                "total_raions": raions.len(),
                "oblasts": oblasts,
                "raions": raions
            },
            "unmapped_summary": {
                "unmapped_total": summary.get("unmapped_total").and_then(|v| v.as_u64()).unwrap_or(0),
                "unmapped_threats": summary.get("unmapped_threats_count").and_then(|v| v.as_u64()).unwrap_or(0),
                "unmapped_regions": summary.get("unmapped_regions_count").and_then(|v| v.as_u64()).unwrap_or(0),
            }
        }))
    ).into_response()
}

async fn handle_regions_geojson(
    State(state): State<AppState>,
) -> Response {
    static GEOJSON_CACHE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let content = GEOJSON_CACHE.get_or_init(|| {
        let path = state.config.data_dir.join("regions.geojson");
        if path.exists() {
            fs::read_to_string(&path).unwrap_or_default()
        } else {
            let default_path = state.config.data_defaults_dir.join("regions.geojson");
            fs::read_to_string(&default_path).unwrap_or_default()
        }
    });

    if !content.is_empty() {
        (
            [
                (header::CONTENT_TYPE, "application/geo+json"),
                (header::CACHE_CONTROL, "public, max-age=86400")
            ],
            content.as_str()
        ).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn handle_get_poi(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let user_opt = authenticate_user(&headers, &query, &state, Some(addr)).await;
    let token_ref = query.token.as_deref().or_else(|| query.api_key.as_deref());
    let is_admin_req = is_admin(&headers, token_ref, Some(addr.ip()), &state.config.admin_secret_key);

    if user_opt.is_none() && !is_admin_req {
        // Guests receive empty list: military strategic POIs are protected from public exposure
        let empty: Vec<crate::storage::PoiItem> = Vec::new();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "private, no-cache")],
            Json(empty)
        ).into_response();
    }

    let pois = state.storage.get_pois();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "private, max-age=60")],
        Json(pois)
    ).into_response()
}

async fn handle_get_slots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let (slots, total) = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => (u.slots.clone(), u.slots.len()),
        None => (std::collections::HashMap::new(), 0),
    };

    Json(json!({
        "status": "ok",
        "slots": slots,
        "total_slots": total,
        "max_slots": 5,
        "can_add": total < 5
    })).into_response()
}

#[derive(Deserialize)]
pub struct CreateSlotPayload {
    pub name: Option<String>,
    pub lat: f64,
    pub lon: f64,
    #[serde(alias = "danger_radius_km")]
    pub danger_zone: Option<f64>,
    #[serde(alias = "type")]
    pub slot_type: Option<String>,
    pub is_dynamic: Option<bool>,
    pub alert_threat: Option<bool>,
    #[serde(alias = "react_threat_types")]
    pub react_threats: Option<Vec<String>>,
    pub alert_siren: Option<bool>,
    pub alert_mig: Option<bool>,
    pub alert_artillery: Option<bool>,
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

    let is_dyn = payload.is_dynamic.unwrap_or_else(|| {
        payload.slot_type.as_deref().map(|t| t == "dynamic").unwrap_or(false)
    });

    match state.storage.create_slot(
        &user.api_key,
        payload.name,
        payload.lat,
        payload.lon,
        payload.danger_zone,
        Some(is_dyn),
        payload.alert_threat,
        payload.react_threats,
        payload.alert_siren,
        payload.alert_mig,
        payload.alert_artillery,
        &state.detector,
    ) {
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
    #[serde(alias = "type")]
    pub slot_type: Option<String>,
    pub is_dynamic: Option<bool>,
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

    let is_dyn = payload.is_dynamic.or_else(|| {
        payload.slot_type.as_deref().map(|t| t == "dynamic")
    });

    match state.storage.update_slot(
        &user.api_key, &slot_id, payload.name, payload.lat, payload.lon, payload.active,
        payload.danger_zone, payload.alert_threat, payload.react_threats, payload.alert_siren,
        payload.alert_mig, payload.alert_artillery, is_dyn, &state.detector,
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
    pub slot_id: Option<String>,
    #[serde(alias = "slot")]
    pub slot: Option<String>,
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
    let target_slot = payload.slot_id.as_deref()
        .or(payload.slot.as_deref())
        .or(query.slot.as_deref());

    match state.storage.update_dynamic_location(&user.api_key, target_slot, lat, lon, acc, &state.detector) {
        Ok(slot) => Json(json!({
            "status": "updated",
            "slot_id": slot.id,
            "name": slot.name,
            "is_dynamic": slot.is_dynamic,
            "lat": slot.lat,
            "lon": slot.lon,
            "oblast": slot.oblast,
            "raion": slot.raion,
            "slot": slot
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

async fn handle_get_location_slots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let mut slots_list = Vec::new();
    let mut active_dyn_id: Option<String> = None;
    let mut sorted_keys: Vec<_> = user.slots.keys().collect();
    sorted_keys.sort();

    for k in sorted_keys {
        if let Some(s) = user.slots.get(k) {
            if s.is_dynamic && active_dyn_id.is_none() {
                active_dyn_id = Some(k.clone());
            }
            slots_list.push(json!({
                "slot_id": k,
                "name": s.name,
                "type": if s.is_dynamic { "dynamic" } else { "static" },
                "is_dynamic": s.is_dynamic,
                "lat": s.lat,
                "lon": s.lon,
                "active": s.active,
                "danger_radius_km": s.danger_zone,
                "oblast": s.oblast,
                "raion": s.raion
            }));
        }
    }

    Json(json!({
        "status": "ok",
        "slots": slots_list,
        "active_dynamic_slot": active_dyn_id.unwrap_or_else(|| "1".to_string()),
        "total": slots_list.len()
    })).into_response()
}

#[derive(Deserialize)]
pub struct MapSettingsPayload {
    pub token: Option<String>,
    pub auth_token: Option<String>,
    #[allow(dead_code)]
    pub provider: Option<String>,
    pub cartodb_key: Option<String>,
    pub cartodb_api_key: Option<String>,
}

async fn handle_get_map_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
) -> Response {
    let key = query.token.as_deref()
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .unwrap_or("")
        .trim();
    let is_authenticated = !key.is_empty() && state.storage.get_user_by_key(key).is_some();
    let relation = if is_authenticated {
        if let Some(user) = state.storage.get_user_by_key(key) {
            user.owner
        } else {
            "Загальна мапа".to_string()
        }
    } else {
        "Загальна мапа".to_string()
    };

    // Глобальний системний ключ CartoDB сервера НІКОЛИ не передається у браузер клієнта
    let user_custom_cartodb = if is_authenticated && relation != "Загальна мапа" {
        state.storage.get_service_keys().cartodb_user_keys.get(&relation).cloned()
    } else {
        None
    };

    Json(json!({
        "status": "ok",
        "default_provider": "arcgis",
        "relation": relation,
        "cartodb_key": user_custom_cartodb,
        "cartodb_api_key": user_custom_cartodb,
        "has_global_cartodb_key": state.storage.get_service_keys().cartodb_global_api_key.is_some()
    })).into_response()
}

async fn handle_save_map_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<MapSettingsPayload>,
) -> Response {
    let auth_token = query.token.as_deref()
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .or(payload.auth_token.as_deref())
        .or(payload.token.as_deref())
        .unwrap_or("")
        .trim();

    let relation = if !auth_token.is_empty() {
        if let Some(user) = state.storage.get_user_by_key(auth_token) {
            user.owner
        } else if is_admin(&headers, Some(auth_token), Some(addr.ip()), &state.config.admin_secret_key) {
            "Загальна мапа".to_string()
        } else {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    } else if is_admin(&headers, None, Some(addr.ip()), &state.config.admin_secret_key) {
        "Загальна мапа".to_string()
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let carto_key = payload.cartodb_api_key.or(payload.cartodb_key);
    if let Some(key) = carto_key {
        let _ = state.storage.set_service_key("cartodb", &relation, Some(key));
    }

    Json(json!({
        "status": "ok",
        "message": "map settings saved",
        "relation": relation
    })).into_response()
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

pub fn build_user_snapshot(
    user: &User,
    st: &crate::tracker::ThreatState,
    slot_id: &str,
    history_mgr: Option<&crate::history::HistoryManager>,
    full_regions: bool,
) -> Value {
    let today_stats_val = if let Some(h) = history_mgr {
        let (tot, cats) = h.get_today_counts();
        let kyiv = crate::history::HistoryManager::now_kyiv();
        let today_str = kyiv.format("%Y-%m-%d").to_string();
        let (status, last_reconciled_at) = if let Some(ds) = h.get_daily_summary(&today_str) {
            (ds.status, ds.last_reconciled_at)
        } else {
            ("accumulated".to_string(), None)
        };
        serde_json::json!({
            "total": tot,
            "categories": cats,
            "status": status,
            "last_reconciled_at": last_reconciled_at
        })
    } else {
        serde_json::json!({
            "total": 0,
            "categories": {},
            "status": "accumulated",
            "last_reconciled_at": serde_json::Value::Null
        })
    };
    // Підтримка вибору декількох точок ("1", "1,2", "all")
    let target_slots: Vec<&crate::storage::Slot> = if slot_id == "all" {
        user.slots.values().collect()
    } else if slot_id.contains(',') {
        let mut list = Vec::new();
        for id in slot_id.split(',') {
            let clean = id.trim();
            if let Some(s) = user.slots.get(clean) {
                list.push(s);
            }
        }
        if list.is_empty() {
            user.slots.values().take(1).collect()
        } else {
            list
        }
    } else if let Some(s) = user.slots.get(slot_id) {
        vec![s]
    } else {
        user.slots.values().take(1).collect()
    };

    let (center_lat, center_lon, eff_danger_km, slot_name, slot_active, slot_alert_threat, slot_alert_siren, slot_alert_mig) = if target_slots.is_empty() {
        (50.4501, 30.5234, user.default_danger_zone, "Точка".to_string(), true, user.target_alert_threat, user.alert_siren, user.alert_mig)
    } else if target_slots.len() == 1 {
        let s = target_slots[0];
        (s.lat, s.lon, s.danger_zone, s.name.clone(), s.active, s.alert_threat, s.alert_siren, s.alert_mig)
    } else {
        let avg_lat = target_slots.iter().map(|s| s.lat).sum::<f64>() / target_slots.len() as f64;
        let avg_lon = target_slots.iter().map(|s| s.lon).sum::<f64>() / target_slots.len() as f64;
        let max_dz = target_slots.iter().map(|s| s.danger_zone).fold(0.0f64, f64::max);
        let any_act = target_slots.iter().any(|s| s.active);
        let any_thr = target_slots.iter().any(|s| s.alert_threat);
        let any_sir = target_slots.iter().any(|s| s.alert_siren);
        let any_mig = target_slots.iter().any(|s| s.alert_mig);
        (avg_lat, avg_lon, max_dz, format!("Обрано точок: {}", target_slots.len()), any_act, any_thr, any_sir, any_mig)
    };

    let mut allowed_categories: Vec<String> = Vec::new();
    for s in &target_slots {
        for cat in &s.react_threats {
            if !allowed_categories.contains(cat) {
                allowed_categories.push(cat.clone());
            }
        }
    }
    if allowed_categories.is_empty() {
        allowed_categories = user.target_react_threats.clone();
    }

    let mut processed_threats = Vec::new();
    let mut closest_threat_obj: Option<Value> = None;
    let mut min_distance = f64::INFINITY;
    let mut closest_threat_slot_id: Option<String> = None;
    let mut closest_threat_slot_name: Option<String> = None;

    for trk in st.tracker.tracks.values() {
        let mut min_trk_dist = f64::INFINITY;
        let mut best_bearing = 0.0;
        let mut best_app_angle = 180.0;
        let mut trk_in_danger = false;
        let mut best_eta = None;
        let mut trk_closest_slot_id = "".to_string();
        let mut trk_closest_slot_name = "".to_string();

        if target_slots.is_empty() {
            let d = calculate_haversine_distance(center_lat, center_lon, trk.lat, trk.lon);
            min_trk_dist = d;
            best_bearing = calculate_bearing(center_lat, center_lon, trk.lat, trk.lon);
            best_app_angle = approach_angle(trk.lat, trk.lon, trk.heading, center_lat, center_lon);
            trk_in_danger = d <= eff_danger_km;
            best_eta = if (best_app_angle <= 85.0 || trk_in_danger) && trk.speed_kmh > 10.0 {
                Some((d / trk.speed_kmh) * 60.0)
            } else {
                None
            };
        } else {
            for s in &target_slots {
                let d = calculate_haversine_distance(s.lat, s.lon, trk.lat, trk.lon);
                let in_d = s.active && s.alert_threat && d <= s.danger_zone;
                if in_d {
                    trk_in_danger = true;
                }
                if d < min_trk_dist {
                    min_trk_dist = d;
                    best_bearing = calculate_bearing(s.lat, s.lon, trk.lat, trk.lon);
                    best_app_angle = approach_angle(trk.lat, trk.lon, trk.heading, s.lat, s.lon);
                    best_eta = if (best_app_angle <= 85.0 || in_d) && trk.speed_kmh > 10.0 {
                        Some((d / trk.speed_kmh) * 60.0)
                    } else {
                        None
                    };
                    trk_closest_slot_id = s.id.clone();
                    trk_closest_slot_name = s.name.clone();
                }
            }
        }

        let compass = bearing_to_compass(best_bearing);
        let approach_status = if best_app_angle <= 45.0 {
            "direct"
        } else if best_app_angle <= 85.0 {
            "approaching"
        } else {
            "passing"
        };

        let approach_desc = if best_app_angle <= 45.0 {
            "Прямий курс на точку"
        } else if best_app_angle <= 85.0 {
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
            "distance_km": (min_trk_dist * 10.0).round() / 10.0,
            "bearing_deg": (best_bearing * 10.0).round() / 10.0,
            "compass": compass,
            "bearing_sector": compass,
            "approach_angle": (best_app_angle * 10.0).round() / 10.0,
            "approach_status": approach_status,
            "approach_desc": approach_desc,
            "eta_minutes": best_eta.map(|v| (v * 10.0).round() / 10.0),
            "eta_formatted": format_eta_ua(best_eta),
            "in_danger_zone": trk_in_danger,
            "closest_slot_id": trk_closest_slot_id,
            "closest_slot_name": trk_closest_slot_name,
            "trajectory": trk.trajectory,
            "extrapolated": corridor,
            "extrapolated_path": corridor
        });

        if allowed_categories.contains(&trk.category) {
            if min_trk_dist < min_distance {
                min_distance = min_trk_dist;
                closest_threat_obj = Some(threat_val.clone());
                closest_threat_slot_id = Some(trk_closest_slot_id);
                closest_threat_slot_name = Some(trk_closest_slot_name);
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

        let is_siren = if s.active && s.alert_siren {
            if let Some(rid) = s.raion_id.as_deref().filter(|id| !id.is_empty() && *id != "0") {
                st.raion_alerts.get(rid).map(|r| r.alert).unwrap_or(false)
            } else if let Some(oid) = s.oblast_id.as_deref().filter(|id| !id.is_empty() && *id != "0") {
                st.oblast_alerts.get(oid).map(|o| o.alert).unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        };

        slots_stats.insert(s_id.clone(), json!({
            "slot_id": s_id,
            "name": s.name,
            "lat": s.lat,
            "lon": s.lon,
            "active": s.active,
            "is_dynamic": s.is_dynamic,
            "danger_zone": s.danger_zone,
            "danger_radius_km": s.danger_zone,
            "danger_zone_active": is_danger,
            "alert_threat": s.alert_threat,
            "alert_siren": s.alert_siren,
            "alert_mig": s.alert_mig,
            "alert_artillery": s.alert_artillery,
            "oblast": s.oblast,
            "raion": s.raion,
            "closest_target_id": c_id,
            "closest_distance_km": if s_min_dist.is_finite() { Some((s_min_dist * 10.0).round() / 10.0) } else { None },
            "closest_type": c_type,
            "closest_eta_minutes": c_eta,
            "closest_eta_formatted": c_eta_f,
            "siren_active": is_siren
        }));
    }

    let closest_threat = closest_threat_obj;
    let closest_target_id = closest_threat.as_ref().and_then(|t| t.get("id")).and_then(|v| v.as_str());
    let closest_dist_km = closest_threat.as_ref().and_then(|t| t.get("distance_km")).and_then(|v| v.as_f64());
    let closest_type = closest_threat.as_ref().and_then(|t| t.get("type")).and_then(|v| v.as_str());
    let closest_eta_min = closest_threat.as_ref().and_then(|t| t.get("eta_minutes")).and_then(|v| v.as_f64());
    let closest_eta_fmt = closest_threat.as_ref().and_then(|t| t.get("eta_formatted")).and_then(|v| v.as_str()).unwrap_or("--");

    let selected_slot = target_slots.first().copied();
    let selected_slot_siren_active = if let Some(s) = selected_slot {
        if s.active && s.alert_siren {
            if let Some(rid) = s.raion_id.as_deref().filter(|id| !id.is_empty() && *id != "0") {
                st.raion_alerts.get(rid).map(|r| r.alert).unwrap_or(false)
            } else if let Some(oid) = s.oblast_id.as_deref().filter(|id| !id.is_empty() && *id != "0") {
                st.oblast_alerts.get(oid).map(|o| o.alert).unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Fallback if user has no slots configured yet: ensure at least Slot 1 is present in slots_stats
    if slots_stats.is_empty() {
        slots_stats.insert("1".to_string(), json!({
            "slot_id": "1",
            "name": "Точка 1",
            "lat": center_lat,
            "lon": center_lon,
            "active": slot_active,
            "is_dynamic": false,
            "danger_zone": eff_danger_km,
            "danger_radius_km": eff_danger_km,
            "danger_zone_active": slot_active && slot_alert_threat && min_distance <= eff_danger_km,
            "alert_threat": slot_alert_threat,
            "alert_siren": slot_alert_siren,
            "alert_mig": slot_alert_mig,
            "alert_artillery": true,
            "closest_target_id": closest_target_id,
            "closest_distance_km": if min_distance.is_finite() { Some((min_distance * 10.0).round() / 10.0) } else { None },
            "closest_type": closest_type,
            "closest_eta_minutes": closest_eta_min,
            "closest_eta_formatted": closest_eta_fmt,
            "siren_active": slot_active && slot_alert_siren && selected_slot_siren_active
        }));
    }

    json!({
        "timestamp": (st.last_update_ts * 1000.0) as i64,
        "owner": user.owner,
        "upstream_provider": st.upstream_provider,
        "sources": {
            "alarms": st.alarms_provider,
            "targets": st.targets_provider,
            "alarms_status": st.last_alarms_provider_status,
            "targets_status": st.last_targets_provider_status,
            "last_alarms_ts": st.last_alerts_update_ts,
            "last_targets_ts": st.last_targets_update_ts
        },
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
        "audio_alert_active": slot_active && ((slot_alert_threat && min_distance <= eff_danger_km) || (slot_alert_siren && selected_slot_siren_active) || (slot_alert_mig && st.mig_active)),
        "audio_alert_reasons": st.alert_reasons,
        "danger_zone": {
            "active": slot_active && slot_alert_threat && min_distance <= eff_danger_km,
            "status": if slot_active && slot_alert_threat && min_distance <= eff_danger_km { "DANGER" } else { "CALM" },
            "radius_km": eff_danger_km,
            "closest_target_id": closest_target_id,
            "closest_distance_km": closest_dist_km,
            "closest_type": closest_type,
            "closest_eta_minutes": closest_eta_min,
            "closest_eta_formatted": closest_eta_fmt,
            "closest_slot_id": closest_threat_slot_id,
            "closest_slot_name": closest_threat_slot_name
        },
        "closest_threat": closest_threat,
        "today_stats": today_stats_val,
        "slots": slots_stats,
        "threats": processed_threats,
        "recent_lost": st.tracker.recent_lost.values().collect::<Vec<_>>(),
        "version": format!("{}_{}", st.update_seq, st.tracker.tracks.len()),
        "map_oblasts": st.oblast_alerts.values().collect::<Vec<_>>(),
        "oblasts": st.oblast_alerts.values().collect::<Vec<_>>(),
        "raions": if full_regions {
            st.raion_alerts.values().collect::<Vec<_>>()
        } else {
            st.raion_alerts.values().filter(|r| r.alert).collect::<Vec<_>>()
        },
        "official_alerts": st.official_alerts.values().filter(|a| a.alert).collect::<Vec<_>>()
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
        None => User::guest(state.config.danger_radius_km),
    };

    let selected_slot_id = query.slot.clone().or_else(|| query.slot_id.clone()).unwrap_or_else(|| "1".to_string());
    let user_slot_status = user.slots.get(&selected_slot_id)
        .map(|s| format!("{}_{:.1}", s.is_dynamic, s.danger_zone))
        .unwrap_or_default();

    let st = state.threat_state.read().await;
    let etag = format!("seq{}_u{}_s{}_{}", st.update_seq, user.api_key, selected_slot_id, user_slot_status);

    if let Some(client_etag) = headers.get(header::IF_NONE_MATCH).and_then(|h| h.to_str().ok()) {
        let clean_client = client_etag.trim().trim_start_matches("W/").trim_matches('"');
        let clean_server = etag.trim().trim_start_matches("W/").trim_matches('"');
        if clean_client == clean_server {
            return (
                StatusCode::NOT_MODIFIED,
                [(header::ETAG, etag.clone())],
                ""
            ).into_response();
        }
    }

    let full_reg = query.full_regions.unwrap_or(false);
    let resp_payload = build_user_snapshot(&user, &st, &selected_slot_id, Some(&state.history_mgr), full_reg);

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
        None => User::guest(state.config.danger_radius_km),
    };

    let st = state.threat_state.read().await;
    let selected_slot_id = query.slot.or(query.slot_id).unwrap_or_else(|| "1".to_string());
    let selected_slot = user.slots.get(&selected_slot_id);

    let (center_lat, center_lon, eff_danger_km, loc_name, slot_active, slot_alert_threat, slot_alert_siren, slot_alert_mig) = match selected_slot {
        Some(s) => (s.lat, s.lon, s.danger_zone, s.name.clone(), s.active, s.alert_threat, s.alert_siren, s.alert_mig),
        None => (query.lat.unwrap_or(50.4501), query.lon.unwrap_or(30.5234), user.default_danger_zone, "Radar".to_string(), true, user.target_alert_threat, user.alert_siren, user.alert_mig),
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

    let slot_siren_active = if slot_active && slot_alert_siren {
        if let Some(s) = selected_slot {
            if let Some(rid) = s.raion_id.as_deref().filter(|id| !id.is_empty() && *id != "0") {
                st.raion_alerts.get(rid).map(|r| r.alert).unwrap_or(false)
            } else if let Some(oid) = s.oblast_id.as_deref().filter(|id| !id.is_empty() && *id != "0") {
                st.oblast_alerts.get(oid).map(|o| o.alert).unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    Json(json!({
        "timestamp": (st.last_update_ts * 1000.0) as i64,
        "owner": user.owner,
        "slot_id": selected_slot_id,
        "location_name": loc_name,
        "radius_km": radius_km,
        "danger_radius_km": eff_danger_km,
        "danger_circle_px": danger_circle_px,
        "threats_count": radar_targets.len(),
        "siren_active": slot_siren_active,
        "mig_active": st.mig_active,
        "closest_km": if min_dist.is_finite() { Some((min_dist * 10.0).round() / 10.0) } else { None },
        "closest_eta": closest_eta.map(|v| (v * 10.0).round() / 10.0),
        "closest_eta_formatted": closest_eta_f,
        "danger_active": slot_active && slot_alert_threat && min_dist <= eff_danger_km,
        "audio_alert_active": slot_active && ((slot_alert_threat && min_dist <= eff_danger_km) || (slot_alert_siren && slot_siren_active) || (slot_alert_mig && st.mig_active)),
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
    let _user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => User::guest(state.config.danger_radius_km),
    };
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
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws_client(socket, headers, state, query, addr))
}

async fn handle_ws_client(
    mut socket: WebSocket,
    headers: HeaderMap,
    state: AppState,
    query: ClientQuery,
    addr: SocketAddr,
) {
    let user = match authenticate_user(&headers, &query, &state, Some(addr)).await {
        Some(u) => u,
        None => User::guest(state.config.danger_radius_km),
    };

    let mut selected_slot = query.slot.or(query.slot_id).unwrap_or_else(|| "1".to_string());
    let mut watch_rx = state.threat_watch_rx.clone();
    let timeout_duration = Duration::from_secs(15);
    let mut fallback_tick = tokio::time::interval(Duration::from_millis(1000));
    let mut last_sent_seq;

    // Первинний снапшот одразу при підключенні клієнта
    {
        let current_user = state.storage.get_user_by_key(&user.api_key).unwrap_or_else(|| user.clone());
        let snapshot = {
            let st = state.threat_state.read().await;
            last_sent_seq = st.update_seq;
            build_user_snapshot(&current_user, &st, &selected_slot, Some(&state.history_mgr), false)
        };
        if tokio::time::timeout(timeout_duration, socket.send(Message::Text(snapshot.to_string()))).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            // Реактивне пробудження при надходженні нових засічок без поллінгу
            res = watch_rx.changed() => {
                if res.is_err() { break; }
                let current_user = state.storage.get_user_by_key(&user.api_key).unwrap_or_else(|| user.clone());
                let snapshot = {
                    let st = state.threat_state.read().await;
                    last_sent_seq = st.update_seq;
                    build_user_snapshot(&current_user, &st, &selected_slot, Some(&state.history_mgr), false)
                };
                if tokio::time::timeout(timeout_duration, socket.send(Message::Text(snapshot.to_string()))).await.is_err() {
                    break;
                }
            }
            // Резервний тікер: перевірка зміни update_seq для гарантованої доставки оновлень
            _ = fallback_tick.tick() => {
                let cur_seq = state.threat_state.read().await.update_seq;
                if cur_seq != last_sent_seq {
                    let current_user = state.storage.get_user_by_key(&user.api_key).unwrap_or_else(|| user.clone());
                    let snapshot = {
                        let st = state.threat_state.read().await;
                        last_sent_seq = st.update_seq;
                        build_user_snapshot(&current_user, &st, &selected_slot, Some(&state.history_mgr), false)
                    };
                    if tokio::time::timeout(timeout_duration, socket.send(Message::Text(snapshot.to_string()))).await.is_err() {
                        break;
                    }
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let trimmed = text.trim();
                        if trimmed == "ping" || trimmed.contains("\"ping\"") {
                            let _ = tokio::time::timeout(timeout_duration, socket.send(Message::Text("{\"type\":\"pong\"}".to_string()))).await;
                        } else if let Ok(cmd) = serde_json::from_str::<Value>(trimmed) {
                            if cmd.get("action").and_then(|a| a.as_str()) == Some("switch_slot") {
                                if let Some(new_slot) = cmd.get("slot").and_then(|s| s.as_str()) {
                                    selected_slot = new_slot.to_string();
                                    let current_user = state.storage.get_user_by_key(&user.api_key).unwrap_or_else(|| user.clone());
                                    let snapshot = {
                                        let st = state.threat_state.read().await;
                                        last_sent_seq = st.update_seq;
                                        build_user_snapshot(&current_user, &st, &selected_slot, Some(&state.history_mgr), false)
                                    };
                                    let _ = tokio::time::timeout(timeout_duration, socket.send(Message::Text(snapshot.to_string()))).await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
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

async fn handle_get_history_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if authenticate_user(&headers, &query, &state, Some(addr)).await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if let Some(ref date) = query.date {
        if !crate::api::admin_routes::is_valid_date_param(date) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        if let Some(summary) = state.history_mgr.get_daily_summary(date) {
            return Json(json!({
                "status": "ok",
                "date": date,
                "summary": summary
            })).into_response();
        }
    }

    if let Some(ref m) = query.month {
        if !crate::api::admin_routes::is_valid_month_param(m) {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    let month = query.month.clone().unwrap_or_else(|| {
        if let Some(ref d) = query.date {
            if d.len() >= 7 { d[..7].to_string() } else { crate::history::HistoryManager::current_month() }
        } else {
            crate::history::HistoryManager::current_month()
        }
    });

    let summaries = state.history_mgr.get_month_summaries(&month);
    Json(json!({
        "status": "ok",
        "month": month,
        "summaries": summaries
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
    if let Some(ref m) = query.month {
        if !crate::api::admin_routes::is_valid_month_param(m) {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }
    if let Some(ref d) = query.date {
        if !crate::api::admin_routes::is_valid_date_param(d) {
            return StatusCode::BAD_REQUEST.into_response();
        }
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
    let content = tokio::fs::read_to_string(&map_file).await.unwrap_or_else(|_| "<h1>radar_map.html not found</h1>".to_string());

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        content
    ).into_response()
}



async fn handle_timeline_map_html(
    State(state): State<AppState>,
) -> Response {
    let map_file = state.config.static_dir.join("radar_map.html");
    let content = tokio::fs::read_to_string(&map_file).await.unwrap_or_else(|_| "<h1>radar_map.html not found</h1>".to_string());

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        content
    ).into_response()
}
