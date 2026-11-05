pub fn is_valid_month_param(m: &str) -> bool {
    if m.len() != 7 {
        return false;
    }
    let parts: Vec<&str> = m.split('-').collect();
    if parts.len() != 2 {
        return false;
    }
    if let (Ok(y), Ok(month)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        (2020..=2050).contains(&y) && (1..=12).contains(&month)
    } else {
        false
    }
}

pub fn is_valid_date_param(d: &str) -> bool {
    chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok()
}

use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::middleware::{is_admin, is_external_request};
use crate::canonical_registry::ExchangeLogManager;
use crate::config::Config;
use crate::history::HistoryManager;
use crate::oblast_detector::OblastDetector;
use crate::storage::{now_ts, StorageManager};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub storage: Arc<StorageManager>,
    pub history_mgr: Arc<HistoryManager>,
    pub exchange_mgr: Arc<ExchangeLogManager>,
    pub detector: Arc<OblastDetector>,
    pub http_client: reqwest::Client,
    pub threat_state: Arc<tokio::sync::RwLock<crate::tracker::ThreatState>>,
}

#[derive(Deserialize)]
pub struct AdminQuery {
    pub admin_key: Option<String>,
}

fn check_admin(headers: &HeaderMap, query: &AdminQuery, addr: Option<SocketAddr>, secret: &str) -> Result<(), StatusCode> {
    let peer_ip = addr.map(|a| a.ip());
    if is_admin(headers, query.admin_key.as_deref(), peer_ip, secret) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(handle_admin_ui))
        .route("/api/v1/admin/verify", get(handle_verify).post(handle_verify))
        .route("/api/v1/admin/keys", get(handle_list_keys).post(handle_create_key))
        .route("/api/v1/admin/keys/:key", put(handle_update_key).delete(handle_delete_key))
        .route("/api/v1/admin/keys/:key/settings", put(handle_update_key_settings))
        .route("/api/v1/admin/history/config", get(handle_get_history_config).post(handle_set_history_config))
        .route("/api/v1/admin/history", get(handle_admin_history_summary))
        .route("/api/v1/admin/history/sync_gdrive/:month", post(handle_gdrive_upload))
        .route("/api/v1/admin/history/upload_gdrive/:month", post(handle_gdrive_upload))
        .route("/api/v1/admin/history/restore_gdrive/:month", post(handle_gdrive_restore))
        .route("/api/v1/admin/history/:month", delete(handle_delete_history_month))
        .route("/api/v1/admin/history/download/:month", get(handle_download_history_month))
        .route("/api/v1/admin/history/upload", post(handle_upload_history_json))
        .route("/api/v1/admin/service_keys", get(handle_get_service_keys).post(handle_save_service_key).delete(handle_delete_service_key))
        .route("/api/v1/admin/poi", get(handle_admin_list_poi).post(handle_admin_save_poi))
        .route("/api/v1/admin/poi/:id", put(handle_admin_save_poi).delete(handle_admin_delete_poi))
        .route("/api/v1/admin/backup", get(handle_download_backup))
        .route("/api/v1/admin/restore", post(handle_restore_backup))
        .route("/api/v1/admin/exchange_log", get(handle_get_exchange_log))
        .route("/api/v1/admin/exchange_log/download", get(handle_download_exchange_log))
        .route("/api/v1/admin/exchange_log/clear", post(handle_clear_exchange_log))
        .layer(axum::extract::DefaultBodyLimit::max(15 * 1024 * 1024))
}

async fn handle_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if is_external_request::<()>(&headers, Some(addr.ip())) {
        return StatusCode::NOT_FOUND.into_response();
    }

    static CACHE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let content = CACHE.get_or_init(|| {
        let admin_file = state.config.static_dir.join("admin.html");
        fs::read_to_string(&admin_file).unwrap_or_else(|_| "<h1>admin.html not found</h1>".to_string())
    });

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        content.as_str()
    ).into_response()
}

async fn handle_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    Json(json!({"status": "ok", "valid": true})).into_response()
}

async fn handle_list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let users = state.storage.get_all_users();
    Json(json!({"status": "ok", "users": users})).into_response()
}

#[derive(Deserialize)]
pub struct CreateKeyPayload {
    pub owner: Option<String>,
}

async fn handle_create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<CreateKeyPayload>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let owner = payload.owner.unwrap_or_else(|| "User".to_string());
    match state.storage.create_user(&owner) {
        Ok(new_user) => {
            // Фронтенд ADMIN_HTML очікує resp.api_key на верхньому рівні
            Json(json!({
                "status": "created",
                "api_key": new_user.api_key,
                "user": new_user
            })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateKeyPayload {
    pub owner: Option<String>,
    pub enabled: Option<bool>,
}

async fn handle_update_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(key): AxumPath<String>,
    Json(payload): Json<UpdateKeyPayload>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    match state.storage.update_user_meta(&key, payload.owner, payload.enabled) {
        Ok(_) => Json(json!({"status": "updated"})).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateKeySettingsPayload {
    #[serde(alias = "danger_radius_km")]
    pub default_danger_zone: Option<f64>,
    pub apply_to_all_slots: Option<bool>,
    pub alert_threat: Option<bool>,
    pub react_threats: Option<Vec<String>>,
    pub alert_siren: Option<bool>,
    pub alert_mig: Option<bool>,
    pub alert_artillery: Option<bool>,
}

async fn handle_update_key_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(key): AxumPath<String>,
    Json(payload): Json<UpdateKeySettingsPayload>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    match state.storage.update_user_settings(
        &key,
        payload.default_danger_zone,
        payload.alert_threat,
        payload.react_threats,
        payload.alert_siren,
        payload.alert_mig,
        payload.alert_artillery,
        payload.apply_to_all_slots.unwrap_or(false),
    ) {
        Ok(user) => Json(json!({"status": "updated", "user": user})).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}

async fn handle_delete_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(key): AxumPath<String>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    match state.storage.delete_user(&key) {
        Ok(true) => Json(json!({"status": "deleted"})).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn handle_get_history_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let cfg = state.storage.get_gdrive_config();
    let gdrive_webhook = cfg.gdrive_webhook_url.clone().unwrap_or_default();
    let gdrive_folder_url = cfg.gdrive_folder_url.clone().unwrap_or_default();

    Json(json!({
        "status": "ok",
        "recording_enabled": cfg.history_recording,
        "enabled": cfg.history_recording,
        "gdrive_webhook": gdrive_webhook,
        "gdrive_url": gdrive_folder_url,
        "gdrive_folder_url": gdrive_folder_url,
        "gdrive_sync_hours": cfg.gdrive_auto_sync_hours,
        "auto_sync_hours": cfg.gdrive_auto_sync_hours,
        "last_sync_ts": cfg.last_gdrive_sync_ts,
        "config": {
            "enabled": cfg.history_recording,
            "recording_enabled": cfg.history_recording,
            "gdrive_webhook": gdrive_webhook,
            "gdrive_url": gdrive_folder_url,
            "gdrive_folder_url": gdrive_folder_url,
            "gdrive_sync_hours": cfg.gdrive_auto_sync_hours,
            "auto_sync_hours": cfg.gdrive_auto_sync_hours,
            "last_sync_ts": cfg.last_gdrive_sync_ts
        }
    })).into_response()
}

#[derive(Deserialize)]
pub struct SetHistoryConfigPayload {
    #[serde(alias = "enabled")]
    pub recording: Option<bool>,
    #[serde(alias = "gdrive_webhook")]
    pub webhook_url: Option<String>,
    #[serde(alias = "gdrive_url", alias = "folder_url")]
    pub folder_url: Option<String>,
    #[serde(alias = "gdrive_sync_hours", alias = "auto_sync_hours")]
    pub auto_sync_hours: Option<u32>,
}

async fn handle_set_history_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<SetHistoryConfigPayload>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    match state.storage.update_gdrive_config(payload.recording, payload.webhook_url, payload.folder_url, payload.auto_sync_hours) {
        Ok(_) => Json(json!({"status": "updated"})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn handle_admin_history_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let files = state.history_mgr.list_files_summary();
    let mut total_targets = 0usize;
    let mut total_size_bytes = 0u64;
    for f in &files {
        total_targets += f.targets_count;
        total_size_bytes += f.size_bytes;
    }
    let total_size_mb = (total_size_bytes as f64) / (1024.0 * 1024.0);

    Json(json!({
        "status": "ok",
        "files": files,
        "total_files": files.len(),
        "total_targets": total_targets,
        "total_size_mb": (total_size_mb * 100.0).round() / 100.0,
        "total_size_bytes": total_size_bytes
    })).into_response()
}

async fn handle_gdrive_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(month): AxumPath<String>,
) -> Response {
    if !is_valid_month_param(&month) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let cfg = state.storage.get_gdrive_config();
    let webhook = cfg.gdrive_webhook_url.unwrap_or_default();
    match state.history_mgr.sync_to_gdrive(&month, &webhook, &state.http_client).await {
        Ok((count, size_kb)) => {
            state.storage.mark_gdrive_synced();
            // Фронтенд ADMIN_HTML очікує status === "uploaded", size_kb та targets_count
            Json(json!({
                "status": "uploaded",
                "month": month,
                "targets_count": count,
                "size_kb": size_kb
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    }
}

async fn handle_gdrive_restore(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(month): AxumPath<String>,
) -> Response {
    if !is_valid_month_param(&month) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let cfg = state.storage.get_gdrive_config();
    let webhook = cfg.gdrive_webhook_url.unwrap_or_default();
    match state.history_mgr.fetch_month_from_gdrive(&month, &webhook, &state.http_client).await {
        Ok(data) => Json(json!({"status": "restored", "month": month, "data": data})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    }
}

async fn handle_delete_history_month(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(month): AxumPath<String>,
) -> Response {
    if !is_valid_month_param(&month) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let file_path = state.history_mgr.history_dir.join(format!("flight_history_{}.json", month));
    if file_path.exists() {
        let _ = fs::remove_file(file_path);
        Json(json!({"status": "deleted", "month": month})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn handle_download_history_month(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(month): AxumPath<String>,
) -> Response {
    if !is_valid_month_param(&month) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let file_path = state.history_mgr.history_dir.join(format!("flight_history_{}.json", month));
    if let Ok(content) = fs::read_to_string(&file_path) {
        (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"flight_history_{}.json\"", month)),
            ],
            content,
        ).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn handle_upload_history_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<Value>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let count = state.history_mgr.import_external_history(&payload);
    Json(json!({
        "status": "imported",
        "imported_targets": count
    })).into_response()
}

#[derive(Deserialize)]
pub struct ServiceKeyPayload {
    pub service: String,
    pub relation: Option<String>,
    pub key: Option<String>,
}

async fn handle_get_service_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }

    let sk = state.storage.get_service_keys();
    let all_users = state.storage.get_all_users();
    let mut relations = vec!["Загальна мапа".to_string()];
    for u in &all_users {
        if !relations.contains(&u.owner) {
            relations.push(u.owner.clone());
        }
    }

    Json(json!({
        "status": "ok",
        "service_keys": {
            "ukrainealarm": {
                "id": "ukrainealarm",
                "name": "UkraineAlarm Офіційний API v3",
                "category": "Мапа тривог",
                "key": sk.ukrainealarm_api_token.unwrap_or_default(),
                "relation": "Загальна мапа",
                "is_fixed_relation": true
            },
            "cartodb": {
                "id": "cartodb",
                "name": "CartoDB Dark Matter",
                "category": "Підложка мапи",
                "global_key": sk.cartodb_global_api_key.unwrap_or_default(),
                "user_keys": sk.cartodb_user_keys,
                "available_relations": relations,
                "is_fixed_relation": false
            }
        }
    })).into_response()
}

async fn handle_save_service_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<ServiceKeyPayload>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }

    let rel = payload.relation.unwrap_or_else(|| "Загальна мапа".to_string());
    match state.storage.set_service_key(&payload.service, &rel, payload.key) {
        Ok(_) => Json(json!({"status": "ok", "message": "saved"})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    }
}

async fn handle_delete_service_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<ServiceKeyPayload>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }

    let rel = payload.relation.unwrap_or_else(|| "Загальна мапа".to_string());
    match state.storage.delete_service_key(&payload.service, &rel) {
        Ok(_) => Json(json!({"status": "ok", "message": "deleted"})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    }
}

async fn handle_download_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let users = state.storage.get_all_users();
    let service_keys = state.storage.get_service_keys();
    let ts = now_ts();
    let backup_data = json!({
        "timestamp": ts,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "users": users,
        "service_keys": service_keys
    });

    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"air_alert_backup_{}.json\"", ts)),
        ],
        backup_data.to_string(),
    ).into_response()
}

async fn handle_restore_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<Value>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    match state.storage.restore_backup(&payload) {
        Ok(count) => Json(json!({
            "status": "success",
            "message": "restored",
            "count": count,
            "users_count": count
        })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    }
}

async fn handle_get_exchange_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let summary = state.exchange_mgr.get_summary();
    Json(summary).into_response()
}

async fn handle_download_exchange_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    let log_file = state.config.data_dir.join("unmapped_exchange.log");
    let content = fs::read_to_string(log_file).unwrap_or_default();

    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"unmapped_exchange.log\""),
        ],
        content,
    ).into_response()
}

async fn handle_clear_exchange_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(status) = check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key) {
        return status.into_response();
    }
    state.exchange_mgr.clear();
    Json(json!({"status": "cleared"})).into_response()
}

async fn handle_admin_list_poi(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, StatusCode> {
    check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key)?;
    let pois = state.storage.get_pois();
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(pois),
    ))
}

async fn handle_admin_save_poi(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(item): Json<crate::storage::PoiItem>,
) -> Result<impl IntoResponse, StatusCode> {
    check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key)?;
    state.storage.save_poi(item).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn handle_admin_delete_poi(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_admin(&headers, &query, Some(addr), &state.config.admin_secret_key)?;
    let removed = state.storage.delete_poi(&id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if removed {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
