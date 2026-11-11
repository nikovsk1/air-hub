use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::geo_math::calculate_haversine_distance;
use crate::oblast_detector::OblastDetector;

pub fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub id: String,
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub active: bool,
    #[serde(alias = "danger_radius_km")]
    pub danger_zone: f64,
    pub alert_threat: bool,
    pub react_threats: Vec<String>,
    pub alert_siren: bool,
    pub alert_mig: bool,
    pub alert_artillery: bool,
    #[serde(default)]
    pub is_dynamic: bool,
    pub oblast: Option<String>,
    pub oblast_id: Option<String>,
    pub raion: Option<String>,
    pub raion_id: Option<String>,
    #[serde(default)]
    pub accuracy_m: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub owner: String,
    pub api_key: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_danger_zone")]
    pub default_danger_zone: f64,
    #[serde(default = "default_true")]
    pub target_alert_threat: bool,
    #[serde(default = "default_react_threats")]
    pub target_react_threats: Vec<String>,
    #[serde(default = "default_true")]
    pub alert_siren: bool,
    #[serde(default = "default_true")]
    pub alert_mig: bool,
    #[serde(default = "default_true")]
    pub alert_artillery: bool,
    #[serde(default)]
    pub slots: HashMap<String, Slot>,
    pub created_at: String,
    pub last_seen_ts: Option<i64>,
}

impl User {
    pub fn guest(default_danger: f64) -> Self {
        Self {
            owner: "Загальний доступ".to_string(),
            api_key: "".to_string(),
            enabled: true,
            default_danger_zone: default_danger,
            target_alert_threat: true,
            target_react_threats: default_react_threats(),
            alert_siren: true,
            alert_mig: true,
            alert_artillery: true,
            slots: HashMap::new(),
            created_at: "".to_string(),
            last_seen_ts: None,
        }
    }
}

fn default_true() -> bool { true }
fn default_danger_zone() -> f64 { 35.0 }
fn default_react_threats() -> Vec<String> {
    vec![
        "missile".to_string(),
        "ballistic".to_string(),
        "shahed".to_string(),
        "shahed_jet".to_string(),
        "kab".to_string(),
        "lancet".to_string(),
        "unknown".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceKeysConfig {
    #[serde(default)]
    pub ukrainealarm_api_token: Option<String>,
    #[serde(default)]
    pub cartodb_global_api_key: Option<String>,
    #[serde(default)]
    pub cartodb_user_keys: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSourceConfig {
    pub id: String,                    // "ukrainealarm_alerts", "neptun_alerts", "ukrainealarm_ws", "neptun_targets"
    pub name: String,                  // "UkraineAlarm Офіційний API v3", "Neptun API (Резерв тривог)", etc.
    pub stream_type: String,           // "alerts" | "targets" | "basemap"
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: u32,                 // 1 = primary, 2 = secondary, 3 = tertiary...
    #[serde(default = "default_poll_interval")]
    pub poll_interval_sec: u64,        // e.g. 15, 6, 0 (real-time WS), 5
    #[serde(default = "default_failover_timeout")]
    pub failover_timeout_sec: f64,     // e.g. 15.0
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default)]
    pub autonomous: bool,
    #[serde(default)]
    pub relation: Option<String>,
}

fn default_priority() -> u32 { 1 }
fn default_poll_interval() -> u64 { 15 }
fn default_failover_timeout() -> f64 { 15.0 }

pub fn default_stream_sources() -> Vec<StreamSourceConfig> {
    vec![
        StreamSourceConfig {
            id: "ukrainealarm_alerts".to_string(),
            name: "UkraineAlarm Офіційний API v3".to_string(),
            stream_type: "alerts".to_string(),
            enabled: true,
            priority: 1,
            poll_interval_sec: 15,
            failover_timeout_sec: 15.0,
            endpoint_url: "api.ukrainealarm.com/api/v3/alerts".to_string(),
            autonomous: false,
            relation: Some("Загальна мапа".to_string()),
        },
        StreamSourceConfig {
            id: "neptun_alerts".to_string(),
            name: "Neptun API (Резерв тривог)".to_string(),
            stream_type: "alerts".to_string(),
            enabled: true,
            priority: 2,
            poll_interval_sec: 6,
            failover_timeout_sec: 15.0,
            endpoint_url: "neptun.in.ua/api/v1/alerts".to_string(),
            autonomous: true,
            relation: Some("Загальна мапа".to_string()),
        },
        StreamSourceConfig {
            id: "ukrainealarm_ws".to_string(),
            name: "WS UkraineAlarm (Парсер цілей)".to_string(),
            stream_type: "targets".to_string(),
            enabled: true,
            priority: 1,
            poll_interval_sec: 0,
            failover_timeout_sec: 15.0,
            endpoint_url: "map.ukrainealarm.com (Centrifugo WS)".to_string(),
            autonomous: true,
            relation: Some("Загальна мапа".to_string()),
        },
        StreamSourceConfig {
            id: "neptun_targets".to_string(),
            name: "Neptun API (Резерв цілей)".to_string(),
            stream_type: "targets".to_string(),
            enabled: true,
            priority: 2,
            poll_interval_sec: 5,
            failover_timeout_sec: 15.0,
            endpoint_url: "neptun.in.ua/api/v1/threats".to_string(),
            autonomous: true,
            relation: Some("Загальна мапа".to_string()),
        },
        StreamSourceConfig {
            id: "mapa_targets".to_string(),
            name: "MAPA.UA API (Цілі/загрози)".to_string(),
            stream_type: "targets".to_string(),
            enabled: true,
            priority: 3,
            poll_interval_sec: 10,
            failover_timeout_sec: 20.0,
            endpoint_url: "mapa.ua/api/v1/current".to_string(),
            autonomous: true,
            relation: Some("Загальна мапа".to_string()),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfigData {
    pub users: HashMap<String, User>,
    #[serde(default)]
    pub history_recording: bool,
    #[serde(default)]
    pub gdrive_sync_enabled: bool,
    pub gdrive_webhook_url: Option<String>,
    pub gdrive_folder_url: Option<String>,
    #[serde(default = "default_sync_hours")]
    pub gdrive_auto_sync_hours: u32,
    pub last_gdrive_sync_ts: Option<i64>,
    #[serde(default)]
    pub service_keys: ServiceKeysConfig,
    #[serde(default = "default_stream_sources")]
    pub streams: Vec<StreamSourceConfig>,
}

fn default_sync_hours() -> u32 { 12 }

impl Default for HubConfigData {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            history_recording: true,
            gdrive_sync_enabled: false,
            gdrive_webhook_url: None,
            gdrive_folder_url: None,
            gdrive_auto_sync_hours: 12,
            last_gdrive_sync_ts: None,
            service_keys: ServiceKeysConfig::default(),
            streams: default_stream_sources(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoiItem {
    pub id: String,
    pub category: String,
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub oblast: String,
    pub significance: String,
    pub status: String,
}

pub struct StorageManager {
    file_path: PathBuf,
    poi_path: PathBuf,
    default_danger_km: f64,
    data: RwLock<HubConfigData>,
    poi_items: RwLock<Vec<PoiItem>>,
}

impl StorageManager {
    pub fn new(data_dir: &Path, initial_users: &[(String, String)], detector: &OblastDetector, default_danger_km: f64) -> Self {
        let file_path = data_dir.join("hub_config.json");
        let mut loaded = HubConfigData::default();

        let poi_path = data_dir.join("poi.json");
        let mut loaded_pois = Vec::new();
        if poi_path.exists() {
            if let Ok(content) = fs::read_to_string(&poi_path) {
                if let Ok(parsed) = serde_json::from_str::<Vec<PoiItem>>(&content) {
                    loaded_pois = parsed;
                }
            }
        }
        if loaded_pois.is_empty() {
            let default_poi_path = PathBuf::from("data_defaults").join("poi.json");
            if default_poi_path.exists() {
                if let Ok(content) = fs::read_to_string(&default_poi_path) {
                    if let Ok(parsed) = serde_json::from_str::<Vec<PoiItem>>(&content) {
                        loaded_pois = parsed;
                    }
                }
            }
        }

        if file_path.exists() {
            if let Ok(content) = fs::read_to_string(&file_path) {
                if let Ok(parsed) = serde_json::from_str::<HubConfigData>(&content) {
                    loaded = parsed;
                }
            }
        }

        // Ініціалізація початкових користувачів, якщо передано INITIAL_USERS
        for (owner, key) in initial_users {
            if !loaded.users.contains_key(key) {
                let mut slots = HashMap::new();
                let loc = detector.find_location_info(50.4501, 30.5234);
                slots.insert("1".to_string(), Slot {
                    id: "1".to_string(),
                    name: "Дім".to_string(),
                    lat: 50.4501,
                    lon: 30.5234,
                    active: true,
                    danger_zone: default_danger_km,
                    alert_threat: true,
                    react_threats: default_react_threats(),
                    alert_siren: true,
                    alert_mig: true,
                    alert_artillery: true,
                    is_dynamic: false,
                    oblast: Some(loc.oblast),
                    oblast_id: Some(loc.oblast_id),
                    raion: Some(loc.raion),
                    raion_id: Some(loc.raion_id),
                    accuracy_m: None,
                });

                loaded.users.insert(key.clone(), User {
                    owner: owner.clone(),
                    api_key: key.clone(),
                    enabled: true,
                    default_danger_zone: default_danger_km,
                    target_alert_threat: true,
                    target_react_threats: default_react_threats(),
                    alert_siren: true,
                    alert_mig: true,
                    alert_artillery: true,
                    slots,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    last_seen_ts: Some(now_ts()),
                });
            }
        }

        // Гарантуємо наявність усіх 4 стандартних потоків конфігурації
        let defaults = default_stream_sources();
        for def in defaults {
            if !loaded.streams.iter().any(|s| s.id == def.id) {
                loaded.streams.push(def);
            }
        }
        loaded.streams.sort_by_key(|s| s.priority);

        let mgr = Self {
            file_path,
            poi_path,
            default_danger_km,
            data: RwLock::new(loaded),
            poi_items: RwLock::new(loaded_pois),
        };
        let _ = mgr.save_atomic();
        let _ = mgr.save_pois_atomic();
        mgr
    }

    pub fn get_streams(&self) -> Vec<StreamSourceConfig> {
        let guard = self.data.read();
        let mut streams = guard.streams.clone();
        streams.sort_by_key(|s| s.priority);
        streams
    }

    pub fn get_stream(&self, id: &str) -> Option<StreamSourceConfig> {
        let guard = self.data.read();
        guard.streams.iter().find(|s| s.id == id).cloned()
    }

    #[allow(dead_code)]
    pub fn is_stream_enabled(&self, id: &str) -> bool {
        let guard = self.data.read();
        guard.streams.iter().find(|s| s.id == id).map(|s| s.enabled).unwrap_or(false)
    }

    pub fn set_streams(&self, new_streams: Vec<StreamSourceConfig>) -> Result<(), String> {
        {
            let mut guard = self.data.write();
            guard.streams = new_streams;
            guard.streams.sort_by_key(|s| s.priority);
        }
        self.save_atomic()
    }

    pub fn update_stream(
        &self,
        id: &str,
        enabled: Option<bool>,
        priority: Option<u32>,
        poll_interval_sec: Option<u64>,
        failover_timeout_sec: Option<f64>,
    ) -> Result<StreamSourceConfig, String> {
        let mut guard = self.data.write();
        let stream = guard.streams.iter_mut().find(|s| s.id == id)
            .ok_or_else(|| format!("Stream '{}' not found", id))?;
        if let Some(en) = enabled { stream.enabled = en; }
        if let Some(pr) = priority { stream.priority = pr; }
        if let Some(pi) = poll_interval_sec { stream.poll_interval_sec = pi; }
        if let Some(ft) = failover_timeout_sec { stream.failover_timeout_sec = ft; }
        let res = stream.clone();
        guard.streams.sort_by_key(|s| s.priority);
        drop(guard);
        self.save_atomic()?;
        Ok(res)
    }

    pub fn get_pois(&self) -> Vec<PoiItem> {
        self.poi_items.read().clone()
    }

    pub fn save_poi(&self, item: PoiItem) -> Result<(), String> {
        let mut guard = self.poi_items.write();
        if let Some(pos) = guard.iter().position(|p| p.id == item.id) {
            guard[pos] = item;
        } else {
            guard.push(item);
        }
        drop(guard);
        self.save_pois_atomic()
    }

    pub fn delete_poi(&self, id: &str) -> Result<bool, String> {
        let mut guard = self.poi_items.write();
        let prev_len = guard.len();
        guard.retain(|p| p.id != id);
        let removed = guard.len() < prev_len;
        drop(guard);
        if removed {
            let _ = self.save_pois_atomic();
        }
        Ok(removed)
    }

    pub fn save_pois_atomic(&self) -> Result<(), String> {
        let json_str = {
            let guard = self.poi_items.read();
            serde_json::to_string_pretty(&*guard).map_err(|e| e.to_string())?
        };

        if let Some(parent) = self.poi_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let pid = std::process::id();
        let ts = now_ts();
        let tmp_path = self.poi_path.with_extension(format!("tmp.{}_{}", pid, ts));
        if let Ok(mut f) = File::create(&tmp_path) {
            let write_ok = f.write_all(json_str.as_bytes()).and_then(|_| f.flush());
            drop(f);
            if write_ok.is_ok() {
                if fs::rename(&tmp_path, &self.poi_path).is_ok() {
                    return Ok(());
                }
                if fs::copy(&tmp_path, &self.poi_path).is_ok() {
                    let _ = fs::remove_file(&tmp_path);
                    return Ok(());
                }
                let _ = fs::remove_file(&tmp_path);
            } else {
                let _ = fs::remove_file(&tmp_path);
            }
        }

        let mut direct_f = File::create(&self.poi_path).map_err(|e| e.to_string())?;
        direct_f.write_all(json_str.as_bytes()).map_err(|e| e.to_string())?;
        direct_f.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Атомарний запис конфігурації (.tmp.{pid}_{ts} -> rename) з багаторівневим fallback (copy / direct write)
    pub fn save_atomic(&self) -> Result<(), String> {
        let json_str = {
            let guard = self.data.read();
            serde_json::to_string_pretty(&*guard).map_err(|e| e.to_string())?
        };

        if let Some(parent) = self.file_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let pid = std::process::id();
        let ts = now_ts();
        let tmp_path = self.file_path.with_extension(format!("tmp.{}_{}", pid, ts));

        // Спроба 1: Створення .tmp файлу та атомарний rename
        if let Ok(mut f) = File::create(&tmp_path) {
            let write_ok = f.write_all(json_str.as_bytes()).and_then(|_| f.flush());
            drop(f);

            if write_ok.is_ok() {
                // Спроба атомарного rename
                if fs::rename(&tmp_path, &self.file_path).is_ok() {
                    return Ok(());
                }

                // Fallback 1: Якщо rename не вдався (наприклад, Docker bind-mount окремого файлу hub_config.json,
                // або різні точки монтування / overlayfs EXDEV/EBUSY/ENOENT), копіюємо вміст поверх цільового файлу
                if fs::copy(&tmp_path, &self.file_path).is_ok() {
                    let _ = fs::remove_file(&tmp_path);
                    tracing::info!("save_atomic: updated {:?} via copy fallback", self.file_path);
                    return Ok(());
                }

                let _ = fs::remove_file(&tmp_path);
            } else {
                let _ = fs::remove_file(&tmp_path);
            }
        }

        // Fallback 2: Прямий запис у цільовий файл (якщо tmp створення або rename заблоковані Docker/правами)
        match File::create(&self.file_path) {
            Ok(mut direct_f) => {
                direct_f.write_all(json_str.as_bytes()).map_err(|e| format!("Direct write failed: {}", e))?;
                direct_f.flush().map_err(|e| format!("Direct flush failed: {}", e))?;
                tracing::warn!("Warning: save_atomic used direct write fallback for {:?}", self.file_path);
                Ok(())
            }
            Err(direct_err) => {
                Err(format!(
                    "Не вдалося зберегти конфігурацію у {:?}: {}. Перевірте права доступу до каталогу даних (наприклад: chmod -R 777 /app/data)",
                    self.file_path, direct_err
                ))
            }
        }
    }

    pub fn get_user_by_key(&self, key: &str) -> Option<User> {
        let guard = self.data.read();
        guard.users.get(key).cloned()
    }

    /// Двоетапне оновлення last_seen_ts: запис у стан блокується тільки якщо минуло > 60 секунд
    pub fn update_user_last_seen(&self, key: &str) {
        let now = now_ts();
        {
            let guard = self.data.read();
            if let Some(user) = guard.users.get(key) {
                if let Some(last) = user.last_seen_ts {
                    if now - last < 60 {
                        return;
                    }
                }
            } else {
                return;
            }
        }
        let mut guard = self.data.write();
        if let Some(user) = guard.users.get_mut(key) {
            user.last_seen_ts = Some(now);
        }
    }

    pub fn get_all_users(&self) -> Vec<User> {
        let guard = self.data.read();
        guard.users.values().cloned().collect()
    }

    pub fn update_user_meta(&self, key: &str, owner: Option<String>, enabled: Option<bool>) -> Result<(), String> {
        {
            let mut guard = self.data.write();
            let user = guard.users.get_mut(key).ok_or_else(|| "User not found".to_string())?;
            if let Some(o) = owner {
                user.owner = o;
            }
            if let Some(e) = enabled {
                user.enabled = e;
            }
        }
        self.save_atomic()
    }

    pub fn update_user_settings(
        &self,
        key: &str,
        danger_radius: Option<f64>,
        alert_threat: Option<bool>,
        react_threats: Option<Vec<String>>,
        alert_siren: Option<bool>,
        alert_mig: Option<bool>,
        alert_artillery: Option<bool>,
        apply_to_all_slots: bool,
    ) -> Result<User, String> {
        let updated_user = {
            let mut guard = self.data.write();
            let user = guard.users.get_mut(key).ok_or_else(|| "User not found".to_string())?;

            if let Some(dr) = danger_radius {
                user.default_danger_zone = dr;
            }
            if let Some(at) = alert_threat {
                user.target_alert_threat = at;
            }
            if let Some(rt) = react_threats.as_ref() {
                user.target_react_threats = rt.clone();
            }
            if let Some(as_) = alert_siren {
                user.alert_siren = as_;
            }
            if let Some(am) = alert_mig {
                user.alert_mig = am;
            }
            if let Some(aa) = alert_artillery {
                user.alert_artillery = aa;
            }

            if apply_to_all_slots {
                for slot in user.slots.values_mut() {
                    if let Some(dr) = danger_radius {
                        slot.danger_zone = dr;
                    }
                    if let Some(at) = alert_threat {
                        slot.alert_threat = at;
                    }
                    if let Some(rt) = react_threats.as_ref() {
                        slot.react_threats = rt.clone();
                    }
                    if let Some(as_) = alert_siren {
                        slot.alert_siren = as_;
                    }
                    if let Some(am) = alert_mig {
                        slot.alert_mig = am;
                    }
                    if let Some(aa) = alert_artillery {
                        slot.alert_artillery = aa;
                    }
                }
            }
            user.clone()
        };

        self.save_atomic()?;
        Ok(updated_user)
    }

    pub fn is_history_recording_enabled(&self) -> bool {
        self.data.read().history_recording
    }

    pub fn restore_backup(&self, payload: &serde_json::Value) -> Result<usize, String> {
        let users_val = if let Some(u) = payload.get("users") {
            u
        } else {
            payload
        };

        let mut restored = 0;
        {
            let mut guard = self.data.write();

            if let Some(arr) = users_val.as_array() {
                for item in arr {
                    if let Ok(user) = serde_json::from_value::<User>(item.clone()) {
                        guard.users.insert(user.api_key.clone(), user);
                        restored += 1;
                    }
                }
            } else if let Some(obj) = users_val.as_object() {
                for (key, item) in obj {
                    if let Ok(mut user) = serde_json::from_value::<User>(item.clone()) {
                        if user.api_key.is_empty() {
                            user.api_key = key.clone();
                        }
                        guard.users.insert(user.api_key.clone(), user);
                        restored += 1;
                    }
                }
            } else if payload.get("service_keys").is_none() {
                return Err("Invalid backup format: users must be an array or an object".to_string());
            }

            // Відновлення сервісних API ключів (якщо присутні в бекапі)
            if let Some(sk_val) = payload.get("service_keys") {
                if let Ok(sk) = serde_json::from_value::<ServiceKeysConfig>(sk_val.clone()) {
                    guard.service_keys = sk;
                }
            }

            // Відновлення конфігурації потоків (якщо присутні в бекапі)
            if let Some(st_val) = payload.get("streams") {
                if let Ok(st) = serde_json::from_value::<Vec<StreamSourceConfig>>(st_val.clone()) {
                    guard.streams = st;
                    guard.streams.sort_by_key(|s| s.priority);
                }
            }
        }

        self.save_atomic()?;
        Ok(restored)
    }

    pub fn get_service_keys(&self) -> ServiceKeysConfig {
        let guard = self.data.read();
        guard.service_keys.clone()
    }

    pub fn set_service_key(&self, service: &str, relation: &str, key: Option<String>) -> Result<(), String> {
        let clean_key = key.and_then(|k| {
            let trimmed = k.trim().to_string();
            if trimmed.is_empty() { None } else { Some(trimmed) }
        });

        {
            let mut guard = self.data.write();
            let s_lower = service.to_lowercase();
            if s_lower.contains("ukrainealarm") {
                guard.service_keys.ukrainealarm_api_token = clean_key;
            } else if s_lower.contains("cartodb") {
                let rel = relation.trim();
                if rel.is_empty() || rel.eq_ignore_ascii_case("global") || rel == "Загальна мапа" {
                    guard.service_keys.cartodb_global_api_key = clean_key;
                } else if let Some(k) = clean_key {
                    guard.service_keys.cartodb_user_keys.insert(rel.to_string(), k);
                } else {
                    guard.service_keys.cartodb_user_keys.remove(rel);
                }
            } else {
                return Err(format!("Unknown service: {}", service));
            }
        }
        self.save_atomic()
    }

    pub fn delete_service_key(&self, service: &str, relation: &str) -> Result<bool, String> {
        self.set_service_key(service, relation, None)?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub fn get_cartodb_key(&self, relation: &str) -> Option<String> {
        let guard = self.data.read();
        let rel = relation.trim();
        if !rel.is_empty() && rel != "Загальна мапа" && !rel.eq_ignore_ascii_case("global") {
            if let Some(k) = guard.service_keys.cartodb_user_keys.get(rel) {
                return Some(k.clone());
            }
        }
        guard.service_keys.cartodb_global_api_key.clone()
    }

    pub fn create_user(&self, owner: &str) -> Result<User, String> {
        let mut random_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let api_key = format!("ak_{}", hex::encode(random_bytes));

        let new_user = User {
            owner: owner.to_string(),
            api_key: api_key.clone(),
            enabled: true,
            default_danger_zone: self.default_danger_km,
            target_alert_threat: true,
            target_react_threats: default_react_threats(),
            alert_siren: true,
            alert_mig: true,
            alert_artillery: true,
            slots: {
                let mut def_slots = HashMap::new();
                def_slots.insert("1".to_string(), Slot {
                    id: "1".to_string(),
                    name: "Точка 1".to_string(),
                    lat: 50.4501,
                    lon: 30.5234,
                    active: true,
                    danger_zone: self.default_danger_km,
                    alert_threat: true,
                    react_threats: default_react_threats(),
                    alert_siren: true,
                    alert_mig: true,
                    alert_artillery: true,
                    is_dynamic: false,
                    oblast: None,
                    oblast_id: None,
                    raion: None,
                    raion_id: None,
                    accuracy_m: None,
                });
                def_slots
            },
            created_at: chrono::Utc::now().to_rfc3339(),
            last_seen_ts: Some(now_ts()),
        };

        {
            let mut guard = self.data.write();
            guard.users.insert(api_key, new_user.clone());
        }
        self.save_atomic()?;
        Ok(new_user)
    }

    pub fn delete_user(&self, key: &str) -> Result<bool, String> {
        let removed = {
            let mut guard = self.data.write();
            guard.users.remove(key).is_some()
        };
        if removed {
            self.save_atomic()?;
        }
        Ok(removed)
    }

    pub fn create_slot(
        &self,
        key: &str,
        name: Option<String>,
        lat: f64,
        lon: f64,
        danger_zone: Option<f64>,
        is_dynamic: Option<bool>,
        alert_threat: Option<bool>,
        react_threats: Option<Vec<String>>,
        alert_siren: Option<bool>,
        alert_mig: Option<bool>,
        alert_artillery: Option<bool>,
        detector: &OblastDetector,
    ) -> Result<Slot, String> {
        let mut guard = self.data.write();
        let user = guard.users.get_mut(key).ok_or_else(|| "User not found".to_string())?;

        if user.slots.len() >= 5 {
            return Err("Maximum of 5 slots allowed".to_string());
        }

        // Знаходимо перший вільний ID від "1" до "5"
        let mut target_id = None;
        for i in 1..=5 {
            let s_id = i.to_string();
            if !user.slots.contains_key(&s_id) {
                target_id = Some(s_id);
                break;
            }
        }
        let slot_id = target_id.ok_or_else(|| "No free slot available".to_string())?;

        let loc = detector.find_location_info(lat, lon);
        let eff_danger = danger_zone.unwrap_or(user.default_danger_zone);
        let slot_name = name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| format!("Точка {}", slot_id));

        let new_slot = Slot {
            id: slot_id.clone(),
            name: slot_name,
            lat,
            lon,
            active: true,
            danger_zone: eff_danger,
            alert_threat: alert_threat.unwrap_or(true),
            react_threats: react_threats.filter(|v| !v.is_empty()).unwrap_or_else(|| user.target_react_threats.clone()),
            alert_siren: alert_siren.unwrap_or(user.alert_siren),
            alert_mig: alert_mig.unwrap_or(user.alert_mig),
            alert_artillery: alert_artillery.unwrap_or(user.alert_artillery),
            is_dynamic: is_dynamic.unwrap_or(false),
            oblast: Some(loc.oblast),
            oblast_id: Some(loc.oblast_id),
            raion: Some(loc.raion),
            raion_id: Some(loc.raion_id),
            accuracy_m: None,
        };

        user.slots.insert(slot_id, new_slot.clone());
        drop(guard);
        self.save_atomic()?;
        Ok(new_slot)
    }

    pub fn update_slot(
        &self,
        key: &str,
        slot_id: &str,
        name: Option<String>,
        lat: Option<f64>,
        lon: Option<f64>,
        active: Option<bool>,
        danger_zone: Option<f64>,
        alert_threat: Option<bool>,
        react_threats: Option<Vec<String>>,
        alert_siren: Option<bool>,
        alert_mig: Option<bool>,
        alert_artillery: Option<bool>,
        is_dynamic: Option<bool>,
        detector: &OblastDetector,
    ) -> Result<Slot, String> {
        let mut guard = self.data.write();
        let user = guard.users.get_mut(key).ok_or_else(|| "User not found".to_string())?;
        let slot = user.slots.get_mut(slot_id).ok_or_else(|| "Slot not found".to_string())?;

        if let Some(n) = name { slot.name = n; }
        if let Some(act) = active { slot.active = act; }
        if let Some(dz) = danger_zone { slot.danger_zone = dz; }
        if let Some(at) = alert_threat { slot.alert_threat = at; }
        if let Some(rt) = react_threats.filter(|v| !v.is_empty()) { slot.react_threats = rt; }
        if let Some(as_) = alert_siren { slot.alert_siren = as_; }
        if let Some(am) = alert_mig { slot.alert_mig = am; }
        if let Some(aa) = alert_artillery { slot.alert_artillery = aa; }
        if let Some(dyn_flag) = is_dynamic { slot.is_dynamic = dyn_flag; }

        let coord_changed = match (lat, lon) {
            (Some(new_lat), Some(new_lon)) => {
                slot.lat = new_lat;
                slot.lon = new_lon;
                true
            }
            (Some(new_lat), None) => {
                slot.lat = new_lat;
                true
            }
            (None, Some(new_lon)) => {
                slot.lon = new_lon;
                true
            }
            (None, None) => false,
        };

        if coord_changed {
            let loc = detector.find_location_info(slot.lat, slot.lon);
            slot.oblast = Some(loc.oblast);
            slot.oblast_id = Some(loc.oblast_id);
            slot.raion = Some(loc.raion);
            slot.raion_id = Some(loc.raion_id);
        }

        let updated = slot.clone();
        drop(guard);
        self.save_atomic()?;
        Ok(updated)
    }

    pub fn delete_slot(&self, key: &str, slot_id: &str) -> Result<bool, String> {
        let mut guard = self.data.write();
        let user = guard.users.get_mut(key).ok_or_else(|| "User not found".to_string())?;
        let removed = user.slots.remove(slot_id).is_some();
        drop(guard);
        if removed {
            self.save_atomic()?;
        }
        Ok(removed)
    }

    /// Оновлення динамічної GPS мітки смартфона з успадкуванням стаціонарного слота
    pub fn update_dynamic_location(
        &self,
        key: &str,
        target_slot_id: Option<&str>,
        lat: f64,
        lon: f64,
        accuracy_m: Option<f64>,
        detector: &OblastDetector,
    ) -> Result<Slot, String> {
        let mut guard = self.data.write();
        let user = guard.users.get_mut(key).ok_or_else(|| "User not found".to_string())?;

        let dynamic_slot_id = if let Some(sid) = target_slot_id.filter(|s| !s.is_empty()) {
            sid.to_string()
        } else if let Some((sid, _)) = user.slots.iter().find(|(_, s)| s.is_dynamic) {
            sid.clone()
        } else {
            let mut free_id = None;
            for i in 1..=5 {
                let id_s = i.to_string();
                if !user.slots.contains_key(&id_s) {
                    free_id = Some(id_s);
                    break;
                }
            }
            free_id.unwrap_or_else(|| "1".to_string())
        };

        let (old_lat, old_lon, existed) = match user.slots.get(&dynamic_slot_id) {
            Some(s) => (s.lat, s.lon, true),
            None => (0.0, 0.0, false),
        };

        // Перевіряємо чи потрапляє динамічна точка в зону небезпеки будь-якого стаціонарного слота
        // Якщо потрапляє -> вона повністю приймає параметри (радіус, фільтри загроз та локацію) цього слота
        let mut inherited_loc = None;
        let mut inherited_params = None;
        for (sid, s) in &user.slots {
            if sid != &dynamic_slot_id && !s.is_dynamic {
                let dist = calculate_haversine_distance(lat, lon, s.lat, s.lon);
                if dist <= s.danger_zone {
                    inherited_loc = Some((s.oblast.clone(), s.oblast_id.clone(), s.raion.clone(), s.raion_id.clone()));
                    inherited_params = Some((
                        s.danger_zone,
                        s.react_threats.clone(),
                        s.alert_threat,
                        s.alert_siren,
                        s.alert_mig,
                        s.alert_artillery,
                    ));
                    break;
                }
            }
        }

        let (ob, ob_id, ra, ra_id) = if let Some(inh) = inherited_loc {
            inh
        } else {
            let loc = detector.find_location_info(lat, lon);
            (Some(loc.oblast), Some(loc.oblast_id), Some(loc.raion), Some(loc.raion_id))
        };

        let slot = user.slots.entry(dynamic_slot_id.clone()).or_insert_with(|| Slot {
            id: dynamic_slot_id.clone(),
            name: "Смартфон".to_string(),
            lat,
            lon,
            active: true,
            danger_zone: user.default_danger_zone,
            alert_threat: true,
            react_threats: user.target_react_threats.clone(),
            alert_siren: user.alert_siren,
            alert_mig: user.alert_mig,
            alert_artillery: user.alert_artillery,
            is_dynamic: true,
            oblast: ob.clone(),
            oblast_id: ob_id.clone(),
            raion: ra.clone(),
            raion_id: ra_id.clone(),
            accuracy_m,
        });

        slot.lat = lat;
        slot.lon = lon;
        slot.is_dynamic = true;
        slot.accuracy_m = accuracy_m;
        slot.oblast = ob;
        slot.oblast_id = ob_id;
        slot.raion = ra;
        slot.raion_id = ra_id;

        // Застосування успадкованих параметрів стаціонарного слота
        if let Some((inh_dz, inh_react, inh_threat, inh_siren, inh_mig, inh_art)) = inherited_params {
            slot.danger_zone = inh_dz;
            slot.react_threats = inh_react;
            slot.alert_threat = inh_threat;
            slot.alert_siren = inh_siren;
            slot.alert_mig = inh_mig;
            slot.alert_artillery = inh_art;
        }

        let res = slot.clone();
        drop(guard);

        let moved_dist = if existed {
            calculate_haversine_distance(old_lat, old_lon, lat, lon)
        } else {
            1.0 // new slot, save immediately
        };

        // Записуємо на диск (eMMC iHost) тільки при переміщенні > 50м для збереження ресурсу флеш-пам'яті
        if moved_dist > 0.05 {
            self.save_atomic()?;
        }
        Ok(res)
    }

    pub fn get_gdrive_config(&self) -> HubConfigData {
        self.data.read().clone()
    }

    pub fn update_gdrive_config(
        &self,
        recording: Option<bool>,
        webhook_url: Option<String>,
        folder_url: Option<String>,
        auto_sync_hours: Option<u32>,
    ) -> Result<(), String> {
        let mut guard = self.data.write();
        if let Some(r) = recording { guard.history_recording = r; }
        if let Some(w) = webhook_url { guard.gdrive_webhook_url = Some(w); }
        if let Some(f) = folder_url { guard.gdrive_folder_url = Some(f); }
        if let Some(h) = auto_sync_hours { guard.gdrive_auto_sync_hours = h; }
        drop(guard);
        self.save_atomic()
    }

    pub fn mark_gdrive_synced(&self) {
        {
            let mut guard = self.data.write();
            guard.last_gdrive_sync_ts = Some(now_ts());
        }
        let _ = self.save_atomic();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_user_isolation_contract() {
        let guest = User::guest(35.0);
        assert_eq!(guest.owner, "Загальний доступ");
        assert_eq!(guest.api_key, "");
        assert!(guest.slots.is_empty(), "Guest must not have pre-configured private observation slots");
        assert_eq!(guest.default_danger_zone, 35.0);
        assert!(guest.enabled);
    }

    #[test]
    fn test_stream_source_config_defaults_and_sorting() {
        let mut defaults = default_stream_sources();
        assert_eq!(defaults.len(), 5);
        assert_eq!(defaults[0].id, "ukrainealarm_alerts");
        assert_eq!(defaults[1].id, "neptun_alerts");
        assert_eq!(defaults[2].id, "ukrainealarm_ws");
        assert_eq!(defaults[3].id, "neptun_targets");
        assert_eq!(defaults[4].id, "mapa_targets");

        // Пріоритет переставляється динамічно
        defaults[3].priority = 0;
        defaults.sort_by_key(|s| s.priority);
        assert_eq!(defaults[0].priority, 0);
        assert_eq!(defaults[0].id, "neptun_targets");
    }
}
