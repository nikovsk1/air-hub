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
        }
    }
}

pub struct StorageManager {
    file_path: PathBuf,
    default_danger_km: f64,
    data: RwLock<HubConfigData>,
}

impl StorageManager {
    pub fn new(data_dir: &Path, initial_users: &[(String, String)], detector: &OblastDetector, default_danger_km: f64) -> Self {
        let file_path = data_dir.join("hub_config.json");
        let mut loaded = HubConfigData::default();

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

        let mgr = Self {
            file_path,
            default_danger_km,
            data: RwLock::new(loaded),
        };
        let _ = mgr.save_atomic();
        mgr
    }

    /// Атомарний запис конфігурації (.tmp.{pid}_{ts} -> rename)
    pub fn save_atomic(&self) -> Result<(), String> {
        let json_str = {
            let guard = self.data.read();
            serde_json::to_string_pretty(&*guard).map_err(|e| e.to_string())?
        };

        let pid = std::process::id();
        let ts = now_ts();
        let tmp_path = self.file_path.with_extension(format!("tmp.{}_{}", pid, ts));

        let mut f = File::create(&tmp_path).map_err(|e| format!("Create tmp file failed: {}", e))?;
        f.write_all(json_str.as_bytes()).map_err(|e| format!("Write failed: {}", e))?;
        f.flush().map_err(|e| format!("Flush failed: {}", e))?;
        drop(f);

        fs::rename(&tmp_path, &self.file_path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("Atomic rename failed: {}", e)
        })?;

        Ok(())
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

    pub fn restore_users(&self, payload: &serde_json::Value) -> Result<usize, String> {
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
            } else {
                return Err("Invalid backup format: users must be an array or an object".to_string());
            }
        }

        self.save_atomic()?;
        Ok(restored)
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
