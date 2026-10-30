use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use parking_lot::RwLock;
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::storage::now_ts;
use crate::tracker::TargetTrack;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct HistoryTargetItem {
    pub id: String,
    pub type_ua: String,
    pub category: String,
    pub color_hex: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub status: String,
    pub trajectory: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFileInfo {
    pub month: String,
    pub filename: String,
    pub targets_count: usize,
    pub total_targets: usize,
    pub last_modified_ts: i64,
    pub updated_at: String,
    pub is_synced: bool,
    pub on_gdrive: bool,
    pub days_count: usize,
    pub days_min: Option<u32>,
    pub days_max: Option<u32>,
    pub size_kb: f64,
    pub size_bytes: u64,
}

pub struct HistoryManager {
    pub history_dir: PathBuf,
    dirty_months: RwLock<HashSet<String>>,
    cache: RwLock<HashMap<String, HashMap<String, Value>>>, // month -> targets
    gdrive_synced_months: RwLock<HashSet<String>>,
}

impl HistoryManager {
    pub fn new(data_dir: &Path) -> Self {
        let history_dir = data_dir.join("history");
        let _ = fs::create_dir_all(&history_dir);

        Self {
            history_dir,
            dirty_months: RwLock::new(HashSet::new()),
            cache: RwLock::new(HashMap::new()),
            gdrive_synced_months: RwLock::new(HashSet::new()),
        }
    }

    pub fn current_month() -> String {
        let now = Utc::now();
        format!("{:04}-{:02}", now.year(), now.month())
    }

    /// Фіксація треку цілі в оперативному буфері історії
    pub fn record_track(&self, trk: &TargetTrack, status: &str) {
        let month = Self::current_month();

        // Повнорозмірні координати f64 без зрізання та округлення
        let path_json: Vec<Value> = trk.trajectory.iter().map(|p| {
            json!([
                p.ts,
                p.lat,
                p.lon,
                trk.heading,
                trk.speed_kmh
            ])
        }).collect();

        let traj_json: Vec<Value> = trk.trajectory.iter().map(|p| {
            json!({
                "lat": p.lat,
                "lon": p.lon,
                "ts": p.ts
            })
        }).collect();

        let date_str = Utc::now().format("%Y-%m-%d").to_string();

        let item = json!({
            "id": trk.id,
            "cat": trk.category,
            "name_ua": trk.type_ua,
            "raw_type": trk.raw_code,
            "type": trk.type_ua,
            "category": trk.category,
            "color_hex": trk.color_hex,
            "date": date_str,
            "start_time": trk.first_seen as i64,
            "end_time": trk.last_seen as i64,
            "first_seen": trk.first_seen as i64,
            "last_seen": trk.last_seen as i64,
            "status": status,
            "path": path_json,
            "trajectory": traj_json
        });

        {
            let mut cache_guard = self.cache.write();
            let month_targets = cache_guard.entry(month.clone()).or_insert_with(|| {
                // Завантаження існуючого місяця з диска, якщо є
                self.load_month_from_disk(&month).unwrap_or_default()
            });
            month_targets.insert(trk.id.clone(), item);
        }

        {
            let mut dirty = self.dirty_months.write();
            dirty.insert(month);
        }
    }

    /// Періодичний атомарний скид "брудних" місяців на диск (раз на 300 сек для захисту SD-карти)
    pub fn flush_dirty(&self) {
        let dirty: Vec<String> = {
            let mut guard = self.dirty_months.write();
            let list = guard.iter().cloned().collect();
            guard.clear();
            list
        };

        if dirty.is_empty() {
            return;
        }

        let cache_guard = self.cache.read();
        for month in dirty {
            if let Some(targets) = cache_guard.get(&month) {
                let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
                let pid = std::process::id();
                let tmp_path = file_path.with_extension(format!("tmp.{}_{}", pid, now_ts()));

                let mut dates_set = std::collections::BTreeSet::new();
                for t in targets.values() {
                    if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                        if !d.is_empty() {
                            dates_set.insert(d.to_string());
                        }
                    }
                }
                let dates_vec: Vec<String> = dates_set.into_iter().collect();

                let full_data = json!({
                    "month": month,
                    "updated_at": Utc::now().to_rfc3339(),
                    "total_targets": targets.len(),
                    "dates": dates_vec,
                    "targets": targets
                });

                if let Ok(json_str) = serde_json::to_string(&full_data) {
                    if let Ok(mut f) = File::create(&tmp_path) {
                        let _ = f.write_all(json_str.as_bytes());
                        let _ = f.flush();
                        drop(f);
                        if let Err(e) = fs::rename(&tmp_path, &file_path) {
                            let _ = fs::remove_file(&tmp_path);
                            warn!("Failed to save flight history {}: {}", month, e);
                        } else {
                            info!("Flushed flight history for {} ({} targets)", month, targets.len());
                        }
                    }
                }
            }
        }
    }

    fn load_month_from_disk(&self, month: &str) -> Option<HashMap<String, Value>> {
        let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
        if !file_path.exists() {
            return None;
        }

        let content = fs::read_to_string(&file_path).ok()?;
        let val: Value = serde_json::from_str(&content).ok()?;
        let targets = val.get("targets")?.as_object()?;

        let mut res = HashMap::new();
        for (k, v) in targets {
            res.insert(k.clone(), v.clone());
        }
        Some(res)
    }

    pub fn get_month_data(&self, month: &str) -> Option<Value> {
        self.get_month_history_filtered(month, None)
    }

    /// Отримання даних місяця з опціональною фільтрацією за датою (день YYYY-MM-DD)
    pub fn get_month_history_filtered(&self, month: &str, date_filter: Option<&str>) -> Option<Value> {
        let targets = {
            let cache_guard = self.cache.read();
            if let Some(t) = cache_guard.get(month) {
                Some(t.clone())
            } else {
                None
            }
        };

        let targets = match targets {
            Some(t) => t,
            None => {
                if let Some(disk_targets) = self.load_month_from_disk(month) {
                    let mut cache_guard = self.cache.write();
                    if cache_guard.len() >= 3 {
                        let first_key = cache_guard.keys().next().cloned();
                        if let Some(k) = first_key {
                            cache_guard.remove(&k);
                        }
                    }
                    cache_guard.insert(month.to_string(), disk_targets.clone());
                    disk_targets
                } else {
                    return None;
                }
            }
        };

        let mut dates_set = std::collections::BTreeSet::new();
        for t in targets.values() {
            if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                if !d.is_empty() {
                    dates_set.insert(d.to_string());
                }
            }
        }
        let dates_vec: Vec<String> = dates_set.into_iter().collect();

        if let Some(df) = date_filter {
            if !df.is_empty() && df != "all" {
                let mut filtered_targets = HashMap::new();
                for (id, t) in &targets {
                    if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                        if d == df {
                            filtered_targets.insert(id.clone(), t.clone());
                        }
                    }
                }
                return Some(json!({
                    "month": month,
                    "date": df,
                    "updated_at": Utc::now().to_rfc3339(),
                    "total_targets": filtered_targets.len(),
                    "dates": dates_vec,
                    "targets": filtered_targets
                }));
            }
        }

        Some(json!({
            "month": month,
            "updated_at": Utc::now().to_rfc3339(),
            "total_targets": targets.len(),
            "dates": dates_vec,
            "targets": targets
        }))
    }

    /// Словник доступних місяців та дат для плеєра історії ukraine-radar-card (локальні + хмара)
    pub fn get_available_months_map(&self) -> (HashMap<String, Vec<String>>, HashMap<String, String>) {
        let mut months_dict: HashMap<String, Vec<String>> = HashMap::new();
        let mut sources_dict: HashMap<String, String> = HashMap::new();

        if let Ok(entries) = fs::read_dir(&self.history_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.starts_with("flight_history_") && name.ends_with(".json") {
                        let m = name
                            .trim_start_matches("flight_history_")
                            .trim_end_matches(".json")
                            .to_string();

                        let mut dates_list = Vec::new();
                        if let Some(data) = self.get_month_data(&m) {
                            if let Some(d_arr) = data.get("dates").and_then(|d| d.as_array()) {
                                dates_list = d_arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                            }
                        }
                        months_dict.insert(m.clone(), dates_list);
                        sources_dict.insert(m, "local".to_string());
                    }
                }
            }
        }

        let gdrive_synced = self.gdrive_synced_months.read();
        for gm in gdrive_synced.iter() {
            if months_dict.contains_key(gm) {
                sources_dict.insert(gm.clone(), "both".to_string());
            } else {
                months_dict.insert(gm.clone(), Vec::new());
                sources_dict.insert(gm.clone(), "gdrive".to_string());
            }
        }

        (months_dict, sources_dict)
    }

    /// Список локальних файлів історії з детальною аналітикою для Admin UI
    pub fn list_files_summary(&self) -> Vec<HistoryFileInfo> {
        let mut list = Vec::new();
        let entries = match fs::read_dir(&self.history_dir) {
            Ok(e) => e,
            Err(_) => return list,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("flight_history_") && name.ends_with(".json") {
                let month = name
                    .trim_start_matches("flight_history_")
                    .trim_end_matches(".json")
                    .to_string();

                let metadata = path.metadata().ok();
                let size_bytes = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                let size_kb = (size_bytes as f64) / 1024.0;
                let last_mod_ts = metadata
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                let mut targets_count = 0;
                let mut days_set = HashSet::new();

                if let Some(month_data) = self.get_month_data(&month) {
                    if let Some(targets) = month_data.get("targets").and_then(|t| t.as_object()) {
                        targets_count = targets.len();
                        for t in targets.values() {
                            if let Some(first_seen) = t.get("first_seen").and_then(|f| f.as_i64()) {
                                if let Some(dt) = chrono::DateTime::from_timestamp(first_seen, 0) {
                                    days_set.insert(dt.day());
                                }
                            }
                        }
                    }
                }

                let days_min = days_set.iter().min().copied();
                let days_max = days_set.iter().max().copied();
                let is_synced = self.gdrive_synced_months.read().contains(&month);

                list.push(HistoryFileInfo {
                    month: month.clone(),
                    filename: name.to_string(),
                    targets_count,
                    total_targets: targets_count,
                    last_modified_ts: last_mod_ts,
                    updated_at: chrono::DateTime::from_timestamp(last_mod_ts, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default(),
                    is_synced,
                    on_gdrive: is_synced,
                    days_count: days_set.len(),
                    days_min,
                    days_max,
                    size_kb: (size_kb * 10.0).round() / 10.0,
                    size_bytes,
                });
            }
        }

        list.sort_by(|a, b| b.month.cmp(&a.month));
        list
    }

    /// Синхронізація місяця в Google Drive через Webhook Apps Script
    pub async fn sync_to_gdrive(&self, month: &str, webhook_url: &str, client: &reqwest::Client) -> Result<(usize, f64), String> {
        if webhook_url.trim().is_empty() {
            return Err("Google Apps Script Webhook URL не налаштовано!".to_string());
        }

        let month_data = self.get_month_data(month)
            .ok_or_else(|| format!("Місяць {} не знайдено на диску", month))?;

        let targets_count = month_data.get("total_targets").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
        let payload_str = serde_json::to_string(&month_data).map_err(|e| e.to_string())?;
        let size_kb = (payload_str.len() as f64) / 1024.0;

        let resp = client.post(webhook_url)
            .json(&json!({
                "action": "upload_month",
                "month": month,
                "data": month_data
            }))
            .send()
            .await
            .map_err(|e| format!("HTTP request to Google Apps Script failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Google Apps Script returned HTTP {}", resp.status()));
        }

        self.gdrive_synced_months.write().insert(month.to_string());
        Ok((targets_count, (size_kb * 10.0).round() / 10.0))
    }

    /// Отримання місяця з Google Drive, якщо він відсутній локально
    pub async fn fetch_month_from_gdrive(&self, month: &str, webhook_url: &str, client: &reqwest::Client) -> Result<Value, String> {
        let resp = client.post(webhook_url)
            .json(&json!({
                "action": "get_month",
                "month": month
            }))
            .send()
            .await
            .map_err(|e| format!("HTTP request to Google Apps Script failed: {}", e))?;

        let val: Value = resp.json().await.map_err(|e| format!("Invalid JSON from GDrive: {}", e))?;
        if let Some(_targets) = val.get("targets").and_then(|t| t.as_object()) {
            // Зберігаємо завантажений файл локально
            let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
            if let Ok(json_str) = serde_json::to_string(&val) {
                let _ = fs::write(&file_path, json_str);
            }
            Ok(val)
        } else {
            Err("Місяць не знайдено в Google Drive".to_string())
        }
    }

    /// Імпорт зовнішньої історії (наприклад, із Python-бекапу або завантаженого JSON файлу)
    pub fn import_external_history(&self, raw_data: &Value) -> usize {
        let items: Vec<&Value> = if let Some(obj) = raw_data.get("targets").and_then(|t| t.as_object()) {
            obj.values().collect()
        } else if let Some(arr) = raw_data.as_array() {
            arr.iter().collect()
        } else if let Some(obj) = raw_data.as_object() {
            obj.values().collect()
        } else {
            return 0;
        };

        if items.is_empty() {
            return 0;
        }

        let mut imported_count = 0;
        let mut dirty_to_mark = Vec::new();

        for item in items.into_iter().take(5000) {
            let tid = match item.get("display_id").or_else(|| item.get("id")).and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };

            let name_ua = item.get("type_ua").or_else(|| item.get("type")).or_else(|| item.get("name_ua")).and_then(|v| v.as_str()).unwrap_or("Ціль").to_string();
            let cat = item.get("category").or_else(|| item.get("cat")).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let color = item.get("color_hex").or_else(|| item.get("color")).and_then(|v| v.as_str()).unwrap_or("#38bdf8").to_string();
            let first_seen = item.get("first_seen").or_else(|| item.get("start_time")).and_then(|v| v.as_i64()).unwrap_or_else(now_ts);
            let last_seen = item.get("last_seen").or_else(|| item.get("end_time")).and_then(|v| v.as_i64()).unwrap_or(first_seen);
            let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("lost").to_string();

            let target_dt = chrono::DateTime::from_timestamp(first_seen, 0).unwrap_or_else(Utc::now);
            let target_month = format!("{:04}-{:02}", target_dt.year(), target_dt.month());
            let target_date = format!("{:04}-{:02}-{:02}", target_dt.year(), target_dt.month(), target_dt.day());

            let raw_path = item.get("path").or_else(|| item.get("trajectory")).and_then(|v| v.as_array());
            let mut norm_path = Vec::new();
            if let Some(arr) = raw_path {
                for p in arr {
                    if let Some(sub) = p.as_array() {
                        if sub.len() >= 3 {
                            norm_path.push(json!([
                                sub[0].as_i64().or_else(|| sub[0].as_f64().map(|v| v as i64)).unwrap_or(first_seen),
                                sub[1].as_f64().unwrap_or(0.0),
                                sub[2].as_f64().unwrap_or(0.0),
                                sub.get(3).and_then(|v| v.as_f64()).unwrap_or(0.0),
                                sub.get(4).and_then(|v| v.as_f64()).unwrap_or(185.0)
                            ]));
                        }
                    } else if let Some(obj) = p.as_object() {
                        norm_path.push(json!([
                            obj.get("time").or_else(|| obj.get("ts")).and_then(|v| v.as_i64()).unwrap_or(first_seen),
                            obj.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0),
                            obj.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0),
                            obj.get("heading").and_then(|v| v.as_f64()).unwrap_or(0.0),
                            obj.get("speed").and_then(|v| v.as_f64()).unwrap_or(185.0)
                        ]));
                    }
                }
            }

            let entry = json!({
                "id": tid.clone(),
                "name_ua": name_ua,
                "cat": cat,
                "color_hex": color,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "path": norm_path,
                "dates": [target_date],
                "status": status
            });

            let mut cache = self.cache.write();
            let m_map = cache.entry(target_month.clone()).or_insert_with(|| {
                self.load_month_from_disk(&target_month).unwrap_or_default()
            });
            m_map.insert(tid, entry);
            imported_count += 1;
            dirty_to_mark.push(target_month);
        }

        let mut dirty = self.dirty_months.write();
        for m in dirty_to_mark {
            dirty.insert(m);
        }
        drop(dirty);

        self.flush_dirty();
        imported_count
    }
}

