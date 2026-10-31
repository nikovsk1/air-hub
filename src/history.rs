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

/// Легка структура статистики за поточну добу (живе в RAM, O(1) доступ)
#[derive(Debug, Clone)]
struct TodayStats {
    date: String,
    tracked_target_ids: HashSet<String>,
    total: usize,
    by_category: HashMap<String, usize>,
}

pub struct HistoryManager {
    pub history_dir: PathBuf,
    dirty_months: RwLock<HashSet<String>>,
    pending_dirty: RwLock<HashMap<String, HashMap<String, Value>>>, // month -> targets pending write
    read_cache: RwLock<HashMap<String, Value>>,                     // LRU cache for queries (max 2)
    today_stats: RwLock<TodayStats>,                               // O(1) instant stats for gauge
    gdrive_synced_months: RwLock<HashSet<String>>,
}

impl HistoryManager {
    pub fn new(data_dir: &Path) -> Self {
        let history_dir = data_dir.join("history");
        let _ = fs::create_dir_all(&history_dir);

        let now = Utc::now();
        let today_str = now.format("%Y-%m-%d").to_string();
        let current_month = format!("{:04}-{:02}", now.year(), now.month());

        // Завантажуємо статистику за сьогодні з диску під час старту (якщо файл уже існує)
        let mut today_ids = HashSet::new();
        let mut today_total = 0;
        let mut today_by_cat = HashMap::new();

        let month_file = history_dir.join(format!("flight_history_{}.json", current_month));
        if month_file.exists() {
            if let Ok(content) = fs::read_to_string(&month_file) {
                if let Ok(val) = serde_json::from_str::<Value>(&content) {
                    if let Some(targets) = val.get("targets").and_then(|t| t.as_object()) {
                        for (tid, t) in targets {
                            if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                                if d == today_str {
                                    today_ids.insert(tid.clone());
                                    today_total += 1;
                                    let cat = t.get("cat")
                                        .or_else(|| t.get("category"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    *today_by_cat.entry(cat.to_string()).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        Self {
            history_dir,
            dirty_months: RwLock::new(HashSet::new()),
            pending_dirty: RwLock::new(HashMap::new()),
            read_cache: RwLock::new(HashMap::new()),
            today_stats: RwLock::new(TodayStats {
                date: today_str,
                tracked_target_ids: today_ids,
                total: today_total,
                by_category: today_by_cat,
            }),
            gdrive_synced_months: RwLock::new(HashSet::new()),
        }
    }

    pub fn current_month() -> String {
        let now = Utc::now();
        format!("{:04}-{:02}", now.year(), now.month())
    }

    /// Запис активного або завершеного треку в історію
    pub fn record_track(&self, trk: &TargetTrack, status: &str) {
        let now = Utc::now();
        let month = format!("{:04}-{:02}", now.year(), now.month());
        let date_str = now.format("%Y-%m-%d").to_string();

        // 1. Оновлюємо легку статистику за сьогодні (O(1) в RAM)
        {
            let mut ts = self.today_stats.write();
            if ts.date != date_str {
                ts.date = date_str.clone();
                ts.tracked_target_ids.clear();
                ts.total = 0;
                ts.by_category.clear();
            }
            if ts.tracked_target_ids.insert(trk.id.clone()) {
                ts.total += 1;
                *ts.by_category.entry(trk.category.clone()).or_insert(0) += 1;
            }
        }

        // 2. Формуємо запис траєкторії для збереження
        let path_json: Vec<Value> = trk.trajectory.iter().map(|p| {
            json!([
                p.ts,
                p.lat,
                p.lon,
                trk.heading,
                trk.speed_kmh
            ])
        }).collect();

        let item = json!({
            "id": trk.id,
            "cat": trk.category,
            "date": date_str,
            "start_time": trk.first_seen as i64,
            "end_time": trk.last_seen as i64,
            "status": status,
            "path": path_json
        });

        // 3. Додаємо виключно в буфер незбережених змін (не тримаємо повний місяць у RAM!)
        {
            let mut pending = self.pending_dirty.write();
            pending.entry(month.clone()).or_default().insert(trk.id.clone(), item);
        }
        {
            let mut dirty = self.dirty_months.write();
            dirty.insert(month);
        }
    }

    /// Періодичний скид накопичених "брудних" даних на диск (кожні 300 секунд)
    pub fn flush_dirty(&self) {
        let dirty_batch: HashMap<String, HashMap<String, Value>> = {
            let mut guard = self.pending_dirty.write();
            let mut dm = self.dirty_months.write();
            dm.clear();
            std::mem::take(&mut *guard)
        };

        if dirty_batch.is_empty() {
            return;
        }

        for (month, new_targets) in dirty_batch {
            let mut targets = self.load_month_from_disk(&month).unwrap_or_default();
            for (tid, item) in new_targets {
                targets.insert(tid, item);
            }

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

            let total_t = targets.len();
            let full_data = json!({
                "month": month,
                "updated_at": Utc::now().to_rfc3339(),
                "total_targets": total_t,
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
                        info!("Flushed flight history for {} ({} targets)", month, total_t);
                        // Інвалідуємо старий запис у read_cache, щоб при запиті історії читався свіжий файл
                        self.read_cache.write().remove(&month);
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

    /// Легке зчитування тільки заголовка місячного файлу без десеріалізації масиву цілей
    fn load_month_metadata(&self, month: &str) -> Option<(usize, Vec<String>, String)> {
        let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
        if !file_path.exists() {
            return None;
        }

        let content = fs::read_to_string(&file_path).ok()?;
        #[derive(Deserialize)]
        struct HeaderOnly {
            total_targets: Option<usize>,
            dates: Option<Vec<String>>,
            updated_at: Option<String>,
        }

        if let Ok(hdr) = serde_json::from_str::<HeaderOnly>(&content) {
            Some((
                hdr.total_targets.unwrap_or(0),
                hdr.dates.unwrap_or_default(),
                hdr.updated_at.unwrap_or_default(),
            ))
        } else {
            None
        }
    }

    /// Миттєве повернення лічильників за сьогодні для віджета та live-панелі (O(1))
    pub fn get_today_counts(&self) -> (usize, HashMap<String, usize>) {
        let now_date = Utc::now().format("%Y-%m-%d").to_string();
        let ts = self.today_stats.read();
        if ts.date == now_date {
            (ts.total, ts.by_category.clone())
        } else {
            (0, HashMap::new())
        }
    }

    pub fn get_month_data(&self, month: &str) -> Option<Value> {
        self.get_month_history_filtered(month, None)
    }

    /// Отримання історії за вибраний місяць з фільтрацією за днем (YYYY-MM-DD)
    pub fn get_month_history_filtered(&self, month: &str, date_filter: Option<&str>) -> Option<Value> {
        let cached = {
            let guard = self.read_cache.read();
            guard.get(month).cloned()
        };

        let full_month = match cached {
            Some(v) => v,
            None => {
                let targets = self.load_month_from_disk(month)?;
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

                // LRU-кеш: максимум 2 місяці
                let mut guard = self.read_cache.write();
                if guard.len() >= 2 {
                    let oldest_key = guard.keys().next().cloned();
                    if let Some(k) = oldest_key {
                        guard.remove(&k);
                    }
                }
                guard.insert(month.to_string(), full_data.clone());
                full_data
            }
        };

        let targets = full_month.get("targets").and_then(|t| t.as_object())?;
        let dates_vec = full_month.get("dates").cloned().unwrap_or_else(|| json!([]));

        if let Some(df) = date_filter {
            if !df.is_empty() && df != "all" {
                let mut filtered_targets = serde_json::Map::new();
                for (id, t) in targets {
                    if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                        if d == df {
                            filtered_targets.insert(id.clone(), t.clone());
                        }
                    }
                }
                return Some(json!({
                    "month": month,
                    "date": df,
                    "updated_at": full_month.get("updated_at"),
                    "total_targets": filtered_targets.len(),
                    "dates": dates_vec,
                    "targets": filtered_targets
                }));
            }
        }

        Some(full_month)
    }

    /// Отримання доступних місяців та дат для ukraine-radar-card (легке зчитування без парсингу цілей)
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

                        let dates_list = if let Some((_, dates, _)) = self.load_month_metadata(&m) {
                            dates
                        } else {
                            Vec::new()
                        };

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

    /// Список файлів історії для Admin UI (легке зчитування метаданих без навантаження на RAM)
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
                let mut updated_at_str = String::new();

                if let Some((cnt, dates, updated_at)) = self.load_month_metadata(&month) {
                    targets_count = cnt;
                    updated_at_str = updated_at;
                    for d in dates {
                        if let Some(day_part) = d.split('-').nth(2) {
                            if let Ok(day_num) = day_part.parse::<u32>() {
                                days_set.insert(day_num);
                            }
                        }
                    }
                }

                let days_count = days_set.len();
                let days_min = days_set.iter().min().copied();
                let days_max = days_set.iter().max().copied();

                let is_synced = self.gdrive_synced_months.read().contains(&month);

                list.push(HistoryFileInfo {
                    month,
                    filename: name.to_string(),
                    targets_count,
                    total_targets: targets_count,
                    last_modified_ts: last_mod_ts,
                    updated_at: updated_at_str,
                    is_synced,
                    on_gdrive: is_synced,
                    days_count,
                    days_min,
                    days_max,
                    size_kb,
                    size_bytes,
                });
            }
        }

        list.sort_by(|a, b| b.month.cmp(&a.month));
        list
    }

    /// Імпорт зовнішнього JSON (наприклад, архівні дані каналів)
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
                    if let Some(pt_arr) = p.as_array() {
                        norm_path.push(json!(pt_arr));
                    }
                }
            }

            let entry = json!({
                "id": tid,
                "name": name_ua,
                "cat": cat,
                "color": color,
                "date": target_date,
                "start_time": first_seen,
                "end_time": last_seen,
                "status": status,
                "path": norm_path
            });

            {
                let mut pending = self.pending_dirty.write();
                pending.entry(target_month.clone()).or_default().insert(tid.clone(), entry);
            }

            if !dirty_to_mark.contains(&target_month) {
                dirty_to_mark.push(target_month);
            }
            imported_count += 1;
        }

        if !dirty_to_mark.is_empty() {
            let mut dm = self.dirty_months.write();
            for m in dirty_to_mark {
                dm.insert(m);
            }
        }

        info!("Imported {} targets from external JSON payload", imported_count);
        imported_count
    }
}
