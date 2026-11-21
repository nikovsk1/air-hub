use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use parking_lot::RwLock;
use chrono::{Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::storage::now_ts;
use crate::tracker::TargetTrack;

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

/// Погодинний підсумок активності для добового зведення
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HourlySummary {
    pub hour: u8,
    pub total: usize,
    pub types: HashMap<String, usize>,
}

/// Статистика активності по області/регіону
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegionSummary {
    pub region_id: String,
    pub name: String,
    pub total: usize,
}

/// Агреговане зведення доби (формується накопичувально та верифікується з targetHistory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySummary {
    pub date: String,
    pub status: String, // "accumulated" | "reconciled"
    pub total: usize,
    pub types: HashMap<String, usize>,
    #[serde(default)]
    pub eliminated: usize,
    #[serde(default)]
    pub hit_target: usize,
    #[serde(default)]
    pub lost: usize,
    pub hours: Vec<HourlySummary>,
    pub regions: Vec<RegionSummary>,
    pub last_updated_at: String,
    #[serde(default)]
    pub last_reconciled_at: Option<String>,
}

impl DailySummary {
    pub fn new_empty(date: &str) -> Self {
        let mut hours = Vec::with_capacity(24);
        for h in 0..24 {
            hours.push(HourlySummary {
                hour: h as u8,
                total: 0,
                types: HashMap::new(),
            });
        }
        Self {
            date: date.to_string(),
            status: "accumulated".to_string(),
            total: 0,
            types: HashMap::new(),
            eliminated: 0,
            hit_target: 0,
            lost: 0,
            hours,
            regions: Vec::new(),
            last_updated_at: Utc::now().to_rfc3339(),
            last_reconciled_at: None,
        }
    }
}

/// Легка структура статистики за поточну добу (живе в RAM, O(1) доступ)
#[derive(Debug, Clone, Default)]
struct TodayStats {
    date: String,
    tracked_target_ids: HashSet<String>,
    tracked_target_statuses: HashMap<String, String>,
    total: usize,
    by_category: HashMap<String, usize>,
    eliminated_count: usize,
    hit_target_count: usize,
    lost_count: usize,
}

pub struct HistoryManager {
    pub history_dir: PathBuf,
    dirty_months: RwLock<HashSet<String>>,
    pending_dirty: RwLock<HashMap<String, HashMap<String, Value>>>, // month -> targets pending write
    read_cache: RwLock<HashMap<String, Value>>,                     // LRU cache for queries (max 2)
    month_meta_cache: RwLock<HashMap<String, (usize, Vec<String>, String)>>, // In-memory metadata index (dates, counts)
    today_stats: RwLock<TodayStats>,                               // O(1) instant stats for gauge
    pub daily_summaries: RwLock<HashMap<String, HashMap<String, DailySummary>>>, // month -> (date -> DailySummary)
    gdrive_synced_months: RwLock<HashSet<String>>,
}

impl HistoryManager {
    pub fn new(data_dir: &Path) -> Self {
        let history_dir = data_dir.join("history");
        let _ = fs::create_dir_all(&history_dir);

        let kyiv = Self::now_kyiv();
        let today_str = kyiv.format("%Y-%m-%d").to_string();
        let current_month = format!("{:04}-{:02}", kyiv.year(), kyiv.month());

        // Завантажуємо збережені daily_summaries та today_stats з диску під час старту
        let mut today_ids = HashSet::new();
        let mut today_statuses = HashMap::new();
        let mut today_total = 0;
        let mut today_by_cat = HashMap::new();
        let mut today_eliminated = 0;
        let mut today_hit = 0;
        let mut today_lost = 0;
        let mut initial_daily_summaries = HashMap::new();

        let month_file = history_dir.join(format!("flight_history_{}.json", current_month));
        if month_file.exists() {
            if let Ok(content) = fs::read_to_string(&month_file) {
                if let Ok(val) = serde_json::from_str::<Value>(&content) {
                    // 1. Завантаження збережених daily_summaries
                    if let Some(ds_map) = val.get("daily_summaries").and_then(|d| d.as_object()) {
                        let mut loaded_days = HashMap::new();
                        for (d_key, d_val) in ds_map {
                            if let Ok(summary) = serde_json::from_value::<DailySummary>(d_val.clone()) {
                                loaded_days.insert(d_key.clone(), summary);
                            }
                        }
                        initial_daily_summaries.insert(current_month.clone(), loaded_days);
                    }

                    // 2. Ініціалізація швидких лічильників today_stats
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

                                    let status = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                                    match status {
                                        "eliminated" => today_eliminated += 1,
                                        "hit_target" => today_hit += 1,
                                        "lost" => today_lost += 1,
                                        _ => {}
                                    }
                                    if !status.is_empty() {
                                        today_statuses.insert(tid.clone(), status.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Перевірка узгодження лічильників з daily_summaries за сьогодні
        if let Some(month_days) = initial_daily_summaries.get(&current_month) {
            if let Some(ds) = month_days.get(&today_str) {
                if ds.eliminated > today_eliminated { today_eliminated = ds.eliminated; }
                if ds.hit_target > today_hit { today_hit = ds.hit_target; }
                if ds.lost > today_lost { today_lost = ds.lost; }
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
                tracked_target_statuses: today_statuses,
                total: today_total,
                by_category: today_by_cat,
                eliminated_count: today_eliminated,
                hit_target_count: today_hit,
                lost_count: today_lost,
            }),
            month_meta_cache: RwLock::new(HashMap::new()),
            daily_summaries: RwLock::new(initial_daily_summaries),
            gdrive_synced_months: RwLock::new(HashSet::new()),
        }
    }

    pub fn current_month() -> String {
        let kyiv = Self::now_kyiv();
        format!("{:04}-{:02}", kyiv.year(), kyiv.month())
    }

    /// Визначення поточного локального київського часу (Europe/Kyiv: UTC+2 зима / UTC+3 літо)
    pub fn now_kyiv() -> chrono::DateTime<chrono::FixedOffset> {
        let utc = Utc::now();
        let month = utc.month();
        let day = utc.day() as i32;
        let dow = utc.weekday().num_days_from_sunday() as i32; // 0 = Неділя .. 6 = Субота
        let prev_sunday = day - dow;

        let is_dst = match month {
            4..=9 => true,
            3 => {
                if prev_sunday >= 25 {
                    if dow == 0 { utc.hour() >= 1 } else { true }
                } else {
                    false
                }
            }
            10 => {
                if prev_sunday >= 25 {
                    if dow == 0 { utc.hour() < 1 } else { false }
                } else {
                    true
                }
            }
            _ => false,
        };
        let offset_hours = if is_dst { 3 } else { 2 };
        let offset = chrono::FixedOffset::east_opt(offset_hours * 3600).unwrap();
        utc.with_timezone(&offset)
    }

    /// Запис активного або завершеного треку в історію з накопичувальним оновленням DailySummary
    pub fn record_track(&self, trk: &TargetTrack, status: &str) {
        if status == "superseded" {
            return; // Superseded треки тихо завершуються без створення фальшивих цілей чи маркерів "Х"
        }

        let kyiv = Self::now_kyiv();
        let date_str = kyiv.format("%Y-%m-%d").to_string();
        let month = kyiv.format("%Y-%m").to_string();
        let cur_hour = kyiv.hour() as usize;

        // Визначаємо канонічний ключ цілі
        let mut track_key = if !trk.canonical_id.is_empty() {
            trk.canonical_id.clone()
        } else {
            trk.id.clone()
        };

        // Рівень 2 (Safety Net): якщо ціль ще не зареєстрована в TodayStats, перевіряємо, чи немає
        // недавньої закритої або активної цілі тієї ж категорії в радіусі 10 км за останні 120 с
        {
            let ts = self.today_stats.read();
            if !ts.tracked_target_ids.contains(&track_key) {
                drop(ts);
                let pending = self.pending_dirty.read();
                if let Some(m_pending) = pending.get(&month) {
                    for (cand_id, cand_item) in m_pending {
                        if cand_item.get("date").and_then(|v| v.as_str()) != Some(&date_str) {
                            continue;
                        }
                        let cand_cat = cand_item.get("cat").and_then(|v| v.as_str()).unwrap_or("");
                        let cat_ok = cand_cat == trk.category || cand_cat == "unknown" || trk.category == "unknown";
                        if !cat_ok {
                            continue;
                        }
                        let cand_end = cand_item.get("end_time").and_then(|v| v.as_i64()).unwrap_or(0);
                        if (trk.first_seen as i64 - cand_end).abs() <= 120 {
                            if let Some(path) = cand_item.get("path").and_then(|p| p.as_array()) {
                                if let Some(last_pt) = path.last().and_then(|pt| pt.as_array()) {
                                    if last_pt.len() >= 3 {
                                        let last_lat = last_pt[1].as_f64().unwrap_or(0.0);
                                        let last_lon = last_pt[2].as_f64().unwrap_or(0.0);
                                        let dist = crate::geo_math::calculate_haversine_distance(last_lat, last_lon, trk.lat, trk.lon);
                                        if dist <= 10.0 {
                                            track_key = cand_id.clone();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut is_new_target = false;

        // 1. Оновлюємо легку статистику за сьогодні (O(1) в RAM)
        {
            let mut ts = self.today_stats.write();
            if ts.date != date_str {
                ts.date = date_str.clone();
                ts.tracked_target_ids.clear();
                ts.tracked_target_statuses.clear();
                ts.total = 0;
                ts.by_category.clear();
                ts.eliminated_count = 0;
                ts.hit_target_count = 0;
                ts.lost_count = 0;
            }
            if ts.tracked_target_ids.insert(track_key.clone()) {
                ts.total += 1;
                *ts.by_category.entry(trk.category.clone()).or_insert(0) += 1;
                is_new_target = true;
            }
        }

        // 2. Накопичувальне формування DailySummary (перша поява борту за добу)
        if is_new_target {
            let mut all_summaries = self.daily_summaries.write();
            let month_map = all_summaries.entry(month.clone()).or_default();
            let day_summary = month_map.entry(date_str.clone()).or_insert_with(|| DailySummary::new_empty(&date_str));

            day_summary.total += 1;
            *day_summary.types.entry(trk.category.clone()).or_insert(0) += 1;
            if cur_hour < day_summary.hours.len() {
                day_summary.hours[cur_hour].total += 1;
                *day_summary.hours[cur_hour].types.entry(trk.category.clone()).or_insert(0) += 1;
            }
            if !trk.oblast.is_empty() {
                if let Some(r) = day_summary.regions.iter_mut().find(|r| r.name == trk.oblast || (!trk.oblast_id.is_empty() && r.region_id == trk.oblast_id)) {
                    r.total += 1;
                } else {
                    day_summary.regions.push(RegionSummary {
                        region_id: trk.oblast_id.clone(),
                        name: trk.oblast.clone(),
                        total: 1,
                    });
                }
            }
            day_summary.last_updated_at = Utc::now().to_rfc3339();
        }

        // 2.1 Накопичувальний облік завершення цілей (збито / приліт / втрачено) без подвійного підрахунку
        let status_transition = {
            let mut ts = self.today_stats.write();
            if ts.date != date_str {
                ts.date = date_str.clone();
                ts.tracked_target_ids.clear();
                ts.tracked_target_statuses.clear();
                ts.total = 0;
                ts.by_category.clear();
                ts.eliminated_count = 0;
                ts.hit_target_count = 0;
                ts.lost_count = 0;
            }
            let old_status = ts.tracked_target_statuses.get(&track_key).cloned();
            if old_status.as_deref() != Some(status) {
                ts.tracked_target_statuses.insert(track_key.clone(), status.to_string());
                if let Some(ref prev) = old_status {
                    match prev.as_str() {
                        "eliminated" => ts.eliminated_count = ts.eliminated_count.saturating_sub(1),
                        "hit_target" => ts.hit_target_count = ts.hit_target_count.saturating_sub(1),
                        "lost" => ts.lost_count = ts.lost_count.saturating_sub(1),
                        _ => {}
                    }
                }
                match status {
                    "eliminated" => ts.eliminated_count += 1,
                    "hit_target" => ts.hit_target_count += 1,
                    "lost" => ts.lost_count += 1,
                    _ => {}
                }
                Some(old_status)
            } else {
                None
            }
        };

        if let Some(prev_status_opt) = status_transition {
            let mut all_summaries = self.daily_summaries.write();
            let month_map = all_summaries.entry(month.clone()).or_default();
            let day_summary = month_map.entry(date_str.clone()).or_insert_with(|| DailySummary::new_empty(&date_str));
            if let Some(ref prev) = prev_status_opt {
                match prev.as_str() {
                    "eliminated" => day_summary.eliminated = day_summary.eliminated.saturating_sub(1),
                    "hit_target" => day_summary.hit_target = day_summary.hit_target.saturating_sub(1),
                    "lost" => day_summary.lost = day_summary.lost.saturating_sub(1),
                    _ => {}
                }
            }
            match status {
                "eliminated" => day_summary.eliminated += 1,
                "hit_target" => day_summary.hit_target += 1,
                "lost" => day_summary.lost += 1,
                _ => {}
            }
            day_summary.last_updated_at = Utc::now().to_rfc3339();
        }

        // 3. Формуємо запис траєкторії для збереження
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
            "id": track_key,
            "canonical_id": track_key,
            "cat": trk.category,
            "name_ua": trk.type_ua,
            "name_en": trk.type_en,
            "date": date_str,
            "start_time": trk.first_seen as i64,
            "end_time": trk.last_seen as i64,
            "status": status,
            "sources_seen": trk.sources_seen,
            "path": path_json
        });

        // 4. Додаємо виключно в буфер незбережених змін (не тримаємо повний місяць у RAM!)
        {
            let mut pending = self.pending_dirty.write();
            pending.entry(month.clone()).or_default().insert(track_key, item);
        }
        {
            let mut dirty = self.dirty_months.write();
            dirty.insert(month);
        }
    }

    /// Cleanly evict month data from in-memory caches, pending writes, and summaries
    pub fn evict_month(&self, month: &str) {
        self.dirty_months.write().remove(month);
        self.pending_dirty.write().remove(month);
        self.read_cache.write().remove(month);
        self.month_meta_cache.write().remove(month);
        self.daily_summaries.write().remove(month);
        self.gdrive_synced_months.write().remove(month);
    }

    /// Періодичний скид накопичених "брудних" даних на диск (кожні 300 секунд)
    pub fn flush_dirty(&self) {
        let (dirty_batch, extra_dirty) = {
            let mut guard = self.pending_dirty.write();
            let mut dm = self.dirty_months.write();
            let batch = std::mem::take(&mut *guard);
            let extra = std::mem::take(&mut *dm);
            (batch, extra)
        };

        let mut months_to_save: HashSet<String> = dirty_batch.keys().cloned().collect();
        months_to_save.extend(extra_dirty);

        if months_to_save.is_empty() {
            return;
        }

        for month in months_to_save {
            let (mut targets, mut disk_summaries) = self.load_month_full_from_disk(&month);
            if let Some(new_targets) = dirty_batch.get(&month) {
                for (tid, item) in new_targets {
                    targets.insert(tid.clone(), item.clone());
                }
            }

            // Актуалізуємо daily_summaries з пам'яті
            {
                let guard = self.daily_summaries.read();
                if let Some(m_summaries) = guard.get(&month) {
                    for (d_key, d_val) in m_summaries {
                        if let Some(existing) = disk_summaries.get(d_key) {
                            if existing.status == "reconciled" && d_val.status != "reconciled" {
                                continue; // Захист: не затирати офіційно верифіковані дані локальними
                            }
                        }
                        disk_summaries.insert(d_key.clone(), d_val.clone());
                    }
                }
            }

            let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
            let meta_file_path = self.history_dir.join(format!("flight_history_{}.meta.json", month));
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
            let now_rfc3339 = Utc::now().to_rfc3339();
            let full_data = json!({
                "meta": {
                    "month": &month,
                    "updated_at": &now_rfc3339,
                    "total_targets": total_t,
                    "dates": &dates_vec
                },
                "daily_summaries": disk_summaries,
                "month": &month,
                "updated_at": &now_rfc3339,
                "total_targets": total_t,
                "dates": &dates_vec,
                "targets": targets
            });

            if let Ok(json_str) = serde_json::to_string(&full_data) {
                if let Ok(mut f) = File::create(&tmp_path) {
                    let _ = f.write_all(json_str.as_bytes());
                    let _ = f.sync_all();
                    drop(f);
                    let rename_res = fs::rename(&tmp_path, &file_path);
                    let success = if rename_res.is_ok() {
                        true
                    } else if fs::copy(&tmp_path, &file_path).is_ok() {
                        let _ = fs::remove_file(&tmp_path);
                        true
                    } else {
                        let _ = fs::remove_file(&tmp_path);
                        false
                    };

                    if success {
                        // Збереження легкого .meta.json індексу поруч із основним файлом
                        let meta_json = json!({
                            "meta": {
                                "month": &month,
                                "updated_at": &now_rfc3339,
                                "total_targets": total_t,
                                "dates": &dates_vec
                            }
                        });
                        if let Ok(meta_str) = serde_json::to_string(&meta_json) {
                            let _ = fs::write(&meta_file_path, meta_str.as_bytes());
                        }

                        // Зберігаємо також окремий добовий файл у history/YYYY-MM/YYYY-MM-DD.json
                        let month_dir = self.history_dir.join(&month);
                        let _ = fs::create_dir_all(&month_dir);
                        let mut days_to_update: HashMap<String, HashMap<String, Value>> = HashMap::new();
                        if let Some(new_targets) = dirty_batch.get(&month) {
                            for (tid, item) in new_targets {
                                if let Some(d) = item.get("date").and_then(|v| v.as_str()) {
                                    days_to_update.entry(d.to_string()).or_default().insert(tid.clone(), item.clone());
                                }
                            }
                        }
                        for (date_str, day_items) in days_to_update {
                            let day_file_path = month_dir.join(format!("{}.json", date_str));
                            let mut day_targets = HashMap::new();
                            if day_file_path.exists() {
                                if let Ok(c) = fs::read_to_string(&day_file_path) {
                                    if let Ok(v) = serde_json::from_str::<Value>(&c) {
                                        if let Some(t_obj) = v.get("targets").and_then(|t| t.as_object()) {
                                            for (k, val) in t_obj {
                                                day_targets.insert(k.clone(), val.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            for (tid, item) in day_items {
                                day_targets.insert(tid, item);
                            }
                            let day_summary = disk_summaries.get(&date_str).cloned();
                            let day_data = json!({
                                "date": &date_str,
                                "month": &month,
                                "summary": day_summary,
                                "total_targets": day_targets.len(),
                                "targets": day_targets
                            });
                            if let Ok(d_str) = serde_json::to_string(&day_data) {
                                let tmp_day = day_file_path.with_extension(format!("tmp.{}_{}", pid, now_ts()));
                                if let Ok(mut df) = File::create(&tmp_day) {
                                    let _ = df.write_all(d_str.as_bytes());
                                    let _ = df.sync_all();
                                    drop(df);
                                    let _ = fs::rename(&tmp_day, &day_file_path);
                                }
                            }
                        }

                        info!("Flushed flight history for {} ({} targets, {} daily summaries)", month, total_t, disk_summaries.len());
                        // Інвалідуємо старий запис у read_cache та оновлюємо мета-кеш дат
                        self.read_cache.write().remove(&month);
                        self.month_meta_cache.write().insert(month.clone(), (total_t, dates_vec, now_rfc3339));
                    } else {
                        warn!("Failed to save flight history {}: rename and copy fallback failed", month);
                    }
                }
            }
        }
    }

    fn load_month_from_disk(&self, month: &str) -> Option<HashMap<String, Value>> {
        let (targets, _) = self.load_month_full_from_disk(month);
        if targets.is_empty() {
            None
        } else {
            Some(targets)
        }
    }

    fn load_month_full_from_disk(&self, month: &str) -> (HashMap<String, Value>, HashMap<String, DailySummary>) {
        let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
        if !file_path.exists() {
            return (HashMap::new(), HashMap::new());
        }

        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => return (HashMap::new(), HashMap::new()),
        };

        let val: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return (HashMap::new(), HashMap::new()),
        };

        let mut targets_res = HashMap::new();
        if let Some(targets) = val.get("targets").and_then(|t| t.as_object()) {
            for (k, v) in targets {
                targets_res.insert(k.clone(), v.clone());
            }
        }

        let mut summaries_res = HashMap::new();
        if let Some(ds_map) = val.get("daily_summaries").and_then(|d| d.as_object()) {
            for (k, v) in ds_map {
                if let Ok(summary) = serde_json::from_value::<DailySummary>(v.clone()) {
                    summaries_res.insert(k.clone(), summary);
                }
            }
        }

        (targets_res, summaries_res)
    }

    /// Щогодинна звірка та виправлення накопичених даних за добу з офіційним API targetHistory
    pub async fn reconcile_date_with_upstream(
        &self,
        date_str: &str,
        http_client: &reqwest::Client,
    ) -> Result<bool, String> {
        let url = format!("https://map.ukrainealarm.com/api/data/targetHistory?date={}", date_str);
        let resp = http_client
            .get(&url)
            .header(reqwest::header::USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36")
            .header(reqwest::header::REFERER, "https://map.ukrainealarm.com/")
            .header(reqwest::header::ORIGIN, "https://map.ukrainealarm.com")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP status {}", resp.status()));
        }

        let val = resp.json::<Value>().await
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let total = val.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        let mut official_types = HashMap::new();
        if let Some(types_arr) = val.get("types").and_then(|t| t.as_array()) {
            for t_obj in types_arr {
                let key = t_obj.get("key").and_then(|k| k.as_str()).unwrap_or("");
                let cnt = t_obj.get("total").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
                if !key.is_empty() {
                    official_types.insert(key.to_string(), cnt);
                }
            }
        }

        let mut official_hours = Vec::with_capacity(24);
        if let Some(hours_arr) = val.get("hours").and_then(|h| h.as_array()) {
            for h_obj in hours_arr {
                let hour = h_obj.get("hour").and_then(|h| h.as_u64()).unwrap_or(0) as u8;
                let h_total = h_obj.get("total").and_then(|t| t.as_u64()).unwrap_or(0) as usize;
                let mut h_types = HashMap::new();
                if let Some(types_map) = h_obj.get("types").and_then(|m| m.as_object()) {
                    for (k, v) in types_map {
                        let c = v.as_u64().unwrap_or(0) as usize;
                        h_types.insert(k.clone(), c);
                    }
                }
                official_hours.push(HourlySummary {
                    hour,
                    total: h_total,
                    types: h_types,
                });
            }
        }

        let mut official_regions = Vec::new();
        if let Some(reg_arr) = val.get("regions").and_then(|r| r.as_array()) {
            for r_obj in reg_arr {
                let region_id = r_obj.get("regionId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = r_obj.get("nameEn")
                    .or_else(|| r_obj.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let r_total = r_obj.get("total")
                    .or_else(|| r_obj.get("tracks"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;

                if !region_id.is_empty() {
                    official_regions.push(RegionSummary {
                        region_id,
                        name,
                        total: r_total,
                    });
                }
            }
        }

        let month = if date_str.len() >= 7 { date_str[..7].to_string() } else { Self::current_month() };

        {
            let mut all_summaries = self.daily_summaries.write();
            let month_map = all_summaries.entry(month.clone()).or_default();
            let day_summary = month_map.entry(date_str.to_string()).or_insert_with(|| DailySummary::new_empty(date_str));

            day_summary.total = total;
            day_summary.types = official_types;
            if !official_hours.is_empty() {
                day_summary.hours = official_hours;
            }
            if !official_regions.is_empty() {
                day_summary.regions = official_regions;
            }
            day_summary.status = "reconciled".to_string();
            day_summary.last_reconciled_at = Some(Utc::now().to_rfc3339());
            day_summary.last_updated_at = Utc::now().to_rfc3339();
        }

        self.dirty_months.write().insert(month);
        info!("Successfully reconciled daily summary for {} with UkraineAlarm: total {} targets", date_str, total);

        Ok(true)
    }

    /// Отримання добового зведення (із пам'яті або з диску)
    pub fn get_daily_summary(&self, date_str: &str) -> Option<DailySummary> {
        let month = if date_str.len() >= 7 { date_str[..7].to_string() } else { return None; };

        // 1. Спочатку перевіряємо оперативну пам'ять
        {
            let guard = self.daily_summaries.read();
            if let Some(m_map) = guard.get(&month) {
                if let Some(ds) = m_map.get(date_str) {
                    return Some(ds.clone());
                }
            }
        }

        // 2. Якщо ще не завантажено в RAM, підтягуємо з диску
        self.ensure_month_summaries_loaded(&month);

        let guard = self.daily_summaries.read();
        guard.get(&month)?.get(date_str).cloned()
    }

    /// Отримання зведень за весь вибраний місяць
    pub fn get_month_summaries(&self, month_str: &str) -> HashMap<String, DailySummary> {
        self.ensure_month_summaries_loaded(month_str);
        let guard = self.daily_summaries.read();
        guard.get(month_str).cloned().unwrap_or_default()
    }

    fn ensure_month_summaries_loaded(&self, month: &str) {
        {
            let guard = self.daily_summaries.read();
            if guard.contains_key(month) {
                return;
            }
        }

        let (_, summaries) = self.load_month_full_from_disk(month);
        let mut guard = self.daily_summaries.write();
        guard.insert(month.to_string(), summaries);
    }

    /// Легке зчитування тільки заголовка місячного файлу без десеріалізації масиву цілей
    fn load_month_metadata(&self, month: &str) -> Option<(usize, Vec<String>, String)> {
        if let Some(cached) = self.month_meta_cache.read().get(month) {
            return Some(cached.clone());
        }

        // 1. Спроба читання з окремого компактного індекс-файлу .meta.json (<5 КБ)
        let meta_file = self.history_dir.join(format!("flight_history_{}.meta.json", month));
        if meta_file.exists() {
            if let Ok(content) = fs::read_to_string(&meta_file) {
                if let Ok(val) = serde_json::from_str::<Value>(&content) {
                    let total = val.pointer("/meta/total_targets").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    let updated_at = val.pointer("/meta/updated_at").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let dates = val.pointer("/meta/dates")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let res = (total, dates, updated_at);
                    self.month_meta_cache.write().insert(month.to_string(), res.clone());
                    return Some(res);
                }
            }
        }

        let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
        if !file_path.exists() {
            return None;
        }

        #[derive(Deserialize)]
        struct FileMetaHeader {
            meta: MonthMeta,
        }

        #[derive(Deserialize, Clone)]
        struct MonthMeta {
            #[serde(default)]
            total_targets: usize,
            #[serde(default)]
            dates: Vec<String>,
            #[serde(default)]
            updated_at: String,
        }

        // Оптимізація пам'яті: зчитуємо лише перші 64 КБ префікса файлу замість 15-20 МБ усього масиву цілей
        let mut parsed_meta: Option<MonthMeta> = None;
        if let Ok(mut f) = fs::File::open(&file_path) {
            let mut buf = vec![0u8; 65536];
            if let Ok(n) = f.read(&mut buf) {
                buf.truncate(n);
                let chunk = String::from_utf8_lossy(&buf);
                if let Some(pos) = chunk.find("\"targets\"") {
                    let prefix = chunk[..pos].trim().trim_end_matches(',');
                    let valid_json = format!("{}}}", prefix);
                    if let Ok(hdr) = serde_json::from_str::<FileMetaHeader>(&valid_json) {
                        parsed_meta = Some(hdr.meta);
                    }
                }
            }
        }

        // Fallback для застарілих версій файлів без блоку "meta"
        let meta = match parsed_meta {
            Some(m) => m,
            None => {
                let content = fs::read_to_string(&file_path).ok()?;
                #[derive(Deserialize)]
                struct LegacyHeader {
                    total_targets: Option<usize>,
                    dates: Option<Vec<String>>,
                    updated_at: Option<String>,
                }
                if let Ok(legacy) = serde_json::from_str::<LegacyHeader>(&content) {
                    MonthMeta {
                        total_targets: legacy.total_targets.unwrap_or(0),
                        dates: legacy.dates.unwrap_or_default(),
                        updated_at: legacy.updated_at.unwrap_or_default(),
                    }
                } else {
                    return None;
                }
            }
        };

        let res = (meta.total_targets, meta.dates, meta.updated_at);
        {
            let mut cache = self.month_meta_cache.write();
            if cache.len() >= 36 {
                let oldest_key = cache.keys().next().cloned();
                if let Some(k) = oldest_key {
                    cache.remove(&k);
                }
            }
            cache.insert(month.to_string(), res.clone());
        }
        Some(res)
    }

    /// Миттєве повернення лічильників за сьогодні для віджета та live-панелі (O(1))
    pub fn get_today_counts(&self) -> (usize, HashMap<String, usize>) {
        let kyiv = Self::now_kyiv();
        let now_date = kyiv.format("%Y-%m-%d").to_string();
        let ts = self.today_stats.read();
        if ts.date == now_date {
            (ts.total, ts.by_category.clone())
        } else {
            (0, HashMap::new())
        }
    }

    /// Повертає кількість збитих, прильотів та втрачених цілей за поточну добу (eliminated, hit_target, lost)
    #[allow(dead_code)]
    pub fn get_today_outcome_stats(&self) -> (usize, usize, usize) {
        let kyiv = Self::now_kyiv();
        let now_date = kyiv.format("%Y-%m-%d").to_string();
        let ts = self.today_stats.read();
        if ts.date == now_date {
            (ts.eliminated_count, ts.hit_target_count, ts.lost_count)
        } else {
            (0, 0, 0)
        }
    }

    /// Отримання історії за вибраний місяць з фільтрацією за днем (YYYY-MM-DD)
    pub fn get_month_history_filtered(&self, month: &str, date_filter: Option<&str>) -> Option<Value> {
        // Примусовий сброс свіжих цілей з оперативної пам'яті перед читанням вибірки
        self.flush_dirty();

        // 1. Швидке завантаження з добового файлу якщо запитано конкретний день
        if let Some(date_str) = date_filter {
            let day_file = self.history_dir.join(month).join(format!("{}.json", date_str));
            if day_file.exists() {
                if let Ok(content) = fs::read_to_string(&day_file) {
                    if let Ok(val) = serde_json::from_str::<Value>(&content) {
                        if let Some(day_targets) = val.get("targets").and_then(|t| t.as_object()) {
                            let now_str = Utc::now().to_rfc3339();
                            let mut disk_summaries = HashMap::new();
                            if let Some(ds) = self.get_daily_summary(date_str) {
                                disk_summaries.insert(date_str.to_string(), ds);
                            }
                            return Some(json!({
                                "meta": {
                                    "month": month,
                                    "updated_at": &now_str,
                                    "total_targets": day_targets.len(),
                                    "dates": vec![date_str.to_string()]
                                },
                                "daily_summaries": disk_summaries,
                                "month": month,
                                "updated_at": &now_str,
                                "total_targets": day_targets.len(),
                                "dates": vec![date_str.to_string()],
                                "targets": day_targets
                            }));
                        }
                    }
                }
            }
        }

        let cached = {
            let guard = self.read_cache.read();
            guard.get(month).cloned()
        };

        let full_month = match cached {
            Some(v) => v,
            None => {
                let (targets, disk_summaries) = self.load_month_full_from_disk(month);
                if targets.is_empty() && disk_summaries.is_empty() {
                    return None;
                }

                let mut dates_set = std::collections::BTreeSet::new();
                for t in targets.values() {
                    if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                        if !d.is_empty() {
                            dates_set.insert(d.to_string());
                        }
                    }
                }
                for d in disk_summaries.keys() {
                    dates_set.insert(d.clone());
                }

                let dates_vec: Vec<String> = dates_set.into_iter().collect();
                let now_str = Utc::now().to_rfc3339();

                let full_data = json!({
                    "meta": {
                        "month": month,
                        "updated_at": &now_str,
                        "total_targets": targets.len(),
                        "dates": &dates_vec
                    },
                    "daily_summaries": disk_summaries,
                    "month": month,
                    "updated_at": &now_str,
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

        let targets = full_month.get("targets").and_then(|t| t.as_object());
        let dates_vec = full_month.get("dates")
            .or_else(|| full_month.get("meta").and_then(|m| m.get("dates")))
            .cloned()
            .unwrap_or_else(|| json!([]));

        if let Some(df) = date_filter {
            if !df.is_empty() && df != "all" {
                let mut filtered_targets = serde_json::Map::new();
                if let Some(all_t) = targets {
                    for (id, t) in all_t {
                        if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                            if d == df {
                                filtered_targets.insert(id.clone(), t.clone());
                            }
                        }
                    }
                }
                let day_summary = self.get_daily_summary(df);
                return Some(json!({
                    "month": month,
                    "date": df,
                    "updated_at": full_month.get("updated_at"),
                    "total_targets": filtered_targets.len(),
                    "summary": day_summary,
                    "dates": dates_vec,
                    "targets": filtered_targets
                }));
            }
        }

        let summaries = self.get_month_summaries(month);
        let mut res_data = full_month;
        if let Some(obj) = res_data.as_object_mut() {
            obj.insert("daily_summaries".to_string(), json!(summaries));
        }
        Some(res_data)
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

                if let Some((cnt, dates, up_at)) = self.load_month_metadata(&month) {
                    targets_count = cnt;
                    days_set = dates.into_iter().collect();
                    updated_at_str = up_at;
                }

                let mut days_nums: Vec<u32> = days_set
                    .iter()
                    .filter_map(|d| d.split('-').nth(2).and_then(|s| s.parse::<u32>().ok()))
                    .collect();
                days_nums.sort_unstable();

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
                    days_count: days_set.len(),
                    days_min: days_nums.first().copied(),
                    days_max: days_nums.last().copied(),
                    size_kb,
                    size_bytes,
                });
            }
        }

        list.sort_by(|a, b| b.month.cmp(&a.month));
        list
    }

    /// Експорт даних за місяць у форматі JSON для завантаження
    pub fn export_month_json(&self, month: &str) -> Option<String> {
        let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
        if file_path.exists() {
            fs::read_to_string(&file_path).ok()
        } else {
            None
        }
    }

    /// Імпорт зовнішньої історії (наприклад, з backup файлу)
    pub fn import_external_history(&self, json_data: &Value) -> usize {
        let targets = match json_data.get("targets").and_then(|t| t.as_object()) {
            Some(t) => t,
            None => return 0,
        };

        let mut imported_count = 0;
        let mut by_month: HashMap<String, HashMap<String, Value>> = HashMap::new();

        for (id, item) in targets {
            let month = item
                .get("date")
                .and_then(|d| d.as_str())
                .filter(|s| s.len() >= 7)
                .map(|s| s[..7].to_string())
                .unwrap_or_else(|| Self::current_month());

            by_month.entry(month).or_default().insert(id.clone(), item.clone());
            imported_count += 1;
        }

        for (month, new_items) in by_month {
            let mut existing = self.load_month_from_disk(&month).unwrap_or_default();
            for (id, item) in new_items {
                existing.insert(id, item);
            }

            let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
            let mut dates_set = HashSet::new();
            for t in existing.values() {
                if let Some(d) = t.get("date").and_then(|v| v.as_str()) {
                    dates_set.insert(d.to_string());
                }
            }
            let mut dates_vec: Vec<String> = dates_set.into_iter().collect();
            dates_vec.sort();

            let full_data = json!({
                "meta": {
                    "month": &month,
                    "updated_at": Utc::now().to_rfc3339(),
                    "total_targets": existing.len(),
                    "dates": &dates_vec
                },
                "month": &month,
                "updated_at": Utc::now().to_rfc3339(),
                "total_targets": existing.len(),
                "dates": &dates_vec,
                "targets": existing
            });

            if let Ok(serialized) = serde_json::to_string(&full_data) {
                let _ = fs::write(&file_path, serialized.as_bytes());
                self.read_cache.write().remove(&month);
                self.month_meta_cache.write().remove(&month);
            }
        }

        imported_count
    }

    /// Синхронізація місяця в Google Drive через Webhook
    pub async fn sync_to_gdrive(&self, month: &str, webhook_url: &str, http_client: &reqwest::Client) -> Result<(usize, u64), String> {
        let content = self.export_month_json(month).ok_or_else(|| format!("Місяць {} не знайдено на диску", month))?;
        let size = content.len() as u64;

        let payload = json!({
            "action": "upload",
            "month": month,
            "filename": format!("flight_history_{}.json", month),
            "content": content
        });

        let resp = http_client
            .post(webhook_url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| format!("Помилка відправки в Google Drive: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Google Drive webhook повернув HTTP {}", resp.status()));
        }

        let resp_json: Value = resp.json().await.unwrap_or(json!({}));
        let targets_count = resp_json.get("targets_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        self.gdrive_synced_months.write().insert(month.to_string());
        info!("Successfully synced month {} to Google Drive ({} bytes)", month, size);

        Ok((targets_count, size / 1024))
    }

    /// Завантаження місяця з Google Drive
    pub async fn fetch_month_from_gdrive(&self, month: &str, webhook_url: &str, http_client: &reqwest::Client) -> Result<Value, String> {
        let payload = json!({
            "action": "download",
            "month": month
        });

        let resp = http_client
            .post(webhook_url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| format!("Помилка запиту до Google Drive: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Google Drive webhook повернув HTTP {}", resp.status()));
        }

        let data: Value = resp.json().await.map_err(|e| format!("Помилка читання відповіді Google Drive: {}", e))?;

        if let Some(err_status) = data.get("status").and_then(|s| s.as_str()) {
            if err_status == "error" {
                let msg = data.get("message").and_then(|m| m.as_str()).unwrap_or("Невідома помилка");
                return Err(format!("Google Drive помилка: {}", msg));
            }
        }

        if data.get("targets").is_some() || data.get("dates").is_some() {
            let file_path = self.history_dir.join(format!("flight_history_{}.json", month));
            let tmp_path = self.history_dir.join(format!("flight_history_{}.json.tmp", month));

            let serialized = serde_json::to_string(&data).map_err(|e| e.to_string())?;
            fs::write(&tmp_path, serialized.as_bytes()).map_err(|e| e.to_string())?;
            if fs::rename(&tmp_path, &file_path).is_err() {
                let _ = fs::copy(&tmp_path, &file_path);
                let _ = fs::remove_file(&tmp_path);
            }

            self.read_cache.write().insert(month.to_string(), data.clone());
            self.gdrive_synced_months.write().insert(month.to_string());

            let targets_count = data.get("targets").and_then(|t| t.as_object()).map(|o| o.len()).unwrap_or(0);
            info!("Successfully restored month {} from Google Drive ({} targets)", month, targets_count);

            Ok(data)
        } else {
            Err(format!("Отримані дані за місяць {} не містять цілей", month))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_kyiv_timezone_offset() {
        let kyiv = HistoryManager::now_kyiv();
        let offset_hours = kyiv.offset().local_minus_utc() / 3600;
        // Україна завжди має зміщення UTC+2 (взимку) або UTC+3 (влітку)
        assert!(offset_hours == 2 || offset_hours == 3, "Kyiv offset must be +2 or +3 hours from UTC, got: {}", offset_hours);
    }

    #[test]
    fn test_current_month_format() {
        let month = HistoryManager::current_month();
        assert_eq!(month.len(), 7);
        assert!(month.contains('-'));
        let parts: Vec<&str> = month.split('-').collect();
        assert_eq!(parts.len(), 2);
        let year: i32 = parts[0].parse().unwrap();
        let mon: u32 = parts[1].parse().unwrap();
        assert!(year >= 2024);
        assert!(mon >= 1 && mon <= 12);
    }

    #[test]
    fn test_today_stats_transition_deduplication() {
        let mut stats = TodayStats::default();
        let target_id = "test_target_001".to_string();

        // 1. Поява цілі: додаємо в active
        stats.total = 1;
        stats.tracked_target_ids.insert(target_id.clone());
        stats.tracked_target_statuses.insert(target_id.clone(), "active".to_string());
        assert_eq!(stats.total, 1);
        assert_eq!(stats.eliminated_count, 0);

        // 2. Зміна статусу: active -> eliminated
        let prev = stats.tracked_target_statuses.get(&target_id).cloned();
        assert_eq!(prev.as_deref(), Some("active"));
        if prev.as_deref() != Some("eliminated") {
            stats.eliminated_count += 1;
            stats.tracked_target_statuses.insert(target_id.clone(), "eliminated".to_string());
        }
        assert_eq!(stats.eliminated_count, 1);

        // 3. Захист від повторного інкременту при повторному eliminated
        let current = stats.tracked_target_statuses.get(&target_id).cloned();
        assert_eq!(current.as_deref(), Some("eliminated"));
        if current.as_deref() != Some("eliminated") {
            stats.eliminated_count += 1;
        }
        assert_eq!(stats.eliminated_count, 1, "Duplicate eliminated status must not double-increment");
    }

    #[test]
    fn test_record_track_with_canonical_id_and_daily_file() {
        let temp_dir = std::env::temp_dir().join(format!("air_hub_hist_test_{}", now_ts()));
        let _ = fs::create_dir_all(&temp_dir);

        let mgr = HistoryManager::new(&temp_dir);
        let kyiv = HistoryManager::now_kyiv();
        let month = kyiv.format("%Y-%m").to_string();
        let date_str = kyiv.format("%Y-%m-%d").to_string();

        let mut t1 = TargetTrack::new(
            "trk_source1".to_string(),
            "shahed".to_string(),
            1,
            50.45,
            30.52,
            90.0,
            185.0,
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
        );
        t1.canonical_id = "canon_drone_001".to_string();

        // Запис треку від джерела 1
        mgr.record_track(&t1, "active");
        let (tot1, _) = mgr.get_today_counts();
        assert_eq!(tot1, 1);

        // Джерело 2 надсилає той самий дрон під іншим локальним ID, але з тим самим canonical_id
        let mut t2 = t1.clone();
        t2.id = "trk_source2".to_string();
        t2.canonical_id = "canon_drone_001".to_string();
        t2.lat = 50.46;
        t2.lon = 30.53;

        mgr.record_track(&t2, "active");
        // Лічильник total НЕ повинен зрости, оскільки canonical_id той самий!
        let (tot2, _) = mgr.get_today_counts();
        assert_eq!(tot2, 1, "Canonical ID must prevent duplicate target count");

        // Збиття цілі
        mgr.record_track(&t2, "eliminated");
        let (elim, hit, lost) = mgr.get_today_outcome_stats();
        assert_eq!(elim, 1);
        assert_eq!(hit, 0);
        assert_eq!(lost, 0);

        // Скидаємо на диск
        mgr.flush_dirty();

        // Перевіряємо що створено і монолітний місячний файл, і добовий файл
        let month_file = temp_dir.join("history").join(format!("flight_history_{}.json", month));
        assert!(month_file.exists(), "Master monthly file must exist");

        let day_file = temp_dir.join("history").join(&month).join(format!("{}.json", date_str));
        assert!(day_file.exists(), "Daily sharded file must exist");

        // Читаємо через get_month_history_filtered з фільтром по дню
        let day_data = mgr.get_month_history_filtered(&month, Some(&date_str));
        assert!(day_data.is_some());
        let val = day_data.unwrap();
        assert_eq!(val["total_targets"], 1);
        assert!(val["targets"].get("canon_drone_001").is_some());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
