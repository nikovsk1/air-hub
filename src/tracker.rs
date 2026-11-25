use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

use crate::canonical_registry::{classify_target, ExchangeLogManager};
use crate::crypto_decoder::RawExtractedTarget;
use crate::geo_math::{
    calculate_bearing, calculate_haversine_distance
};
use crate::oblast_detector::OblastDetector;

pub fn now_sec() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryPoint {
    pub lat: f64,
    pub lon: f64,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtrapolatedPoint {
    pub minutes: u32,
    #[serde(default)]
    pub minutes_ahead: u32,
    pub lat: f64,
    pub lon: f64,
}

pub const MAX_TRAJECTORY_POINTS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTrack {
    pub id: String,
    pub raw_type: String,
    pub raw_code: i64,
    pub category: String,
    pub type_ua: String,
    pub type_en: String,
    pub ha_icon: String,
    pub esp_code: u8,
    pub color_hex: String,
    pub is_drone: bool,
    pub lat: f64,
    pub lon: f64,
    pub heading: f64,
    pub speed_kmh: f64,
    pub oblast: String,
    pub oblast_id: String,
    #[serde(default)]
    pub raion_id: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub trajectory: Vec<TrajectoryPoint>,
    #[serde(default)]
    pub confidence: Option<u8>,
    #[serde(default)]
    pub last_history_sync_ts: f64,
    #[serde(default = "default_active_status")]
    pub status: String,
    #[serde(default)]
    pub cooldown_start_ts: Option<f64>,
    #[serde(default)]
    pub filt_lat: f64,
    #[serde(default)]
    pub filt_lon: f64,
    #[serde(default)]
    pub filtered_speed_kmh: f64,
    #[serde(default)]
    pub smoothed_heading: f64,
    #[serde(default)]
    pub last_moved_ts: f64,
    #[serde(default)]
    pub heading_confidence: f64,
    #[serde(default)]
    pub raw_lat: f64,
    #[serde(default)]
    pub raw_lon: f64,
    #[serde(default)]
    pub raw_speed_kmh: f64,
    #[serde(default)]
    pub raw_heading: f64,
    #[serde(default)]
    pub raw_ts: f64,
    #[serde(default)]
    pub consecutive_high_speed_ticks: u8,
    #[serde(default)]
    pub canonical_id: String,
    #[serde(default)]
    pub sources_seen: Vec<String>,
}

fn default_active_status() -> String {
    "active".to_string()
}

fn heading_diff(a: f64, b: f64) -> f64 {
    let diff = (a - b).abs() % 360.0;
    if diff > 180.0 { 360.0 - diff } else { diff }
}

impl TargetTrack {
    pub fn new(
        id: String,
        raw_type: String,
        raw_code: i64,
        lat: f64,
        lon: f64,
        heading: f64,
        speed: f64,
        oblast: String,
        oblast_id: String,
        raion_id: String,
    ) -> Self {
        let (cat, meta) = classify_target(&raw_type, raw_code);
        let now = now_sec();
        let eff_speed = if speed > 0.0 { speed } else { meta.default_speed };

        Self {
            id: id.clone(),
            raw_type,
            raw_code,
            category: cat.to_string(),
            type_ua: meta.name_ua.to_string(),
            type_en: meta.name_en.to_string(),
            ha_icon: meta.ha_icon.to_string(),
            esp_code: meta.esp_code,
            color_hex: meta.color_hex.to_string(),
            is_drone: meta.is_drone,
            lat,
            lon,
            heading,
            speed_kmh: eff_speed,
            oblast,
            oblast_id,
            raion_id,
            first_seen: now,
            last_seen: now,
            trajectory: vec![TrajectoryPoint {
                lat,
                lon,
                ts: now as i64,
            }],
            confidence: None,
            last_history_sync_ts: 0.0,
            status: "active".to_string(),
            cooldown_start_ts: None,
            filt_lat: lat,
            filt_lon: lon,
            filtered_speed_kmh: eff_speed,
            smoothed_heading: heading,
            last_moved_ts: now,
            heading_confidence: if heading > 0.0 { 0.8 } else { 0.3 },
            raw_lat: lat,
            raw_lon: lon,
            raw_speed_kmh: eff_speed,
            raw_heading: heading,
            raw_ts: now,
            consecutive_high_speed_ticks: 0,
            canonical_id: id.clone(),
            sources_seen: Vec::new(),
        }
    }

    pub fn with_trail(mut self, trail_pts: &[(f64, f64)], base_ts: i64) -> Self {
        if !trail_pts.is_empty() {
            let total = trail_pts.len();
            let step = if total > 100 { total / 60 } else { 1 };
            let mut traj = Vec::with_capacity(total / step + 2);
            for (idx, pt) in trail_pts.iter().enumerate().step_by(step) {
                let offset_sec = ((total - idx) * 10) as i64;
                traj.push(TrajectoryPoint {
                    lat: pt.0,
                    lon: pt.1,
                    ts: base_ts.saturating_sub(offset_sec),
                });
            }
            traj.push(TrajectoryPoint {
                lat: self.lat,
                lon: self.lon,
                ts: base_ts,
            });
            self.trajectory = traj;
        }
        self
    }

    pub fn cap_trajectory(&mut self) {
        if self.trajectory.len() > MAX_TRAJECTORY_POINTS {
            let excess = self.trajectory.len() - MAX_TRAJECTORY_POINTS;
            self.trajectory.drain(0..excess);
        }
    }

    pub fn update(
        &mut self,
        lat: f64,
        lon: f64,
        heading: f64,
        speed: f64,
        oblast: String,
        oblast_id: String,
        raion_id: String,
        raw_type: Option<&str>,
        raw_code: Option<i64>,
    ) {
        let now = now_sec();
        let dt = (now - self.last_seen).max(0.1);

        // Сирі координати (raw_lat, raw_lon, raw_ts, raw_heading) — Dual-State інваріант безпеки
        self.raw_lat = lat;
        self.raw_lon = lon;
        self.raw_heading = heading;
        self.raw_ts = now;

        // 1. Дедуплікація та правило «стоячої точки»:
        // Якщо зміщення від попередньої засічки < 50 метрів (радарна сітка/джиттер) —
        // НЕ обнуляти filtered_speed_kmh і не перераховувати smoothed_heading; оновлювати лише last_seen
        let dist_from_current = calculate_haversine_distance(self.lat, self.lon, lat, lon);
        if dist_from_current < 0.05 {
            self.last_seen = now;
            self.raw_speed_kmh = 0.0;
            self.consecutive_high_speed_ticks = 0;
            let last_ts = self.trajectory.last().map(|p| p.ts).unwrap_or(0);
            if (now as i64).saturating_sub(last_ts) >= 30 {
                self.trajectory.push(TrajectoryPoint {
                    lat: self.lat,
                    lon: self.lon,
                    ts: now as i64,
                });
                self.cap_trajectory();
            }
            return;
        }

        self.last_moved_ts = now;
        let (_, meta) = classify_target(raw_type.unwrap_or(&self.raw_type), raw_code.unwrap_or(self.raw_code));

        // 2. Кінематична фільтрація швидкості (Dual-State: 2D alpha-beta з 2-tick promotion):
        let raw_speed = if speed > 0.0 {
            speed
        } else {
            (dist_from_current / dt) * 3600.0
        };
        self.raw_speed_kmh = raw_speed;

        // Захист від хибної класифікації (2-tick promotion):
        // Якщо 2 пакети поспіль підтверджують високу швидкість (> 1.4 * max_speed_kmh за dt < 3 с),
        // негайно піднімаємо alpha = 0.65, щоб візуальний маркер не відставав від реальної цілі.
        // Одиничний сплеск згладжується м'яко (alpha = 0.15) без відкидання точки.
        let mut alpha = 0.35;
        if raw_speed > meta.max_speed_kmh * 1.4 && dt < 3.0 {
            self.consecutive_high_speed_ticks = self.consecutive_high_speed_ticks.saturating_add(1);
            if self.consecutive_high_speed_ticks >= 2 {
                alpha = 0.65;
            } else {
                alpha = 0.15;
            }
        } else {
            self.consecutive_high_speed_ticks = 0;
        }

        let new_filt_speed = (1.0 - alpha) * self.filtered_speed_kmh + alpha * raw_speed;
        self.filtered_speed_kmh = if self.consecutive_high_speed_ticks >= 2 {
            new_filt_speed
        } else {
            new_filt_speed.clamp(meta.min_speed_kmh, meta.max_speed_kmh)
        };
        self.speed_kmh = self.filtered_speed_kmh;

        // Координатна фільтрація позиції (візуальний стан)
        self.filt_lat = (1.0 - alpha) * self.filt_lat + alpha * lat;
        self.filt_lon = (1.0 - alpha) * self.filt_lon + alpha * lon;

        // 3. Згладжування курсу через векторне осереднення (EMA sin/cos)
        if let Some(last_pt) = self.trajectory.last() {
            let dist_from_last = calculate_haversine_distance(last_pt.lat, last_pt.lon, lat, lon);

            // Захист від фізично неможливих стрибків (телепортація > 120 км між пакетами)
            if dist_from_last > 120.0 {
                self.trajectory.clear();
                self.trajectory.push(TrajectoryPoint {
                    lat,
                    lon,
                    ts: now as i64,
                });
                self.heading = if heading > 0.0 { heading } else { self.heading };
                self.smoothed_heading = self.heading;
                self.filt_lat = lat;
                self.filt_lon = lon;
            } else {
                let calculated_heading = if heading > 0.0 {
                    heading
                } else if dist_from_last > 0.3 {
                    calculate_bearing(last_pt.lat, last_pt.lon, lat, lon)
                } else {
                    self.smoothed_heading
                };

                let time_since_last = (now as i64) - last_pt.ts;
                let h_diff = heading_diff(self.smoothed_heading, calculated_heading);

                let is_turn = dist_from_last >= 0.4 && h_diff >= 4.0;
                let is_distance_step = dist_from_last >= 1.5;
                let is_speed_change = (speed - self.speed_kmh).abs() >= 30.0 && speed > 0.0 && self.speed_kmh > 0.0;
                let is_heartbeat = time_since_last >= 30 && dist_from_last >= 0.3;

                if is_turn || is_distance_step || is_speed_change || is_heartbeat {
                    self.trajectory.push(TrajectoryPoint {
                        lat,
                        lon,
                        ts: now as i64,
                    });
                    self.cap_trajectory();
                }

                // Adaptive heading alpha: snap faster (alpha = 0.80) on sharp turns (> 40 deg)
                // ONLY if movement delta S >= 1.0 km to prevent noise jitter on stationary reports
                let heading_alpha = if dist_from_last >= 1.0 && h_diff >= 40.0 {
                    0.80
                } else {
                    alpha
                };

                // Векторне EMA згладжування курсу (sin/cos без розривів через 0/360)
                let target_rad = calculated_heading.to_radians();
                let cur_rad = self.smoothed_heading.to_radians();
                let sin_avg = (1.0 - heading_alpha) * cur_rad.sin() + heading_alpha * target_rad.sin();
                let cos_avg = (1.0 - heading_alpha) * cur_rad.cos() + heading_alpha * target_rad.cos();
                let mut smoothed = sin_avg.atan2(cos_avg).to_degrees();
                if smoothed < 0.0 { smoothed += 360.0; }
                self.smoothed_heading = smoothed;
                self.heading = smoothed;
                self.heading_confidence = (self.heading_confidence * 0.85 + (if dist_from_last >= 1.0 { 0.15 } else { 0.05 })).min(1.0);
            }
        }

        self.lat = lat;
        self.lon = lon;
        self.oblast = oblast;
        self.oblast_id = oblast_id;
        self.raion_id = raion_id;
        self.last_seen = now;

        if let (Some(rt), Some(rc)) = (raw_type, raw_code) {
            let (cat, meta) = classify_target(rt, rc);
            // Оновлюємо тип, опис та іконку цілі, якщо категорія змінилась або уточнилась
            // Захист: відома ідентифікована ціль не скидається в "unknown", якщо прийшла порожня/загальна засічка
            if cat != "unknown" || self.category == "unknown" {
                self.category = cat.to_string();
                self.type_ua = meta.name_ua.to_string();
                self.type_en = meta.name_en.to_string();
                self.ha_icon = meta.ha_icon.to_string();
                self.esp_code = meta.esp_code;
                self.color_hex = meta.color_hex.to_string();
                self.is_drone = meta.is_drone;
                self.raw_type = rt.to_string();
                self.raw_code = rc;
            }
        }
    }

    /// Екстраполяція коридору підльоту на 5, 10 та 15 хвилин
    pub fn get_extrapolated_corridor(&self) -> Vec<ExtrapolatedPoint> {
        let mut corridor = Vec::with_capacity(3);
        let dist_per_min = self.speed_kmh / 60.0;
        let bearing_rad = self.heading.to_radians();

        for mins in [5u32, 10, 15] {
            let travel_dist_km = dist_per_min * (mins as f64);
            let d_r = travel_dist_km / 6371.0;
            let lat_rad = self.lat.to_radians();
            let lon_rad = self.lon.to_radians();

            let target_lat_rad = (lat_rad.sin() * d_r.cos() + lat_rad.cos() * d_r.sin() * bearing_rad.cos()).asin();
            let target_lon_rad = lon_rad + (bearing_rad.sin() * d_r.sin() * lat_rad.cos()).atan2(d_r.cos() - lat_rad.sin() * target_lat_rad.sin());

            corridor.push(ExtrapolatedPoint {
                minutes: mins,
                minutes_ahead: mins,
                lat: target_lat_rad.to_degrees(),
                lon: target_lon_rad.to_degrees(),
            });
        }

        corridor
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LostTargetRecord {
    pub id: String,
    pub type_ua: String,
    pub category: String,
    pub color_hex: String,
    pub lat: f64,
    pub lon: f64,
    pub heading: f64,
    pub status: String, // "lost" (Варіант А: тактичний червоний хрест для мапи)
    #[serde(default = "default_lost_outcome")]
    pub outcome: String, // "lost" | "eliminated" | "hit_target" (точний результат для статистики)
    pub lost_ts: f64,
    #[serde(default)]
    pub first_seen: f64,
    #[serde(default)]
    pub trajectory: Vec<TrajectoryPoint>,
}

fn default_lost_outcome() -> String {
    "lost".to_string()
}

#[derive(Default)]
pub struct TargetTracker {
    pub tracks: HashMap<String, TargetTrack>,
    pub recent_lost: HashMap<String, LostTargetRecord>,
    pub current_source: String,
}

impl TargetTracker {
    /// Безслідне видалення цілі з пам'яті та карти (remove) без створення хрестика в recent_lost
    pub fn silent_remove(&mut self, id: &str) {
        self.tracks.remove(id);
        self.recent_lost.remove(id);
    }

    #[allow(dead_code)]
    pub fn silent_source_switch(&mut self, new_source: &str) {
        self.tracks.clear();
        self.current_source = new_source.to_string();
    }

    pub fn update_batch(
        &mut self,
        incoming_targets: &[RawExtractedTarget],
        detector: &OblastDetector,
        exchange_mgr: Option<&ExchangeLogManager>,
        source: &str,
    ) -> Vec<TargetTrack> {
        let now = now_sec();
        let mut seen_ids = std::collections::HashSet::new();
        let mut lost_tracks = Vec::new();

        // Захист від хибних хрестів збиття та дедуплікація цілей:
        // Spatial Track Stitching з 1-to-1 жадібним матчингом для захисту від колізій у роях
        let is_source_switch = !self.current_source.is_empty()
            && !source.is_empty()
            && self.current_source != source;

        if is_source_switch {
            let old_tracks: Vec<TargetTrack> = self.tracks.drain().map(|(_, v)| v).collect();
            let mut matched_old_indices = std::collections::HashSet::new();
            let mut candidate_matches: Vec<(f64, usize, usize)> = Vec::new();

            for (inc_idx, t) in incoming_targets.iter().enumerate() {
                if t.upstream_status == "remove" {
                    continue;
                }
                let (t_cat, t_meta) = classify_target(&t.raw_name, t.raw_type_code);
                for (old_idx, old_trk) in old_tracks.iter().enumerate() {
                    let cat_compatible = old_trk.category == t_cat 
                        || old_trk.category == "unknown" 
                        || t_cat == "unknown"
                        || (old_trk.is_drone && t_meta.is_drone);
                    if !cat_compatible {
                        continue;
                    }

                    let dt = (now - old_trk.last_seen).abs().max(1.0);
                    let eff_speed = old_trk.speed_kmh.max(60.0);
                    let max_dist_km = (eff_speed * (dt / 3600.0) * 1.5).max(12.0);
                    let dist_km = calculate_haversine_distance(old_trk.lat, old_trk.lon, t.lat, t.lon);
                    if dist_km > max_dist_km {
                        continue;
                    }

                    let mut heading_penalty = 0.0;
                    if dist_km > 0.3 && old_trk.heading > 0.0 {
                        let bearing = calculate_bearing(old_trk.lat, old_trk.lon, t.lat, t.lon);
                        let h_diff = heading_diff(bearing, old_trk.heading);
                        if h_diff > 65.0 {
                            continue;
                        }
                        heading_penalty += h_diff * 0.05;
                    }
                    let inc_h = t.heading_deg;
                    if inc_h > 0.0 && old_trk.heading > 0.0 {
                        let h_diff = heading_diff(inc_h, old_trk.heading);
                        if h_diff > 75.0 {
                            continue;
                        }
                        heading_penalty += h_diff * 0.05;
                    }

                    let score = dist_km + heading_penalty;
                    candidate_matches.push((score, inc_idx, old_idx));
                }
            }

            candidate_matches.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            let mut matched_inc_indices = std::collections::HashSet::new();

            for (_score, inc_idx, old_idx) in candidate_matches {
                if matched_inc_indices.contains(&inc_idx) || matched_old_indices.contains(&old_idx) {
                    continue;
                }
                matched_inc_indices.insert(inc_idx);
                matched_old_indices.insert(old_idx);

                let inc_target = &incoming_targets[inc_idx];
                let mut stitched_track = old_tracks[old_idx].clone();
                stitched_track.id = inc_target.id.clone();
                if stitched_track.canonical_id.is_empty() {
                    stitched_track.canonical_id = old_tracks[old_idx].id.clone();
                }
                if !stitched_track.sources_seen.contains(&source.to_string()) {
                    stitched_track.sources_seen.push(source.to_string());
                }
                self.recent_lost.remove(&inc_target.id);
                self.tracks.insert(inc_target.id.clone(), stitched_track);
            }

            // Незшиті старі треки переходять у статус "superseded" (тихе затухання БЕЗ recent_lost та БЕЗ тривог)
            for (old_idx, mut old_trk) in old_tracks.into_iter().enumerate() {
                if !matched_old_indices.contains(&old_idx) {
                    old_trk.status = "superseded".to_string();
                    old_trk.last_seen = now;
                    lost_tracks.push(old_trk);
                }
            }
        }
        self.current_source = source.to_string();

        for t in incoming_targets {
            seen_ids.insert(&t.id);

            // 1. Обробка "remove" — видалення БЕЗСЛІДНО (без хрестика, без cooldown)
            if t.upstream_status == "remove" {
                self.silent_remove(&t.id);
                continue;
            }

            // 2. Обробка "eliminated" (збиття ППО) або "hit_target" (приліт) — остаточна фіксація
            if t.upstream_status == "eliminated" || t.upstream_status == "hit_target" {
                let status_str = t.upstream_status.clone();
                if let Some(mut trk) = self.tracks.remove(&t.id) {
                    trk.status = status_str.clone();
                    trk.last_seen = now;
                    self.recent_lost.insert(
                        t.id.clone(),
                        LostTargetRecord {
                            id: t.id.clone(),
                            type_ua: trk.type_ua.clone(),
                            category: trk.category.clone(),
                            color_hex: trk.color_hex.clone(),
                            lat: trk.lat,
                            lon: trk.lon,
                            heading: trk.heading,
                            status: "lost".to_string(), // Варіант А: єдиний червоний хрест для мапи
                            outcome: status_str,        // точний результат для статистики
                            lost_ts: now,
                            first_seen: trk.first_seen,
                            trajectory: trk.trajectory.clone(),
                        },
                    );
                    lost_tracks.push(trk);
                }
                continue;
            }

            let ob_info = detector.find_location_info(t.lat, t.lon);

            // Автоматична фіксація нерозпізнаних типів цілей у журналі обміну
            let (cat, _meta) = classify_target(&t.raw_name, t.raw_type_code);
            let raw_lower = t.raw_name.trim().to_lowercase();
            let is_generic = raw_lower.is_empty()
                || raw_lower == "ціль"
                || raw_lower == "цілі"
                || raw_lower == "target"
                || raw_lower == "об'єкт"
                || raw_lower == "обєкт"
                || raw_lower == "unknown"
                || t.raw_type_code == 0;

            if cat == "unknown" && !is_generic && t.raw_type_code != 0 {
                if let Some(mgr) = exchange_mgr {
                    mgr.record_unmapped(
                        "threat",
                        &t.raw_name,
                        Some(t.raw_type_code),
                        "unknown",
                        source,
                        Some(&format!("Нерозпізнана назва '{}', сирий код {}", t.raw_name, t.raw_type_code)),
                    );
                }
            }

            let eff_speed = t.speed_kmh.unwrap_or(0.0);

            // 3. Статуси "lost", "disappeared", "cooldown" входять у стан cooldown з вікном мовчання 30 сек
            let is_incoming_cooldown = t.upstream_status == "cooldown"
                || t.upstream_status == "lost"
                || t.upstream_status == "disappeared";

            if let Some(trk) = self.tracks.get_mut(&t.id) {
                if is_incoming_cooldown {
                    if trk.status != "cooldown" {
                        trk.status = "cooldown".to_string();
                        trk.cooldown_start_ts = Some(now);
                    }
                } else {
                    trk.status = "active".to_string();
                    trk.cooldown_start_ts = None;
                    self.recent_lost.remove(&t.id);
                }
                // Timestamp Guard: захист від перескоків назад у часі між стрімами
                let obs_ts = if let Some(offset) = t.time_offset_ms {
                    now - (offset as f64 / 1000.0)
                } else {
                    now
                };

                let is_newer = obs_ts >= (trk.last_seen - 3.0);
                if is_newer {
                    trk.update(
                        t.lat,
                        t.lon,
                        t.heading_deg,
                        eff_speed,
                        ob_info.name,
                        ob_info.id,
                        ob_info.raion_id.clone(),
                        Some(&t.raw_name),
                        Some(t.raw_type_code),
                    );
                } else if eff_speed > 0.0 {
                    trk.speed_kmh = eff_speed;
                }

                if let Some(c) = t.confidence {
                    trk.confidence = Some(c);
                }
                if !trk.sources_seen.contains(&source.to_string()) {
                    trk.sources_seen.push(source.to_string());
                }
            } else {
                let mut trk = TargetTrack::new(
                    t.id.clone(),
                    t.raw_name.clone(),
                    t.raw_type_code,
                    t.lat,
                    t.lon,
                    t.heading_deg,
                    eff_speed,
                    ob_info.name,
                    ob_info.id,
                    ob_info.raion_id,
                );
                if is_incoming_cooldown {
                    trk.status = "cooldown".to_string();
                    trk.cooldown_start_ts = Some(now);
                } else {
                    self.recent_lost.remove(&t.id);
                }
                if !t.trail_points.is_empty() {
                    trk = trk.with_trail(&t.trail_points, now as i64);
                }
                if let Some(c) = t.confidence {
                    trk.confidence = Some(c);
                }
                if !trk.sources_seen.contains(&source.to_string()) {
                    trk.sources_seen.push(source.to_string());
                }
                self.tracks.insert(t.id.clone(), trk);
            }
        }

        // Дворівневий життєвий цикл без оновлень від джерела:
        // 1. Якщо ціль у статусі "active" не оновлювалась >= 20 сек -> переводимо в "cooldown"
        // 2. Якщо ціль у статусі "cooldown" мовчить >= 30 сек (від cooldown_start_ts) -> остаточний перехід у "lost"
        let mut expired_ids = Vec::new();
        for (id, trk) in self.tracks.iter_mut() {
            if !seen_ids.contains(id) {
                let silence = now - trk.last_seen;
                if trk.status == "active" {
                    if silence >= 20.0 {
                        trk.status = "cooldown".to_string();
                        trk.cooldown_start_ts = Some(now);
                    }
                } else if trk.status == "cooldown" {
                    let cd_start = trk.cooldown_start_ts.unwrap_or(trk.last_seen);
                    if (now - cd_start) >= 30.0 {
                        expired_ids.push(id.clone());
                    }
                }
            } else if trk.status == "cooldown" {
                // Якщо ціль передається джерелом у статусі cooldown/lost довше ніж 30 секунд без повернення в active
                let cd_start = trk.cooldown_start_ts.unwrap_or(trk.last_seen);
                if (now - cd_start) >= 30.0 {
                    expired_ids.push(id.clone());
                }
            }
        }

        // Expired / silent tracks
        for tid in expired_ids {
            if let Some(trk) = self.tracks.remove(&tid) {
                self.recent_lost.insert(
                    tid.clone(),
                    LostTargetRecord {
                        id: tid,
                        type_ua: trk.type_ua.clone(),
                        category: trk.category.clone(),
                        color_hex: trk.color_hex.clone(),
                        lat: trk.lat,
                        lon: trk.lon,
                        heading: trk.heading,
                        status: "lost".to_string(),
                        outcome: "lost".to_string(),
                        lost_ts: now,
                        first_seen: trk.first_seen,
                        trajectory: trk.trajectory.clone(),
                    },
                );
                lost_tracks.push(trk);
            }
        }

        // Автоматичне очищення міток втрачених цілей, старших за 600 секунд (10 хв - максимальний ліміт клієнтських налаштувань)
        self.recent_lost.retain(|_, v| (now - v.lost_ts) <= 600.0);
        lost_tracks
    }

    /// Періодичне очищення застарілих цілей без оновлення від upstream
    pub fn has_stale_or_expired(&self, now: f64) -> bool {
        self.tracks.values().any(|trk| (now - trk.last_seen) > 180.0)
            || self.recent_lost.values().any(|v| (now - v.lost_ts) > 600.0)
    }

    pub fn cleanup_stale(&mut self, now: f64) -> Vec<TargetTrack> {
        let expired_ids: Vec<String> = self.tracks.iter()
            .filter(|(_, trk)| (now - trk.last_seen) > 180.0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut expired_tracks = Vec::new();
        for tid in expired_ids {
            if let Some(trk) = self.tracks.remove(&tid) {
                self.recent_lost.insert(
                    tid.clone(),
                    LostTargetRecord {
                        id: tid,
                        type_ua: trk.type_ua.clone(),
                        category: trk.category.clone(),
                        color_hex: trk.color_hex.clone(),
                        lat: trk.lat,
                        lon: trk.lon,
                        heading: trk.heading,
                        status: "lost".to_string(),
                        outcome: "lost".to_string(),
                        lost_ts: now,
                        first_seen: trk.first_seen,
                        trajectory: trk.trajectory.clone(),
                    },
                );
                expired_tracks.push(trk);
            }
        }
        self.recent_lost.retain(|_, v| (now - v.lost_ts) <= 600.0);
        expired_tracks
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficialAlert {
    pub id: String,
    pub name: String,
    pub alert: bool,
    pub alert_type: String, // "missile" | "artillery" | "drone" | ...
    pub color: String,      // "red" | "yellow" | "gray"
    pub level: String,      // "State" | "Raion" | "Community"
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OblastAlertState {
    pub id: String,
    pub name: String,
    pub alert: bool,
    pub color: String,
    pub alert_type: String,
    pub targets_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaionAlertState {
    pub id: String,
    pub name: String,
    pub oblast_id: String,
    pub alert: bool,
    pub color: String,
    pub alert_type: String,
    pub targets_count: usize,
}

/// 3-етапний тайм-аут для опитування (пробудження) джерел у стані offline:
/// 1-й етап: 60 сек (1 хв)
/// 2-й етап: 120 сек (2 хв)
/// 3-й етап: 300 сек (5 хв) і далі залишається 300 сек.
pub fn calculate_offline_backoff_secs(consecutive_failures: u32) -> u64 {
    match consecutive_failures {
        0 => 0,
        1 => 60,
        2 => 120,
        _ => 300,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRuntimeStatus {
    pub id: String,
    pub status: String, // "active" | "suspended" | "offline"
    #[serde(default)]
    pub error_reason: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub next_probe_ts: f64,
    #[serde(default)]
    pub last_success_ts: f64,
    #[serde(default)]
    pub last_attempt_ts: f64,
}

pub struct ThreatState {
    pub tracker: TargetTracker,
    pub official_alerts: HashMap<String, OfficialAlert>,
    pub oblast_alerts: HashMap<String, OblastAlertState>,
    pub raion_alerts: HashMap<String, RaionAlertState>,
    pub mig_active: bool,
    pub last_update_ts: f64,
    pub last_targets_update_ts: f64,
    pub last_primary_targets_ts: f64,
    pub last_ws_targets_ts: f64,
    pub last_alerts_update_ts: f64,
    pub ua_alerts_cooldown_until: f64,
    pub update_seq: u64,
    pub notifier: Option<tokio::sync::watch::Sender<u64>>,
    pub upstream_provider: String,
    pub alarms_provider: String,
    pub targets_provider: String,
    pub last_alarms_provider_status: String,
    pub last_targets_provider_status: String,
    pub alert_reasons: Vec<String>,
    pub stream_runtime_statuses: HashMap<String, StreamRuntimeStatus>,
}

impl Default for ThreatState {
    fn default() -> Self {
        let now = now_sec();
        let mut statuses = HashMap::new();
        statuses.insert(
            "ukrainealarm_alerts".to_string(),
            StreamRuntimeStatus {
                id: "ukrainealarm_alerts".to_string(),
                status: "active".to_string(),
                error_reason: None,
                consecutive_failures: 0,
                next_probe_ts: 0.0,
                last_success_ts: now,
                last_attempt_ts: now,
            },
        );
        statuses.insert(
            "neptun_alerts".to_string(),
            StreamRuntimeStatus {
                id: "neptun_alerts".to_string(),
                status: "suspended".to_string(),
                error_reason: None,
                consecutive_failures: 0,
                next_probe_ts: 0.0,
                last_success_ts: now,
                last_attempt_ts: now,
            },
        );
        statuses.insert(
            "ukrainealarm_ws".to_string(),
            StreamRuntimeStatus {
                id: "ukrainealarm_ws".to_string(),
                status: "active".to_string(),
                error_reason: None,
                consecutive_failures: 0,
                next_probe_ts: 0.0,
                last_success_ts: now,
                last_attempt_ts: now,
            },
        );
        statuses.insert(
            "neptun_targets".to_string(),
            StreamRuntimeStatus {
                id: "neptun_targets".to_string(),
                status: "suspended".to_string(),
                error_reason: None,
                consecutive_failures: 0,
                next_probe_ts: 0.0,
                last_success_ts: now,
                last_attempt_ts: now,
            },
        );
        statuses.insert(
            "mapa_targets".to_string(),
            StreamRuntimeStatus {
                id: "mapa_targets".to_string(),
                status: "suspended".to_string(),
                error_reason: None,
                consecutive_failures: 0,
                next_probe_ts: 0.0,
                last_success_ts: now,
                last_attempt_ts: now,
            },
        );

        Self {
            tracker: TargetTracker::default(),
            official_alerts: HashMap::new(),
            oblast_alerts: HashMap::new(),
            raion_alerts: HashMap::new(),
            mig_active: false,
            last_update_ts: now,
            last_targets_update_ts: now,
            last_primary_targets_ts: now,
            last_ws_targets_ts: now,
            last_alerts_update_ts: now,
            ua_alerts_cooldown_until: 0.0,
            update_seq: 1,
            notifier: None,
            upstream_provider: "Centrifugo (ws.ukrainealarm.com)".to_string(),
            alarms_provider: "UkraineAlarm (API v3)".to_string(),
            targets_provider: "WS UkraineAlarm".to_string(),
            last_alarms_provider_status: "active".to_string(),
            last_targets_provider_status: "active".to_string(),
            alert_reasons: Vec::new(),
            stream_runtime_statuses: statuses,
        }
    }
}

impl ThreatState {
    /// Подієве оновлення seq та миттєве пробудження WebSocket-клієнтів
    pub fn bump_seq(&mut self) {
        self.update_seq = self.update_seq.wrapping_add(1);
        if let Some(ref tx) = self.notifier {
            let _ = tx.send_replace(self.update_seq);
        }
    }

    pub fn get_stream_runtime_status(&self, id: &str) -> Option<&StreamRuntimeStatus> {
        self.stream_runtime_statuses.get(id)
    }

    pub fn report_stream_success(&mut self, stream_id: &str) {
        let now = now_sec();
        let entry = self.stream_runtime_statuses.entry(stream_id.to_string()).or_insert_with(|| StreamRuntimeStatus {
            id: stream_id.to_string(),
            status: "suspended".to_string(),
            error_reason: None,
            consecutive_failures: 0,
            next_probe_ts: 0.0,
            last_success_ts: now,
            last_attempt_ts: now,
        });
        entry.error_reason = None;
        entry.consecutive_failures = 0;
        entry.next_probe_ts = 0.0;
        entry.last_success_ts = now;
        entry.last_attempt_ts = now;
    }

    pub fn report_stream_failure(&mut self, stream_id: &str, reason: &str) {
        let now = now_sec();
        let entry = self.stream_runtime_statuses.entry(stream_id.to_string()).or_insert_with(|| StreamRuntimeStatus {
            id: stream_id.to_string(),
            status: "offline".to_string(),
            error_reason: Some(reason.to_string()),
            consecutive_failures: 0,
            next_probe_ts: 0.0,
            last_success_ts: 0.0,
            last_attempt_ts: now,
        });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        let backoff = calculate_offline_backoff_secs(entry.consecutive_failures);
        entry.next_probe_ts = now + (backoff as f64);
        entry.error_reason = Some(reason.to_string());
        entry.status = "offline".to_string();
        entry.last_attempt_ts = now;
    }

    pub fn can_probe_stream(&self, stream_id: &str) -> bool {
        if let Some(st) = self.stream_runtime_statuses.get(stream_id) {
            if st.status != "offline" {
                return true;
            }
            let now = now_sec();
            now >= st.next_probe_ts
        } else {
            true
        }
    }

    /// Перераховує статуси active / suspended / offline для всіх потоків за їхніми пріоритетами
    /// Правила:
    /// - active має рівно 1 потік на кожен тип (alerts / targets)
    /// - Зміна на active може потік тільки з найвищого справного рівня (1 -> 2 -> 3)
    /// - Всі інші справні потоки цього типу стають suspended
    /// - Всі несправні потоки залишаються offline(reason)
    pub fn recompute_all_stream_statuses(&mut self, configs: &[crate::storage::StreamSourceConfig]) {
        for stream_type in &["alerts", "targets"] {
            let mut eligible: Vec<&crate::storage::StreamSourceConfig> = configs
                .iter()
                .filter(|s| s.stream_type == *stream_type)
                .collect();
            eligible.sort_by_key(|s| s.priority);

            let mut assigned_active = false;

            for cfg in eligible {
                let entry = self.stream_runtime_statuses.entry(cfg.id.clone()).or_insert_with(|| StreamRuntimeStatus {
                    id: cfg.id.clone(),
                    status: if cfg.enabled { "suspended".to_string() } else { "offline".to_string() },
                    error_reason: if !cfg.enabled { Some("Вимкнено в налаштуваннях".to_string()) } else { None },
                    consecutive_failures: 0,
                    next_probe_ts: 0.0,
                    last_success_ts: 0.0,
                    last_attempt_ts: 0.0,
                });

                if !cfg.enabled {
                    entry.status = "offline".to_string();
                    entry.error_reason = Some("Вимкнено в налаштуваннях".to_string());
                    continue;
                }

                // Якщо потік у стані failure
                if entry.consecutive_failures > 0 || (entry.status == "offline" && entry.error_reason.is_some()) {
                    entry.status = "offline".to_string();
                    continue;
                }

                // Перший справний потік стає active
                if !assigned_active {
                    entry.status = "active".to_string();
                    entry.error_reason = None;
                    assigned_active = true;
                } else {
                    entry.status = "suspended".to_string();
                    entry.error_reason = None;
                }
            }
        }

        // Оновлюємо публічні/клієнтські маркери alarms_status та targets_status
        let has_active_alerts = self.stream_runtime_statuses.values().any(|s| {
            configs.iter().any(|c| c.id == s.id && c.stream_type == "alerts") && s.status == "active"
        });
        self.last_alarms_provider_status = if has_active_alerts { "active".to_string() } else { "offline".to_string() };

        let has_active_targets = self.stream_runtime_statuses.values().any(|s| {
            configs.iter().any(|c| c.id == s.id && c.stream_type == "targets") && s.status == "active"
        });
        self.last_targets_provider_status = if has_active_targets { "active".to_string() } else { "offline".to_string() };
    }

    /// Суворий перерахунок тривог: колір визначається сиренами та цілями (Red / Yellow)
    pub fn recompute_oblast_alerts(&mut self, detector: &OblastDetector) {
        let mut ob_targets: HashMap<String, usize> = HashMap::new();
        let mut ra_targets: HashMap<String, usize> = HashMap::new();

        for trk in self.tracker.tracks.values() {
            if trk.status == "superseded" {
                continue;
            }
            *ob_targets.entry(trk.oblast_id.clone()).or_insert(0) += 1;
            if !trk.raion_id.is_empty() && trk.raion_id != "0" {
                *ra_targets.entry(trk.raion_id.clone()).or_insert(0) += 1;
            }
        }

        // Області (Rank 1)
        for ob in &detector.regions {
            let ob_id = &ob.id;
            let official = self.official_alerts.get(ob_id);

            let (official_has_alert, official_color, official_alert_type) = if let Some(off) = official {
                (off.alert, off.color.clone(), off.alert_type.clone())
            } else {
                (false, "none".to_string(), "none".to_string())
            };

            let count = ob_targets.get(ob_id).copied().unwrap_or(0);

            let (has_alert, color, alert_type) = if official_color == "red" {
                (true, "red".to_string(), official_alert_type)
            } else if official_color == "yellow" || count > 0 {
                (true, "yellow".to_string(), if official_alert_type == "none" { "drone".to_string() } else { official_alert_type })
            } else {
                (official_has_alert, official_color, official_alert_type)
            };

            self.oblast_alerts.insert(
                ob_id.clone(),
                OblastAlertState {
                    id: ob_id.clone(),
                    name: ob.name.clone(),
                    alert: has_alert,
                    color,
                    alert_type,
                    targets_count: count,
                },
            );
        }

        // Примітка: м. Київ (31) є окремою адміністративно-територіальною одиницею першого рівня (Rank 1)
        // із власною системою оповіщення та офіційним каналом тривог (КМВА). Київ НЕ успадковує
        // тривоги від Київської області (14), що повністю відповідає офіційним картам тривог (alerts.in.ua).
        // Статус Києва визначається виключно власним офіційним потоком або безпосередньою наявністю цілей у межах міста.

        // Райони (Rank 2 + Анклави)
        for ra in &detector.raion_regions {
            let ra_id = &ra.id;
            let official = self.official_alerts.get(ra_id);
            let parent_ob = self.oblast_alerts.get(&ra.oblast_id);

            let (mut has_alert, mut color, mut alert_type) = if let Some(off) = official {
                (off.alert, off.color.clone(), off.alert_type.clone())
            } else {
                (false, "none".to_string(), "none".to_string())
            };

            // Правило: Red перекриває Yellow. Якщо область "red", райони піднімаються до "red"
            // Якщо область "yellow", а район без тривоги — район піднімається до "yellow"
            if let Some(p_ob) = parent_ob {
                if p_ob.color == "red" {
                    has_alert = true;
                    color = "red".to_string();
                    alert_type = p_ob.alert_type.clone();
                } else if p_ob.color == "yellow" && color != "red" {
                    has_alert = true;
                    color = "yellow".to_string();
                    if alert_type == "none" {
                        alert_type = p_ob.alert_type.clone();
                    }
                }
            }

            let count = ra_targets.get(ra_id).copied().unwrap_or(0);
            if color != "red" && count > 0 {
                has_alert = true;
                color = "yellow".to_string();
                if alert_type == "none" {
                    alert_type = "drone".to_string();
                }
            }

            let ra_name = detector.get_canonical_name(ra_id)
                .map(|s| s.to_string())
                .unwrap_or_else(|| ra.name.clone());

            self.raion_alerts.insert(
                ra_id.clone(),
                RaionAlertState {
                    id: ra_id.clone(),
                    name: ra_name,
                    oblast_id: ra.oblast_id.clone(),
                    alert: has_alert,
                    color,
                    alert_type,
                    targets_count: count,
                },
            );
        }

        // Додаткова синхронізація міст-анклавів
        let enclave_sync = [
            ("1293", "124", "22"), // Харків -> Харківський р-н / Харківська обл
            ("564",  "149", "12"), // Запоріжжя -> Запорізький р-н / Запорізька обл
            ("750",  "74",  "14"), // Славутич -> Вишгородський р-н / Київська обл
            ("707",  "75",  "14"), // Коцюбинське -> Бучанський р-н / Київська обл
        ];
        for (enc_id, ra_id, ob_id) in enclave_sync {
            let parent_ra_alert = self.raion_alerts.get(ra_id).cloned();
            let parent_ob_alert = self.oblast_alerts.get(ob_id).cloned();
            if let Some(enc) = self.raion_alerts.get_mut(enc_id) {
                if enc.color != "red" {
                    if let Some(ra) = parent_ra_alert {
                        if ra.alert {
                            enc.alert = true;
                            enc.color = ra.color;
                            if enc.alert_type == "none" {
                                enc.alert_type = ra.alert_type;
                            }
                        }
                    }
                    if enc.color != "red" {
                        if let Some(ob) = parent_ob_alert {
                            if ob.alert {
                                enc.alert = true;
                                enc.color = ob.color;
                                if enc.alert_type == "none" {
                                    enc.alert_type = ob.alert_type;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oblast_detector::RegionFeatureData;

    #[test]
    fn test_heading_diff_wraparound() {
        assert!((heading_diff(10.0, 20.0) - 10.0).abs() < 0.001);
        assert!((heading_diff(20.0, 10.0) - 10.0).abs() < 0.001);
        // Через границю 0/360°
        assert!((heading_diff(355.0, 5.0) - 10.0).abs() < 0.001);
        assert!((heading_diff(5.0, 355.0) - 10.0).abs() < 0.001);
        // Протилежні напрямки
        assert!((heading_diff(0.0, 180.0) - 180.0).abs() < 0.001);
    }

    #[test]
    fn test_corridor_extrapolation_forward_continuity() {
        let track = TargetTrack::new(
            "test_1".to_string(),
            "shahed".to_string(),
            1,
            50.0,
            30.0,
            90.0, // Схід
            600.0, // 600 км/год = 10 км/хв
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
        );

        let corridor = track.get_extrapolated_corridor();
        assert_eq!(corridor.len(), 3, "Corridor must have 3 steps (5, 10, 15 min)");
        
        // Перша точка екстраполяції (5 хв) має бути на схід (lon > 30.0)
        assert!(corridor[0].lon > 30.0, "Heading east must increase longitude");
        assert!((corridor[0].lat - 50.0).abs() < 0.05, "Heading east must maintain approximately same latitude");
        // Друга точка (10 хв) далі за першу
        assert!(corridor[1].lon > corridor[0].lon);
        // Третя точка (15 хв) далі за другу
        assert!(corridor[2].lon > corridor[1].lon);
    }

    #[test]
    fn test_track_update_and_monotonicity() {
        let mut track = TargetTrack::new(
            "trk_test_1".to_string(),
            "shahed".to_string(),
            1,
            50.0,
            30.0,
            0.0,
            200.0,
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
        );

        assert_eq!(track.id, "trk_test_1");
        assert_eq!(track.trajectory.len(), 1);
        assert_eq!(track.lat, 50.0);
        assert_eq!(track.lon, 30.0);

        // Рух цілі вперед на північ
        track.update(
            50.05,
            30.0,
            0.0,
            220.0,
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
            None,
            None,
        );

        assert_eq!(track.lat, 50.05);
        assert_eq!(track.lon, 30.0);
        // Кінематичний alpha-beta фільтр плавно згладжує прискорення: швидкість зростає у напрямку 220, не перевищуючи max
        assert!(track.speed_kmh > 175.0 && track.speed_kmh <= 220.0);
        assert!(track.filtered_speed_kmh > 175.0 && track.filtered_speed_kmh <= 220.0);
    }

    #[test]
    fn test_target_reclassification_and_anti_downgrade() {
        let mut track = TargetTrack::new(
            "reclass_test_1".to_string(),
            "unknown".to_string(),
            0,
            50.0,
            30.0,
            90.0,
            0.0,
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
        );

        assert_eq!(track.category, "unknown");
        assert_eq!(track.type_ua, "Неідентифікована ціль");

        // 1. Уточнення джерелом: ціль розпізнана як поршневий Шахед
        track.update(
            50.01,
            30.02,
            90.0,
            185.0,
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
            Some("Шахед-136"),
            Some(1),
        );

        assert_eq!(track.category, "shahed");
        assert_eq!(track.type_ua, "Шахед");
        assert_eq!(track.color_hex, "#FACC15");
        assert_eq!(track.esp_code, 1);
        assert_eq!(track.ha_icon, "mdi:navigation-variant");

        // 2. Перекваліфікація (виявлено реактивний двигун -> Реактивний шахед)
        track.update(
            50.02,
            30.05,
            90.0,
            450.0,
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
            Some("Реакт.уд.дрон"),
            Some(8),
        );

        assert_eq!(track.category, "shahed_jet");
        assert_eq!(track.type_ua, "Реактивний шахед");
        assert_eq!(track.color_hex, "#00E5FF");
        assert_eq!(track.esp_code, 2);
        assert_eq!(track.ha_icon, "mdi:rocket-outline");

        // 3. Захист від деградації: наступний пакет прийшов з порожньою назвою/кодом 0
        track.update(
            50.03,
            30.08,
            90.0,
            450.0,
            "Київська".to_string(),
            "10".to_string(),
            "101".to_string(),
            Some("Ціль"),
            Some(0),
        );

        // Ціль зберігає вже підтверджений статус "shahed_jet", не скидаючись в "unknown"
        assert_eq!(track.category, "shahed_jet");
        assert_eq!(track.type_ua, "Реактивний шахед");
        assert_eq!(track.color_hex, "#00E5FF");
    }

    #[test]
    fn test_silent_source_switch_zero_fake_shootdowns() {
        let detector = OblastDetector::default();
        let mut tracker = TargetTracker::default();

        let ua_target = RawExtractedTarget {
            id: "trk_001".to_string(),
            lat: 50.45,
            lon: 30.52,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![(50.45, 30.50), (50.45, 30.52)],
            upstream_status: "active".to_string(),
        };

        // 1. Початковий пакет цілей від WS UkraineAlarm
        let _ = tracker.update_batch(&[ua_target], &detector, None, "WS UkraineAlarm");
        assert_eq!(tracker.tracks.len(), 1);
        assert!(tracker.tracks.contains_key("trk_001"));
        assert!(tracker.recent_lost.is_empty());

        // 2. Перехід на Neptun: тихий перехід має видалити trk_001 БЕЗ переведення у recent_lost
        let neptun_target = RawExtractedTarget {
            id: "nep_001".to_string(),
            lat: 50.46,
            lon: 30.53,
            raw_name: "uav".to_string(),
            raw_type_code: 8,
            heading_deg: 95.0,
            speed_kmh: Some(180.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        let _ = tracker.update_batch(&[neptun_target], &detector, None, "Neptun Failover");
        assert_eq!(tracker.tracks.len(), 1);
        assert!(tracker.tracks.contains_key("nep_001"));
        assert!(!tracker.tracks.contains_key("trk_001"));
        // КРИТИЧНИЙ ІНВАРІАНТ: recent_lost має бути пустим, жодних хибних червоних хрестів збиття!
        assert!(tracker.recent_lost.is_empty(), "Silent source switch must NOT add retired provider targets to recent_lost!");

        // 3. Перехід на MAPA.UA: тихий перехід має очистити nep_001 БЕЗ хибних хрестів збиття
        let mapa_target = RawExtractedTarget {
            id: "mapa_1001".to_string(),
            lat: 50.47,
            lon: 30.54,
            raw_name: "drone_piston shahed Shahed-136".to_string(),
            raw_type_code: 8,
            heading_deg: 100.0,
            speed_kmh: Some(185.0),
            confidence: Some(95),
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        let _ = tracker.update_batch(&[mapa_target], &detector, None, "MAPA.UA (Резервний)");
        assert_eq!(tracker.tracks.len(), 1);
        assert!(tracker.tracks.contains_key("mapa_1001"));
        assert!(!tracker.tracks.contains_key("nep_001"));
        assert!(tracker.recent_lost.is_empty(), "Silent source switch to MAPA.UA must NOT create fake shootdowns!");
    }

    #[test]
    fn test_target_lifecycle_remove_and_cooldown_30s_invariants() {
        let detector = OblastDetector::default();
        let mut tracker = TargetTracker::default();

        let t1 = RawExtractedTarget {
            id: "trk_alpha".to_string(),
            lat: 50.45,
            lon: 30.52,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        // 1. Поява активної цілі
        let _ = tracker.update_batch(&[t1.clone()], &detector, None, "TestFeed");
        assert_eq!(tracker.tracks.len(), 1);
        assert_eq!(tracker.tracks["trk_alpha"].status, "active");

        // 2. Джерело надсилає статус "lost" / "disappeared" -> перехід у cooldown на 30 сек
        let mut t1_lost = t1.clone();
        t1_lost.upstream_status = "lost".to_string();
        let _ = tracker.update_batch(&[t1_lost.clone()], &detector, None, "TestFeed");
        assert_eq!(tracker.tracks.len(), 1, "Target in lost/cooldown must remain in tracks during 30s window");
        assert_eq!(tracker.tracks["trk_alpha"].status, "cooldown");
        assert!(tracker.tracks["trk_alpha"].cooldown_start_ts.is_some());
        assert!(tracker.recent_lost.is_empty(), "Cooldown must NOT create impact cross yet!");

        // 3. Повернення свіжої телеметрії "active" -> повернення в active без втрати треку
        let mut t1_active = t1.clone();
        t1_active.upstream_status = "active".to_string();
        let _ = tracker.update_batch(&[t1_active], &detector, None, "TestFeed");
        assert_eq!(tracker.tracks["trk_alpha"].status, "active");
        assert!(tracker.tracks["trk_alpha"].cooldown_start_ts.is_none());

        // 4. Подія "remove" -> безслідне видалення
        let mut t1_remove = t1.clone();
        t1_remove.upstream_status = "remove".to_string();
        let _ = tracker.update_batch(&[t1_remove], &detector, None, "TestFeed");
        assert!(!tracker.tracks.contains_key("trk_alpha"), "Remove must delete track from memory");
        assert!(!tracker.recent_lost.contains_key("trk_alpha"), "Remove must be silent without red cross!");

        // 5. Подія "eliminated" (збиття ППО) -> миттєвий хрест та статус
        let t2 = RawExtractedTarget {
            id: "trk_beta".to_string(),
            lat: 49.0,
            lon: 32.0,
            raw_name: "missile".to_string(),
            raw_type_code: 3,
            heading_deg: 270.0,
            speed_kmh: Some(850.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };
        let _ = tracker.update_batch(&[t2.clone()], &detector, None, "TestFeed");
        assert_eq!(tracker.tracks.len(), 1);

        let mut t2_elim = t2.clone();
        t2_elim.upstream_status = "eliminated".to_string();
        let lost_list = tracker.update_batch(&[t2_elim], &detector, None, "TestFeed");
        assert!(!tracker.tracks.contains_key("trk_beta"));
        assert_eq!(lost_list.len(), 1);
        assert_eq!(lost_list[0].status, "eliminated");
        assert!(tracker.recent_lost.contains_key("trk_beta"));
        assert_eq!(tracker.recent_lost["trk_beta"].outcome, "eliminated");
        assert_eq!(tracker.recent_lost["trk_beta"].status, "lost"); // Варіант А на мапі

        // 6. Воскресіння цілі: якщо ціль була в recent_lost, але джерело знову надсилає її як active
        let mut t2_resurrected = t2.clone();
        t2_resurrected.upstream_status = "active".to_string();
        let _ = tracker.update_batch(&[t2_resurrected], &detector, None, "TestFeed");
        assert!(tracker.tracks.contains_key("trk_beta"), "Resurrected target must be in active tracks");
        assert_eq!(tracker.tracks["trk_beta"].status, "active");
        assert!(!tracker.recent_lost.contains_key("trk_beta"), "Resurrected target must be purged from recent_lost!");
    }

    #[test]
    fn test_phase1_kinematic_alpha_beta_and_heading_smoothing() {
        let mut track = TargetTrack::new(
            "shahed_kine_01".to_string(),
            "shahed".to_string(),
            1,
            50.0,
            30.0,
            90.0,
            175.0,
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
        );

        assert_eq!(track.filtered_speed_kmh, 175.0);
        assert_eq!(track.smoothed_heading, 90.0);

        // 1. Правило «стоячої точки»: зсув < 0.05 км (50 м) не обнуляє швидкість і не ламає курс
        track.update(
            50.0001,
            30.0001,
            0.0,
            0.0,
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
            None,
            None,
        );
        assert_eq!(track.filtered_speed_kmh, 175.0, "Stationary jitter must NOT zero out filtered speed");
        assert_eq!(track.smoothed_heading, 90.0, "Stationary jitter must NOT corrupt smoothed heading");

        // 2. Реальний зсув: плавний поворот курсу та фільтрація швидкості в межах [min, max]
        track.update(
            50.02,
            30.05,
            105.0,
            240.0, // перевищує max_speed (220)
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
            None,
            None,
        );
        // Швидкість затиснута в межах фізичного профілю Шахеда [110, 220]
        assert!(track.filtered_speed_kmh <= 220.0, "Speed must be clamped to max_speed_kmh");
        assert!(track.filtered_speed_kmh >= 110.0, "Speed must be above min_speed_kmh");
        // Курс плавно змістився у напрямку 105 без стрибка
        assert!(track.smoothed_heading >= 90.0 && track.smoothed_heading <= 105.0);
    }

    #[test]
    fn test_dual_state_and_2tick_promotion() {
        let mut track = TargetTrack::new(
            "dual_state_target".to_string(),
            "shahed".to_string(),
            1,
            50.0,
            30.0,
            90.0,
            175.0,
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
        );

        assert_eq!(track.raw_lat, 50.0);
        assert_eq!(track.raw_lon, 30.0);
        assert_eq!(track.lat, 50.0);
        assert_eq!(track.lon, 30.0);
        assert_eq!(track.consecutive_high_speed_ticks, 0);

        // Tick 1: Одиничний сплеск швидкості (600 км/год > 220 * 1.4 = 308 км/год)
        // Повинен застосувати alpha = 0.15, затиснути filtered_speed_kmh до max (220),
        // але зберегти сирі координати та raw_speed_kmh = 600 без жодного відкидання!
        track.update(
            50.05,
            30.05,
            90.0,
            600.0,
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
            None,
            None,
        );

        assert_eq!(track.raw_lat, 50.05, "Raw lat must NEVER be clamped or modified");
        assert_eq!(track.raw_lon, 30.05, "Raw lon must NEVER be clamped or modified");
        assert_eq!(track.lat, 50.05, "Combat lat must match raw lat for siren/danger-zone alerts");
        assert_eq!(track.raw_speed_kmh, 600.0);
        assert_eq!(track.consecutive_high_speed_ticks, 1);
        assert!(track.filtered_speed_kmh <= 220.0, "Tick 1 must clamp filtered speed to max_speed_kmh");
        assert!(track.filt_lat < 50.05, "Visual filt_lat should be smoothly interpolated");

        // Tick 2: Другий поспіль сплеск (підтвердження, що ціль насправді є швидкісною ракетою)
        // 2-tick promotion: consecutive_high_speed_ticks >= 2 -> alpha = 0.65, unclamped
        track.update(
            50.10,
            30.10,
            90.0,
            650.0,
            "Київська область".to_string(),
            "10".to_string(),
            "101".to_string(),
            None,
            None,
        );

        assert_eq!(track.consecutive_high_speed_ticks, 2);
        assert!(track.filtered_speed_kmh > 220.0, "2-tick promotion must allow speed > 220 to avoid visual lag");
        assert_eq!(track.raw_lat, 50.10);
        assert_eq!(track.lat, 50.10);
    }

    #[test]
    fn test_spatial_stitching_canonical_id_retention() {
        let detector = OblastDetector::default();
        let mut tracker = TargetTracker::default();

        let t1 = RawExtractedTarget {
            id: "ua_drone_101".to_string(),
            lat: 50.45,
            lon: 30.52,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        let _ = tracker.update_batch(&[t1], &detector, None, "WS UkraineAlarm");
        assert_eq!(tracker.tracks.len(), 1);
        assert_eq!(tracker.tracks["ua_drone_101"].canonical_id, "ua_drone_101");

        // Failover на Neptun: новий ID "nep_trk_999", але координати поруч (50.46, 30.53) і курс сумісний
        let t2 = RawExtractedTarget {
            id: "nep_trk_999".to_string(),
            lat: 50.46,
            lon: 30.53,
            raw_name: "uav".to_string(),
            raw_type_code: 8,
            heading_deg: 95.0,
            speed_kmh: Some(180.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        let _ = tracker.update_batch(&[t2], &detector, None, "Neptun Failover");
        assert_eq!(tracker.tracks.len(), 1);
        assert!(tracker.tracks.contains_key("nep_trk_999"));
        // КРИТИЧНО: канонічний ID збережено від первинного джерела!
        assert_eq!(tracker.tracks["nep_trk_999"].canonical_id, "ua_drone_101");
        assert!(tracker.tracks["nep_trk_999"].sources_seen.contains(&"WS UkraineAlarm".to_string()));
        assert!(tracker.tracks["nep_trk_999"].sources_seen.contains(&"Neptun Failover".to_string()));
        assert!(tracker.recent_lost.is_empty(), "Recent lost must remain empty on clean stitch");
    }

    #[test]
    fn test_swarm_anticollision_stitching() {
        let detector = OblastDetector::default();
        let mut tracker = TargetTracker::default();

        // Два Шахеди летять парою в рою на відстані ~3.5 км один від одного
        let drone_north = RawExtractedTarget {
            id: "swarm_north".to_string(),
            lat: 50.50,
            lon: 30.50,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };
        let drone_south = RawExtractedTarget {
            id: "swarm_south".to_string(),
            lat: 50.47,
            lon: 30.50,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        let _ = tracker.update_batch(&[drone_north, drone_south], &detector, None, "PrimaryFeed");
        assert_eq!(tracker.tracks.len(), 2);

        // Failover: резервне джерело надсилає нові ID
        let backup_north = RawExtractedTarget {
            id: "backup_n".to_string(),
            lat: 50.505,
            lon: 30.515,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };
        let backup_south = RawExtractedTarget {
            id: "backup_s".to_string(),
            lat: 50.475,
            lon: 30.515,
            raw_name: "shahed".to_string(),
            raw_type_code: 8,
            heading_deg: 90.0,
            speed_kmh: Some(185.0),
            confidence: None,
            time_offset_ms: None,
            trail_points: vec![],
            upstream_status: "active".to_string(),
        };

        let _ = tracker.update_batch(&[backup_north, backup_south], &detector, None, "SecondaryFeed");
        assert_eq!(tracker.tracks.len(), 2);

        // Завдяки 1-to-1 найменшому скорингу північний дрон зшивається з північним, а південний - з південним!
        assert_eq!(tracker.tracks["backup_n"].canonical_id, "swarm_north");
        assert_eq!(tracker.tracks["backup_s"].canonical_id, "swarm_south");
    }

    #[test]
    fn test_kyiv_city_independent_from_oblast_alert() {
        let mut threat_state = ThreatState::default();
        let mut detector = OblastDetector::default();
        detector.regions.push(RegionFeatureData {
            id: "14".to_string(),
            name: "Київська область".to_string(),
            rank: 1,
            oblast_id: "14".to_string(),
            bbox: (29.0, 49.0, 32.0, 52.0),
            center: (50.0, 30.0),
            polygons: vec![],
        });
        detector.regions.push(RegionFeatureData {
            id: "31".to_string(),
            name: "м. Київ".to_string(),
            rank: 1,
            oblast_id: "31".to_string(),
            bbox: (30.2, 50.3, 30.8, 50.6),
            center: (50.45, 30.52),
            polygons: vec![],
        });

        // Сценарій 1: Київська область (14) у тривозі "yellow" (шахеди в області), Київ (31) — без тривоги
        threat_state.official_alerts.insert("14".to_string(), OfficialAlert {
            id: "14".to_string(),
            name: "Київська область".to_string(),
            alert: true,
            color: "yellow".to_string(),
            alert_type: "drone".to_string(),
            level: "State".to_string(),
            updated_at: "2026-11-21T10:00:00Z".to_string(),
        });
        threat_state.official_alerts.insert("31".to_string(), OfficialAlert {
            id: "31".to_string(),
            name: "м. Київ".to_string(),
            alert: false,
            color: "none".to_string(),
            alert_type: "none".to_string(),
            level: "State".to_string(),
            updated_at: "2026-11-21T10:00:00Z".to_string(),
        });

        threat_state.recompute_oblast_alerts(&detector);

        let kyiv_ob = threat_state.oblast_alerts.get("14").unwrap();
        assert!(kyiv_ob.alert);
        assert_eq!(kyiv_ob.color, "yellow");

        // Київ (31) НЕ повинен успадковувати тривогу області!
        let kyiv_city = threat_state.oblast_alerts.get("31").unwrap();
        assert!(!kyiv_city.alert);
        assert_eq!(kyiv_city.color, "none");

        // Сценарій 2: Київська область (14) у тривозі "red" (ракета в бік Білої Церкви), Київ без тривоги
        threat_state.official_alerts.get_mut("14").unwrap().color = "red".to_string();
        threat_state.official_alerts.get_mut("14").unwrap().alert_type = "missile".to_string();

        threat_state.recompute_oblast_alerts(&detector);

        let kyiv_city = threat_state.oblast_alerts.get("31").unwrap();
        assert!(!kyiv_city.alert);
        assert_eq!(kyiv_city.color, "none");

        // Сценарій 3: Офіційна сирена вмикається безпосередньо для міста Київ -> Київ стає Red
        threat_state.official_alerts.insert("31".to_string(), OfficialAlert {
            id: "31".to_string(),
            name: "м. Київ".to_string(),
            alert: true,
            color: "red".to_string(),
            alert_type: "missile".to_string(),
            level: "State".to_string(),
            updated_at: "2026-11-21T10:05:00Z".to_string(),
        });

        threat_state.recompute_oblast_alerts(&detector);

        let kyiv_city = threat_state.oblast_alerts.get("31").unwrap();
        assert!(kyiv_city.alert);
        assert_eq!(kyiv_city.color, "red");
    }

    #[test]
    fn test_enclaves_kharkiv_zaporizhzhia_synchronization() {
        let mut threat_state = ThreatState::default();
        let mut detector = OblastDetector::default();
        detector.regions.push(RegionFeatureData {
            id: "22".to_string(),
            name: "Харківська область".to_string(),
            rank: 1,
            oblast_id: "22".to_string(),
            bbox: (35.0, 49.0, 38.0, 51.0),
            center: (50.0, 36.5),
            polygons: vec![],
        });
        detector.regions.push(RegionFeatureData {
            id: "12".to_string(),
            name: "Запорізька область".to_string(),
            rank: 1,
            oblast_id: "12".to_string(),
            bbox: (34.5, 46.5, 37.5, 48.5),
            center: (47.5, 35.5),
            polygons: vec![],
        });
        detector.raion_regions.push(RegionFeatureData {
            id: "124".to_string(),
            name: "Харківський район".to_string(),
            rank: 2,
            oblast_id: "22".to_string(),
            bbox: (35.8, 49.7, 36.6, 50.3),
            center: (50.0, 36.2),
            polygons: vec![],
        });
        detector.raion_regions.push(RegionFeatureData {
            id: "149".to_string(),
            name: "Запорізький район".to_string(),
            rank: 2,
            oblast_id: "12".to_string(),
            bbox: (34.8, 47.6, 35.6, 48.2),
            center: (47.8, 35.2),
            polygons: vec![],
        });
        detector.raion_regions.push(RegionFeatureData {
            id: "1293".to_string(),
            name: "м. Харків".to_string(),
            rank: 2,
            oblast_id: "22".to_string(),
            bbox: (36.1, 49.9, 36.4, 50.1),
            center: (50.0, 36.23),
            polygons: vec![],
        });
        detector.raion_regions.push(RegionFeatureData {
            id: "564".to_string(),
            name: "м. Запоріжжя".to_string(),
            rank: 2,
            oblast_id: "12".to_string(),
            bbox: (35.0, 47.8, 35.3, 48.0),
            center: (47.84, 35.14),
            polygons: vec![],
        });

        // Тривога в Харківській області (22) -> Red
        threat_state.official_alerts.insert("22".to_string(), OfficialAlert {
            id: "22".to_string(),
            name: "Харківська область".to_string(),
            alert: true,
            color: "red".to_string(),
            alert_type: "missile".to_string(),
            level: "State".to_string(),
            updated_at: "2026-11-21T10:00:00Z".to_string(),
        });
        // Тривога в Запорізькій області (12) -> Yellow
        threat_state.official_alerts.insert("12".to_string(), OfficialAlert {
            id: "12".to_string(),
            name: "Запорізька область".to_string(),
            alert: true,
            color: "yellow".to_string(),
            alert_type: "drone".to_string(),
            level: "State".to_string(),
            updated_at: "2026-11-21T10:00:00Z".to_string(),
        });

        threat_state.recompute_oblast_alerts(&detector);

        // м. Харків (1293) гарантовано успадковує Red від області/району і НЕ залишається чорною діркою!
        let kharkiv_city = threat_state.raion_alerts.get("1293").unwrap();
        assert!(kharkiv_city.alert, "Харків має успадкувати тривогу від області/району!");
        assert_eq!(kharkiv_city.color, "red");

        // м. Запоріжжя (564) гарантовано успадковує Yellow від області/району!
        let zap_city = threat_state.raion_alerts.get("564").unwrap();
        assert!(zap_city.alert, "Запоріжжя має успадкувати тривогу від області/району!");
        assert_eq!(zap_city.color, "yellow");
    }

    #[test]
    fn test_3_stage_offline_backoff_and_cascade_recompute() {
        use crate::storage::default_stream_sources;

        // 1. Перевірка 3-етапного бекофу: 1 -> 60s, 2 -> 120s, 3 -> 300s, 4 -> 300s
        assert_eq!(calculate_offline_backoff_secs(0), 0);
        assert_eq!(calculate_offline_backoff_secs(1), 60);
        assert_eq!(calculate_offline_backoff_secs(2), 120);
        assert_eq!(calculate_offline_backoff_secs(3), 300);
        assert_eq!(calculate_offline_backoff_secs(4), 300);

        let mut st = ThreatState::default();
        let configs = default_stream_sources();

        // 2. Початковий стан: primary потоки активні (рівно 1 active на тип)
        st.recompute_all_stream_statuses(&configs);
        let s_ua_ws = st.get_stream_runtime_status("ukrainealarm_ws").unwrap();
        let s_nep_tgt = st.get_stream_runtime_status("neptun_targets").unwrap();
        let s_mapa_tgt = st.get_stream_runtime_status("mapa_targets").unwrap();

        assert_eq!(s_ua_ws.status, "active");
        assert_eq!(s_nep_tgt.status, "suspended");
        assert_eq!(s_mapa_tgt.status, "suspended");

        // 3. Відмова Рівня #1 (UkraineAlarm WS -> 401 Unauthorized)
        st.report_stream_failure("ukrainealarm_ws", "Сесію Дії вичерпано (HTTP 401)");
        st.recompute_all_stream_statuses(&configs);

        let s_ua_ws2 = st.get_stream_runtime_status("ukrainealarm_ws").unwrap();
        let s_nep_tgt2 = st.get_stream_runtime_status("neptun_targets").unwrap();
        let s_mapa_tgt2 = st.get_stream_runtime_status("mapa_targets").unwrap();

        assert_eq!(s_ua_ws2.status, "offline");
        assert!(s_ua_ws2.error_reason.as_ref().unwrap().contains("401"));
        assert_eq!(s_nep_tgt2.status, "active", "Рівень #2 Neptun має стати active!");
        assert_eq!(s_mapa_tgt2.status, "suspended", "Рівень #3 MAPA має залишатись suspended!");

        // 4. Відмова Рівня #2 (Neptun targets -> disconnect)
        st.report_stream_failure("neptun_targets", "Помилка підключення до сокету");
        st.recompute_all_stream_statuses(&configs);

        let s_nep_tgt3 = st.get_stream_runtime_status("neptun_targets").unwrap();
        let s_mapa_tgt3 = st.get_stream_runtime_status("mapa_targets").unwrap();
        assert_eq!(s_nep_tgt3.status, "offline");
        assert_eq!(s_mapa_tgt3.status, "active", "Рівень #3 MAPA має стати active!");

        // 5. Відновлення Рівня #1
        st.report_stream_success("ukrainealarm_ws");
        st.recompute_all_stream_statuses(&configs);

        let s_ua_ws4 = st.get_stream_runtime_status("ukrainealarm_ws").unwrap();
        let s_mapa_tgt4 = st.get_stream_runtime_status("mapa_targets").unwrap();
        assert_eq!(s_ua_ws4.status, "active", "Рівень #1 знову має стати active!");
        assert_eq!(s_mapa_tgt4.status, "suspended", "Рівень #3 знову має повернутись у suspended!");
    }
}
