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
    pub first_seen: f64,
    pub last_seen: f64,
    pub trajectory: Vec<TrajectoryPoint>,
    #[serde(default)]
    pub confidence: Option<u8>,
    #[serde(default)]
    pub last_history_sync_ts: f64,
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
    ) -> Self {
        let (cat, meta) = classify_target(&raw_type, raw_code);
        let now = now_sec();
        let eff_speed = if speed > 0.0 { speed } else { meta.default_speed };

        Self {
            id,
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
            first_seen: now,
            last_seen: now,
            trajectory: vec![TrajectoryPoint {
                lat,
                lon,
                ts: now as i64,
            }],
            confidence: None,
            last_history_sync_ts: 0.0,
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

    pub fn update(
        &mut self,
        lat: f64,
        lon: f64,
        heading: f64,
        speed: f64,
        oblast: String,
        oblast_id: String,
        raw_type: Option<&str>,
        raw_code: Option<i64>,
    ) {
        let now = now_sec();
        if let Some(last_pt) = self.trajectory.last() {
            let dist_from_last = calculate_haversine_distance(last_pt.lat, last_pt.lon, lat, lon);

            // Захист від фізично неможливих стрибків (телепортація > 350 км за один пакет):
            // скидаємо попередні точки тільки при аномальному перескоку координат (захист надзвукових ракет)
            if dist_from_last > 350.0 {
                self.trajectory.clear();
                self.trajectory.push(TrajectoryPoint {
                    lat,
                    lon,
                    ts: now as i64,
                });
                self.heading = if heading > 0.0 { heading } else { self.heading };
            } else {
                let calculated_heading = if dist_from_last > 0.3 {
                    calculate_bearing(last_pt.lat, last_pt.lon, lat, lon)
                } else if heading > 0.0 {
                    heading
                } else {
                    self.heading
                };

                let time_since_last = (now as i64) - last_pt.ts;
                let h_diff = heading_diff(self.heading, calculated_heading);

                // Точка фіксується у постійну траєкторію, якщо:
                // 1. Поворот курсу >= 4.0 градусів на відстані від 400 метрів (збереження віражів)
                // 2. Або ціль пролетіла понад 1.5 км по прямій від останньої точки
                // 3. Або різка зміна швидкості >= 30 км/год (маневр/розгін)
                // 4. Або минуло понад 30 секунд без нових точок (контрольний чекпоінт)
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
                    // Захист від надмірного розростання понад 1000 точок
                    if self.trajectory.len() > 1000 {
                        self.trajectory.drain(0..100);
                    }
                }
                // На прямих відрізках між фіксованими точками ми НЕ мутуємо self.trajectory.last_mut().
                // Це гарантує, що dist_from_last та time_since_last накопичуються від дійсно зафіксованої
                // опорної точки, а поточні координати цілі оновлюються у self.lat та self.lon нижче.

                self.heading = calculated_heading;
            }
        }

        self.lat = lat;
        self.lon = lon;
        if speed > 0.0 {
            self.speed_kmh = speed;
        }
        self.oblast = oblast;
        self.oblast_id = oblast_id;
        self.last_seen = now;

        if let (Some(rt), Some(rc)) = (raw_type, raw_code) {
            let (cat, meta) = classify_target(rt, rc);
            self.category = cat.to_string();
            self.type_ua = meta.name_ua.to_string();
            self.type_en = meta.name_en.to_string();
            self.ha_icon = meta.ha_icon.to_string();
            self.esp_code = meta.esp_code;
            self.color_hex = meta.color_hex.to_string();
            self.is_drone = meta.is_drone;
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
    pub status: String, // "lost"
    pub lost_ts: f64,
    #[serde(default)]
    pub first_seen: f64,
    #[serde(default)]
    pub trajectory: Vec<TrajectoryPoint>,
}

#[derive(Default)]
pub struct TargetTracker {
    pub tracks: HashMap<String, TargetTrack>,
    pub recent_lost: HashMap<String, LostTargetRecord>,
}

impl TargetTracker {
    pub fn update_batch(
        &mut self,
        incoming_targets: &[RawExtractedTarget],
        detector: &OblastDetector,
        exchange_mgr: Option<&ExchangeLogManager>,
        source: &str,
    ) -> Vec<TargetTrack> {
        let now = now_sec();
        let mut seen_ids = std::collections::HashSet::new();

        for t in incoming_targets {
            seen_ids.insert(&t.id);
            let ob_info = detector.find_location_info(t.lat, t.lon);

            // Автоматична фіксація нерозпізнаних типів цілей у журналі обміну
            let (cat, _meta) = classify_target(&t.raw_name, t.raw_type_code);
            if cat == "unknown" && (!t.raw_name.is_empty() || t.raw_type_code != 0) {
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

            if let Some(trk) = self.tracks.get_mut(&t.id) {
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
                        Some(&t.raw_name),
                        Some(t.raw_type_code),
                    );
                } else if eff_speed > 0.0 {
                    trk.speed_kmh = eff_speed;
                }

                if let Some(c) = t.confidence {
                    trk.confidence = Some(c);
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
                );
                if !t.trail_points.is_empty() {
                    trk = trk.with_trail(&t.trail_points, now as i64);
                }
                if let Some(c) = t.confidence {
                    trk.confidence = Some(c);
                }
                self.tracks.insert(t.id.clone(), trk);
            }
        }

        // Перевірка застарілих треків (> 40 сек) -> фіксація як status: "lost"
        let mut expired_ids = Vec::new();
        for (id, trk) in &self.tracks {
            if !seen_ids.contains(id) && (now - trk.last_seen) > 40.0 {
                expired_ids.push(id.clone());
            }
        }

        let mut lost_tracks = Vec::new();
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
                        lost_ts: now,
                        first_seen: trk.first_seen,
                        trajectory: trk.trajectory.clone(),
                    },
                );
                lost_tracks.push(trk);
            }
        }

        // Автоматичне очищення міток втрачених цілей, старших за 120 секунд (2 хв)
        self.recent_lost.retain(|_, v| (now - v.lost_ts) <= 120.0);
        lost_tracks
    }

    /// Періодичне очищення застарілих цілей без оновлення від upstream
    pub fn has_stale_or_expired(&self, now: f64) -> bool {
        self.tracks.values().any(|trk| (now - trk.last_seen) > 180.0)
            || self.recent_lost.values().any(|v| (now - v.lost_ts) > 120.0)
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
                        lost_ts: now,
                        first_seen: trk.first_seen,
                        trajectory: trk.trajectory.clone(),
                    },
                );
                expired_tracks.push(trk);
            }
        }
        self.recent_lost.retain(|_, v| (now - v.lost_ts) <= 120.0);
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
    pub update_seq: u64,
    pub upstream_provider: String,
    pub alert_reasons: Vec<String>,
}

impl Default for ThreatState {
    fn default() -> Self {
        Self {
            tracker: TargetTracker::default(),
            official_alerts: HashMap::new(),
            oblast_alerts: HashMap::new(),
            raion_alerts: HashMap::new(),
            mig_active: false,
            last_update_ts: now_sec(),
            last_targets_update_ts: now_sec(),
            last_primary_targets_ts: now_sec(),
            last_ws_targets_ts: 0.0,
            last_alerts_update_ts: now_sec(),
            update_seq: 1,
            upstream_provider: "Centrifugo (ws.ukrainealarm.com)".to_string(),
            alert_reasons: Vec::new(),
        }
    }
}

impl ThreatState {
    #[allow(dead_code)]
    pub fn get_etag(&self) -> String {
        format!("W/\"seq-{}\"", self.update_seq)
    }

    /// Суворий перерахунок тривог: колір визначається виключно сиренами
    pub fn recompute_oblast_alerts(&mut self, detector: &OblastDetector) {
        let mut ob_targets: HashMap<String, usize> = HashMap::new();
        let ra_targets: HashMap<String, usize> = HashMap::new();

        for trk in self.tracker.tracks.values() {
            *ob_targets.entry(trk.oblast_id.clone()).or_insert(0) += 1;
        }

        // Області (Rank 1)
        for ob in &detector.regions {
            let ob_id = &ob.id;
            let official = self.official_alerts.get(ob_id);

            let (has_alert, color, alert_type) = if let Some(off) = official {
                (off.alert, off.color.clone(), off.alert_type.clone())
            } else {
                (false, "none".to_string(), "none".to_string())
            };

            let count = ob_targets.get(ob_id).copied().unwrap_or(0);

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

        // Синхронізація анклаву Києва: якщо Київська область (14) "red", Київ (31) успадковує "red"
        if let Some(kyiv_ob) = self.oblast_alerts.get("14") {
            if kyiv_ob.color == "red" {
                if let Some(kyiv_city) = self.oblast_alerts.get_mut("31") {
                    kyiv_city.alert = true;
                    kyiv_city.color = "red".to_string();
                    if kyiv_city.alert_type == "none" {
                        kyiv_city.alert_type = "missile".to_string();
                    }
                }
            }
        }

        // Райони (Rank 2)
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
            if let Some(p_ob) = parent_ob {
                if p_ob.color == "red" {
                    has_alert = true;
                    color = "red".to_string();
                    alert_type = p_ob.alert_type.clone();
                }
            }

            let count = ra_targets.get(ra_id).copied().unwrap_or(0);

            self.raion_alerts.insert(
                ra_id.clone(),
                RaionAlertState {
                    id: ra_id.clone(),
                    name: ra.name.clone(),
                    oblast_id: ra.oblast_id.clone(),
                    alert: has_alert,
                    color,
                    alert_type,
                    targets_count: count,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_state_primary_targets_ts() {
        let st = ThreatState::default();
        assert!(st.last_primary_targets_ts > 0.0);
        assert!(st.last_targets_update_ts > 0.0);
        assert_eq!(st.official_alerts.len(), 0);
    }

    #[test]
    fn test_cleanup_stale_returns_tracks() {
        let mut tracker = TargetTracker::default();
        let trk = TargetTrack::new(
            "test_1".to_string(),
            "shahed".to_string(),
            1,
            50.0,
            30.0,
            90.0,
            185.0,
            "Київська".to_string(),
            "14".to_string(),
        );
        tracker.tracks.insert("test_1".to_string(), trk);
        let future_now = now_sec() + 200.0;
        assert!(tracker.has_stale_or_expired(future_now));
        let lost = tracker.cleanup_stale(future_now);
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].id, "test_1");
        assert_eq!(tracker.tracks.len(), 0);
        assert_eq!(tracker.recent_lost.len(), 1);
    }

    #[test]
    fn test_target_jump_resets_trajectory() {
        let mut trk = TargetTrack::new(
            "tgt_teleport".to_string(),
            "shahed".to_string(),
            1,
            50.0,
            30.0,
            90.0,
            185.0,
            "Київська".to_string(),
            "14".to_string(),
        );
        assert_eq!(trk.trajectory.len(), 1);

        // Нормальний невеликий рух (1 км)
        trk.update(50.01, 30.01, 45.0, 185.0, "Київська".to_string(), "14".to_string(), None, None);
        assert!(trk.trajectory.len() >= 1);

        // Аномальний стрибок на 300 км (наприклад у Суми або Львів)
        trk.update(52.5, 34.0, 90.0, 185.0, "Сумська".to_string(), "18".to_string(), None, None);
        // Захист від телепортації повинен очистити старі точки і не креслити павутиння
        assert_eq!(trk.trajectory.len(), 1);
        assert_eq!(trk.trajectory[0].lat, 52.5);
        assert_eq!(trk.trajectory[0].lon, 34.0);
    }


    #[test]
    fn test_trajectory_accumulation_straight_flight() {
        let mut trk = TargetTrack::new(
            "straight_drone".to_string(),
            "shahed".to_string(),
            8,
            50.0,
            30.0,
            90.0,
            185.0,
            "Київська".to_string(),
            "14".to_string(),
        );
        assert_eq!(trk.trajectory.len(), 1);

        // Рух мікро-кроками по 150 метрів (~0.002 градуса довготи на 50° пн. ш.)
        // Раніше баг затирав верхівку і за 30 км залишалося лише 1-2 точки!
        for i in 1..=30 {
            let lon_offset = (i as f64) * 0.002;
            trk.update(50.0, 30.0 + lon_offset, 90.0, 185.0, "Київська".to_string(), "14".to_string(), None, None);
        }
        // Загальна дистанція ~4.3 км (понад 1.5 км двічі)
        // Траєкторія обов'язково повинна містити збережені проміжні точки!
        assert!(trk.trajectory.len() >= 3, "Trajectory should accumulate intermediate points, got {}", trk.trajectory.len());
    }

    #[test]
    fn test_missile_speed_does_not_clear_trajectory() {
        let mut trk = TargetTrack::new(
            "kalibr".to_string(),
            "missile".to_string(),
            3,
            48.0,
            31.0,
            0.0,
            850.0,
            "Миколаївська".to_string(),
            "12".to_string(),
        );
        trk.update(48.05, 31.0, 0.0, 850.0, "Миколаївська".to_string(), "12".to_string(), None, None);
        assert_eq!(trk.trajectory.len(), 2);

        // Зсув ракети на 80 км (наприклад, пауза апстріму або політ за 5 хвилин)
        // 80 км / 111.0 = ~0.72 градуса
        trk.update(48.77, 31.0, 0.0, 850.0, "Кіровоградська".to_string(), "10".to_string(), None, None);
        // Не повинно очищати траєкторію (80 км < 350 км)!
        assert_eq!(trk.trajectory.len(), 3, "Trajectory must retain history for fast cruise missiles");
    }
}
