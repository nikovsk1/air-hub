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
        raion_id: String,
        raw_type: Option<&str>,
        raw_code: Option<i64>,
    ) {
        let now = now_sec();

        // 1. Дедуплікація виключно за первинними координатами від джерел:
        // Якщо зміщення від останньої реальної засічки < 30 метрів — повторний дублікат відкидається
        let dist_from_current = calculate_haversine_distance(self.lat, self.lon, lat, lon);
        if dist_from_current < 0.03 {
            self.last_seen = now;
            if speed > 0.0 { self.speed_kmh = speed; }
            let last_ts = self.trajectory.last().map(|p| p.ts).unwrap_or(0);
            if (now as i64).saturating_sub(last_ts) >= 30 {
                if self.trajectory.len() >= 200 {
                    self.trajectory.remove(0);
                }
                self.trajectory.push(TrajectoryPoint {
                    lat: self.lat,
                    lon: self.lon,
                    ts: now as i64,
                });
            }
            return;
        }

        if let Some(last_pt) = self.trajectory.last() {
            let dist_from_last = calculate_haversine_distance(last_pt.lat, last_pt.lon, lat, lon);

            // 2. Захист від фізично неможливих стрибків (телепортація > 120 км між пакетами)
            if dist_from_last > 120.0 {
                self.trajectory.clear();
                self.trajectory.push(TrajectoryPoint {
                    lat,
                    lon,
                    ts: now as i64,
                });
                self.heading = if heading > 0.0 { heading } else { self.heading };
            } else {
                let calculated_heading = if heading > 0.0 {
                    heading
                } else if dist_from_last > 0.3 {
                    calculate_bearing(last_pt.lat, last_pt.lon, lat, lon)
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
        self.raion_id = raion_id;
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
        let mut lost_tracks = Vec::new();

        for t in incoming_targets {
            seen_ids.insert(&t.id);

            // Якщо джерело явно сповіщає про втрату / знищення цілі ("lost")
            if t.upstream_status == "lost" {
                if let Some(mut trk) = self.tracks.remove(&t.id) {
                    trk.status = "lost".to_string();
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
                            status: "lost".to_string(),
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

            if let Some(trk) = self.tracks.get_mut(&t.id) {
                if t.upstream_status == "cooldown" {
                    trk.status = "cooldown".to_string();
                    trk.cooldown_start_ts = Some(now);
                } else if t.upstream_status == "active" {
                    trk.status = "active".to_string();
                    trk.cooldown_start_ts = None;
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
                if !t.trail_points.is_empty() {
                    trk = trk.with_trail(&t.trail_points, now as i64);
                }
                if let Some(c) = t.confidence {
                    trk.confidence = Some(c);
                }
                self.tracks.insert(t.id.clone(), trk);
            }
        }

        // Дворівневий життєвий цикл без оновлень від джерела:
        // 1. Якщо ціль у статусі "active" не оновлювалась >= 20 сек -> переводимо в "cooldown"
        // 2. Якщо ціль у статусі "cooldown" не оновлювалась >= 60 сек -> остаточний перехід у "lost"
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
                    if (now - cd_start) >= 60.0 {
                        expired_ids.push(id.clone());
                    }
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
    pub alarms_provider: String,
    pub targets_provider: String,
    pub last_alarms_provider_status: String,
    pub last_targets_provider_status: String,
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
            last_ws_targets_ts: now_sec(),
            last_alerts_update_ts: now_sec(),
            update_seq: 1,
            upstream_provider: "Centrifugo (ws.ukrainealarm.com)".to_string(),
            alarms_provider: "UkraineAlarm (API v3)".to_string(),
            targets_provider: "WS UkraineAlarm".to_string(),
            last_alarms_provider_status: "primary".to_string(),
            last_targets_provider_status: "primary".to_string(),
            alert_reasons: Vec::new(),
        }
    }
}

impl ThreatState {
    /// Суворий перерахунок тривог: колір визначається сиренами та цілями (Red / Yellow)
    pub fn recompute_oblast_alerts(&mut self, detector: &OblastDetector) {
        let mut ob_targets: HashMap<String, usize> = HashMap::new();
        let mut ra_targets: HashMap<String, usize> = HashMap::new();

        for trk in self.tracker.tracks.values() {
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

        // Синхронізація анклаву Києва: якщо Київська область (14) в тривозі ("red" або "yellow"), Київ (31) успадковує статус
        if let Some(kyiv_ob) = self.oblast_alerts.get("14") {
            if kyiv_ob.color == "red" {
                if let Some(kyiv_city) = self.oblast_alerts.get_mut("31") {
                    kyiv_city.alert = true;
                    kyiv_city.color = "red".to_string();
                    if kyiv_city.alert_type == "none" {
                        kyiv_city.alert_type = "missile".to_string();
                    }
                }
            } else if kyiv_ob.color == "yellow" {
                if let Some(kyiv_city) = self.oblast_alerts.get_mut("31") {
                    if kyiv_city.color != "red" {
                        kyiv_city.alert = true;
                        kyiv_city.color = "yellow".to_string();
                        if kyiv_city.alert_type == "none" {
                            kyiv_city.alert_type = "drone".to_string();
                        }
                    }
                }
            }
        }

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
        assert_eq!(track.speed_kmh, 220.0);
    }
}
