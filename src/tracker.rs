use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

use crate::canonical_registry::classify_target;
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
        raw_type: Option<&str>,
        raw_code: Option<i64>,
    ) {
        let now = now_sec();
        if let Some(last_pt) = self.trajectory.last() {
            let dist_from_last = calculate_haversine_distance(last_pt.lat, last_pt.lon, lat, lon);

            // Динамічний розрахунок істинного курсу при зміщенні > 0.2 км
            if dist_from_last > 0.2 {
                self.heading = calculate_bearing(last_pt.lat, last_pt.lon, lat, lon);
            } else if heading > 0.0 {
                self.heading = heading;
            }

            // Додавання нової точки треку: зміщення > 0.3 км або минуло >= 10 сек
            // Зберігаємо повну траєкторію польоту цілі до моменту її зникнення
            if dist_from_last > 0.3 || (now as i64 - last_pt.ts) >= 10 {
                self.trajectory.push(TrajectoryPoint {
                    lat,
                    lon,
                    ts: now as i64,
                });
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
    pub fn update_batch(&mut self, incoming_targets: &[RawExtractedTarget], detector: &OblastDetector) -> Vec<TargetTrack> {
        let now = now_sec();
        let mut seen_ids = std::collections::HashSet::new();

        for t in incoming_targets {
            seen_ids.insert(&t.id);
            let ob_info = detector.find_location_info(t.lat, t.lon);

            if let Some(trk) = self.tracks.get_mut(&t.id) {
                trk.update(
                    t.lat,
                    t.lon,
                    t.heading_deg,
                    0.0,
                    ob_info.name,
                    ob_info.id,
                    Some(&t.raw_name),
                    Some(t.raw_type_code),
                );
            } else {
                let trk = TargetTrack::new(
                    t.id.clone(),
                    t.raw_name.clone(),
                    t.raw_type_code,
                    t.lat,
                    t.lon,
                    t.heading_deg,
                    0.0,
                    ob_info.name,
                    ob_info.id,
                );
                self.tracks.insert(t.id.clone(), trk);
            }
        }

        // Перевірка застарілих треків (> 25 сек) -> фіксація як status: "lost"
        let mut expired_ids = Vec::new();
        for (id, trk) in &self.tracks {
            if !seen_ids.contains(id) && (now - trk.last_seen) > 25.0 {
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
            last_alerts_update_ts: now_sec(),
            update_seq: 1,
            upstream_provider: "Centrifugo (ws.ukrainealarm.com)".to_string(),
            alert_reasons: Vec::new(),
        }
    }
}

impl ThreatState {
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
