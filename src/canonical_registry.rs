use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMeta {
    pub category: &'static str,
    pub code: i64,
    pub esp_code: u8,
    pub name_ua: &'static str,
    pub name_en: &'static str,
    pub description: &'static str,
    pub ha_icon: &'static str,
    pub svg_icon: &'static str,
    pub color_hex: &'static str,
    pub default_speed_kmh: f64,
    pub default_speed: f64,
    pub is_drone: bool,
    pub threat_level: &'static str,
}

pub static THREAT_SHAHED: ThreatMeta = ThreatMeta {
    category: "shahed",
    code: 1,
    esp_code: 1,
    name_ua: "Шахед",
    name_en: "Shahed-136",
    description: "Ударний БпЛА Shahed-136 / Герань-2",
    ha_icon: "mdi:navigation-variant",
    svg_icon: "ic_shahed.svg",
    color_hex: "#FACC15",
    default_speed_kmh: 185.0,
    default_speed: 185.0,
    is_drone: true,
    threat_level: "medium",
};

pub static THREAT_SHAHED_JET: ThreatMeta = ThreatMeta {
    category: "shahed_jet",
    code: 2,
    esp_code: 2,
    name_ua: "Реактивний шахед",
    name_en: "Jet-powered Shahed",
    description: "Швидкісний реактивний Shahed-238 / Jet UAV",
    ha_icon: "mdi:rocket-outline",
    svg_icon: "ic_shahed_jet.svg",
    color_hex: "#00E5FF",
    default_speed_kmh: 420.0,
    default_speed: 420.0,
    is_drone: true,
    threat_level: "high",
};

pub static THREAT_MISSILE: ThreatMeta = ThreatMeta {
    category: "missile",
    code: 3,
    esp_code: 3,
    name_ua: "Ракета",
    name_en: "Cruise / Guided Missile",
    description: "Крилата або керована авіаційна ракета (Х-101, Калібр, Х-59/69)",
    ha_icon: "mdi:rocket",
    svg_icon: "ic_missile.svg",
    color_hex: "#EF4444",
    default_speed_kmh: 850.0,
    default_speed: 850.0,
    is_drone: false,
    threat_level: "critical",
};

pub static THREAT_BALLISTIC: ThreatMeta = ThreatMeta {
    category: "ballistic",
    code: 12,
    esp_code: 12,
    name_ua: "Балістична ракета",
    name_en: "Ballistic Missile",
    description: "Надзвукова балістична або аеробалістична ракета (Іскандер-М, Кинджал, С-300/400)",
    ha_icon: "mdi:rocket-launch",
    svg_icon: "ic_missile.svg",
    color_hex: "#DC2626",
    default_speed_kmh: 3600.0,
    default_speed: 3600.0,
    is_drone: false,
    threat_level: "critical",
};

pub static THREAT_KAB: ThreatMeta = ThreatMeta {
    category: "kab",
    code: 5,
    esp_code: 5,
    name_ua: "КАБ / УАБ",
    name_en: "Guided Aerial Bomb",
    description: "Керована плануюча авіабомба з модулем УМПК",
    ha_icon: "mdi:bomb",
    svg_icon: "ic_airbomb.svg",
    color_hex: "#FB923C",
    default_speed_kmh: 750.0,
    default_speed: 750.0,
    is_drone: false,
    threat_level: "high",
};

pub static THREAT_LANCET: ThreatMeta = ThreatMeta {
    category: "lancet",
    code: 8,
    esp_code: 8,
    name_ua: "Ланцет",
    name_en: "Lancet loitering munition",
    description: "Баражуючий боєприпас Ланцет / Куб",
    ha_icon: "mdi:navigation-variant-outline",
    svg_icon: "ic_lancet.svg",
    color_hex: "#F43F5E",
    default_speed_kmh: 110.0,
    default_speed: 110.0,
    is_drone: true,
    threat_level: "medium",
};

pub static THREAT_RECON: ThreatMeta = ThreatMeta {
    category: "recon",
    code: 6,
    esp_code: 6,
    name_ua: "Розвідник",
    name_en: "Reconnaissance UAV",
    description: "Розвідувальний тактичний БпЛА (Zala, Supercam, Орлан-10, Mohajer)",
    ha_icon: "mdi:crosshairs-gps",
    svg_icon: "ic_recon.svg",
    color_hex: "#A855F7",
    default_speed_kmh: 130.0,
    default_speed: 130.0,
    is_drone: true,
    threat_level: "low",
};

pub static THREAT_FPV: ThreatMeta = ThreatMeta {
    category: "fpv",
    code: 7,
    esp_code: 7,
    name_ua: "FPV-дрон",
    name_en: "FPV / Molniya strike drone",
    description: "Ударний FPV-дрон або крило Молнія в прифронтовій смузі",
    ha_icon: "mdi:quadcopter",
    svg_icon: "ic_fpv.svg",
    color_hex: "#EAB308",
    default_speed_kmh: 120.0,
    default_speed: 120.0,
    is_drone: true,
    threat_level: "medium",
};

pub static THREAT_AVIATION: ThreatMeta = ThreatMeta {
    category: "aviation",
    code: 9,
    esp_code: 9,
    name_ua: "Авіація",
    name_en: "Tactical Aviation",
    description: "Тактична / стратегічна ворожа авіація (Су-34, Су-35, Ту-95, МіГ-31К)",
    ha_icon: "mdi:airplane-alert",
    svg_icon: "ic_air_threat_combined_white.svg",
    color_hex: "#E11D48",
    default_speed_kmh: 750.0,
    default_speed: 750.0,
    is_drone: false,
    threat_level: "high",
};

pub static THREAT_BANDEROL: ThreatMeta = ThreatMeta {
    category: "banderol",
    code: 4,
    esp_code: 4,
    name_ua: "Бандероль",
    name_en: "Banderol Decoy",
    description: "Фальш-ціль / приманка / пародія",
    ha_icon: "mdi:paper-plane-outline",
    svg_icon: "ic_banderol.svg",
    color_hex: "#A7F3D0",
    default_speed_kmh: 150.0,
    default_speed: 150.0,
    is_drone: true,
    threat_level: "low",
};

pub static THREAT_ARTILLERY: ThreatMeta = ThreatMeta {
    category: "artillery",
    code: 10,
    esp_code: 10,
    name_ua: "Артилерія / РСЗВ",
    name_en: "Artillery / MLRS",
    description: "Загроза артилерійського обстрілу або залпу РСЗВ",
    ha_icon: "mdi:ammunition",
    svg_icon: "ic_airbomb.svg",
    color_hex: "#DC2626",
    default_speed_kmh: 0.0,
    default_speed: 0.0,
    is_drone: false,
    threat_level: "critical",
};

pub static THREAT_UNKNOWN: ThreatMeta = ThreatMeta {
    category: "unknown",
    code: 0,
    esp_code: 0,
    name_ua: "Неідентифікована ціль",
    name_en: "Unidentified Target",
    description: "Повітряний об'єкт, тип якого ще уточнюється засобами РЕР / ППО",
    ha_icon: "mdi:help-rhombus",
    svg_icon: "ic_air_threat_combined_white.svg",
    color_hex: "#94A3B8",
    default_speed_kmh: 200.0,
    default_speed: 200.0,
    is_drone: true,
    threat_level: "unknown",
};

/// Класифікація цілей зі строгим пріоритетом вирішення
pub fn classify_target(raw_str: &str, raw_code: i64) -> (&'static str, &'static ThreatMeta) {
    let lower = raw_str.to_lowercase();

    // 1. Реактивний шахед (shahed_jet)
    if raw_code == 2 || lower.contains("jet") || lower.contains("238") || lower.contains("реактив") {
        return ("shahed_jet", &THREAT_SHAHED_JET);
    }

    // 2. Бандероль / фальш-ціль (banderol)
    if raw_code == 4 || lower.contains("бандерол") || lower.contains("decoy") || lower.contains("фальш") || lower.contains("пароді") {
        return ("banderol", &THREAT_BANDEROL);
    }

    // 3. Ланцет (lancet)
    if raw_code == 80 || lower.contains("ланцет") || lower.contains("lancet") || lower.contains("куб") {
        return ("lancet", &THREAT_LANCET);
    }

    // 4. Балістика (ballistic)
    if raw_code == 12 || raw_code == 112 || lower.contains("баліст") || lower.contains("ballistic") || lower.contains("іскандер-м") || lower.contains("кинджал") || lower.contains("с-300") || lower.contains("с-400") || lower.contains("kn-23") {
        return ("ballistic", &THREAT_BALLISTIC);
    }

    // 5. Крилата ракета (missile)
    if [3, 100, 101, 102, 103, 104, 105, 106, 107].contains(&raw_code)
        || lower.contains("ракета") || lower.contains("missile") || lower.contains("х-101") || lower.contains("калібр") || lower.contains("х-59") || lower.contains("х-69") || lower.contains("х-22") || lower.contains("х-32") || lower.contains("циркон") || lower.contains("онікс") {
        return ("missile", &THREAT_MISSILE);
    }

    // 6. КАБ / УАБ (kab)
    if raw_code == 5 || lower.contains("каб") || lower.contains("уаб") || lower.contains("бомб") || lower.contains("airbomb") {
        return ("kab", &THREAT_KAB);
    }

    // 7. FPV-дрон / Молнія (fpv)
    if raw_code == 7 || raw_code == 17 || lower.contains("fpv") || lower.contains("молнія") || lower.contains("молния") {
        return ("fpv", &THREAT_FPV);
    }

    // 8. Розвідник (recon)
    if raw_code == 6 || raw_code == 16 || lower.contains("розвід") || lower.contains("recon") || lower.contains("zala") || lower.contains("supercam") || lower.contains("орлан") || lower.contains("mohajer") {
        return ("recon", &THREAT_RECON);
    }

    // 9. Авіація (aviation)
    if raw_code == 9 || raw_code == 19 || lower.contains("авіа") || lower.contains("літак") || lower.contains("су-34") || lower.contains("су-35") || lower.contains("ту-95") || lower.contains("міг-31") {
        return ("aviation", &THREAT_AVIATION);
    }

    // 10. Артилерія / РСЗВ (artillery)
    if raw_code == 10 || lower.contains("артилер") || lower.contains("рсзв") || lower.contains("обстріл") || lower.contains("град") || lower.contains("ураган") || lower.contains("смерч") {
        return ("artillery", &THREAT_ARTILLERY);
    }

    // 11. Поршневий шахед (shahed)
    if raw_code == 8 || raw_code == 11 || lower.contains("шахед") || lower.contains("shahed") || lower.contains("геран") || lower.contains("136") || lower.contains("бпла") || lower.contains("дрон") {
        return ("shahed", &THREAT_SHAHED);
    }

    // 12. Невідома ціль (unknown)
    ("unknown", &THREAT_UNKNOWN)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeLogEntry {
    pub timestamp: i64,
    #[serde(rename = "category", alias = "log_type")]
    pub log_type: String, // "threat" | "region" | "alert"
    #[serde(rename = "raw_value", alias = "raw_identifier")]
    pub raw_identifier: String,
    pub raw_code: Option<i64>,
    pub mapped_as: String,
    pub source: String,
    #[serde(default, alias = "details")]
    pub details: Option<String>,
}

pub struct ExchangeLogManager {
    log_file_path: PathBuf,
    recent_entries: RwLock<VecDeque<ExchangeLogEntry>>,
    unmapped_threats_count: RwLock<u64>,
    unmapped_regions_count: RwLock<u64>,
}

impl ExchangeLogManager {
    pub fn new(data_dir: &Path) -> Self {
        let log_file_path = data_dir.join("unmapped_exchange.log");
        Self {
            log_file_path,
            recent_entries: RwLock::new(VecDeque::with_capacity(300)),
            unmapped_threats_count: RwLock::new(0),
            unmapped_regions_count: RwLock::new(0),
        }
    }

    #[allow(dead_code)]
    pub fn record_unmapped(&self, log_type: &str, raw_id: &str, raw_code: Option<i64>, mapped_as: &str, source: &str) {
        let now = Utc::now().timestamp();
        let entry = ExchangeLogEntry {
            timestamp: now,
            log_type: log_type.to_string(),
            raw_identifier: raw_id.to_string(),
            raw_code,
            mapped_as: mapped_as.to_string(),
            source: source.to_string(),
            details: Some(format!("Mapped as {}", mapped_as)),
        };

        if log_type == "threat" {
            let mut count = self.unmapped_threats_count.write();
            *count += 1;
        } else if log_type == "region" {
            let mut count = self.unmapped_regions_count.write();
            *count += 1;
        }

        // Запис у файл
        let line = format!(
            "[{}] [{}] ID='{}' CODE={:?} MAPPED='{}' SRC='{}'\n",
            now, log_type, raw_id, raw_code, mapped_as, source
        );
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.log_file_path) {
            let _ = f.write_all(line.as_bytes());
        }

        // Оновлення кільцевого буфера в оперативній пам'яті (макс 300)
        let mut entries = self.recent_entries.write();
        if entries.len() >= 300 {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn get_summary(&self) -> serde_json::Value {
        let threats = *self.unmapped_threats_count.read();
        let regions = *self.unmapped_regions_count.read();
        let total = threats + regions;
        let entries = self.recent_entries.read();
        let list: Vec<ExchangeLogEntry> = entries.iter().cloned().collect();

        serde_json::json!({
            "unmapped_total": total,
            "unmapped_threats_count": threats,
            "unmapped_regions_count": regions,
            "recent_entries": list,
            "summary": {
                "total": total,
                "threats": threats,
                "regions": regions,
                "buffer_size": list.len()
            },
            "logs": list
        })
    }

    pub fn clear(&self) {
        *self.unmapped_threats_count.write() = 0;
        *self.unmapped_regions_count.write() = 0;
        self.recent_entries.write().clear();
        let _ = File::create(&self.log_file_path);
    }
}
