use std::collections::{HashSet, VecDeque};
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
    color_hex: "#FFE600",
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
    color_hex: "#00F0FF",
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
    color_hex: "#FF2D55",
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
    color_hex: "#FF003C",
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
    color_hex: "#FF9500",
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
    color_hex: "#FF007A",
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
    color_hex: "#B388FF",
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
    color_hex: "#CF9B6D",
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
    color_hex: "#FF3B30",
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
    color_hex: "#34E7E4",
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
    color_hex: "#FF453A",
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
    color_hex: "#80959E",
    default_speed_kmh: 200.0,
    default_speed: 200.0,
    is_drone: true,
    threat_level: "unknown",
};

/// Класифікація цілей за принципом Semantic-First (текстова назва має вищий пріоритет над кодом)
pub fn classify_target(raw_str: &str, raw_code: i64) -> (&'static str, &'static ThreatMeta) {
    let lower = raw_str.trim().to_lowercase();

    // =========================================================================
    // ФАЗА 1: СЕМАНТИЧНИЙ АНАЛІЗ ЗА НАЗВОЮ ДОТИЧНО ДО ДОВІДНИКА (Semantic-First)
    // Якщо назва містить осмислені ключові слова, вона однозначно визначає тип,
    // запобігаючи спотворенню цілей через неочікувані або змінені коди першоджерел.
    // =========================================================================
    if !lower.is_empty() && lower != "ціль" && lower != "повітряна ціль" && lower != "об'єкт" && lower != "target" && lower != "unknown" {
        // 1. Реактивний шахед (shahed_jet)
        if lower.contains("jet") || lower.contains("238") || lower.contains("реактив") || lower.contains("shahedjet") {
            return ("shahed_jet", &THREAT_SHAHED_JET);
        }

        // 2. Балістика (ballistic)
        if lower.contains("баліст") || lower.contains("ballistic") || lower.contains("іскандер-м")
            || lower.contains("кинджал") || lower.contains("кінжал") || lower.contains("с-300")
            || lower.contains("с-400") || lower.contains("kn-23")
        {
            return ("ballistic", &THREAT_BALLISTIC);
        }

        // 3. Крилата або керована авіаційна ракета (missile)
        if lower.contains("х-101") || lower.contains("калібр") || lower.contains("х-555")
            || lower.contains("х-55") || lower.contains("х-59") || lower.contains("х-69")
            || lower.contains("х-22") || lower.contains("х-32") || lower.contains("циркон")
            || lower.contains("онікс") || lower.contains("ракета") || lower.contains("missile")
            || lower.contains("крилат")
        {
            return ("missile", &THREAT_MISSILE);
        }

        // 4. КАБ / УАБ (kab)
        if lower.contains("каб") || lower.contains("уаб") || lower.contains("авіабомб")
            || lower.contains("бомб") || lower.contains("airbomb") || lower.contains("плануюч")
        {
            return ("kab", &THREAT_KAB);
        }

        // 5. Ланцет / баражуючий боєприпас (lancet)
        if lower.contains("ланцет") || lower.contains("lancet") || lower.contains("куб") {
            return ("lancet", &THREAT_LANCET);
        }

        // 6. FPV-дрон / Молнія (fpv)
        if lower.contains("fpv") || lower.contains("молнія") || lower.contains("молния") {
            return ("fpv", &THREAT_FPV);
        }

        // 7. Розвідувальний БпЛА (recon)
        if lower.contains("розвід") || lower.contains("recon") || lower.contains("zala")
            || lower.contains("зала") || lower.contains("supercam") || lower.contains("суперкам")
            || lower.contains("орлан") || lower.contains("orlan") || lower.contains("mohajer")
        {
            return ("recon", &THREAT_RECON);
        }

        // 8. Ворожа авіація (aviation)
        if lower.contains("авіа") || lower.contains("літак") || lower.contains("plane")
            || lower.contains("винищувач") || lower.contains("бомбардувальник")
            || lower.contains("су-34") || lower.contains("су-35") || lower.contains("ту-95")
            || lower.contains("ту-22") || lower.contains("міг-31")
        {
            return ("aviation", &THREAT_AVIATION);
        }

        // 9. Артилерія / РСЗВ (artillery)
        if lower.contains("артилер") || lower.contains("рсзв") || lower.contains("обстріл")
            || lower.contains("град") || lower.contains("ураган") || lower.contains("смерч")
        {
            return ("artillery", &THREAT_ARTILLERY);
        }

        // 10. Бандероль / фальш-ціль (banderol)
        if lower.contains("бандерол") || lower.contains("decoy") || lower.contains("фальш")
            || lower.contains("пароді") || lower.contains("приманка")
        {
            return ("banderol", &THREAT_BANDEROL);
        }

        // 11. Поршневий або mesh-дрон Shahed / Герань (shahed)
        if raw_code == 1 || raw_code == 8 || raw_code == 11
            || lower.contains("шахед") || lower.contains("shahed") || lower.contains("геран")
            || lower.contains("136") || lower.contains("дрон-камікадзе") || lower.contains("гербера")
            || lower.contains("бпла") || lower.contains("дрон") || lower.contains("mesh")
            || lower.contains("удар") || lower.contains("мопед")
        {
            return ("shahed", &THREAT_SHAHED);
        }
    }

    // =========================================================================
    // ФАЗА 2: СТРАХОВКА ЗА ЧИСЛОВИМ КОДОМ (Fallback by Raw Code)
    // Використовується, якщо назва цілі відсутня, порожня або є суто загальною
    // ("Ціль", "Об'єкт"), забезпечуючи надійність радарних засічок та API Neptun.
    // =========================================================================
    match raw_code {
        // Реактивний дрон
        2 => ("shahed_jet", &THREAT_SHAHED_JET),
        // Балістика
        12 | 112 => ("ballistic", &THREAT_BALLISTIC),
        // Крилата ракета
        3 | 100..=107 => ("missile", &THREAT_MISSILE),
        // КАБ / УАБ
        5 => ("kab", &THREAT_KAB),
        // Бандероль / приманка
        4 => ("banderol", &THREAT_BANDEROL),
        // Ланцет
        80 => ("lancet", &THREAT_LANCET),
        // FPV
        7 | 17 => ("fpv", &THREAT_FPV),
        // Розвідник
        6 | 16 => ("recon", &THREAT_RECON),
        // Авіація
        9 | 19 => ("aviation", &THREAT_AVIATION),
        // Артилерія
        10 => ("artillery", &THREAT_ARTILLERY),
        // Поршневий шахед (включаючи канонічний код 1)
        1 | 8 | 11 => ("shahed", &THREAT_SHAHED),
        // =====================================================================
        // ФАЗА 3: НЕВІДОМИЙ ОБ'ЄКТ
        // =====================================================================
        _ => ("unknown", &THREAT_UNKNOWN),
    }
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
    known_keys: RwLock<HashSet<String>>,
}

impl ExchangeLogManager {
    pub fn new(data_dir: &Path) -> Self {
        let log_file_path = data_dir.join("unmapped_exchange.log");
        Self {
            log_file_path,
            recent_entries: RwLock::new(VecDeque::with_capacity(300)),
            unmapped_threats_count: RwLock::new(0),
            unmapped_regions_count: RwLock::new(0),
            known_keys: RwLock::new(HashSet::new()),
        }
    }

    pub fn record_unmapped(
        &self,
        log_type: &str,
        raw_id: &str,
        raw_code: Option<i64>,
        mapped_as: &str,
        source: &str,
        details: Option<&str>,
    ) {
        let norm_id: String = raw_id.trim().chars().take(64).collect::<String>().to_lowercase();
        let key = format!("{}:{}:{:?}", log_type, norm_id, raw_code);
        if self.known_keys.read().contains(&key) {
            return;
        }
        {
            let mut known = self.known_keys.write();
            if known.len() >= 2048 {
                known.clear();
            }
            if !known.insert(key) {
                return;
            }
        }

        let now = Utc::now().timestamp();
        let effective_raw_id = if raw_id.trim().is_empty() {
            if let Some(c) = raw_code {
                format!("code_{}", c)
            } else {
                "unknown".to_string()
            }
        } else if raw_id.len() > 256 {
            let truncated: String = raw_id.trim().chars().take(256).collect();
            format!("{}... [len={}]", truncated, raw_id.len())
        } else {
            raw_id.trim().to_string()
        };

        let detail_str = details
            .map(|s| s.to_string())
            .unwrap_or_else(|| match log_type {
                "threat" | "threat_type" => {
                    format!("Невідомий тип цілі raw='{}', код={:?} -> інтерпретовано як '{}'", effective_raw_id, raw_code, mapped_as)
                }
                "region" => {
                    format!("Регіон '{}' не знайдено в канонічному переліку 26 областей / 136 районів", effective_raw_id)
                }
                "protocol" => {
                    format!("Непідтримуваний протокол/префікс пакета: '{}'", effective_raw_id)
                }
                _ => format!("Нерозпізнане значення: '{}' -> '{}'", effective_raw_id, mapped_as),
            });

        let entry = ExchangeLogEntry {
            timestamp: now,
            log_type: log_type.to_string(),
            raw_identifier: effective_raw_id.clone(),
            raw_code,
            mapped_as: mapped_as.to_string(),
            source: source.to_string(),
            details: Some(detail_str.clone()),
        };

        if log_type == "threat" || log_type == "threat_type" {
            let mut count = self.unmapped_threats_count.write();
            *count += 1;
        } else if log_type == "region" || log_type == "alert" {
            let mut count = self.unmapped_regions_count.write();
            *count += 1;
        }

        // Запис у файл
        let line = format!(
            "[{}] [{}] [{}] ID='{}' CODE={:?} MAPPED='{}' | {}\n",
            Utc::now().to_rfc3339(), source, log_type, effective_raw_id, raw_code, mapped_as, detail_str
        );
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.log_file_path) {
            let _ = f.write_all(line.as_bytes());
        }

        // Оновлення кільцевого буфера в оперативній пам'яті (макс 300, найновіші на початку)
        let mut entries = self.recent_entries.write();
        if entries.len() >= 300 {
            entries.pop_back();
        }
        entries.push_front(entry);
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
        self.known_keys.write().clear();
        self.recent_entries.write().clear();
        let _ = File::create(&self.log_file_path);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertMeta {
    pub category: &'static str,
    pub name_ua: &'static str,
    pub name_en: &'static str,
    pub color: &'static str,
    pub description: &'static str,
}

pub static ALERT_MISSILE: AlertMeta = AlertMeta {
    category: "missile",
    name_ua: "Повітряна тривога (Ракетна небезпека)",
    name_en: "Air Alert (Missile danger)",
    color: "red",
    description: "Повна повітряна тривога / ракетна загроза (UkraineAlarm AIR / Neptun red)",
};

pub static ALERT_DRONE: AlertMeta = AlertMeta {
    category: "drone",
    name_ua: "Підвищена небезпека (БпЛА / Шахед)",
    name_en: "Heightened Alert (UAV / Shahed)",
    color: "yellow",
    description: "Підвищена загроза застосування ударних БпЛА / локальна небезпека (Neptun yellow)",
};

pub static ALERT_ARTILLERY: AlertMeta = AlertMeta {
    category: "artillery",
    name_ua: "Артилерійський обстріл / РСЗВ",
    name_en: "Artillery / MLRS Danger",
    color: "red",
    description: "Загроза артилерійського обстрілу або РСЗВ (UkraineAlarm ARTILLERY)",
};

pub static ALERT_CLEAR: AlertMeta = AlertMeta {
    category: "none",
    name_ua: "Відбій тривоги",
    name_en: "All Clear",
    color: "none",
    description: "Відбій загрози для регіону",
};

pub fn classify_neptun_alert(level: &str) -> (&'static str, &'static str, &'static AlertMeta) {
    match level.trim().to_lowercase().as_str() {
        "red" => ("missile", "red", &ALERT_MISSILE),
        "yellow" => ("drone", "yellow", &ALERT_DRONE),
        _ => ("none", "none", &ALERT_CLEAR),
    }
}

pub fn classify_official_alert(alert_type: &str, level: Option<&str>) -> (&'static str, &'static str, &'static AlertMeta) {
    let t = alert_type.trim().to_uppercase();
    if t == "ARTILLERY" {
        ("artillery", "red", &ALERT_ARTILLERY)
    } else if t == "AIR" || t == "MISSILE" {
        if let Some(lvl) = level {
            if lvl.eq_ignore_ascii_case("yellow") || lvl.eq_ignore_ascii_case("community") {
                return ("drone", "yellow", &ALERT_DRONE);
            }
        }
        ("missile", "red", &ALERT_MISSILE)
    } else if t == "CHEMICAL" || t == "NUCLEAR" || t == "URBAN_FIGHTS" {
        ("missile", "red", &ALERT_MISSILE)
    } else {
        ("none", "none", &ALERT_CLEAR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_target_semantic_first() {
        let (cat1, meta1) = classify_target("Шахед-136 курсом на Полтаву", 0);
        assert_eq!(cat1, "shahed");
        assert_eq!(meta1.color_hex, "#FFE600");

        let (cat2, meta2) = classify_target("Реактивний шахед Shahed-238", 0);
        assert_eq!(cat2, "shahed_jet");
        assert_eq!(meta2.color_hex, "#00F0FF");

        let (cat3, meta3) = classify_target("Загроза балістики (Іскандер-М)", 0);
        assert_eq!(cat3, "ballistic");
        assert_eq!(meta3.color_hex, "#FF003C");

        let (cat4, meta4) = classify_target("Крилата ракета Х-101 / Калібр", 0);
        assert_eq!(cat4, "missile");
        assert_eq!(meta4.color_hex, "#FF2D55");

        let (cat5, meta5) = classify_target("Скидання КАБ / керованих авіабомб", 0);
        assert_eq!(cat5, "kab");
        assert_eq!(meta5.color_hex, "#FF9500");

        let (cat6, meta6) = classify_target("БпЛА Ланцет у зоні ураження", 0);
        assert_eq!(cat6, "lancet");
        assert_eq!(meta6.color_hex, "#FF007A");

        let (cat7, meta7) = classify_target("Розвідник Zala / Supercam", 0);
        assert_eq!(cat7, "recon");
        assert_eq!(meta7.color_hex, "#B388FF");
    }

    #[test]
    fn test_classify_target_raw_code_fallback() {
        // Коли текстова назва відсутня або загальна ("ціль")
        let (cat1, _) = classify_target("Ціль", 1);
        assert_eq!(cat1, "shahed");

        let (cat2, _) = classify_target("", 2);
        assert_eq!(cat2, "shahed_jet");

        let (cat3, _) = classify_target("Повітряна ціль", 3);
        assert_eq!(cat3, "missile");

        let (cat4, _) = classify_target("unknown", 12);
        assert_eq!(cat4, "ballistic");

        let (cat5, _) = classify_target("", 5);
        assert_eq!(cat5, "kab");

        let (cat6, _) = classify_target("", 99999);
        assert_eq!(cat6, "unknown");
    }

    #[test]
    fn test_classify_official_and_neptun_alerts() {
        let (cat1, col1, _) = classify_official_alert("AIR", None);
        assert_eq!(cat1, "missile");
        assert_eq!(col1, "red");

        let (cat2, col2, _) = classify_official_alert("AIR", Some("yellow"));
        assert_eq!(cat2, "drone");
        assert_eq!(col2, "yellow");

        let (cat3, col3, _) = classify_official_alert("ARTILLERY", None);
        assert_eq!(cat3, "artillery");
        assert_eq!(col3, "red");

        let (cat4, col4, _) = classify_neptun_alert("red");
        assert_eq!(cat4, "missile");
        assert_eq!(col4, "red");

        let (cat5, col5, _) = classify_neptun_alert("yellow");
        assert_eq!(cat5, "drone");
        assert_eq!(col5, "yellow");

        let (cat6, col6, _) = classify_neptun_alert("none");
        assert_eq!(cat6, "none");
        assert_eq!(col6, "none");
    }
}
