use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use rstar::{RTree, RTreeObject, AABB};

#[derive(Clone, Debug, PartialEq)]
pub struct SpatialRegionItem {
    pub id: String,
    pub rank: u8,
    pub envelope: AABB<[f64; 2]>,
}

impl RTreeObject for SpatialRegionItem {
    type Envelope = AABB<[f64; 2]>;
    fn envelope(&self) -> Self::Envelope {
        self.envelope
    }
}

impl rstar::PointDistance for SpatialRegionItem {
    fn distance_2(&self, point: &[f64; 2]) -> f64 {
        self.envelope.distance_2(point)
    }
}

/// Канонічна відповідність 122 районів до 26 областей (державні ID)
pub fn get_canonical_raion_to_oblast() -> &'static HashMap<&'static str, &'static str> {
    static RAION_TO_OBLAST: std::sync::OnceLock<HashMap<&'static str, &'static str>> = std::sync::OnceLock::new();
    RAION_TO_OBLAST.get_or_init(|| {
        let mut m = HashMap::with_capacity(130);
        // Вінницька (4)
        m.insert("32", "4"); m.insert("33", "4"); m.insert("34", "4");
        m.insert("35", "4"); m.insert("36", "4"); m.insert("37", "4");
        // Волинська (8)
        m.insert("38", "8"); m.insert("39", "8"); m.insert("40", "8"); m.insert("41", "8");
        // Дніпропетровська (9)
        m.insert("42", "9"); m.insert("43", "9"); m.insert("44", "9");
        m.insert("45", "9"); m.insert("46", "9"); m.insert("47", "9"); m.insert("48", "9");
        // Донецька (28)
        m.insert("49", "28"); m.insert("50", "28"); m.insert("51", "28"); m.insert("52", "28");
        m.insert("53", "28"); m.insert("54", "28"); m.insert("55", "28"); m.insert("56", "28");
        // Житомирська (10)
        m.insert("57", "10"); m.insert("58", "10"); m.insert("59", "10"); m.insert("60", "10");
        // Закарпатська (11)
        m.insert("61", "11"); m.insert("62", "11"); m.insert("63", "11");
        m.insert("64", "11"); m.insert("65", "11"); m.insert("66", "11");
        // Івано-Франківська (13)
        m.insert("67", "13"); m.insert("68", "13"); m.insert("69", "13");
        m.insert("70", "13"); m.insert("71", "13"); m.insert("72", "13");
        // Київська (14)
        m.insert("73", "14"); m.insert("74", "14"); m.insert("75", "14");
        m.insert("76", "14"); m.insert("77", "14"); m.insert("78", "14"); m.insert("79", "14");
        // Кіровоградська (15)
        m.insert("80", "15"); m.insert("81", "15"); m.insert("82", "15"); m.insert("83", "15");
        // Луганська (16)
        m.insert("84", "16"); m.insert("85", "16"); m.insert("86", "16"); m.insert("87", "16");
        // Львівська (27)
        m.insert("88", "27"); m.insert("89", "27"); m.insert("90", "27"); m.insert("91", "27");
        m.insert("92", "27"); m.insert("93", "27"); m.insert("94", "27");
        // Миколаївська (17)
        m.insert("95", "17"); m.insert("96", "17"); m.insert("97", "17"); m.insert("98", "17");
        // Одеська (18)
        m.insert("99", "18"); m.insert("100", "18"); m.insert("101", "18");
        m.insert("102", "18"); m.insert("103", "18"); m.insert("104", "18"); m.insert("105", "18");
        // Полтавська (19)
        m.insert("106", "19"); m.insert("107", "19"); m.insert("108", "19"); m.insert("109", "19");
        // Рівненська (5)
        m.insert("110", "5"); m.insert("111", "5"); m.insert("112", "5"); m.insert("113", "5");
        // Сумська (20)
        m.insert("114", "20"); m.insert("115", "20"); m.insert("116", "20");
        m.insert("117", "20"); m.insert("118", "20");
        // Тернопільська (21)
        m.insert("119", "21"); m.insert("120", "21"); m.insert("121", "21");
        // Харківська (22)
        m.insert("122", "22"); m.insert("123", "22"); m.insert("124", "22");
        m.insert("125", "22"); m.insert("126", "22"); m.insert("127", "22"); m.insert("128", "22");
        // Херсонська (23)
        m.insert("129", "23"); m.insert("130", "23"); m.insert("131", "23");
        m.insert("132", "23"); m.insert("133", "23");
        // Хмельницька (3)
        m.insert("134", "3"); m.insert("135", "3"); m.insert("136", "3");
        // Чернівецька (26)
        m.insert("137", "26"); m.insert("138", "26"); m.insert("139", "26");
        // Чернігівська (25)
        m.insert("140", "25"); m.insert("141", "25"); m.insert("142", "25");
        m.insert("143", "25"); m.insert("144", "25");
        // Запорізька (12)
        m.insert("145", "12"); m.insert("146", "12"); m.insert("147", "12");
        m.insert("148", "12"); m.insert("149", "12");
        // Черкаська (24)
        m.insert("150", "24"); m.insert("151", "24"); m.insert("152", "24"); m.insert("153", "24");
        m
    })
}

/// Канонічні аліаси перейменованих районів України (згідно з постановами Верховної Ради України)
pub fn get_renamed_raion_aliases() -> &'static [(&'static str, &'static str)] {
    &[
        // Звягельський район (Житомирська обл., ID 60, раніше Новоград-Волинський, Постанова ВРУ № 2779-IX)
        ("звягельський район", "60"),
        ("звягельський", "60"),
        ("звягельський р-н", "60"),
        ("звягель", "60"),
        ("м. звягель", "60"),
        ("м.звягель", "60"),
        ("новоград-волинський район", "60"),
        ("новоград-волинський", "60"),
        ("новоград-волинський р-н", "60"),
        ("новоград волинський", "60"),
        ("новоград", "60"),
        ("м. новоград-волинський", "60"),
        ("novohrad-volynskyi", "60"),
        ("novohrad", "60"),
        ("zviahel", "60"),

        // Володимирський район (Волинська обл., ID 38, раніше Володимир-Волинський, Постанова ВРУ № 2443-IX)
        ("володимирський район", "38"),
        ("володимирський", "38"),
        ("володимирський р-н", "38"),
        ("володимир", "38"),
        ("м. володимир", "38"),
        ("володимир-волинський район", "38"),
        ("володимир-волинський", "38"),
        ("володимир-волинський р-н", "38"),
        ("володимир волинський", "38"),
        ("м. володимир-волинський", "38"),
        ("volodymyr-volynskyi", "38"),
        ("volodymyr", "38"),

        // Шептицький район (Львівська обл., ID 92, раніше Червоноградський, Постанова ВРУ № 3984-IX)
        ("шептицький район", "92"),
        ("шептицький", "92"),
        ("шептицький р-н", "92"),
        ("шептицького", "92"),
        ("шептицького район", "92"),
        ("шептицького р-н", "92"),
        ("м. шептицький", "92"),
        ("червоноградський район", "92"),
        ("червоноградський", "92"),
        ("червоноградський р-н", "92"),
        ("червоноград", "92"),
        ("м. червоноград", "92"),
        ("chervonohrad", "92"),
        ("sheptytskyi", "92"),

        // Самарівський район (Дніпропетровська обл., ID 43, раніше Новомосковський, Постанова ВРУ № 3984-IX)
        ("самарівський район", "43"),
        ("самарівський", "43"),
        ("самарівський р-н", "43"),
        ("самарський район", "43"),
        ("самарський", "43"),
        ("самарський р-н", "43"),
        ("самар", "43"),
        ("м. самар", "43"),
        ("новомосковський район", "43"),
        ("новомосковський", "43"),
        ("новомосковський р-н", "43"),
        ("новомосковськ", "43"),
        ("м. новомосковськ", "43"),
        ("novomoskovsk", "43"),
        ("samar", "43"),

        // Сіверськодонецький район (Луганська обл., ID 84, раніше Сєвєродонецький, Постанова ВРУ № 3984-IX)
        ("сіверськодонецький район", "84"),
        ("сіверськодонецький", "84"),
        ("сіверськодонецький р-н", "84"),
        ("сіверськодонецьк", "84"),
        ("м. сіверськодонецьк", "84"),
        ("сєвєродонецький район", "84"),
        ("сєвєродонецький", "84"),
        ("сєвєродонецький р-н", "84"),
        ("сєвєродонецьк", "84"),
        ("м. сєвєродонецьк", "84"),
        ("северодонецк", "84"),
        ("severodonetsk", "84"),
        ("sievierodonetsk", "84"),

        // Берестинський район (Харківська обл., ID 127, раніше Красноградський, Постанова ВРУ № 3984-IX)
        ("берестинський район", "127"),
        ("берестинський", "127"),
        ("берестинський р-н", "127"),
        ("берестин", "127"),
        ("м. берестин", "127"),
        ("красноградський район", "127"),
        ("красноградський", "127"),
        ("красноградський р-н", "127"),
        ("красноград", "127"),
        ("м. красноград", "127"),
        ("krasnohrad", "127"),
        ("berestyn", "127"),
    ]
}

/// Повертає офіційну канонічну назву для регіону/району/громади за його числовим ID
pub fn get_canonical_name_for_id(id: &str) -> Option<&'static str> {
    match id {
        // Канонічні райони (Rank 2)
        "60" => Some("Звягельський район"),
        "38" => Some("Володимирський район"),
        "92" => Some("Шептицький район"),
        "43" => Some("Самарівський район"),
        "84" => Some("Сіверськодонецький район"),
        "127" => Some("Берестинський район"),
        // Канонічні міста та територіальні громади (Rank 3)
        "471" => Some("м. Звягель та Звягельська територіальна громада"),
        "255" => Some("м. Володимир та Володимирська територіальна громада"),
        "832" => Some("м. Шептицький та Шептицька територіальна громада"),
        "327" => Some("м. Самар та Самарська територіальна громада"),
        "315" => Some("м. Шахтарське та Шахтарська територіальна громада"),
        "950" => Some("м. Південноукраїнськ та Південноукраїнська територіальна громада"),
        "971" => Some("м. Південне та Південнівська територіальна громада"),
        "1324" => Some("Берестинська територіальна громада"),
        "1476" => Some("м. Багачеве та Багачівська територіальна громада"),
        "820" => Some("м. Сіверськодонецьк та Сіверськодонецька територіальна громада"),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationInfo {
    pub oblast: String,
    pub oblast_id: String,
    pub raion: String,
    pub raion_id: String,
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionFeatureData {
    pub id: String,
    pub name: String,
    pub rank: u8,
    pub oblast_id: String,
    pub bbox: (f64, f64, f64, f64), // (min_lon, min_lat, max_lon, max_lat)
    pub center: (f64, f64),         // (lat, lon)
    #[serde(skip)]
    pub polygons: Vec<Vec<Vec<(f64, f64)>>>, // [ Polygon[ Ring[ (lon, lat) ] ] ]
}

#[derive(Clone, Default)]
pub struct OblastDetector {
    pub regions: Vec<RegionFeatureData>,       // Rank 1 (26 областей)
    pub raion_regions: Vec<RegionFeatureData>, // Rank 2 (122 райони)
    pub oblasts_by_id: HashMap<String, RegionFeatureData>,
    pub region_to_oblast: HashMap<String, String>,
    pub raions_by_id: HashMap<String, RegionFeatureData>,
    pub raion_name_to_id: HashMap<String, String>,
    pub rtree: RTree<SpatialRegionItem>,
}

impl OblastDetector {
    pub fn load(geojson_path: &Path) -> Result<Self, String> {
        if !geojson_path.exists() {
            return Err(format!("regions.geojson not found at {:?}", geojson_path));
        }

        let content = fs::read_to_string(geojson_path)
            .map_err(|e| format!("Failed to read regions.geojson: {}", e))?;

        let val: Value = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid GeoJSON format: {}", e))?;

        let canonical_map = get_canonical_raion_to_oblast();
        let mut detector = Self::default();

        let features = val.get("features").and_then(|f| f.as_array());
        if let Some(feats) = features {
            // 1. Обробка 26 Областей (Rank 1)
            for feat in feats {
                let props = match feat.get("properties") {
                    Some(p) => p,
                    None => continue,
                };

                let rank = props.get("rank").and_then(|r| r.as_u64()).unwrap_or(0);
                if rank == 1 {
                    let name = props.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let reg_id = props.get("regionId")
                        .or_else(|| props.get("id"))
                        .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                        .unwrap_or_default();

                    let polygons = extract_polygons(feat.get("geometry"));
                    if polygons.is_empty() {
                        continue;
                    }

                    let bbox = calculate_bbox(&polygons);
                    let center = ((bbox.1 + bbox.3) / 2.0, (bbox.0 + bbox.2) / 2.0);

                    let data = RegionFeatureData {
                        id: reg_id.clone(),
                        name: name.clone(),
                        rank: 1,
                        oblast_id: reg_id.clone(),
                        bbox,
                        center,
                        polygons,
                    };

                    detector.regions.push(data.clone());
                    detector.oblasts_by_id.insert(reg_id.clone(), data);
                    detector.region_to_oblast.insert(reg_id.clone(), reg_id);
                }
            }

            // 2. Обробка Районів (Rank 2)
            for feat in feats {
                let props = match feat.get("properties") {
                    Some(p) => p,
                    None => continue,
                };

                let rank = props.get("rank").and_then(|r| r.as_u64()).unwrap_or(0);
                if rank == 2 {
                    let reg_id = props.get("regionId")
                        .or_else(|| props.get("id"))
                        .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                        .unwrap_or_default();
                    let raw_name = props.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let name = get_canonical_name_for_id(&reg_id)
                        .map(|s| s.to_string())
                        .unwrap_or(raw_name.clone());

                    let polygons = extract_polygons(feat.get("geometry"));
                    if polygons.is_empty() {
                        continue;
                    }

                    let bbox = calculate_bbox(&polygons);
                    let center = ((bbox.1 + bbox.3) / 2.0, (bbox.0 + bbox.2) / 2.0);

                    let parent_ob_id = canonical_map.get(reg_id.as_str())
                        .map(|&s| s.to_string())
                        .unwrap_or_else(|| {
                            props.get("oblast_id")
                                .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                                .unwrap_or_else(|| "0".to_string())
                        });

                    detector.region_to_oblast.insert(reg_id.clone(), parent_ob_id.clone());

                    let data = RegionFeatureData {
                        id: reg_id.clone(),
                        name: name.clone(),
                        rank: 2,
                        oblast_id: parent_ob_id,
                        bbox,
                        center,
                        polygons,
                    };

                    detector.raions_by_id.insert(reg_id.clone(), data.clone());
                    detector.raion_regions.push(data);

                    if !name.is_empty() {
                        let rn_lower = name.to_lowercase().trim().to_string();
                        detector.raion_name_to_id.insert(rn_lower.clone(), reg_id.clone());
                        let short = rn_lower.replace("район", "").trim().to_string();
                        detector.raion_name_to_id.insert(short, reg_id.clone());
                    }
                    if !raw_name.is_empty() && raw_name != name {
                        let old_lower = raw_name.to_lowercase().trim().to_string();
                        detector.raion_name_to_id.insert(old_lower.clone(), reg_id.clone());
                        let short_old = old_lower.replace("район", "").trim().to_string();
                        detector.raion_name_to_id.insert(short_old, reg_id);
                    }
                }
            }

            // Реєстрація канонічних аліасів офіційно перейменованих районів України
            for &(alias, raion_id) in get_renamed_raion_aliases() {
                detector.raion_name_to_id.insert(alias.to_string(), raion_id.to_string());
            }

            // 3. Обробка міст-анклавів (Rank 3, які утворюють геометричні вирізи в областях та районах)
            let enclave_to_oblast_raion: HashMap<&str, (&str, &str)> = HashMap::from([
                ("1293", ("22", "124")), // м. Харків -> Харківська обл., Харківський р-н
                ("564",  ("12", "149")), // м. Запоріжжя -> Запорізька обл., Запорізький р-н
                ("750",  ("14", "74")),  // м. Славутич -> Київська обл., Вишгородський р-н
                ("707",  ("14", "75")),  // Коцюбинське -> Київська обл., Бучанський р-н
            ]);

            for feat in feats {
                let props = match feat.get("properties") {
                    Some(p) => p,
                    None => continue,
                };
                let rank = props.get("rank").and_then(|r| r.as_u64()).unwrap_or(0);
                if rank == 3 {
                    let reg_id = props.get("regionId")
                        .or_else(|| props.get("id"))
                        .map(|v| if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() })
                        .unwrap_or_default();

                    if let Some(&(parent_ob_id, _parent_ra_id)) = enclave_to_oblast_raion.get(reg_id.as_str()) {
                        let name = props.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                        let polygons = extract_polygons(feat.get("geometry"));
                        if polygons.is_empty() { continue; }
                        let bbox = calculate_bbox(&polygons);
                        let center = ((bbox.1 + bbox.3) / 2.0, (bbox.0 + bbox.2) / 2.0);

                        detector.region_to_oblast.insert(reg_id.clone(), parent_ob_id.to_string());
                        let data = RegionFeatureData {
                            id: reg_id.clone(),
                            name: name.clone(),
                            rank: 2, // трактуємо як спец-район для R-Tree та мапи
                            oblast_id: parent_ob_id.to_string(),
                            bbox,
                            center,
                            polygons,
                        };
                        detector.raions_by_id.insert(reg_id.clone(), data.clone());
                        detector.raion_regions.push(data);

                        if !name.is_empty() {
                            let rn_lower = name.to_lowercase().trim().to_string();
                            detector.raion_name_to_id.insert(rn_lower.clone(), reg_id.clone());
                            let short = rn_lower.replace("район", "").trim().to_string();
                            detector.raion_name_to_id.insert(short, reg_id);
                        }
                    }
                }
            }
        }

        let mut spatial_items = Vec::with_capacity(detector.regions.len() + detector.raion_regions.len());
        for ob in &detector.regions {
            spatial_items.push(SpatialRegionItem {
                id: ob.id.clone(),
                rank: 1,
                envelope: AABB::from_corners([ob.bbox.0, ob.bbox.1], [ob.bbox.2, ob.bbox.3]),
            });
        }
        for ra in &detector.raion_regions {
            spatial_items.push(SpatialRegionItem {
                id: ra.id.clone(),
                rank: 2,
                envelope: AABB::from_corners([ra.bbox.0, ra.bbox.1], [ra.bbox.2, ra.bbox.3]),
            });
        }
        detector.rtree = RTree::bulk_load(spatial_items);

        info!(
            "OblastDetector loaded: {} Oblasts (Rank 1), {} Raions (Rank 2) with R-Tree spatial index",
            detector.regions.len(),
            detector.raion_regions.len()
        );

        Ok(detector)
    }

    /// 2D Ray-Casting алгоритм перевірки належності точки контуру
    pub fn point_in_polygon(x: f64, y: f64, poly: &[(f64, f64)]) -> bool {
        let n = poly.len();
        if n < 3 {
            return false;
        }
        let mut inside = false;
        let mut p1 = poly[0];

        for i in 1..=n {
            let p2 = poly[i % n];
            if y > p1.1.min(p2.1) && y <= p1.1.max(p2.1) && x <= p1.0.max(p2.0) {
                if p1.1 != p2.1 {
                    let xinters = (y - p1.1) * (p2.0 - p1.0) / (p2.1 - p1.1) + p1.0;
                    if p1.0 == p2.0 || x <= xinters {
                        inside = !inside;
                    }
                }
            }
            p1 = p2;
        }

        inside
    }

    /// Перевірка точки у полігоні з урахуванням внутрішніх отворів/анклавів (holes)
    /// poly[0] - зовнішній периметр, poly[1..] - внутрішні дірки (анклави/озера)
    pub fn point_in_polygon_with_holes(x: f64, y: f64, poly: &[Vec<(f64, f64)>]) -> bool {
        if poly.is_empty() {
            return false;
        }
        if !Self::point_in_polygon(x, y, &poly[0]) {
            return false;
        }
        for hole in &poly[1..] {
            if Self::point_in_polygon(x, y, hole) {
                return false;
            }
        }
        true
    }

    /// Точне географічне визначення локації:
    /// 1. Місто Київ (ID 31) перевіряється першим (анклав всередині Київської області)
    /// 2. Райони (Rank 2) перевіряються другими
    /// 3. Області (Rank 1) перевіряються третіми
    pub fn find_location_info(&self, lat: f64, lon: f64) -> LocationInfo {
        // 1. Перевірка м. Київ (ID "31")
        if let Some(kyiv) = self.oblasts_by_id.get("31") {
            let b = kyiv.bbox;
            if lon >= b.0 && lon <= b.2 && lat >= b.1 && lat <= b.3 {
                for poly in &kyiv.polygons {
                    if Self::point_in_polygon_with_holes(lon, lat, poly) {
                        return LocationInfo {
                            oblast: "м. Київ".to_string(),
                            oblast_id: "31".to_string(),
                            raion: "м. Київ".to_string(),
                            raion_id: "31".to_string(),
                            name: "м. Київ".to_string(),
                            id: "31".to_string(),
                        };
                    }
                }
            }
        }

        // 2. Швидкий просторовий пошук кандидатів через R-Tree O(log N)
        let candidates: Vec<&SpatialRegionItem> = self.rtree.locate_all_at_point(&[lon, lat]).collect();

        // 3. Перевірка Районів (Rank 2) серед кандидатів R-Tree
        for item in candidates.iter().filter(|c| c.rank == 2) {
            if let Some(ra) = self.raions_by_id.get(&item.id) {
                for poly in &ra.polygons {
                    if Self::point_in_polygon_with_holes(lon, lat, poly) {
                        let ob_id = &ra.oblast_id;
                        let ob_name = self.oblasts_by_id.get(ob_id)
                            .map(|o| o.name.clone())
                            .unwrap_or_else(|| "Невідома область".to_string());

                        let raion_name = self.get_canonical_name(&ra.id)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| ra.name.clone());

                        return LocationInfo {
                            oblast: ob_name.clone(),
                            oblast_id: ob_id.clone(),
                            raion: raion_name,
                            raion_id: ra.id.clone(),
                            name: ob_name,
                            id: ob_id.clone(),
                        };
                    }
                }
            }
        }

        // 4. Перевірка Областей (Rank 1, крім Києва 31) серед кандидатів R-Tree
        for item in candidates.iter().filter(|c| c.rank == 1 && c.id != "31") {
            if let Some(ob) = self.oblasts_by_id.get(&item.id) {
                for poly in &ob.polygons {
                    if Self::point_in_polygon_with_holes(lon, lat, poly) {
                        return LocationInfo {
                            oblast: ob.name.clone(),
                            oblast_id: ob.id.clone(),
                            raion: ob.name.clone(),
                            raion_id: ob.id.clone(),
                            name: ob.name.clone(),
                            id: ob.id.clone(),
                        };
                    }
                }
            }
        }

        LocationInfo {
            oblast: "Невідома область".to_string(),
            oblast_id: "0".to_string(),
            raion: "Невідомий район".to_string(),
            raion_id: "0".to_string(),
            name: "Невідома область".to_string(),
            id: "0".to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn get_oblast_id_by_region(&self, region_id: &str) -> String {
        self.region_to_oblast.get(region_id).cloned().unwrap_or_else(|| "0".to_string())
    }

    pub fn get_oblast_id_by_name(&self, name: &str) -> String {
        if name.is_empty() {
            return "0".to_string();
        }
        let lower = name.to_lowercase().trim().to_string();
        if lower == "м. київ" || lower == "місто київ" || lower == "київ" || lower == "kyiv" {
            return "31".to_string();
        }
        let clean = lower.replace("область", "").replace("обл.", "").trim().to_string();
        if clean.contains("севастополь") || clean.contains("крим") {
            return "9999".to_string();
        }
        for reg in &self.regions {
            if reg.id == "31" { continue; }
            let reg_clean = reg.name.to_lowercase().replace("область", "").replace("обл.", "").trim().to_string();
            if clean == reg_clean || clean.contains(&reg_clean) || reg_clean.contains(&clean) {
                return reg.id.clone();
            }
        }
        "0".to_string()
    }

    pub fn get_raion_id_by_name(&self, name: &str) -> String {
        if name.is_empty() {
            return "0".to_string();
        }
        let clean = name.to_lowercase()
            .replace("р-н", "район")
            .replace("р.", "район")
            .trim()
            .to_string();
        if let Some(id) = self.raion_name_to_id.get(&clean) {
            return id.clone();
        }
        let short = clean.replace("район", "").trim().to_string();
        if let Some(id) = self.raion_name_to_id.get(&short) {
            return id.clone();
        }
        for (k, v) in &self.raion_name_to_id {
            if !short.is_empty() && (k.contains(&short) || short.contains(k)) {
                return v.clone();
            }
        }
        // Перевірка аліасів перейменованих районів на випадок прямого звернення
        for &(alias, id) in get_renamed_raion_aliases() {
            if clean == alias || clean.contains(alias) || alias.contains(&clean) {
                return id.to_string();
            }
        }
        "0".to_string()
    }

    pub fn get_canonical_name(&self, id: &str) -> Option<&'static str> {
        get_canonical_name_for_id(id)
    }

    pub fn is_known_region(&self, reg_id: &str) -> bool {
        if reg_id.is_empty() || reg_id == "0" {
            return false;
        }
        self.oblasts_by_id.contains_key(reg_id)
            || self.raions_by_id.contains_key(reg_id)
            || self.region_to_oblast.contains_key(reg_id)
            || self.raion_regions.iter().any(|r| r.id == reg_id)
            || get_canonical_name_for_id(reg_id).is_some()
    }

    pub fn is_known_region_name(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        self.get_oblast_id_by_name(name) != "0" || self.get_raion_id_by_name(name) != "0"
    }
}

fn extract_polygons(geom_val: Option<&Value>) -> Vec<Vec<Vec<(f64, f64)>>> {
    let mut res = Vec::new();
    let geom = match geom_val {
        Some(g) => g,
        None => return res,
    };

    let g_type = geom.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let coords = geom.get("coordinates");

    fn parse_ring(ring_val: &Value) -> Vec<(f64, f64)> {
        let mut pts = Vec::new();
        if let Some(ring) = ring_val.as_array() {
            pts.reserve(ring.len());
            for pt in ring {
                if let Some(p) = pt.as_array() {
                    if p.len() >= 2 {
                        if let (Some(x), Some(y)) = (p[0].as_f64(), p[1].as_f64()) {
                            pts.push((x, y));
                        }
                    }
                }
            }
        }
        pts
    }

    if g_type == "Polygon" {
        if let Some(poly_arr) = coords.and_then(|c| c.as_array()) {
            let mut rings = Vec::new();
            for ring_val in poly_arr {
                let ring = parse_ring(ring_val);
                if !ring.is_empty() {
                    rings.push(ring);
                }
            }
            if !rings.is_empty() {
                res.push(rings);
            }
        }
    } else if g_type == "MultiPolygon" {
        if let Some(mpoly_arr) = coords.and_then(|c| c.as_array()) {
            for poly_val in mpoly_arr {
                if let Some(poly_arr) = poly_val.as_array() {
                    let mut rings = Vec::new();
                    for ring_val in poly_arr {
                        let ring = parse_ring(ring_val);
                        if !ring.is_empty() {
                            rings.push(ring);
                        }
                    }
                    if !rings.is_empty() {
                        res.push(rings);
                    }
                }
            }
        }
    }

    res
}

fn calculate_bbox(polygons: &[Vec<Vec<(f64, f64)>>]) -> (f64, f64, f64, f64) {
    let mut min_lon = f64::INFINITY;
    let mut max_lon = f64::NEG_INFINITY;
    let mut min_lat = f64::INFINITY;
    let mut max_lat = f64::NEG_INFINITY;

    for poly in polygons {
        for ring in poly {
            for &(lon, lat) in ring {
                if lon < min_lon { min_lon = lon; }
                if lon > max_lon { max_lon = lon; }
                if lat < min_lat { min_lat = lat; }
                if lat > max_lat { max_lat = lat; }
            }
        }
    }

    (min_lon, min_lat, max_lon, max_lat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renamed_raion_aliases_resolution() {
        let mut detector = OblastDetector::default();
        for &(alias, id) in get_renamed_raion_aliases() {
            detector.raion_name_to_id.insert(alias.to_string(), id.to_string());
        }

        // Звягельський (60) - Постанова ВРУ № 2779-IX (колишній Новоград-Волинський)
        assert_eq!(detector.get_raion_id_by_name("Звягельський район"), "60");
        assert_eq!(detector.get_raion_id_by_name("Звягельський р-н"), "60");
        assert_eq!(detector.get_raion_id_by_name("Звягель"), "60");
        assert_eq!(detector.get_raion_id_by_name("м. Звягель"), "60");
        assert_eq!(detector.get_raion_id_by_name("Новоград-Волинський район"), "60");
        assert_eq!(detector.get_raion_id_by_name("новоград-волинський"), "60");
        assert_eq!(detector.get_raion_id_by_name("новоград"), "60");

        // Володимирський (38) - Постанова ВРУ № 2443-IX (колишній Володимир-Волинський)
        assert_eq!(detector.get_raion_id_by_name("Володимирський район"), "38");
        assert_eq!(detector.get_raion_id_by_name("Володимирський р-н"), "38");
        assert_eq!(detector.get_raion_id_by_name("Володимир"), "38");
        assert_eq!(detector.get_raion_id_by_name("м. Володимир"), "38");
        assert_eq!(detector.get_raion_id_by_name("Володимир-Волинський район"), "38");
        assert_eq!(detector.get_raion_id_by_name("володимир-волинський"), "38");

        // Шептицький (92) - Постанова ВРУ № 3984-IX (колишній Червоноградський)
        assert_eq!(detector.get_raion_id_by_name("Шептицький район"), "92");
        assert_eq!(detector.get_raion_id_by_name("Шептицький р-н"), "92");
        assert_eq!(detector.get_raion_id_by_name("шептицький"), "92");
        assert_eq!(detector.get_raion_id_by_name("Червоноградський район"), "92");
        assert_eq!(detector.get_raion_id_by_name("червоноград"), "92");

        // Самарівський (43) - Постанова ВРУ № 3984-IX (колишній Новомосковський)
        assert_eq!(detector.get_raion_id_by_name("Самарівський район"), "43");
        assert_eq!(detector.get_raion_id_by_name("Самарський район"), "43");
        assert_eq!(detector.get_raion_id_by_name("самар"), "43");
        assert_eq!(detector.get_raion_id_by_name("Новомосковський район"), "43");
        assert_eq!(detector.get_raion_id_by_name("новомосковськ"), "43");

        // Сіверськодонецький (84) - Постанова ВРУ № 3984-IX (колишній Сєвєродонецький)
        assert_eq!(detector.get_raion_id_by_name("Сіверськодонецький район"), "84");
        assert_eq!(detector.get_raion_id_by_name("сіверськодонецьк"), "84");
        assert_eq!(detector.get_raion_id_by_name("Сєвєродонецький район"), "84");
        assert_eq!(detector.get_raion_id_by_name("сєвєродонецьк"), "84");

        // Берестинський (127) - Постанова ВРУ № 3984-IX (колишній Красноградський)
        assert_eq!(detector.get_raion_id_by_name("Берестинський район"), "127");
        assert_eq!(detector.get_raion_id_by_name("берестин"), "127");
        assert_eq!(detector.get_raion_id_by_name("Красноградський район"), "127");
        assert_eq!(detector.get_raion_id_by_name("красноград"), "127");

        // Канонічні назви
        assert_eq!(detector.get_canonical_name("60"), Some("Звягельський район"));
        assert_eq!(detector.get_canonical_name("38"), Some("Володимирський район"));
        assert_eq!(detector.get_canonical_name("92"), Some("Шептицький район"));
        assert_eq!(detector.get_canonical_name("43"), Some("Самарівський район"));
        assert_eq!(detector.get_canonical_name("84"), Some("Сіверськодонецький район"));
        assert_eq!(detector.get_canonical_name("127"), Some("Берестинський район"));
        assert_eq!(detector.get_canonical_name("471"), Some("м. Звягель та Звягельська територіальна громада"));
        assert_eq!(detector.get_canonical_name("255"), Some("м. Володимир та Володимирська територіальна громада"));
        assert_eq!(detector.get_canonical_name("832"), Some("м. Шептицький та Шептицька територіальна громада"));

        // Невідомий район повертає "0"
        assert_eq!(detector.get_raion_id_by_name("Неіснуючий район"), "0");
        assert_eq!(detector.get_raion_id_by_name(""), "0");
    }

    #[test]
    fn test_canonical_raion_to_oblast_mappings() {
        let canonical = get_canonical_raion_to_oblast();
        // Перевірка районів Київської області (14): 73-79
        assert_eq!(canonical.get("73").copied(), Some("14")); // Білоцерківський
        assert_eq!(canonical.get("75").copied(), Some("14")); // Бучанський
        // Перевірка районів Харківської області (22)
        assert_eq!(canonical.get("124").copied(), Some("22")); // Харківський
        // Перевірка районів Львівської області (27)
        assert_eq!(canonical.get("88").copied(), Some("27")); // Львівський
    }
}
