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
                        detector.raion_name_to_id.insert(short, reg_id);
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

                        return LocationInfo {
                            oblast: ob_name.clone(),
                            oblast_id: ob_id.clone(),
                            raion: ra.name.clone(),
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
        let clean = name.to_lowercase().replace("область", "").replace("обл.", "").trim().to_string();
        if clean.contains("севастополь") || clean.contains("крим") {
            return "9999".to_string();
        }
        for reg in &self.regions {
            let reg_clean = reg.name.to_lowercase().replace("область", "").replace("обл.", "").trim().to_string();
            if clean.contains(&reg_clean) || reg_clean.contains(&clean) {
                return reg.id.clone();
            }
        }
        "0".to_string()
    }

    pub fn get_raion_id_by_name(&self, name: &str) -> String {
        if name.is_empty() {
            return "0".to_string();
        }
        let clean = name.to_lowercase().trim().to_string();
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
        "0".to_string()
    }

    pub fn is_known_region(&self, reg_id: &str) -> bool {
        if reg_id.is_empty() || reg_id == "0" {
            return false;
        }
        self.oblasts_by_id.contains_key(reg_id)
            || self.raions_by_id.contains_key(reg_id)
            || self.region_to_oblast.contains_key(reg_id)
            || self.raion_regions.iter().any(|r| r.id == reg_id)
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
