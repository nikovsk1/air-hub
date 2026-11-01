use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use flate2::read::GzDecoder;
use regex::Regex;
use serde_json::{json, Value};
use std::io::Read;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Prng {
    pub seed: u32,
}

impl Prng {
    pub fn new(seed: u32) -> Self {
        Self { seed }
    }

    pub fn next(&mut self) -> u32 {
        let mut s = self.seed;
        s ^= s.wrapping_shl(13);
        s ^= s.wrapping_shr(17);
        s ^= s.wrapping_shl(5);
        self.seed = s;
        s
    }
}

#[inline(always)]
fn rotl(val: u32, shift: u32) -> u32 {
    val.rotate_left(shift)
}

#[inline(always)]
fn quarter_round(st: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    st[a] = st[a].wrapping_add(st[b]);
    st[d] = rotl(st[d] ^ st[a], 16);
    st[c] = st[c].wrapping_add(st[d]);
    st[b] = rotl(st[b] ^ st[c], 12);
    st[a] = st[a].wrapping_add(st[b]);
    st[d] = rotl(st[d] ^ st[a], 8);
    st[c] = st[c].wrapping_add(st[d]);
    st[b] = rotl(st[b] ^ st[c], 7);
}

/// Декодування зашифрованого ChaCha20/AST корисного навантаження від карти ukrainealarm (~5:, ~6: тощо)
pub fn decode_payload_native(payload_str: &str) -> Result<Value, String> {
    let colon_pos = payload_str.find(':').ok_or_else(|| "Missing colon in payload prefix".to_string())?;
    let b64_part = &payload_str[colon_pos + 1..];
    let sanitized = b64_part.replace('-', "+").replace('_', "/");
    let pad_len = (4 - sanitized.len() % 4) % 4;
    let mut padded = sanitized;
    padded.push_str(&"=".repeat(pad_len));

    let mut raw_bytes = BASE64_STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let raw_len = raw_bytes.len();
    if raw_len < 16 {
        return Err("Payload too short: < 16 bytes".to_string());
    }

    let f = u32::from_le_bytes(raw_bytes[0..4].try_into().unwrap());
    let h = u32::from_le_bytes(raw_bytes[4..8].try_into().unwrap());
    let g = u32::from_le_bytes(raw_bytes[8..12].try_into().unwrap());

    let mut state_arr: [u32; 16] = [
        1634760805, 857760878, 2036477234, 1797285236,
        2838917605, 566540499, 2028117766, 3025996967,
        1063430289, 3353677899, 1519178294, 2422993229,
        1, f, h, g,
    ];

    let mut block = [0u32; 16];

    // ChaCha20 розшифрування блоками по 64 байти
    for i in (16..raw_len).step_by(64) {
        block.copy_from_slice(&state_arr);
        for _ in 0..10 {
            quarter_round(&mut block, 0, 4, 8, 12);
            quarter_round(&mut block, 1, 5, 9, 13);
            quarter_round(&mut block, 2, 6, 10, 14);
            quarter_round(&mut block, 3, 7, 11, 15);
            quarter_round(&mut block, 0, 5, 10, 15);
            quarter_round(&mut block, 1, 6, 11, 12);
            quarter_round(&mut block, 2, 7, 8, 13);
            quarter_round(&mut block, 3, 4, 9, 14);
        }

        let block_len = 64.min(raw_len - i);
        for j in 0..block_len {
            let key_word = block[j >> 2].wrapping_add(state_arr[j >> 2]);
            raw_bytes[i + j] ^= ((key_word >> (8 * (3 & j))) & 0xFF) as u8;
        }
        state_arr[12] = state_arr[12].wrapping_add(1);
    }

    // Type Map Permutation через Fisher-Yates
    let mut type_rng = Prng::new(f ^ h ^ g ^ 668265263);
    let mut types = [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    for i in (1..10).rev() {
        let rand_idx = (type_rng.next() as usize) % (i + 1);
        types.swap(i, rand_idx);
    }
    let mut type_map = [0usize; 10];
    for (i, &t) in types.iter().enumerate() {
        type_map[t] = i;
    }

    // Десеріалізація AST
    let mut offset = 16usize;
    let mut limit = 0usize;
    let mut val_rng = Prng::new(f ^ g ^ 2246822507);
    let mut xor_rng = Prng::new(3266489909 ^ h);
    let mut string_cache: Vec<String> = Vec::new();
    let mut number_cache: Vec<f64> = Vec::new();

    fn read_byte(raw: &[u8], offset: &mut usize) -> Result<u8, String> {
        if *offset >= raw.len() {
            return Err("EOF while reading byte".to_string());
        }
        let b = raw[*offset];
        *offset += 1;
        Ok(b)
    }

    fn read_varint(raw: &[u8], offset: &mut usize) -> Result<u64, String> {
        let mut value: u64 = 0;
        let mut shift: u64 = 1;
        for _ in 0..8 {
            let byte = read_byte(raw, offset)? as u64;
            value += (127 & byte) * shift;
            if (128 & byte) == 0 {
                return Ok(value);
            }
            shift *= 128;
        }
        Err("Invalid varint".to_string())
    }

    fn parse_node(
        raw: &[u8],
        offset: &mut usize,
        limit: &mut usize,
        depth: usize,
        type_map: &[usize; 10],
        val_rng: &mut Prng,
        xor_rng: &mut Prng,
        string_cache: &mut Vec<String>,
        number_cache: &mut Vec<f64>,
    ) -> Result<Value, String> {
        if depth > 63 || *limit > 1_000_000 {
            return Err("AST parse depth or limit exceeded".to_string());
        }
        *limit += 1;

        let b = read_byte(raw, offset)? as usize;
        if b >= type_map.len() {
            return Err(format!("Node type byte out of range: {}", b));
        }
        let node_type = type_map[b];

        match node_type {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(false)),
            2 => Ok(Value::Bool(true)),
            3 => {
                let val = read_varint(raw, offset)?;
                let xor_val = (xor_rng.next() & 65535) as u64;
                let low = ((val as u32) ^ (xor_val as u32)) as u64;
                let high = (val / 4294967296) * 4294967296;
                let num = high + low;
                let int_val = if num % 2 != 0 {
                    -(((num + 1) / 2) as i64)
                } else {
                    (num / 2) as i64
                };
                Ok(json!(int_val))
            }
            4 => {
                if *offset + 8 > raw.len() {
                    return Err("EOF reading f64".to_string());
                }
                let u0 = u32::from_le_bytes(raw[*offset..*offset + 4].try_into().unwrap()) ^ xor_rng.next();
                let u1 = u32::from_le_bytes(raw[*offset + 4..*offset + 8].try_into().unwrap()) ^ xor_rng.next();
                *offset += 8;
                let mut bytes = [0u8; 8];
                bytes[0..4].copy_from_slice(&u0.to_le_bytes());
                bytes[4..8].copy_from_slice(&u1.to_le_bytes());
                let fval = f64::from_le_bytes(bytes);
                number_cache.push(fval);
                Ok(json!(fval))
            }
            5 => {
                let slen = read_varint(raw, offset)? as usize;
                let str_xor = xor_rng.next();
                if *offset + slen > raw.len() {
                    return Err("EOF reading string bytes".to_string());
                }
                let mut chars = Vec::with_capacity(slen);
                for i in 0..slen {
                    let b = raw[*offset + i] ^ (((str_xor >> (8 * (3 & i))) & 0xFF) as u8);
                    chars.push(b);
                }
                *offset += slen;
                let s = match String::from_utf8(chars.clone()) {
                    Ok(valid_s) => valid_s,
                    Err(_) => chars.iter().map(|&c| c as char).collect(),
                };
                string_cache.push(s.clone());
                Ok(json!(s))
            }
            6 => {
                let alen = read_varint(raw, offset)? as usize;
                if alen == 0 {
                    return Ok(json!([]));
                }
                if alen > 10_000 || alen > raw.len() {
                    return Err("Array length exceeds bounds".to_string());
                }
                let mut arr = vec![Value::Null; alen];
                let start_offset = (val_rng.next() as usize) % alen;
                let is_reverse = (val_rng.next() & 1) != 0;
                for i in 0..alen {
                    let idx = (start_offset + (if is_reverse { alen - i } else { i })) % alen;
                    arr[idx] = parse_node(
                        raw, offset, limit, depth + 1, type_map, val_rng, xor_rng, string_cache, number_cache,
                    )?;
                }
                Ok(Value::Array(arr))
            }
            7 => {
                let s_idx = read_varint(raw, offset)? as usize;
                if s_idx < string_cache.len() {
                    Ok(json!(string_cache[s_idx]))
                } else {
                    Err(format!("String cache index out of bounds: {}", s_idx))
                }
            }
            8 => {
                let n_idx = read_varint(raw, offset)? as usize;
                if n_idx < number_cache.len() {
                    Ok(json!(number_cache[n_idx]))
                } else {
                    Err(format!("Number cache index out of bounds: {}", n_idx))
                }
            }
            _ => Err(format!("Unknown node type: {}", node_type)),
        }
    }

    parse_node(
        &raw_bytes,
        &mut offset,
        &mut limit,
        0,
        &type_map,
        &mut val_rng,
        &mut xor_rng,
        &mut string_cache,
        &mut number_cache,
    )
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawExtractedTarget {
    pub id: String,
    pub lat: f64,
    pub lon: f64,
    pub raw_name: String,
    pub raw_type_code: i64,
    pub heading_deg: f64,
    #[serde(default)]
    pub speed_kmh: Option<f64>,
    #[serde(default)]
    pub confidence: Option<u8>,
    #[serde(default)]
    pub time_offset_ms: Option<i64>,
    #[serde(default)]
    pub trail_points: Vec<(f64, f64)>,
    #[serde(default = "default_active_status")]
    pub upstream_status: String,
}

fn default_active_status() -> String {
    "active".to_string()
}

impl RawExtractedTarget {
    #[allow(dead_code)]
    pub fn simple(id: String, lat: f64, lon: f64, raw_name: String, raw_type_code: i64, heading_deg: f64) -> Self {
        Self {
            id,
            lat,
            lon,
            raw_name,
            raw_type_code,
            heading_deg,
            speed_kmh: None,
            confidence: None,
            time_offset_ms: None,
            trail_points: Vec::new(),
            upstream_status: "active".to_string(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMeta {
    pub revision_hash: Option<String>,
    pub sequence_num: Option<String>,
    pub combat_active: bool,
    pub server_ts_ms: Option<i64>,
    pub ttl_sec: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaxonomyItem {
    pub code: i64,
    pub name_ua: String,
    pub name_en: String,
    pub icon: String,
    pub scale: f64,
}

/// Витяг метаданих знімка кадру з decoded[0..3]
pub fn extract_snapshot_meta(decoded: &Value) -> SnapshotMeta {
    let mut meta = SnapshotMeta {
        revision_hash: None,
        sequence_num: None,
        combat_active: true,
        server_ts_ms: None,
        ttl_sec: Some(30),
    };

    if let Some(arr) = decoded.as_array() {
        // decoded[1]: revision metadata (seq, hash)
        if arr.len() > 1 {
            if let Some(rev_arr) = arr[1].as_array() {
                for item in rev_arr {
                    if let Some(s) = item.as_str() {
                        if s.starts_with("http-") || s.len() > 16 {
                            meta.revision_hash = Some(s.to_string());
                        } else if s.chars().all(|c| c.is_ascii_digit()) {
                            meta.sequence_num = Some(s.to_string());
                        }
                    }
                }
            } else if let Some(s) = arr[1].as_str() {
                meta.revision_hash = Some(s.to_string());
            }
        }

        // decoded[2]: TTL & combat active flag
        if arr.len() > 2 {
            if let Some(ttl_arr) = arr[2].as_array() {
                if let Some(ttl) = ttl_arr.first().and_then(|v| v.as_u64()) {
                    meta.ttl_sec = Some(ttl);
                }
                if let Some(active) = ttl_arr.get(1).and_then(|v| v.as_bool()) {
                    meta.combat_active = active;
                }
            } else if let Some(active) = arr[2].as_bool() {
                meta.combat_active = active;
            }
        }

        // decoded[3]: Server timestamp
        if arr.len() > 3 {
            if let Some(ts) = arr[3].as_i64() {
                meta.server_ts_ms = Some(ts);
            } else if let Some(ts_arr) = arr[3].as_array() {
                if let Some(ts) = ts_arr.first().and_then(|v| v.as_i64()) {
                    meta.server_ts_ms = Some(ts);
                }
            }
        }
    }

    meta
}

/// Витяг динамічної таксономії типів цілей з decoded[4][2]
pub fn extract_taxonomy(decoded: &Value) -> Vec<TaxonomyItem> {
    let mut items = Vec::new();
    if let Some(arr) = decoded.as_array() {
        if arr.len() > 4 {
            if let Some(fourth) = arr[4].as_array() {
                for sec in fourth {
                    if let Some(table) = sec.as_array() {
                        if !table.is_empty() {
                            if let Some(first_row) = table[0].as_array() {
                                if first_row.len() >= 4 && first_row[0].is_number() && first_row[1].is_string() {
                                    for row in table {
                                        if let Some(r) = row.as_array() {
                                            if r.len() >= 3 {
                                                let code = r[0].as_i64().unwrap_or(0);
                                                let name_ua = r[1].as_str().unwrap_or("").to_string();
                                                let name_en = r[2].as_str().unwrap_or("").to_string();
                                                let icon = if r.len() > 3 { r[3].as_str().unwrap_or("").to_string() } else { String::new() };
                                                let scale = if r.len() > 4 { r[4].as_f64().unwrap_or(1.0) } else { 1.0 };
                                                items.push(TaxonomyItem { code, name_ua, name_en, icon, scale });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    items
}

/// Витяг координат та типів цілей з розкодованого AST дерева
pub fn extract_targets(decoded: &Value) -> Vec<RawExtractedTarget> {
    let mut found_coords: Option<Vec<Vec<f64>>> = None;
    let mut found_types: Option<Vec<(i64, String)>> = None;
    let mut found_targets: Option<Vec<Vec<f64>>> = None;
    let mut found_uuids: Option<Vec<String>> = None;

    // Спроба знайти UUIDs у decoded[4] (Item 4[0])
    if let Some(arr) = decoded.as_array() {
        if arr.len() > 4 {
            if let Some(fourth) = arr[4].as_array() {
                for item in fourth {
                    if let Some(inner) = item.as_array() {
                        if !inner.is_empty() && inner.iter().take(3).all(|v| v.is_string()) {
                            let uuids: Vec<String> = inner
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            if !uuids.is_empty() {
                                found_uuids = Some(uuids);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    fn search_global(
        node: &Value,
        coords: &mut Option<Vec<Vec<f64>>>,
        types: &mut Option<Vec<(i64, String)>>,
        targets: &mut Option<Vec<Vec<f64>>>,
    ) {
        if let Some(arr) = node.as_array() {
            if coords.is_none() && !arr.is_empty() {
                if let Some(first) = arr[0].as_array() {
                    if first.len() >= 4 {
                        let is_coord = first[0..4].iter().all(|x| {
                            x.as_f64().map_or(false, |v| (0.0..=1.0).contains(&v))
                        });
                        if is_coord {
                            let mut extracted_coords = Vec::new();
                            for item in arr {
                                if let Some(row) = item.as_array() {
                                    let numbers: Vec<f64> = row.iter().filter_map(|x| x.as_f64()).collect();
                                    if numbers.len() >= 4 {
                                        extracted_coords.push(numbers);
                                    }
                                }
                            }
                            *coords = Some(extracted_coords);
                        }
                    }
                }
            }

            if types.is_none() && !arr.is_empty() {
                if let Some(first) = arr[0].as_array() {
                    if first.len() >= 2 && first[0].is_number() && first[1].is_string() {
                        let mut extracted_types = Vec::new();
                        for item in arr {
                            if let Some(row) = item.as_array() {
                                if row.len() >= 2 {
                                    let code = row[0].as_i64().unwrap_or(0);
                                    let name_parts: Vec<&str> = row[1..].iter().filter_map(|x| x.as_str()).collect();
                                    let name = if name_parts.is_empty() {
                                        "Ціль".to_string()
                                    } else {
                                        name_parts.join(" ")
                                    };
                                    extracted_types.push((code, name));
                                }
                            }
                        }
                        *types = Some(extracted_types);
                    }
                }
            }

            if targets.is_none() && !arr.is_empty() {
                if let Some(first) = arr[0].as_array() {
                    // Гнучкий розбір цілей: масив має містити щонайменше 3 числових індекси [uuid, coords, type],
                    // але не повинен бути масивом координат (де всі числа в діапазоні 0..=1)
                    let is_coords_array = first.len() >= 4 && first[0..4].iter().all(|x| {
                        x.as_f64().map_or(false, |v| (0.0..=1.0).contains(&v))
                    });

                    if !is_coords_array && first.len() >= 8 && first[0].is_number() && first[1].is_number() && first[2].is_number() {
                        let mut extracted_targets = Vec::new();
                        for item in arr {
                            if let Some(row) = item.as_array() {
                                let numbers: Vec<f64> = row.iter().filter_map(|x| x.as_f64()).collect();
                                if numbers.len() >= 3 {
                                    extracted_targets.push(numbers);
                                }
                            }
                        }
                        if !extracted_targets.is_empty() {
                            *targets = Some(extracted_targets);
                        }
                    }
                }
            }

            for item in arr {
                if item.is_array() {
                    search_global(item, coords, types, targets);
                }
            }
        }
    }

    search_global(&decoded, &mut found_coords, &mut found_types, &mut found_targets);

    let (coords, types, targets) = match (found_coords, found_types, found_targets) {
        (Some(c), Some(t), Some(tgt)) => (c, t, tgt),
        _ => return Vec::new(),
    };


    // decoded[5][0] містить конфігурацію сповіщень сирен, а не траєкторії.
    // Траєкторії надійно та органічно накопичуються трекером TargetTracker у реальному часі.

    let mut result = Vec::new();

    for t in targets.iter() {
        if t.len() < 3 {
            continue;
        }
        if t[0] < 0.0 || t[1] < 0.0 || t[2] < 0.0 || t[0].is_nan() || t[1].is_nan() || t[2].is_nan() {
            continue;
        }
        // Статус засічки з t[4]: 1.0 => active, 0.0 => lost (archived), 2.0 => cooldown (blind zone), 3.0 => lost (destroyed)
        let upstream_status = if t.len() > 4 {
            match t[4] as i64 {
                0 | 3 => "lost".to_string(),
                2 => "cooldown".to_string(),
                _ => "active".to_string(),
            }
        } else {
            "active".to_string()
        };
        let uuid_idx = t[0] as usize;
        let c_idx = t[1] as usize;
        let typ_idx = t[2] as usize;
        let heading = if t.len() > 3 && !t[3].is_nan() { t[3] } else { 0.0 };

        // Витяг confidence, time_offset, vel_x, vel_y
        let confidence = if t.len() > 5 && t[5] >= 1.0 && t[5] <= 5.0 {
            Some(t[5] as u8)
        } else {
            None
        };

        let time_offset_ms = if t.len() > 6 && t[6] >= 0.0 && t[6] <= 600000.0 {
            Some(t[6] as i64)
        } else {
            None
        };

        let speed_kmh = if t.len() >= 9 {
            let vel_x = t[7];
            let vel_y = t[8];
            if vel_x.abs() > 0.000001 || vel_y.abs() > 0.000001 {
                let dx_km = vel_x * 1320.0;
                let dy_km = vel_y * 888.0;
                let dist_unit = (dx_km * dx_km + dy_km * dy_km).sqrt();
                let cand = dist_unit * 180.0;
                if cand >= 30.0 && cand <= 3500.0 {
                    Some(cand)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let trail = Vec::new();

        let uid = if let Some(ref uuids) = found_uuids {
            if uuid_idx < uuids.len() {
                uuids[uuid_idx].clone()
            } else {
                format!("t_{}", uuid_idx)
            }
        } else {
            format!("t_{}", uuid_idx)
        };

        if c_idx < coords.len() {
            let norm_x = coords[c_idx][0];
            let norm_y = coords[c_idx][1];
            // Точна геодезична лінійна проекція AST без Mercator-зсуву:
            let lon = 22.137059 + (norm_x * 18.090521);
            let lat = 52.379147 - (norm_y * 7.994549);

            let (raw_code, raw_name) = if typ_idx < types.len() {
                types[typ_idx].clone()
            } else {
                (0, "Ціль".to_string())
            };

            result.push(RawExtractedTarget {
                id: uid,
                lat,
                lon,
                raw_name,
                raw_type_code: raw_code,
                heading_deg: heading,
                speed_kmh,
                confidence,
                time_offset_ms,
                trail_points: trail,
                upstream_status,
            });
        }
    }

    result
}

/// Перетворення координат SVG (viewBox 0 0 260 175) у географічні (lon, lat)
pub fn svg_xy_to_lon_lat(x: f64, y: f64) -> (f64, f64) {
    let ce = |deg: f64| deg * std::f64::consts::PI / 180.0;
    let te = |rad: f64| rad * 180.0 / std::f64::consts::PI;
    let re = |lat: f64| ((std::f64::consts::PI / 4.0) + (ce(lat) / 2.0)).tan().ln();

    let fe = ce(40.2275801 - 22.137059);
    let ie = re(52.3791473) - re(44.184598);
    let pe = (260.0 / fe).min(175.0 / ie);
    let de = (260.0 - fe * pe) / 2.0;
    let ke = (175.0 - ie * pe) / 2.0;

    let lon = 22.137059 + te((x - de) / pe);
    let c = re(52.3791473) - (y - ke) / pe;
    let lat = te(2.0 * c.exp().atan() - (std::f64::consts::PI / 2.0));

    (lon, lat)
}

/// Класифікація типу за назвою/міткою з SVG у канонічний код та назву
pub fn classify_raw_surface_target(label: &str) -> (i64, String) {
    let lower = label.to_lowercase();
    if lower.contains("шахед") || lower.contains("shahed") || lower.contains("герань") {
        (1, "Шахед".to_string())
    } else if lower.contains("крилат") || lower.contains("х-101") || lower.contains("калібр") || lower.contains("missile") || lower.contains("ракета") {
        (3, "Ракета".to_string())
    } else if lower.contains("баліст") || lower.contains("ballistic") || lower.contains("іскандер-м") || lower.contains("кінжал") || lower.contains("srr") || lower.contains("mrr") {
        (12, "Балістика".to_string())
    } else if lower.contains("каб") || lower.contains("airbomb") || lower.contains("бомб") {
        (5, "КАБ".to_string())
    } else if lower.contains("дрон") || lower.contains("бпла") || lower.contains("drone") || lower.contains("розвід") {
        (11, "БпЛА".to_string())
    } else if lower.contains("літак") || lower.contains("plane") || lower.contains("авіація") || lower.contains("винищувач") || lower.contains("бомбардувальник") {
        (9, "Авіація".to_string())
    } else {
        (0, if label.trim().is_empty() { "Ціль".to_string() } else { label.trim().to_string() })
    }
}

static RE_TITLE_TAG: OnceLock<Regex> = OnceLock::new();
static RE_TITLE_ATTR: OnceLock<Regex> = OnceLock::new();
static RE_ID: OnceLock<Regex> = OnceLock::new();
static RE_TRANS: OnceLock<Regex> = OnceLock::new();
static RE_ANIM_TRANS: OnceLock<Regex> = OnceLock::new();
static RE_MATRIX: OnceLock<Regex> = OnceLock::new();
static RE_ROT: OnceLock<Regex> = OnceLock::new();
static RE_ANIM_ROT: OnceLock<Regex> = OnceLock::new();

/// Парсинг векторних цілей з декомпресованого SVG-документа
pub fn extract_targets_from_svg(svg_str: &str) -> Result<Vec<RawExtractedTarget>, String> {
    let re_title_tag = RE_TITLE_TAG.get_or_init(|| Regex::new(r"(?i)<title\b([^>]*)>(.*?)</title>").unwrap());
    let re_title_attr = RE_TITLE_ATTR.get_or_init(|| Regex::new(r#"(?i)\bdata-l=["']([^"']+)["']"#).unwrap());
    let re_id = RE_ID.get_or_init(|| Regex::new(r#"(?i)\bid=["']([^"']+)["']"#).unwrap());
    let re_trans = RE_TRANS.get_or_init(|| Regex::new(r"(?i)translate\(\s*([-\d\.]+)[,\s]+([-\d\.]+)\s*\)").unwrap());
    let re_anim_trans = RE_ANIM_TRANS.get_or_init(|| Regex::new(r#"(?is)<animateTransform\b[^>]*\btype=["']translate["'][^>]*(?:from|to|values)=["']([-\d\.]+)[,\s]+([-\d\.]+)"#).unwrap());
    let re_matrix = RE_MATRIX.get_or_init(|| Regex::new(r"(?i)matrix\(\s*[-\d\.]+[,\s]+[-\d\.]+[,\s]+[-\d\.]+[,\s]+[-\d\.]+[,\s]+([-\d\.]+)[,\s]+([-\d\.]+)\s*\)").unwrap());
    let re_rot = RE_ROT.get_or_init(|| Regex::new(r"(?i)rotate\(\s*([-\d\.]+)").unwrap());
    let re_anim_rot = RE_ANIM_ROT.get_or_init(|| Regex::new(r#"(?is)<animateTransform\b[^>]*\btype=["']rotate["'][^>]*(?:from|to|values)=["']([-\d\.]+)"#).unwrap());

    let mut results = Vec::new();

    // Кожна векторна ціль має елемент <title>
    for title_cap in re_title_tag.captures_iter(svg_str) {
        let title_match = title_cap.get(0).unwrap();
        let title_pos = title_match.start();

        // Шукаємо найближчий відкриваючий тег <g перед <title>
        let prefix = &svg_str[..title_pos];
        let g_start = match prefix.rfind("<g") {
            Some(idx) => idx,
            None => continue,
        };

        let g_tag_content = match svg_str[g_start..].find('>') {
            Some(idx) => &svg_str[g_start..g_start + idx + 1],
            None => continue,
        };

        // Тіло цілі від закриття <g ...> до наступного </g>
        let body_start = g_start + g_tag_content.len();
        let body_end = match svg_str[title_pos..].find("</g>") {
            Some(idx) => title_pos + idx,
            None => svg_str.len().min(title_pos + 1024),
        };
        let body = &svg_str[body_start..body_end];

        let title_attrs = title_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let title_inner = title_cap.get(2).map(|m| m.as_str()).unwrap_or("");

        let label = if let Some(tc) = re_title_attr.captures(title_attrs) {
            tc.get(1).map(|m| m.as_str().to_string())
        } else if !title_inner.trim().is_empty() {
            Some(title_inner.trim().to_string())
        } else {
            None
        };

        let label_str = label.unwrap_or_else(|| "Ціль".to_string());
        let (raw_type_code, raw_name) = classify_raw_surface_target(&label_str);

        let id = if let Some(ic) = re_id.captures(g_tag_content) {
            ic.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| format!("s2_{}", results.len()))
        } else if let Some(ic) = re_id.captures(body) {
            ic.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| format!("s2_{}", results.len()))
        } else {
            format!("s2_{}", results.len())
        };

        let coords = if let Some(tc) = re_trans.captures(g_tag_content).or_else(|| re_trans.captures(body)) {
            let x: f64 = tc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
            let y: f64 = tc.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
            Some((x, y))
        } else if let Some(tc) = re_anim_trans.captures(body) {
            let x: f64 = tc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
            let y: f64 = tc.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
            Some((x, y))
        } else if let Some(mc) = re_matrix.captures(g_tag_content).or_else(|| re_matrix.captures(body)) {
            let x: f64 = mc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
            let y: f64 = mc.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
            Some((x, y))
        } else {
            None
        };

        let (x, y) = match coords {
            Some((x, y)) if x >= 0.0 && y >= 0.0 && !x.is_nan() && !y.is_nan() => (x, y),
            _ => continue,
        };

        let heading_deg = if let Some(rc) = re_rot.captures(g_tag_content).or_else(|| re_rot.captures(body)) {
            rc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0)
        } else if let Some(rc) = re_anim_rot.captures(body) {
            rc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0)
        } else {
            0.0
        };

        let (lon, lat) = svg_xy_to_lon_lat(x, y);

        results.push(RawExtractedTarget {
            id,
            lat,
            lon,
            raw_name,
            raw_type_code,
            heading_deg,
            speed_kmh: None,
            confidence: None,
            time_offset_ms: None,
            trail_points: Vec::new(),
            upstream_status: "active".to_string(),
        });
    }

    Ok(results)
}

/// Декодування зашифрованого ChaCha20 + GZIP корисного навантаження Surface v2/vX (~s2:, ~s3:, ~s4: тощо)
pub fn decode_surface_v2_payload(payload_str: &str) -> Result<Vec<RawExtractedTarget>, String> {
    let colon_pos = payload_str.find(':').ok_or_else(|| "Missing colon in payload prefix".to_string())?;
    let b64_part = &payload_str[colon_pos + 1..];
    let sanitized = b64_part.replace('-', "+").replace('_', "/");
    let pad_len = (4 - sanitized.len() % 4) % 4;
    let mut padded = sanitized;
    padded.push_str(&"=".repeat(pad_len));

    let mut raw_bytes = BASE64_STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let raw_len = raw_bytes.len();
    if raw_len < 16 {
        return Err("Payload too short: < 16 bytes".to_string());
    }

    let f = u32::from_le_bytes(raw_bytes[0..4].try_into().unwrap());
    let h = u32::from_le_bytes(raw_bytes[4..8].try_into().unwrap());
    let g = u32::from_le_bytes(raw_bytes[8..12].try_into().unwrap());
    let checksum_expected = u32::from_le_bytes(raw_bytes[12..16].try_into().unwrap());

    let mut state_arr: [u32; 16] = [
        1634760805, 857760878, 2036477234, 1797285236,
        2838917605, 566540499, 2028117766, 3025996967,
        1063430289, 3353677899, 1519178294, 2422993229,
        1, f, h, g,
    ];

    let mut block = [0u32; 16];

    // ChaCha20 розшифрування блоками по 64 байти
    for i in (16..raw_len).step_by(64) {
        block.copy_from_slice(&state_arr);
        for _ in 0..10 {
            quarter_round(&mut block, 0, 4, 8, 12);
            quarter_round(&mut block, 1, 5, 9, 13);
            quarter_round(&mut block, 2, 6, 10, 14);
            quarter_round(&mut block, 3, 7, 11, 15);
            quarter_round(&mut block, 0, 5, 10, 15);
            quarter_round(&mut block, 1, 6, 11, 12);
            quarter_round(&mut block, 2, 7, 8, 13);
            quarter_round(&mut block, 3, 4, 9, 14);
        }

        let block_len = 64.min(raw_len - i);
        for j in 0..block_len {
            let key_word = block[j >> 2].wrapping_add(state_arr[j >> 2]);
            raw_bytes[i + j] ^= ((key_word >> (8 * (3 & j))) & 0xFF) as u8;
        }
        state_arr[12] = state_arr[12].wrapping_add(1);
    }

    // FNV-1a перевірка цілісності корисного навантаження
    let mut fnv: u32 = 2166136261;
    for &b in &raw_bytes[16..] {
        fnv = (fnv ^ (b as u32)).wrapping_mul(16777619);
    }
    if fnv != checksum_expected {
        return Err(format!(
            "FNV-1a checksum mismatch: expected {}, got {}",
            checksum_expected, fnv
        ));
    }

    let compressed_slice = &raw_bytes[16..];
    let mut xml_str = String::new();

    if compressed_slice.len() >= 2 && compressed_slice[0] == 0x1f && compressed_slice[1] == 0x8b {
        let mut gz = GzDecoder::new(compressed_slice);
        gz.read_to_string(&mut xml_str)
            .map_err(|e| format!("Gzip decompression failed: {}", e))?;
    } else {
        use flate2::read::DeflateDecoder;
        let mut def = DeflateDecoder::new(compressed_slice);
        if def.read_to_string(&mut xml_str).is_err() {
            xml_str.clear();
            use flate2::read::ZlibDecoder;
            let mut zlib = ZlibDecoder::new(compressed_slice);
            zlib.read_to_string(&mut xml_str)
                .map_err(|e| format!("Decompression failed: {}", e))?;
        }
    }

    extract_targets_from_svg(&xml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_svg_xy_to_lon_lat() {
        // Київ: lon ~30.5234, lat ~50.4501 -> x ~120.66, y ~43.83
        let (lon, lat) = svg_xy_to_lon_lat(120.66, 43.83);
        assert!((lon - 30.5234).abs() < 0.1, "Longitude mismatch: {}", lon);
        assert!((lat - 50.4501).abs() < 0.1, "Latitude mismatch: {}", lat);
    }

    #[test]
    fn test_extract_targets_from_svg() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 260 175" data-f="4">
            <g data-z="m">
                <g id="tgt-shahed-1" transform="translate(120.66, 43.83)">
                    <title data-l="Shahed">Шахед</title>
                    <animateTransform type="rotate" from="135" to="135"/>
                </g>
                <g id="tgt-missile-2">
                    <title data-l="Ракета">Крилата ракета</title>
                    <animateTransform type="translate" from="150.0 60.0" to="152.0 62.0"/>
                    <animateTransform type="rotate" from="270" to="270"/>
                </g>
            </g>
        </svg>"#;

        let targets = extract_targets_from_svg(svg).expect("Extraction should succeed");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].id, "tgt-shahed-1");
        assert_eq!(targets[0].raw_name, "Шахед");
        assert_eq!(targets[0].raw_type_code, 1);
        assert_eq!(targets[0].heading_deg, 135.0);
        assert!((targets[0].lon - 30.5234).abs() < 0.1);
        assert!((targets[0].lat - 50.4501).abs() < 0.1);

        assert_eq!(targets[1].id, "tgt-missile-2");
        assert_eq!(targets[1].raw_name, "Ракета");
        assert_eq!(targets[1].raw_type_code, 3);
        assert_eq!(targets[1].heading_deg, 270.0);
    }

    #[test]
    fn test_decode_surface_v2_payload() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 260 175" data-f="4">
            <g data-z="m">
                <g id="tgt-shahed-test" transform="translate(120.66, 43.83)">
                    <title data-l="Shahed">Шахед</title>
                    <animateTransform type="rotate" from="180" to="180"/>
                </g>
            </g>
        </svg>"#;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(svg.as_bytes()).unwrap();
        let gz_bytes = encoder.finish().unwrap();

        let mut fnv: u32 = 2166136261;
        for &b in &gz_bytes {
            fnv = (fnv ^ (b as u32)).wrapping_mul(16777619);
        }

        let f = 0x11223344u32;
        let h = 0x55667788u32;
        let g = 0x99aabbc0u32;

        let mut state_arr: [u32; 16] = [
            1634760805, 857760878, 2036477234, 1797285236,
            2838917605, 566540499, 2028117766, 3025996967,
            1063430289, 3353677899, 1519178294, 2422993229,
            1, f, h, g,
        ];

        let mut encrypted = gz_bytes.clone();
        let mut block = [0u32; 16];
        let raw_len = encrypted.len();

        for i in (0..raw_len).step_by(64) {
            block.copy_from_slice(&state_arr);
            for _ in 0..10 {
                quarter_round(&mut block, 0, 4, 8, 12);
                quarter_round(&mut block, 1, 5, 9, 13);
                quarter_round(&mut block, 2, 6, 10, 14);
                quarter_round(&mut block, 3, 7, 11, 15);
                quarter_round(&mut block, 0, 5, 10, 15);
                quarter_round(&mut block, 1, 6, 11, 12);
                quarter_round(&mut block, 2, 7, 8, 13);
                quarter_round(&mut block, 3, 4, 9, 14);
            }
            let block_len = 64.min(raw_len - i);
            for j in 0..block_len {
                let key_word = block[j >> 2].wrapping_add(state_arr[j >> 2]);
                encrypted[i + j] ^= ((key_word >> (8 * (3 & j))) & 0xFF) as u8;
            }
            state_arr[12] = state_arr[12].wrapping_add(1);
        }

        let mut full_bytes = Vec::new();
        full_bytes.extend_from_slice(&f.to_le_bytes());
        full_bytes.extend_from_slice(&h.to_le_bytes());
        full_bytes.extend_from_slice(&g.to_le_bytes());
        full_bytes.extend_from_slice(&fnv.to_le_bytes());
        full_bytes.extend_from_slice(&encrypted);

        let b64 = BASE64_STANDARD.encode(&full_bytes);
        let payload = format!("~s2:{}", b64);

        let decoded = decode_surface_v2_payload(&payload).expect("Decryption should succeed");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].id, "tgt-shahed-test");
        assert_eq!(decoded[0].raw_name, "Шахед");
        assert_eq!(decoded[0].raw_type_code, 1);
        assert_eq!(decoded[0].heading_deg, 180.0);
    }

}
