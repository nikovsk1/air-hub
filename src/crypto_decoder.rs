use std::collections::HashMap;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use tracing::warn;

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

/// Декодування зашифрованого ChaCha20/AST корисного навантаження від карти ukrainealarm
pub fn decode_payload_native(payload_str: &str) -> Result<Value, String> {
    if !payload_str.starts_with("~5:") {
        return Err("Unsupported payload: missing ~5: prefix".to_string());
    }

    let b64_part = &payload_str[3..];
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
}

/// Витяг координат та типів цілей з розкодованого AST дерева
pub fn extract_targets(decoded: &Value) -> Vec<RawExtractedTarget> {
    let mut found_coords: Option<Vec<Vec<f64>>> = None;
    let mut found_types: Option<Vec<(i64, String)>> = None;
    let mut found_targets: Option<Vec<Vec<f64>>> = None;
    let mut found_uuids: Option<Vec<String>> = None;

    // Спроба знайти UUIDs у decoded[4]
    if let Some(arr) = decoded.as_array() {
        if arr.len() > 4 {
            if let Some(fourth) = arr[4].as_array() {
                for item in fourth {
                    if let Some(inner) = item.as_array() {
                        if !inner.is_empty() {
                            if let Some(first_str) = inner[0].as_str() {
                                if first_str.starts_with('~') {
                                    let uuids: Vec<String> = inner
                                        .iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect();
                                    found_uuids = Some(uuids);
                                    break;
                                }
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
                    if first.len() >= 8 && first[0].is_number() && first[7].is_number() {
                        let mut extracted_targets = Vec::new();
                        for item in arr {
                            if let Some(row) = item.as_array() {
                                let numbers: Vec<f64> = row.iter().filter_map(|x| x.as_f64()).collect();
                                if numbers.len() >= 8 {
                                    extracted_targets.push(numbers);
                                }
                            }
                        }
                        *targets = Some(extracted_targets);
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

    const MIN_LON: f64 = 22.13;
    const LON_RANGE: f64 = 18.09;
    const MAX_LAT: f64 = 52.37;
    const LAT_RANGE: f64 = 7.99;

    let mut result = Vec::new();

    for t in targets {
        if t.len() < 3 {
            continue;
        }
        let uuid_idx = t[0] as usize;
        let c_idx = t[1] as usize;
        let typ_idx = t[2] as usize;
        let heading = if t.len() > 3 { t[3] } else { 0.0 };

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
            let lon = MIN_LON + (coords[c_idx][0] * LON_RANGE);
            let lat = MAX_LAT - (coords[c_idx][1] * LAT_RANGE);

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
                raw_type_code,
                heading_deg: heading,
            });
        }
    }

    result
}
