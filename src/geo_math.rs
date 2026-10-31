
pub const EARTH_RADIUS_KM: f64 = 6371.0;

/// Обчислення відстані за формулою гаверсинуса (у кілометрах)
pub fn calculate_haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let r_lat1 = lat1.to_radians();
    let r_lat2 = lat2.to_radians();

    let a = (dlat / 2.0).sin().powi(2)
        + r_lat1.cos() * r_lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).max(0.0).sqrt());
    EARTH_RADIUS_KM * c
}

/// Обчислення істинного пеленгу (bearing) від точки 1 до точки 2 в градусах (0.0..360.0)
pub fn calculate_bearing(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let delta_lambda = (lon2 - lon1).to_radians();

    let y = delta_lambda.sin() * phi2.cos();
    let x = phi1.cos() * phi2.sin() - phi1.sin() * phi2.cos() * delta_lambda.cos();
    let bearing_rad = y.atan2(x);
    (bearing_rad.to_degrees() + 360.0) % 360.0
}

/// Отримання напрямку за компасом (16 румбів)
pub fn bearing_to_compass(deg: f64) -> &'static str {
    let sectors = [
        "Пн (N)", "Пн-Пн-Сх (NNE)", "Пн-Сх (NE)", "Сх-Пн-Сх (ENE)",
        "Сх (E)", "Сх-Пд-Сх (ESE)", "Пд-Сх (SE)", "Пд-Пд-Сх (SSE)",
        "Пд (S)", "Пд-Пд-Зх (SSW)", "Пд-Зх (SW)", "Зх-Пд-Зх (WSW)",
        "Зх (W)", "Зх-Пн-Зх (WNW)", "Пн-Зх (NW)", "Пн-Пн-Зх (NNW)"
    ];
    let idx = (((deg + 11.25) / 22.5).floor() as usize) % 16;
    sectors[idx]
}

/// Канонічне форматування часу підльоту (ETA):
/// - до 59.59 хв: формат "MM.SS хв"
/// - після 1 години: формат "H год MM хв"
/// - якщо час не визначено або віддаляється: "--"
pub fn format_eta_ua(eta_minutes: Option<f64>) -> String {
    let val = match eta_minutes {
        Some(v) if v > 0.0 => v,
        _ => return "--".to_string(),
    };

    let total_seconds = (val * 60.0).round() as u64;
    if total_seconds == 0 {
        return "--".to_string();
    }

    if total_seconds < 3600 {
        let mins = total_seconds / 60;
        let secs = total_seconds % 60;
        format!("{:02}:{:02} хв", mins, secs)
    } else {
        let hours = total_seconds / 3600;
        let rem_mins = (total_seconds % 3600) / 60;
        format!("{} год {:02} хв", hours, rem_mins)
    }
}

/// Розрахунок кута наближення (approach angle) вектора руху цілі до точки
pub fn approach_angle(target_lat: f64, target_lon: f64, heading: f64, slot_lat: f64, slot_lon: f64) -> f64 {
    let bearing_to_slot = calculate_bearing(target_lat, target_lon, slot_lat, slot_lon);
    let diff = (heading - bearing_to_slot).abs();
    if diff > 180.0 {
        360.0 - diff
    } else {
        diff
    }
}

/// Проєкція полярних координат у пікселі для Waveshare ESP32-S3 AMOLED (368x448)
pub fn project_radar_point(
    center_x: f64,
    center_y: f64,
    max_px: f64,
    radius_km: f64,
    center_lat: f64,
    center_lon: f64,
    target_lat: f64,
    target_lon: f64,
) -> (i32, i32, f64, f64) {
    let dist = calculate_haversine_distance(center_lat, center_lon, target_lat, target_lon);
    let bearing = calculate_bearing(center_lat, center_lon, target_lat, target_lon);
    let norm_dist = (dist / radius_km).min(1.0);
    let angle_rad = bearing.to_radians();
    let px_dist = norm_dist * max_px;

    let px_x = center_x + px_dist * angle_rad.sin();
    let px_y = center_y - px_dist * angle_rad.cos();

    (px_x.round() as i32, px_y.round() as i32, dist, bearing)
}
