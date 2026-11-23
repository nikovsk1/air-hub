
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

/// Оцінка статусу цілі відносно точки спостереження та її зони безпеки (допрацьований Варіант 1:
/// аналітичний перетин променя з колом).
///
/// Логіка:
/// - Для D <= R:
///     theta > 90° => "Віддаляється від «[Точка]»", інакше "Курс на точку «[Точка]»"
/// - Для D > R (при theta < 90° і V >= 5 км/г):
///     d_perp = D * sin(theta_rad)
///     якщо d_perp > R => "Поза радіусом безпеки"
///     s_entry = D * cos(theta_rad) - sqrt(R^2 - d_perp^2)
///     ETA_zone = (s_entry / V) * 60 хв
///     якщо ETA_zone <= 15.0 => "Курс на точку «[Точка]»", інакше "Поза радіусом безпеки"
pub fn compute_point_approach_status(
    dist_km: f64,
    danger_radius_km: f64,
    approach_angle_deg: f64,
    speed_kmh: f64,
    point_name: &str,
) -> (String, &'static str) {
    let clean_name = if point_name.trim().is_empty() {
        "Точка"
    } else {
        point_name.trim()
    };

    if dist_km <= danger_radius_km {
        if approach_angle_deg > 90.0 {
            (format!("Віддаляється від «{}»", clean_name), "moving_away")
        } else {
            (format!("Курс на точку «{}»", clean_name), "direct")
        }
    } else {
        if approach_angle_deg >= 90.0 || speed_kmh < 5.0 {
            return ("Поза радіусом безпеки".to_string(), "outside");
        }

        let theta_rad = approach_angle_deg.to_radians();
        let d_perp = dist_km * theta_rad.sin();

        if d_perp > danger_radius_km {
            return ("Поза радіусом безпеки".to_string(), "outside");
        }

        let under_sqrt = (danger_radius_km * danger_radius_km - d_perp * d_perp).max(0.0);
        let s_entry = dist_km * theta_rad.cos() - under_sqrt.sqrt();

        let eta_zone = (s_entry / speed_kmh) * 60.0;
        if eta_zone <= 15.0 {
            (format!("Курс на точку «{}»", clean_name), "direct")
        } else {
            ("Поза радіусом безпеки".to_string(), "outside")
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_known_distances() {
        // Київ: 50.4501° N, 30.5234° E
        let kyiv_lat = 50.4501;
        let kyiv_lon = 30.5234;
        
        // Відстань точки до самої себе має бути 0
        let zero_dist = calculate_haversine_distance(kyiv_lat, kyiv_lon, kyiv_lat, kyiv_lon);
        assert!(zero_dist < 0.001, "Zero distance assertion failed");

        // Харків: 49.9935° N, 36.2304° E (~410-425 км)
        let kharkiv_lat = 49.9935;
        let kharkiv_lon = 36.2304;
        let dist_kharkiv = calculate_haversine_distance(kyiv_lat, kyiv_lon, kharkiv_lat, kharkiv_lon);
        assert!(dist_kharkiv > 400.0 && dist_kharkiv < 430.0, "Kyiv-Kharkiv distance was {}", dist_kharkiv);

        // Одеса: 46.4825° N, 30.7233° E (~440-455 км)
        let odesa_lat = 46.4825;
        let odesa_lon = 30.7233;
        let dist_odesa = calculate_haversine_distance(kyiv_lat, kyiv_lon, odesa_lat, odesa_lon);
        assert!(dist_odesa > 430.0 && dist_odesa < 460.0, "Kyiv-Odesa distance was {}", dist_odesa);
    }

    #[test]
    fn test_bearing_cardinal_directions() {
        let lat0 = 50.0;
        let lon0 = 30.0;

        // Прямо на північ
        let b_north = calculate_bearing(lat0, lon0, lat0 + 1.0, lon0);
        assert!((b_north - 0.0).abs() < 1.0 || (b_north - 360.0).abs() < 1.0, "North bearing was {}", b_north);

        // Прямо на схід
        let b_east = calculate_bearing(lat0, lon0, lat0, lon0 + 1.0);
        assert!((b_east - 90.0).abs() < 1.5, "East bearing was {}", b_east);

        // Прямо на південь
        let b_south = calculate_bearing(lat0, lon0, lat0 - 1.0, lon0);
        assert!((b_south - 180.0).abs() < 1.0, "South bearing was {}", b_south);

        // Прямо на захід
        let b_west = calculate_bearing(lat0, lon0, lat0, lon0 - 1.0);
        assert!((b_west - 270.0).abs() < 1.5, "West bearing was {}", b_west);
    }

    #[test]
    fn test_approach_angle_direct_and_receding() {
        let slot_lat = 50.0;
        let slot_lon = 30.0;

        // Ціль на півдні (49.0, 30.0), летить на північ (курс 0°) прямо на спостережний пункт
        let app_direct = approach_angle(49.0, 30.0, 0.0, slot_lat, slot_lon);
        assert!(app_direct < 2.0, "Direct approach angle should be ~0°, got {}", app_direct);

        // Ціль на півдні (49.0, 30.0), летить на південь (курс 180°) віддаляючись від пункту
        let app_receding = approach_angle(49.0, 30.0, 180.0, slot_lat, slot_lon);
        assert!(app_receding > 178.0, "Receding approach angle should be ~180°, got {}", app_receding);

        // Ціль летить перпендикулярно (курс 90°)
        let app_tangent = approach_angle(49.0, 30.0, 90.0, slot_lat, slot_lon);
        assert!((app_tangent - 90.0).abs() < 2.0, "Tangent approach angle should be ~90°, got {}", app_tangent);
    }

    #[test]
    fn test_format_eta_ua_contract() {
        assert_eq!(format_eta_ua(None), "--");
        assert_eq!(format_eta_ua(Some(0.0)), "--");
        assert_eq!(format_eta_ua(Some(1.5)), "01:30 хв");
        assert_eq!(format_eta_ua(Some(10.25)), "10:15 хв");
        assert_eq!(format_eta_ua(Some(65.0)), "1 год 05 хв");
        assert_eq!(format_eta_ua(Some(122.5)), "2 год 02 хв");
    }

    #[test]
    fn test_radar_screen_projection() {
        let cx = 184.0;
        let cy = 224.0;
        let max_r = 150.0;
        let danger_km = 35.0;

        // Ціль в центрі
        let (px, py, d, _) = project_radar_point(cx, cy, max_r, danger_km, 50.0, 30.0, 50.0, 30.0);
        assert_eq!(px, 184);
        assert_eq!(py, 224);
        assert!(d < 0.001);
    }

    #[test]
    fn test_point_approach_status_analytical_cases() {
        let point_name = "Київ";

        // Кейс 1: Проліт повз (D=60, R=35, theta=60°, V=400) -> d_perp = 60 * sin(60°) = 51.96 > 35 -> Поза радіусом безпеки
        let (desc1, code1) = compute_point_approach_status(60.0, 35.0, 60.0, 400.0, point_name);
        assert_eq!(desc1, "Поза радіусом безпеки");
        assert_eq!(code1, "outside");

        // Кейс 2: Швидка ракета наскрізь (D=40, R=35, V=850, theta=0°) -> s_entry = 40 - 35 = 5 км, ETA = 0.35 хв <= 15 -> Курс на точку «Київ»
        let (desc2, code2) = compute_point_approach_status(40.0, 35.0, 0.0, 850.0, point_name);
        assert_eq!(desc2, "Курс на точку «Київ»");
        assert_eq!(code2, "direct");

        // Кейс 3: Віддалення всередині зони (D=20, R=35, theta=120°, V=300) -> D <= R, theta > 90° -> Віддаляється від «Київ»
        let (desc3, code3) = compute_point_approach_status(20.0, 35.0, 120.0, 300.0, point_name);
        assert_eq!(desc3, "Віддаляється від «Київ»");
        assert_eq!(code3, "moving_away");

        // Додатковий кейс 4: Наближення всередині зони (D=20, R=35, theta=30°, V=300) -> Курс на точку «Київ»
        let (desc4, code4) = compute_point_approach_status(20.0, 35.0, 30.0, 300.0, point_name);
        assert_eq!(desc4, "Курс на точку «Київ»");
        assert_eq!(code4, "direct");

        // Додатковий кейс 5: Повільний шахед за 120 км строго курсом на точку (D=120, R=35, theta=0°, V=180) -> s_entry = 85 км, ETA = 28.3 хв > 15 -> Поза радіусом безпеки
        let (desc5, code5) = compute_point_approach_status(120.0, 35.0, 0.0, 180.0, point_name);
        assert_eq!(desc5, "Поза радіусом безпеки");
        assert_eq!(code5, "outside");
    }
}
