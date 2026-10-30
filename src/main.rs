use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod geo_math;
mod crypto_decoder;
mod oblast_detector;
mod canonical_registry;
mod tracker;
mod storage;
mod history;
mod collectors;
mod api;

use api::admin_routes::AppState;
use config::Config;
use oblast_detector::OblastDetector;
use storage::StorageManager;
use history::HistoryManager;
use canonical_registry::ExchangeLogManager;
use tracker::ThreatState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Ініціалізація логування
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,air_alert_hub_rs=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Air Alert Radar Hub (Rust Edition) v1.0.0...");

    // 2. Завантаження конфігурації
    let config = Config::from_env();
    config.ensure_directories();

    info!("Data directory: {:?}", config.data_dir);
    info!("Data defaults directory: {:?}", config.data_defaults_dir);
    info!("Static directory: {:?}", config.static_dir);
    info!("Server port: {}", config.port);

    // 3. Завантаження географічного детектора областей та районів
    let geojson_path = config.data_dir.join("regions.geojson");
    let detector = match OblastDetector::load(&geojson_path) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            warn!("Could not load {:?}: {}. Using fallback defaults.", geojson_path, e);
            Arc::new(OblastDetector::default())
        }
    };

    // 4. Ініціалізація сховища конфігурації та користувачів
    let storage = Arc::new(StorageManager::new(&config.data_dir, &config.initial_users, &detector, config.danger_radius_km));

    // 5. Ініціалізація менеджерів історії та логу обміну
    let history_mgr = Arc::new(HistoryManager::new(&config.data_dir));
    let exchange_mgr = Arc::new(ExchangeLogManager::new(&config.data_dir));

    // 6. Ініціалізація глобального стану загроз
    let threat_state = Arc::new(RwLock::new(ThreatState::default()));

    // 7. Створення HTTP-клієнта (з опціональним SOCKS5/HTTP проксі)
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(15));

    if let Some(ref proxy_url) = config.upstream_proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            info!("Configured upstream proxy for collectors");
            client_builder = client_builder.proxy(proxy);
        }
    }
    let http_client = client_builder.build()?;

    // 8. Запуск фонових сервісів (збирачів телеметрії та сирен)
    {
        let t_state = threat_state.clone();
        let det = detector.clone();
        let hist = history_mgr.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            collectors::ukrainealarm_ws::run_ukrainealarm_collector(t_state, det, hist, client).await;
        });
    }

    {
        let t_state = threat_state.clone();
        let det = detector.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            collectors::official_alerts::run_official_alerts_collector(t_state, det, client).await;
        });
    }

    {
        let t_state = threat_state.clone();
        let det = detector.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            collectors::neptun_failover::run_failover_neptun_collector(t_state, det, client).await;
        });
    }

    // 9. Фонова задача періодичного скиду історії на диск (кожні 300 сек для захисту SD-карти)
    {
        let hist = history_mgr.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(300)).await;
                hist.flush_dirty();
            }
        });
    }

    // 10. Фонова задача синхронізації з Google Drive
    {
        let hist = history_mgr.clone();
        let stor = storage.clone();
        let client = http_client.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(3600)).await; // Перевірка щогодини
                let cfg = stor.get_gdrive_config();
                if cfg.gdrive_sync_enabled && cfg.gdrive_auto_sync_hours > 0 {
                    let interval_secs = (cfg.gdrive_auto_sync_hours as i64) * 3600;
                    let last_sync = cfg.last_gdrive_sync_ts.unwrap_or(0);
                    let now = crate::storage::now_ts();
                    if now - last_sync >= interval_secs {
                        if let Some(ref webhook) = cfg.gdrive_webhook_url {
                            let cur_month = HistoryManager::current_month();
                            info!("Running scheduled Google Drive auto-sync for {}...", cur_month);
                            if let Ok((count, size)) = hist.sync_to_gdrive(&cur_month, webhook, &client).await {
                                stor.mark_gdrive_synced();
                                info!("Auto-sync complete: {} targets, {} KB", count, size);
                            }
                        }
                    }
                }
            }
        });
    }

    // 11. Побудова роутера API
    let app_state = AppState {
        config: config.clone(),
        storage,
        history_mgr,
        exchange_mgr,
        detector,
        http_client,
        threat_state,
    };

    let app = api::create_router(app_state);

    // 12. Запуск HTTP/WebSocket сервера Axum
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Air Alert Hub listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
