pub mod middleware;
pub mod admin_routes;
pub mod client_routes;

use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use admin_routes::{admin_routes, AppState};
use client_routes::client_routes;

pub fn create_router(state: AppState) -> Router {
    let client_cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any)
        .allow_origin(tower_http::cors::Any);
    let static_dir = state.config.static_dir.clone();

    Router::new()
        .nest_service("/static", ServeDir::new(static_dir))
        .merge(client_routes().layer(client_cors))
        .merge(admin_routes())
        .layer(CompressionLayer::new())
        .layer(axum::middleware::from_fn(middleware::security_headers_middleware))
        .with_state(state)
}
