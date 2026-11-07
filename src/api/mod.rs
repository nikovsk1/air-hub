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
    let client_cors = CorsLayer::permissive();

    Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .merge(client_routes().layer(client_cors))
        .merge(admin_routes())
        .layer(CompressionLayer::new())
        .with_state(state)
}
