pub mod middleware;
pub mod admin_routes;
pub mod client_routes;

use axum::Router;
use tower_http::cors::CorsLayer;
use admin_routes::{admin_routes, AppState};
use client_routes::client_routes;

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::permissive();

    Router::new()
        .merge(client_routes())
        .merge(admin_routes())
        .layer(cors)
        .with_state(state)
}
