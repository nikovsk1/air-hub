use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub admin_secret_key: String,
    pub data_dir: PathBuf,
    pub data_defaults_dir: PathBuf,
    pub static_dir: PathBuf,
    pub danger_radius_km: f64,
    pub upstream_proxy: Option<String>,
    pub initial_users: Vec<(String, String)>, // (owner, api_key)
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8088);

        let admin_secret_key = env::var("ADMIN_SECRET_KEY")
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .unwrap_or_else(|_| "admin_super_secret_master_key_123".to_string());

        let data_dir = PathBuf::from(
            env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string())
        );

        let data_defaults_dir = PathBuf::from(
            env::var("DATA_DEFAULTS_DIR").unwrap_or_else(|_| "./data_defaults".to_string())
        );

        let static_dir = PathBuf::from(
            env::var("STATIC_DIR").unwrap_or_else(|_| "./static".to_string())
        );

        let danger_radius_km = env::var("DANGER_RADIUS_KM")
            .ok()
            .and_then(|r| r.parse::<f64>().ok())
            .unwrap_or(35.0);

        let upstream_proxy = env::var("UPSTREAM_PROXY")
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty());

        let mut initial_users = Vec::new();
        if let Ok(users_str) = env::var("INITIAL_USERS") {
            for pair in users_str.split(',') {
                let parts: Vec<&str> = pair.split(':').collect();
                if parts.len() == 2 {
                    let owner = parts[0].trim().to_string();
                    let key = parts[1].trim().to_string();
                    if !owner.is_empty() && !key.is_empty() {
                        initial_users.push((owner, key));
                    }
                }
            }
        }

        Self {
            port,
            admin_secret_key,
            data_dir,
            data_defaults_dir,
            static_dir,
            danger_radius_km,
            upstream_proxy,
            initial_users,
        }
    }

    pub fn ensure_directories(&self) {
        if let Err(e) = fs::create_dir_all(&self.data_dir) {
            warn!("Failed to create data dir {:?}: {}", self.data_dir, e);
        }

        // Copy default files if not present in data_dir
        if self.data_defaults_dir.exists() {
            if let Ok(entries) = fs::read_dir(&self.data_defaults_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(filename) = path.file_name() {
                            let dest = self.data_dir.join(filename);
                            if !dest.exists() {
                                if let Err(e) = fs::copy(&path, &dest) {
                                    warn!("Failed to copy default {:?} to {:?}: {}", path, dest, e);
                                } else {
                                    info!("Initialized default data file: {:?}", dest);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
