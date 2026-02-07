use crate::errors::AppError;
use crate::schemas::{HealthCheckData, StorageStatus, SuccessResponse};
use crate::storage::StorageProvider;

pub fn health_check(storage: &dyn StorageProvider) -> Result<String, AppError> {
    let cred_path = storage.credentials_path();
    let writable = check_writable(cred_path);

    let count = match storage.load_credentials() {
        Ok(store) => store.users.values().map(|u| u.credentials.len()).sum(),
        Err(_) => 0,
    };

    let data = HealthCheckData {
        status: if writable { "ok".to_string() } else { "degraded".to_string() },
        version: env!("CARGO_PKG_VERSION").to_string(),
        storage: StorageStatus {
            writable,
            path: cred_path.to_string_lossy().to_string(),
            count,
        },
    };
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}

fn check_writable(path: &std::path::Path) -> bool {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            // Try to create the directory
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        // Check if we can write to the directory
        let test_path = parent.join(".write_test");
        if std::fs::write(&test_path, b"test").is_ok() {
            let _ = std::fs::remove_file(&test_path);
            return true;
        }
    }
    false
}
