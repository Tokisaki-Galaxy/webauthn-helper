use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::errors::AppError;

/// Challenge files older than this are considered expired (2 minutes)
const CHALLENGE_MAX_AGE_SECS: u64 = 120;

// ─── Internal Storage Structs (snake_case) ───

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialStore {
    pub users: std::collections::HashMap<String, UserRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id: String,
    pub credentials: Vec<StoredCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub device_name: String,
    pub static_state: String,
    pub dynamic_state: String,
    pub user_handle: String,
    pub transports: u8,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub backup_eligible: bool,
    pub user_verified: bool,
    pub sign_count: u32,
}

// ─── Challenge State ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeState {
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    pub username: String,
    pub rp_id: String,
    pub state: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    Registration,
    Authentication,
}

// ─── StorageProvider Trait ───

pub trait StorageProvider {
    fn load_credentials(&self) -> Result<CredentialStore, AppError>;
    fn save_credentials(&self, store: &CredentialStore) -> Result<(), AppError>;
    fn load_challenge(&self, challenge_id: &str) -> Result<ChallengeState, AppError>;
    fn save_challenge(&self, challenge_id: &str, state: &ChallengeState) -> Result<(), AppError>;
    fn delete_challenge(&self, challenge_id: &str) -> Result<(), AppError>;
    fn cleanup_challenges(&self) -> Result<usize, AppError>;
    fn credentials_path(&self) -> &Path;
}

// ─── FileStorage Implementation ───

pub struct FileStorage {
    credentials_path: PathBuf,
    challenge_dir: PathBuf,
}

impl FileStorage {
    pub fn new() -> Self {
        Self {
            credentials_path: PathBuf::from("/etc/webauthn/credentials.json"),
            challenge_dir: PathBuf::from("/tmp/webauthn/challenges"),
        }
    }

    #[cfg(test)]
    pub fn with_paths(credentials_path: PathBuf, challenge_dir: PathBuf) -> Self {
        Self {
            credentials_path,
            challenge_dir,
        }
    }
}

impl StorageProvider for FileStorage {
    fn load_credentials(&self) -> Result<CredentialStore, AppError> {
        if !self.credentials_path.exists() {
            return Ok(CredentialStore::default());
        }
        let data = fs::read_to_string(&self.credentials_path)?;
        let store: CredentialStore = serde_json::from_str(&data)?;
        Ok(store)
    }

    fn save_credentials(&self, store: &CredentialStore) -> Result<(), AppError> {
        if let Some(parent) = self.credentials_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.credentials_path)?;

        // Acquire exclusive lock
        file.lock_exclusive()
            .map_err(|e| AppError::Storage(format!("Failed to acquire file lock: {}", e)))?;

        let data = serde_json::to_string_pretty(store)?;
        (&file).write_all(data.as_bytes())?;

        // Lock is released when file is dropped
        Ok(())
    }

    fn load_challenge(&self, challenge_id: &str) -> Result<ChallengeState, AppError> {
        let path = self.challenge_dir.join(format!("{}.json", challenge_id));
        if !path.exists() {
            return Err(AppError::ChallengeNotFound(challenge_id.to_string()));
        }
        let data = fs::read_to_string(&path)?;
        let state: ChallengeState = serde_json::from_str(&data)?;
        Ok(state)
    }

    fn save_challenge(&self, challenge_id: &str, state: &ChallengeState) -> Result<(), AppError> {
        fs::create_dir_all(&self.challenge_dir)?;
        let path = self.challenge_dir.join(format!("{}.json", challenge_id));
        let data = serde_json::to_string_pretty(state)?;
        fs::write(&path, data)?;
        Ok(())
    }

    fn delete_challenge(&self, challenge_id: &str) -> Result<(), AppError> {
        let path = self.challenge_dir.join(format!("{}.json", challenge_id));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn cleanup_challenges(&self) -> Result<usize, AppError> {
        if !self.challenge_dir.exists() {
            return Ok(0);
        }
        let mut count = 0;
        let now = SystemTime::now();
        let max_age = std::time::Duration::from_secs(CHALLENGE_MAX_AGE_SECS);

        for entry in fs::read_dir(&self.challenge_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age > max_age {
                                fs::remove_file(&path)?;
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    fn credentials_path(&self) -> &Path {
        &self.credentials_path
    }
}

// ─── Helper Functions ───

pub fn now_iso8601() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (year, month, day) = days_to_date((secs / 86400) as i64);
    let time_of_day = secs % 86400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Civil date from days since Unix epoch (Howard Hinnant's algorithm).
fn days_to_date(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_storage() -> (FileStorage, TempDir) {
        let dir = TempDir::new().unwrap();
        let cred_path = dir.path().join("credentials.json");
        let challenge_dir = dir.path().join("challenges");
        let storage = FileStorage::with_paths(cred_path, challenge_dir);
        (storage, dir)
    }

    #[test]
    fn test_load_empty_credentials() {
        let (storage, _dir) = test_storage();
        let store = storage.load_credentials().unwrap();
        assert!(store.users.is_empty());
    }

    #[test]
    fn test_save_and_load_credentials() {
        let (storage, _dir) = test_storage();
        let mut store = CredentialStore::default();
        store.users.insert(
            "root".to_string(),
            UserRecord {
                user_id: "test_user_id".to_string(),
                credentials: vec![],
            },
        );
        storage.save_credentials(&store).unwrap();
        let loaded = storage.load_credentials().unwrap();
        assert!(loaded.users.contains_key("root"));
    }

    #[test]
    fn test_challenge_lifecycle() {
        let (storage, _dir) = test_storage();
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let state = ChallengeState {
            challenge_type: ChallengeType::Registration,
            username: "root".to_string(),
            rp_id: "192.168.1.1".to_string(),
            state: "test_state_data".to_string(),
            created_at: now_iso8601(),
        };

        storage.save_challenge(&challenge_id, &state).unwrap();
        let loaded = storage.load_challenge(&challenge_id).unwrap();
        assert_eq!(loaded.username, "root");
        assert_eq!(loaded.challenge_type, ChallengeType::Registration);

        storage.delete_challenge(&challenge_id).unwrap();
        assert!(storage.load_challenge(&challenge_id).is_err());
    }

    #[test]
    fn test_challenge_not_found() {
        let (storage, _dir) = test_storage();
        let result = storage.load_challenge("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_challenges() {
        let (storage, _dir) = test_storage();
        let result = storage.cleanup_challenges().unwrap();
        assert_eq!(result, 0);
    }
}
