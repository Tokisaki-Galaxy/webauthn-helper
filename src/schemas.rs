use serde::Serialize;

#[derive(Serialize)]
pub struct SuccessResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorDetail,
}

#[derive(Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl<T: Serialize> SuccessResponse<T> {
    pub fn new(data: T) -> Self {
        Self { success: true, data }
    }
}

impl ErrorResponse {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            success: false,
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }
    }
}

/// Schema B: Register Finish Output
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishData {
    pub credential_id: String,
    pub aaguid: String,
    pub created_at: String,
}

/// Schema D: Login Finish Output
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishData {
    pub username: String,
    pub user_verified: bool,
    pub counter: u32,
}

/// Schema E: Credential List Item
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialListItem {
    pub credential_id: String,
    pub username: String,
    pub device_name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    pub backup_eligible: bool,
    pub user_verified: bool,
}

/// Schema F: Credential Update Output
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialUpdateData {
    pub credential_id: String,
    pub old_name: String,
    pub new_name: String,
}

/// Schema G: Health Check Output
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckData {
    pub status: String,
    pub version: String,
    pub storage: StorageStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageStatus {
    pub writable: bool,
    pub path: String,
    pub count: usize,
}
