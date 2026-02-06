use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Invalid origin: {0}")]
    InvalidOrigin(String),

    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl AppError {
    pub fn error_code(&self) -> &str {
        match self {
            AppError::ChallengeNotFound(_) => "CHALLENGE_NOT_FOUND",
            AppError::UserNotFound(_) => "USER_NOT_FOUND",
            AppError::CredentialNotFound(_) => "CREDENTIAL_NOT_FOUND",
            AppError::InvalidOrigin(_) => "INVALID_ORIGIN",
            AppError::WebAuthn(_) => "WEBAUTHN_ERROR",
            AppError::Storage(_) => "STORAGE_ERROR",
            AppError::Json(_) => "JSON_ERROR",
            AppError::Io(_) => "IO_ERROR",
            AppError::InvalidInput(_) => "INVALID_INPUT",
        }
    }
}
