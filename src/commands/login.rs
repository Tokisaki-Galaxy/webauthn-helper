use std::time::Duration;

use url::Url;
use uuid::Uuid;
use webauthn_rs_core::proto::*;
use webauthn_rs_core::WebauthnCore;

use crate::errors::AppError;
use crate::schemas::{LoginFinishData, SuccessResponse};
use crate::storage::*;

fn build_webauthn_core(rp_id: &str, origin: &Url) -> WebauthnCore {
    WebauthnCore::new_unsafe_experts_only(
        "OpenWrt",
        rp_id,
        vec![origin.clone()],
        Duration::from_secs(60),
        None,
        Some(true),
    )
}

pub fn login_begin(storage: &dyn StorageProvider, username: &str, rp_id: &str) -> Result<String, AppError> {
    let origin = Url::parse(&format!("https://{}", rp_id)).map_err(|e| AppError::InvalidInput(format!("Invalid RP ID: {}", e)))?;
    let core = build_webauthn_core(rp_id, &origin);

    // Load user credentials
    let store = storage.load_credentials()?;
    let user_record = store
        .users
        .get(username)
        .ok_or_else(|| AppError::UserNotFound(username.to_string()))?;

    if user_record.credentials.is_empty() {
        return Err(AppError::UserNotFound(format!("No credentials found for user: {}", username)));
    }

    let creds: Vec<Credential> = user_record.credentials.iter().map(|c| c.credential.clone()).collect();

    let builder = core
        .new_challenge_authenticate_builder(creds, Some(UserVerificationPolicy::Preferred))
        .map_err(|e| AppError::WebAuthn(e.to_string()))?
        .allow_backup_eligible_upgrade(true);

    let (rcr, auth_state) = core
        .generate_challenge_authenticate(builder)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?;

    // Save challenge state
    let challenge_id = Uuid::new_v4().to_string();
    let state = ChallengeState {
        challenge_type: ChallengeType::Authentication,
        username: username.to_string(),
        rp_id: rp_id.to_string(),
        state: serde_json::to_value(&auth_state)?,
        created_at: now_iso8601(),
    };
    storage.save_challenge(&challenge_id, &state)?;

    // Build output: merge RequestChallengeResponse with challengeId
    let output = serde_json::to_value(&rcr)?;
    let data = serde_json::json!({
        "publicKey": output.get("publicKey").cloned().unwrap_or(output.clone()),
        "challengeId": challenge_id,
    });
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}

pub fn login_finish(storage: &dyn StorageProvider, challenge_id: &str, origin_str: &str) -> Result<String, AppError> {
    // Load challenge state
    let challenge = storage.load_challenge(challenge_id)?;
    if challenge.challenge_type != ChallengeType::Authentication {
        return Err(AppError::InvalidInput(
            "Challenge is not an authentication challenge".to_string(),
        ));
    }

    // Parse origin and validate against RP ID
    let origin = Url::parse(origin_str).map_err(|e| AppError::InvalidOrigin(format!("Invalid origin URL: {}", e)))?;
    let origin_host = origin
        .host_str()
        .ok_or_else(|| AppError::InvalidOrigin("Origin has no host".to_string()))?;
    if origin_host != challenge.rp_id {
        return Err(AppError::InvalidOrigin(format!(
            "Origin {} does not match RP ID {}",
            origin_str, challenge.rp_id
        )));
    }

    let core = build_webauthn_core(&challenge.rp_id, &origin);

    // Deserialize authentication state
    let auth_state: AuthenticationState = serde_json::from_value(challenge.state)
        .map_err(|e| AppError::Storage(format!("Failed to deserialize authentication state: {}", e)))?;

    // Read client response from STDIN
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let auth_cred: PublicKeyCredential =
        serde_json::from_str(&input).map_err(|e| AppError::InvalidInput(format!("Invalid client response: {}", e)))?;

    // Finish authentication
    let auth_result = core
        .authenticate_credential(&auth_cred, &auth_state)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?;

    let user_verified = auth_result.user_verified();
    let counter = auth_result.counter();

    // Update credential state (counter, last_used_at, backup flags)
    let mut store = storage.load_credentials()?;
    if let Some(user_record) = store.users.get_mut(&challenge.username) {
        for cred in &mut user_record.credentials {
            if cred.credential.cred_id == *auth_result.cred_id() {
                // Update counter
                if auth_result.counter() > cred.credential.counter {
                    cred.credential.counter = auth_result.counter();
                }
                // Update backup state
                if auth_result.backup_state() != cred.credential.backup_state {
                    cred.credential.backup_state = auth_result.backup_state();
                }
                if auth_result.backup_eligible() && !cred.credential.backup_eligible {
                    cred.credential.backup_eligible = true;
                }
                cred.last_used_at = Some(now_iso8601());
                cred.user_verified = user_verified;
                cred.backup_eligible = cred.credential.backup_eligible;
                break;
            }
        }
    }
    storage.save_credentials(&store)?;

    // Delete challenge
    storage.delete_challenge(challenge_id)?;

    let data = LoginFinishData {
        username: challenge.username,
        user_verified,
        counter,
    };
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}
