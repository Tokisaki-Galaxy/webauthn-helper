use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::auth::{AllowedCredentials, AuthenticationVerificationOptions};
use webauthn_rp::request::register::UserHandle64;
use webauthn_rp::request::{AsciiDomain, Credentials, PublicKeyCredentialDescriptor, RpId};
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, Backup, CredentialId};
use webauthn_rp::{
    AuthenticatedCredential, NonDiscoverableAuthentication64, NonDiscoverableAuthenticationServerState,
    NonDiscoverableCredentialRequestOptions,
};

use crate::errors::AppError;
use crate::schemas::{LoginFinishData, SuccessResponse};
use crate::storage::*;

fn make_rp_id(rp_id: &str) -> Result<RpId, AppError> {
    AsciiDomain::try_from(rp_id.to_owned())
        .map(RpId::Domain)
        .map_err(|e| AppError::InvalidInput(format!("Invalid RP ID: {}", e)))
}

fn extract_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("https://").or_else(|| origin.strip_prefix("http://"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    Some(authority.rsplit_once(':').map_or(authority, |(h, _)| h))
}

pub fn login_begin(storage: &dyn StorageProvider, username: &str, rp_id: &str) -> Result<String, AppError> {
    let rp = make_rp_id(rp_id)?;

    let store = storage.load_credentials()?;
    let user_record = store
        .users
        .get(username)
        .ok_or_else(|| AppError::UserNotFound(username.to_string()))?;

    if user_record.credentials.is_empty() {
        return Err(AppError::UserNotFound(format!("No credentials found for user: {}", username)));
    }

    // Build AllowedCredentials
    let mut allowed_creds = AllowedCredentials::with_capacity(user_record.credentials.len());
    for cred in &user_record.credentials {
        let id_bytes = URL_SAFE_NO_PAD
            .decode(&cred.credential_id)
            .map_err(|e| AppError::Storage(format!("Failed to decode credential ID: {}", e)))?;
        let cred_id = CredentialId::<Vec<u8>>::decode(id_bytes).map_err(|e| AppError::Storage(format!("Invalid credential ID: {}", e)))?;
        let transports = AuthTransports::decode(cred.transports).unwrap_or(AuthTransports::decode(0).unwrap());
        allowed_creds.push(PublicKeyCredentialDescriptor { id: cred_id, transports }.into());
    }

    let options =
        NonDiscoverableCredentialRequestOptions::second_factor(&rp, allowed_creds).map_err(|e| AppError::WebAuthn(e.to_string()))?;

    let (server_state, client_state) = options.start_ceremony().map_err(|e| AppError::WebAuthn(e.to_string()))?;

    // Encode server state
    let state_bytes = server_state
        .encode()
        .map_err(|e| AppError::WebAuthn(format!("Failed to encode server state: {}", e)))?;
    let state_b64 = URL_SAFE_NO_PAD.encode(&state_bytes);

    let challenge_id = Uuid::new_v4().to_string();
    let challenge_state = ChallengeState {
        challenge_type: ChallengeType::Authentication,
        username: username.to_string(),
        rp_id: rp_id.to_string(),
        state: state_b64,
        created_at: now_iso8601(),
    };
    storage.save_challenge(&challenge_id, &challenge_state)?;

    let public_key = serde_json::to_value(&client_state)?;
    let data = serde_json::json!({
        "publicKey": public_key,
        "challengeId": challenge_id,
    });
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}

pub fn login_finish(storage: &dyn StorageProvider, challenge_id: &str, origin_str: &str) -> Result<String, AppError> {
    let challenge = storage.load_challenge(challenge_id)?;
    if challenge.challenge_type != ChallengeType::Authentication {
        return Err(AppError::InvalidInput(
            "Challenge is not an authentication challenge".to_string(),
        ));
    }

    let origin_host = extract_host(origin_str).ok_or_else(|| AppError::InvalidOrigin("Origin has no host".to_string()))?;
    if origin_host != challenge.rp_id {
        return Err(AppError::InvalidOrigin(format!(
            "Origin {} does not match RP ID {}",
            origin_str, challenge.rp_id
        )));
    }

    let rp = make_rp_id(&challenge.rp_id)?;

    // Decode server state
    let state_bytes = URL_SAFE_NO_PAD
        .decode(&challenge.state)
        .map_err(|e| AppError::Storage(format!("Failed to decode server state: {}", e)))?;
    let server_state = NonDiscoverableAuthenticationServerState::decode(state_bytes.as_slice())
        .map_err(|e| AppError::Storage(format!("Failed to decode authentication state: {}", e)))?;

    // Read client response from stdin
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let auth_response = NonDiscoverableAuthentication64::from_json_relaxed(input.as_bytes())
        .map_err(|e| AppError::InvalidInput(format!("Invalid client response: {}", e)))?;

    // Find matching credential
    let store = storage.load_credentials()?;
    let user_record = store
        .users
        .get(&challenge.username)
        .ok_or_else(|| AppError::UserNotFound(challenge.username.clone()))?;

    let response_cred_id_b64 = URL_SAFE_NO_PAD.encode(auth_response.raw_id().as_ref());

    let stored_cred = user_record
        .credentials
        .iter()
        .find(|c| c.credential_id == response_cred_id_b64)
        .ok_or_else(|| AppError::CredentialNotFound("No matching credential found".to_string()))?;

    // Decode stored credential data
    let static_state_bytes = URL_SAFE_NO_PAD
        .decode(&stored_cred.static_state)
        .map_err(|e| AppError::Storage(format!("Failed to decode static state: {}", e)))?;
    let static_state: StaticState<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>> =
        StaticState::decode(static_state_bytes.as_slice())
            .map_err(|e| AppError::Storage(format!("Failed to decode static state: {}", e)))?;

    let dynamic_state_bytes = URL_SAFE_NO_PAD
        .decode(&stored_cred.dynamic_state)
        .map_err(|e| AppError::Storage(format!("Failed to decode dynamic state: {}", e)))?;
    let ds_array: [u8; 7] = dynamic_state_bytes
        .try_into()
        .map_err(|_| AppError::Storage("Invalid dynamic state length".to_string()))?;
    let dynamic_state = DynamicState::decode(ds_array).map_err(|e| AppError::Storage(format!("Failed to decode dynamic state: {}", e)))?;

    let user_handle_bytes = URL_SAFE_NO_PAD
        .decode(&stored_cred.user_handle)
        .map_err(|e| AppError::Storage(format!("Failed to decode user handle: {}", e)))?;
    let uh_array: [u8; 64] = user_handle_bytes
        .try_into()
        .map_err(|_| AppError::Storage("Invalid user handle length".to_string()))?;
    let user_handle = UserHandle64::decode(uh_array).map_err(|e| AppError::Storage(format!("Failed to decode user handle: {}", e)))?;

    // Build AuthenticatedCredential
    let mut auth_cred = AuthenticatedCredential::new(auth_response.raw_id(), &user_handle, static_state, dynamic_state)
        .map_err(|e| AppError::WebAuthn(format!("Failed to create authenticated credential: {}", e)))?;

    // Verify authentication
    let ver_opts: AuthenticationVerificationOptions<'_, '_, String, String> = AuthenticationVerificationOptions {
        allowed_origins: &[origin_str.to_string()],
        error_on_unsolicited_extensions: false,
        update_uv: true,
        ..Default::default()
    };
    server_state
        .verify(&rp, &auth_response, &mut auth_cred, &ver_opts)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?;

    let new_ds = auth_cred.dynamic_state();
    let user_verified = new_ds.user_verified;
    let counter = new_ds.sign_count;

    // Update credential state
    let mut store = storage.load_credentials()?;
    if let Some(user_record) = store.users.get_mut(&challenge.username) {
        for cred in &mut user_record.credentials {
            if cred.credential_id == response_cred_id_b64 {
                let ds_bytes = new_ds.encode().expect("DynamicState encode is infallible");
                cred.dynamic_state = URL_SAFE_NO_PAD.encode(ds_bytes);
                cred.sign_count = new_ds.sign_count;
                cred.user_verified = new_ds.user_verified;
                cred.backup_eligible = !matches!(new_ds.backup, Backup::NotEligible);
                cred.last_used_at = Some(now_iso8601());
                break;
            }
        }
    }
    storage.save_credentials(&store)?;

    storage.delete_challenge(challenge_id)?;

    let data = LoginFinishData {
        username: challenge.username,
        user_verified,
        counter,
    };
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}
