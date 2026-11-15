use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::auth::{AllowedCredentials, AuthenticationVerificationOptions, DiscoverableCredentialRequestOptions};
use webauthn_rp::request::register::UserHandle64;
use webauthn_rp::request::{AsciiDomain, Credentials, PublicKeyCredentialDescriptor, RpId};
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, Backup, CredentialId};
use webauthn_rp::{
    AuthenticatedCredential, DiscoverableAuthentication64, DiscoverableAuthenticationServerState, NonDiscoverableAuthentication64,
    NonDiscoverableAuthenticationServerState, NonDiscoverableCredentialRequestOptions,
};

use crate::errors::AppError;
use crate::schemas::{LoginFinishData, SuccessResponse};
use crate::storage::*;

/// Public key types of a stored credential.
type StoredPubKey = CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>;

/// Type alias for the decoded StaticState with compressed public key types.
type StoredStaticState = StaticState<StoredPubKey>;

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

fn save_login_challenge(
    storage: &dyn StorageProvider,
    challenge_type: ChallengeType,
    username: &str,
    rp_id: &str,
    state_bytes: Vec<u8>,
    client_state: serde_json::Value,
) -> Result<String, AppError> {
    let challenge_id = Uuid::new_v4().to_string();
    let challenge_state = ChallengeState {
        challenge_type,
        username: username.to_string(),
        rp_id: rp_id.to_string(),
        state: URL_SAFE_NO_PAD.encode(&state_bytes),
        created_at: now_iso8601(),
    };
    storage.save_challenge(&challenge_id, &challenge_state)?;

    let data = serde_json::json!({
        "publicKey": client_state,
        "challengeId": challenge_id,
    });
    Ok(serde_json::to_string(&SuccessResponse::new(data))?)
}

/// Start a login for a named user, listing that user's credentials.
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

    let mut allowed_creds = AllowedCredentials::with_capacity(user_record.credentials.len());
    for cred in &user_record.credentials {
        let id_bytes = URL_SAFE_NO_PAD
            .decode(&cred.credential_id)
            .map_err(|e| AppError::Storage(format!("Failed to decode credential ID: {}", e)))?;
        let cred_id = CredentialId::<Vec<u8>>::decode(id_bytes).map_err(|e| AppError::Storage(format!("Invalid credential ID: {}", e)))?;
        let transports =
            AuthTransports::decode(cred.transports).unwrap_or_else(|_| AuthTransports::decode(0u8).expect("zero is always valid"));
        allowed_creds.push(PublicKeyCredentialDescriptor { id: cred_id, transports }.into());
    }

    let options =
        NonDiscoverableCredentialRequestOptions::second_factor(&rp, allowed_creds).map_err(|e| AppError::WebAuthn(e.to_string()))?;
    let (server_state, client_state) = options.start_ceremony().map_err(|e| AppError::WebAuthn(e.to_string()))?;
    let state_bytes = server_state
        .encode()
        .map_err(|e| AppError::WebAuthn(format!("Failed to encode server state: {}", e)))?;

    save_login_challenge(
        storage,
        ChallengeType::Authentication,
        username,
        rp_id,
        state_bytes,
        serde_json::to_value(&client_state)?,
    )
}

/// Start a passwordless login: no username, an empty allow list, and user
/// verification required. The authenticator picks a discoverable credential
/// and returns its user handle, which identifies the user in login-finish.
pub fn login_begin_discoverable(storage: &dyn StorageProvider, rp_id: &str) -> Result<String, AppError> {
    let rp = make_rp_id(rp_id)?;

    let store = storage.load_credentials()?;
    if store.users.values().all(|u| u.credentials.is_empty()) {
        return Err(AppError::CredentialNotFound("No credentials registered".to_string()));
    }

    let options = DiscoverableCredentialRequestOptions::passkey(&rp);
    let (server_state, client_state) = options.start_ceremony().map_err(|e| AppError::WebAuthn(e.to_string()))?;
    let state_bytes = server_state
        .encode()
        .map_err(|e| AppError::WebAuthn(format!("Failed to encode server state: {}", e)))?;

    save_login_challenge(
        storage,
        ChallengeType::DiscoverableAuthentication,
        "",
        rp_id,
        state_bytes,
        serde_json::to_value(&client_state)?,
    )
}

/// Rebuild the credential the library verifies against from its stored form.
fn stored_credential<'a>(
    raw_id: CredentialId<&'a [u8]>,
    user_handle: &'a UserHandle64,
    cred: &StoredCredential,
) -> Result<AuthenticatedCredential<'a, 'a, 64, StoredPubKey>, AppError> {
    let static_state_bytes = URL_SAFE_NO_PAD
        .decode(&cred.static_state)
        .map_err(|e| AppError::Storage(format!("Failed to decode static state: {}", e)))?;
    let static_state: StoredStaticState = StaticState::decode(static_state_bytes.as_slice())
        .map_err(|e| AppError::Storage(format!("Failed to decode static state: {}", e)))?;

    let dynamic_state_bytes = URL_SAFE_NO_PAD
        .decode(&cred.dynamic_state)
        .map_err(|e| AppError::Storage(format!("Failed to decode dynamic state: {}", e)))?;
    let ds_array: [u8; 7] = dynamic_state_bytes
        .try_into()
        .map_err(|_| AppError::Storage("Invalid dynamic state length".to_string()))?;
    let dynamic_state = DynamicState::decode(ds_array).map_err(|e| AppError::Storage(format!("Failed to decode dynamic state: {}", e)))?;

    AuthenticatedCredential::new(raw_id, user_handle, static_state, dynamic_state)
        .map_err(|e| AppError::WebAuthn(format!("Failed to create authenticated credential: {}", e)))
}

fn decode_user_handle(b64: &str) -> Result<UserHandle64, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| AppError::Storage(format!("Failed to decode user handle: {}", e)))?;
    let array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| AppError::Storage("Invalid user handle length".to_string()))?;
    UserHandle64::decode(array).map_err(|e| AppError::Storage(format!("Failed to decode user handle: {}", e)))
}

/// Store the credential's new dynamic state (sign count, flags) after a
/// successful assertion. The caller holds the store lock.
fn record_use(storage: &dyn StorageProvider, username: &str, credential_id: &str, new_ds: DynamicState) -> Result<(), AppError> {
    let mut store = storage.load_credentials()?;
    if let Some(user_record) = store.users.get_mut(username) {
        if let Some(cred) = user_record.credentials.iter_mut().find(|c| c.credential_id == credential_id) {
            let ds_bytes = new_ds.encode().expect("DynamicState encode is infallible");
            cred.dynamic_state = URL_SAFE_NO_PAD.encode(ds_bytes);
            cred.sign_count = new_ds.sign_count;
            cred.user_verified = new_ds.user_verified;
            cred.backup_eligible = !matches!(new_ds.backup, Backup::NotEligible);
            cred.last_used_at = Some(now_iso8601());
        }
    }
    storage.save_credentials(&store)
}

/// `input` is the client's assertion JSON (read from stdin by the CLI).
pub fn login_finish(storage: &dyn StorageProvider, challenge_id: &str, origin_str: &str, input: &str) -> Result<String, AppError> {
    let challenge = storage.load_challenge(challenge_id)?;
    // A challenge is good for one attempt, whatever its outcome.
    storage.delete_challenge(challenge_id)?;

    if challenge.challenge_type == ChallengeType::Registration {
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

    let state_bytes = URL_SAFE_NO_PAD
        .decode(&challenge.state)
        .map_err(|e| AppError::Storage(format!("Failed to decode server state: {}", e)))?;

    let ver_opts: AuthenticationVerificationOptions<'_, '_, String, String> = AuthenticationVerificationOptions {
        allowed_origins: &[origin_str.to_string()],
        error_on_unsolicited_extensions: false,
        update_uv: true,
        ..Default::default()
    };

    let _lock = storage.lock()?;
    let store = storage.load_credentials()?;

    let (username, credential_id, new_ds) = if challenge.challenge_type == ChallengeType::DiscoverableAuthentication {
        let server_state = DiscoverableAuthenticationServerState::decode(state_bytes.as_slice())
            .map_err(|e| AppError::Storage(format!("Failed to decode authentication state: {}", e)))?;
        let auth_response = DiscoverableAuthentication64::from_json_relaxed(input.as_bytes())
            .map_err(|e| AppError::InvalidInput(format!("Invalid client response: {}", e)))?;

        let handle_b64 = URL_SAFE_NO_PAD.encode(
            auth_response
                .response()
                .user_handle()
                .encode()
                .expect("UserHandle encode is infallible"),
        );
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(auth_response.raw_id().as_ref());

        let (username, stored_cred) = store
            .users
            .iter()
            .find_map(|(name, rec)| {
                rec.credentials
                    .iter()
                    .find(|c| c.credential_id == cred_id_b64 && c.user_handle == handle_b64)
                    .map(|c| (name.clone(), c))
            })
            .ok_or_else(|| AppError::CredentialNotFound("No matching credential found".to_string()))?;

        let user_handle = decode_user_handle(&stored_cred.user_handle)?;
        let mut auth_cred = stored_credential(auth_response.raw_id(), &user_handle, stored_cred)?;
        server_state
            .verify(&rp, &auth_response, &mut auth_cred, &ver_opts)
            .map_err(|e| AppError::WebAuthn(e.to_string()))?;

        (username, cred_id_b64, auth_cred.dynamic_state())
    } else {
        let server_state = NonDiscoverableAuthenticationServerState::decode(state_bytes.as_slice())
            .map_err(|e| AppError::Storage(format!("Failed to decode authentication state: {}", e)))?;
        let auth_response = NonDiscoverableAuthentication64::from_json_relaxed(input.as_bytes())
            .map_err(|e| AppError::InvalidInput(format!("Invalid client response: {}", e)))?;

        let user_record = store
            .users
            .get(&challenge.username)
            .ok_or_else(|| AppError::UserNotFound(challenge.username.clone()))?;
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(auth_response.raw_id().as_ref());
        let stored_cred = user_record
            .credentials
            .iter()
            .find(|c| c.credential_id == cred_id_b64)
            .ok_or_else(|| AppError::CredentialNotFound("No matching credential found".to_string()))?;

        let user_handle = decode_user_handle(&stored_cred.user_handle)?;
        let mut auth_cred = stored_credential(auth_response.raw_id(), &user_handle, stored_cred)?;
        server_state
            .verify(&rp, &auth_response, &mut auth_cred, &ver_opts)
            .map_err(|e| AppError::WebAuthn(e.to_string()))?;

        (challenge.username.clone(), cred_id_b64, auth_cred.dynamic_state())
    };

    record_use(storage, &username, &credential_id, new_ds)?;

    let data = LoginFinishData {
        username,
        user_verified: new_ds.user_verified,
        counter: new_ds.sign_count,
    };
    Ok(serde_json::to_string(&SuccessResponse::new(data))?)
}
