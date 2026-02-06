use std::time::Duration;

use url::Url;
use uuid::Uuid;
use webauthn_rs_core::proto::*;
use webauthn_rs_core::WebauthnCore;

use crate::errors::AppError;
use crate::schemas::{RegisterFinishData, SuccessResponse};
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

fn parse_user_verification(uv: &str) -> UserVerificationPolicy {
    match uv {
        "required" => UserVerificationPolicy::Required,
        "discouraged" => UserVerificationPolicy::Discouraged_DO_NOT_USE,
        _ => UserVerificationPolicy::Preferred,
    }
}

pub fn register_begin(storage: &dyn StorageProvider, username: &str, rp_id: &str, user_verification: &str) -> Result<String, AppError> {
    let origin = Url::parse(&format!("https://{}", rp_id)).map_err(|e| AppError::InvalidInput(format!("Invalid RP ID: {}", e)))?;
    let core = build_webauthn_core(rp_id, &origin);

    // Load existing credentials to get user_id and exclude list
    let store = storage.load_credentials()?;
    let (user_id, exclude_creds) = if let Some(user_record) = store.users.get(username) {
        let exclude: Vec<CredentialID> = user_record.credentials.iter().map(|c| c.credential.cred_id.clone()).collect();
        (user_record.user_id, Some(exclude))
    } else {
        (Uuid::new_v4(), None)
    };

    let policy = parse_user_verification(user_verification);

    let extensions = Some(RequestRegistrationExtensions {
        cred_protect: Some(CredProtect {
            credential_protection_policy: CredentialProtectionPolicy::UserVerificationRequired,
            enforce_credential_protection_policy: Some(false),
        }),
        uvm: Some(true),
        cred_props: Some(true),
        min_pin_length: None,
        hmac_create_secret: None,
    });

    let builder = core
        .new_challenge_register_builder(user_id.as_bytes(), username, username)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?
        .attestation(AttestationConveyancePreference::None)
        .credential_algorithms(COSEAlgorithm::secure_algs())
        .require_resident_key(false)
        .authenticator_attachment(None)
        .user_verification_policy(policy)
        .reject_synchronised_authenticators(false)
        .exclude_credentials(exclude_creds)
        .hints(None)
        .extensions(extensions);

    let (ccr, reg_state) = core
        .generate_challenge_register(builder)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?;

    // Save challenge state
    let challenge_id = Uuid::new_v4().to_string();
    let state = ChallengeState {
        challenge_type: ChallengeType::Registration,
        username: username.to_string(),
        rp_id: rp_id.to_string(),
        state: serde_json::to_value(&reg_state)?,
        created_at: now_iso8601(),
    };
    storage.save_challenge(&challenge_id, &state)?;

    // Build output: merge CreationChallengeResponse with challengeId
    let output = serde_json::to_value(&ccr)?;
    let data = serde_json::json!({
        "publicKey": output.get("publicKey").cloned().unwrap_or(output.clone()),
        "challengeId": challenge_id,
    });
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}

pub fn register_finish(storage: &dyn StorageProvider, challenge_id: &str, origin_str: &str, device_name: &str) -> Result<String, AppError> {
    // Load challenge state
    let challenge = storage.load_challenge(challenge_id)?;
    if challenge.challenge_type != ChallengeType::Registration {
        return Err(AppError::InvalidInput("Challenge is not a registration challenge".to_string()));
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

    // Deserialize registration state
    let reg_state: RegistrationState = serde_json::from_value(challenge.state)
        .map_err(|e| AppError::Storage(format!("Failed to deserialize registration state: {}", e)))?;

    // Read client response from STDIN
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let reg_cred: RegisterPublicKeyCredential =
        serde_json::from_str(&input).map_err(|e| AppError::InvalidInput(format!("Invalid client response: {}", e)))?;

    // Finish registration
    let credential = core
        .register_credential(&reg_cred, &reg_state, None)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?;

    let credential_id = encode_credential_id(&credential.cred_id);
    let created_at = now_iso8601();

    // Save credential
    let mut store = storage.load_credentials()?;
    let user_record = store.users.entry(challenge.username.clone()).or_insert_with(|| UserRecord {
        user_id: Uuid::new_v4(),
        credentials: vec![],
    });

    user_record.credentials.push(StoredCredential {
        credential_id: credential_id.clone(),
        device_name: device_name.to_string(),
        credential,
        created_at: created_at.clone(),
        last_used_at: None,
        backup_eligible: false,
        user_verified: false,
    });
    storage.save_credentials(&store)?;

    // Delete challenge
    storage.delete_challenge(challenge_id)?;

    let data = RegisterFinishData {
        credential_id,
        aaguid: "00000000-0000-0000-0000-000000000000".to_string(),
        created_at,
    };
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}
