use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::register::{PublicKeyCredentialUserEntity, RegistrationVerificationOptions, UserHandle64};
use webauthn_rp::request::{AsciiDomain, PublicKeyCredentialDescriptor, RpId};
use webauthn_rp::response::{AuthTransports, Backup, CredentialId};
use webauthn_rp::{PublicKeyCredentialCreationOptions, Registration, RegistrationServerState};

use crate::errors::AppError;
use crate::schemas::{RegisterFinishData, SuccessResponse};
use crate::storage::*;

fn make_rp_id(rp_id: &str) -> Result<RpId, AppError> {
    AsciiDomain::try_from(rp_id.to_owned())
        .map(RpId::Domain)
        .map_err(|e| AppError::InvalidInput(format!("Invalid RP ID: {}", e)))
}

fn format_aaguid(bytes: &[u8]) -> String {
    let hex = data_encoding::HEXLOWER.encode(bytes);
    if hex.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    } else {
        "00000000-0000-0000-0000-000000000000".to_string()
    }
}

fn extract_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("https://").or_else(|| origin.strip_prefix("http://"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    Some(authority.rsplit_once(':').map_or(authority, |(h, _)| h))
}

pub fn register_begin(storage: &dyn StorageProvider, username: &str, rp_id: &str, _user_verification: &str) -> Result<String, AppError> {
    let rp = make_rp_id(rp_id)?;
    let store = storage.load_credentials()?;

    // Generate or load user handle and build exclude credentials
    let (user_handle, exclude_creds) = if let Some(user_record) = store.users.get(username) {
        let uh_bytes = URL_SAFE_NO_PAD
            .decode(&user_record.user_id)
            .map_err(|e| AppError::Storage(format!("Failed to decode user handle: {}", e)))?;
        let uh_array: [u8; 64] = uh_bytes
            .try_into()
            .map_err(|_| AppError::Storage("Invalid user handle length".to_string()))?;
        let uh = UserHandle64::decode(uh_array).map_err(|e| AppError::Storage(format!("Failed to decode user handle: {}", e)))?;

        let creds: Vec<PublicKeyCredentialDescriptor<Vec<u8>>> = user_record
            .credentials
            .iter()
            .filter_map(|c| {
                let id_bytes = URL_SAFE_NO_PAD.decode(&c.credential_id).ok()?;
                let cred_id = CredentialId::<Vec<u8>>::decode(id_bytes).ok()?;
                let transports = AuthTransports::decode(c.transports).unwrap_or(AuthTransports::decode(0).unwrap());
                Some(PublicKeyCredentialDescriptor { id: cred_id, transports })
            })
            .collect();
        (uh, creds)
    } else {
        (UserHandle64::new(), vec![])
    };

    let user_entity = PublicKeyCredentialUserEntity {
        name: username
            .try_into()
            .map_err(|e| AppError::InvalidInput(format!("Invalid username: {}", e)))?,
        id: &user_handle,
        display_name: Some(
            username
                .try_into()
                .map_err(|e| AppError::InvalidInput(format!("Invalid display name: {}", e)))?,
        ),
    };

    let options = PublicKeyCredentialCreationOptions::passkey(&rp, user_entity, exclude_creds);
    let (server_state, client_state) = options.start_ceremony().map_err(|e| AppError::WebAuthn(e.to_string()))?;

    // Encode server state to binary and base64
    let state_bytes = server_state
        .encode()
        .map_err(|e| AppError::WebAuthn(format!("Failed to encode server state: {}", e)))?;
    let state_b64 = URL_SAFE_NO_PAD.encode(&state_bytes);

    let challenge_id = Uuid::new_v4().to_string();
    let challenge_state = ChallengeState {
        challenge_type: ChallengeType::Registration,
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

pub fn register_finish(storage: &dyn StorageProvider, challenge_id: &str, origin_str: &str, device_name: &str) -> Result<String, AppError> {
    let challenge = storage.load_challenge(challenge_id)?;
    if challenge.challenge_type != ChallengeType::Registration {
        return Err(AppError::InvalidInput("Challenge is not a registration challenge".to_string()));
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
    let server_state = RegistrationServerState::<64>::decode(state_bytes.as_slice())
        .map_err(|e| AppError::Storage(format!("Failed to decode registration state: {}", e)))?;

    // Read client response from stdin
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let registration =
        Registration::from_json_relaxed(input.as_bytes()).map_err(|e| AppError::InvalidInput(format!("Invalid client response: {}", e)))?;

    // Verify registration
    let ver_opts: RegistrationVerificationOptions<'_, '_, String, String> = RegistrationVerificationOptions {
        allowed_origins: &[origin_str.to_string()],
        error_on_unsolicited_extensions: false,
        ..Default::default()
    };
    let credential = server_state
        .verify(&rp, &registration, &ver_opts)
        .map_err(|e| AppError::WebAuthn(e.to_string()))?;

    let (cred_id, transports, user_id, static_state, dynamic_state, metadata) = credential.into_parts();

    let credential_id_str = URL_SAFE_NO_PAD.encode(cred_id.as_ref());
    let created_at = now_iso8601();
    let aaguid = format_aaguid(metadata.aaguid.data());

    // Encode parts for storage (these use Infallible error types)
    let static_state_bytes = static_state.encode().expect("StaticState encode is infallible");
    let static_state_b64 = URL_SAFE_NO_PAD.encode(&static_state_bytes);

    let dynamic_state_bytes = dynamic_state.encode().expect("DynamicState encode is infallible");
    let dynamic_state_b64 = URL_SAFE_NO_PAD.encode(dynamic_state_bytes);

    let user_handle_bytes = user_id.encode().expect("UserHandle encode is infallible");
    let user_handle_b64 = URL_SAFE_NO_PAD.encode(user_handle_bytes);

    let transports_u8 = transports.encode().expect("AuthTransports encode is infallible");
    let backup_eligible = !matches!(dynamic_state.backup, Backup::NotEligible);

    // Save credential
    let mut store = storage.load_credentials()?;
    let user_record = store.users.entry(challenge.username.clone()).or_insert_with(|| UserRecord {
        user_id: user_handle_b64.clone(),
        credentials: vec![],
    });

    user_record.credentials.push(StoredCredential {
        credential_id: credential_id_str.clone(),
        device_name: device_name.to_string(),
        static_state: static_state_b64,
        dynamic_state: dynamic_state_b64,
        user_handle: user_handle_b64,
        transports: transports_u8,
        created_at: created_at.clone(),
        last_used_at: None,
        backup_eligible,
        user_verified: dynamic_state.user_verified,
        sign_count: dynamic_state.sign_count,
    });
    storage.save_credentials(&store)?;

    storage.delete_challenge(challenge_id)?;

    let data = RegisterFinishData {
        credential_id: credential_id_str,
        aaguid,
        created_at,
    };
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}
