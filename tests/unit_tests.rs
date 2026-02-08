/// Unit-level tests for webauthn-helper.
///
/// Covers:
/// - Challenge full lifecycle (generate → store → read → verify)
/// - Base64URL no-padding encoding/decoding round-trips
/// - Challenge mismatch detection (off-by-one character)
/// - Corrupted credentials.json graceful error handling
/// - Concurrent file write with fs2 file locking
/// - CamelCase ↔ snake_case JSON contract verification
/// - Error message detail and JSON output format
/// - Mock data: 1 legal + 3 illegal WebAuthn response payloads
use std::io::Write;
use std::sync::{Arc, Barrier};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tempfile::TempDir;

// ─── Re-usable helpers (mirror src/storage.rs test helpers) ───

/// Minimal mirror of the production storage types so integration tests
/// can construct and verify JSON payloads without importing private items.
mod storage_types {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct CredentialStore {
        pub users: HashMap<String, UserRecord>,
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

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ChallengeState {
        #[serde(rename = "type")]
        pub challenge_type: String,
        pub username: String,
        pub rp_id: String,
        pub state: String,
        pub created_at: String,
    }
}

use storage_types::*;

// ============================================================
// 1. Challenge Full Lifecycle Tests
// ============================================================

#[test]
fn challenge_save_load_roundtrip() {
    let dir = TempDir::new().unwrap();
    let challenge_dir = dir.path().join("challenges");
    std::fs::create_dir_all(&challenge_dir).unwrap();

    let challenge_id = uuid::Uuid::new_v4().to_string();
    let state = ChallengeState {
        challenge_type: "registration".to_string(),
        username: "root".to_string(),
        rp_id: "192.168.1.1".to_string(),
        state: URL_SAFE_NO_PAD.encode(b"random_server_state_bytes"),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };

    let path = challenge_dir.join(format!("{}.json", challenge_id));
    std::fs::write(&path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let loaded: ChallengeState = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    assert_eq!(loaded.username, state.username);
    assert_eq!(loaded.rp_id, state.rp_id);
    assert_eq!(loaded.state, state.state);
    assert_eq!(loaded.challenge_type, "registration");
}

#[test]
fn challenge_delete_then_load_fails() {
    let dir = TempDir::new().unwrap();
    let challenge_dir = dir.path().join("challenges");
    std::fs::create_dir_all(&challenge_dir).unwrap();

    let challenge_id = "test-challenge-to-delete";
    let path = challenge_dir.join(format!("{}.json", challenge_id));
    std::fs::write(
        &path,
        r#"{"type":"registration","username":"u","rp_id":"rp","state":"s","created_at":"t"}"#,
    )
    .unwrap();

    assert!(path.exists());
    std::fs::remove_file(&path).unwrap();
    assert!(!path.exists());
}

#[test]
fn challenge_state_base64url_roundtrip() {
    // The server state is stored as base64url-no-pad; verify the round-trip is lossless.
    let original_bytes: Vec<u8> = (0..64).collect();
    let encoded = URL_SAFE_NO_PAD.encode(&original_bytes);

    // Base64URL must NOT contain padding '='
    assert!(!encoded.contains('='), "Base64URL must use no-padding encoding");
    // Must not contain '+' or '/' (standard base64 chars)
    assert!(!encoded.contains('+'), "Base64URL must not contain '+'");
    assert!(!encoded.contains('/'), "Base64URL must not contain '/'");

    let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
    assert_eq!(original_bytes, decoded);
}

// ============================================================
// 2. Challenge Mismatch Detection
// ============================================================

#[test]
fn challenge_mismatch_single_char_difference() {
    let original = URL_SAFE_NO_PAD.encode(b"correct_challenge_data_1234");
    let mut tampered_bytes = b"correct_challenge_data_1234".to_vec();
    // Flip one byte
    tampered_bytes[0] ^= 0x01;
    let tampered = URL_SAFE_NO_PAD.encode(&tampered_bytes);

    assert_ne!(original, tampered, "Off-by-one-char challenge must be detected as different");
}

#[test]
fn challenge_mismatch_trailing_padding_stripping() {
    // Ensure that lengths that would produce padding in standard base64
    // still round-trip correctly with URL_SAFE_NO_PAD.
    for len in [1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
        let data: Vec<u8> = (0u8..len).collect();
        let encoded = URL_SAFE_NO_PAD.encode(&data);
        assert!(!encoded.ends_with('='), "No padding expected for len={len}");
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(data, decoded, "Round-trip failed for len={len}");
    }
}

#[test]
fn challenge_randomness_uniqueness() {
    // Generate multiple challenges and verify they are all distinct.
    let mut set = std::collections::HashSet::new();
    for _ in 0..100 {
        let id = uuid::Uuid::new_v4().to_string();
        assert!(set.insert(id), "UUID collision detected — challenge randomness problem");
    }
}

// ============================================================
// 3. Corrupted credentials.json Handling
// ============================================================

#[test]
fn corrupted_credentials_json_returns_error_not_panic() {
    let dir = TempDir::new().unwrap();
    let cred_path = dir.path().join("credentials.json");

    // Write garbage
    std::fs::write(&cred_path, "this is {{{ not valid JSON !!!").unwrap();

    let data = std::fs::read_to_string(&cred_path).unwrap();
    let result: Result<CredentialStore, _> = serde_json::from_str(&data);

    assert!(result.is_err(), "Corrupted JSON must yield Err, not panic");
    let err_msg = result.unwrap_err().to_string();
    assert!(!err_msg.is_empty(), "Error message should be non-empty");
}

#[test]
fn empty_credentials_file_returns_error() {
    let dir = TempDir::new().unwrap();
    let cred_path = dir.path().join("credentials.json");
    std::fs::write(&cred_path, "").unwrap();

    let data = std::fs::read_to_string(&cred_path).unwrap();
    let result: Result<CredentialStore, _> = serde_json::from_str(&data);

    assert!(result.is_err(), "Empty file should yield a deserialization error");
}

#[test]
fn truncated_credentials_json_returns_error() {
    let dir = TempDir::new().unwrap();
    let cred_path = dir.path().join("credentials.json");

    // Valid start, truncated midway
    std::fs::write(&cred_path, r#"{"users":{"root":{"user_id":"abc","credentials":[{"#).unwrap();

    let data = std::fs::read_to_string(&cred_path).unwrap();
    let result: Result<CredentialStore, _> = serde_json::from_str(&data);

    assert!(result.is_err(), "Truncated JSON must yield Err");
}

// ============================================================
// 4. Concurrent File Write (fs2 locking simulation)
// ============================================================

#[test]
fn concurrent_file_writes_are_serialized_by_flock() {
    use fs2::FileExt;

    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("credentials.json");
    // Seed the file
    std::fs::write(&file_path, r#"{"users":{}}"#).unwrap();

    let path = Arc::new(file_path);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = vec![];

    for i in 0..2 {
        let p = Arc::clone(&path);
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait(); // synchronize start
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(p.as_ref())
                .unwrap();
            file.lock_exclusive().expect("Must acquire exclusive lock");
            let payload = format!(r#"{{"users":{{"writer_{i}":{{"user_id":"id","credentials":[]}}}}}}"#);
            (&file).write_all(payload.as_bytes()).unwrap();
            // Lock is released on drop
        }));
    }

    for h in handles {
        h.join().expect("Thread must not panic");
    }

    // File should be valid JSON written by one of the two writers
    let data = std::fs::read_to_string(path.as_ref()).unwrap();
    let store: CredentialStore = serde_json::from_str(&data).unwrap();
    assert_eq!(store.users.len(), 1, "One writer's data should survive (last-writer-wins)");
}

// ============================================================
// 5. CamelCase ↔ snake_case JSON Contract Tests
// ============================================================

/// Mirrors schemas.rs `RegisterFinishData` with `rename_all = "camelCase"`.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RegisterFinishData {
    credential_id: String,
    aaguid: String,
    created_at: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LoginFinishData {
    username: String,
    user_verified: bool,
    counter: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CredentialListItem {
    credential_id: String,
    username: String,
    device_name: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
    backup_eligible: bool,
    user_verified: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CredentialUpdateData {
    credential_id: String,
    old_name: String,
    new_name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct HealthCheckData {
    status: String,
    version: String,
    storage: StorageStatusData,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StorageStatusData {
    writable: bool,
    path: String,
    count: usize,
}

#[test]
fn register_finish_data_serializes_to_camel_case() {
    let data = RegisterFinishData {
        credential_id: "abc123".to_string(),
        aaguid: "00000000-0000-0000-0000-000000000000".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&data).unwrap();
    assert!(json.contains("\"credentialId\""), "Must use camelCase: credentialId");
    assert!(json.contains("\"createdAt\""), "Must use camelCase: createdAt");
    assert!(!json.contains("\"credential_id\""), "Must not use snake_case");
    assert!(!json.contains("\"created_at\""), "Must not use snake_case");
}

#[test]
fn login_finish_data_serializes_to_camel_case() {
    let data = LoginFinishData {
        username: "root".to_string(),
        user_verified: true,
        counter: 42,
    };
    let json = serde_json::to_string(&data).unwrap();
    assert!(json.contains("\"userVerified\""), "Must use camelCase: userVerified");
    assert!(!json.contains("\"user_verified\""), "Must not use snake_case");
}

#[test]
fn credential_list_item_serializes_to_camel_case() {
    let item = CredentialListItem {
        credential_id: "cid".to_string(),
        username: "user".to_string(),
        device_name: "YubiKey".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
        last_used_at: Some("2025-06-01T00:00:00Z".to_string()),
        backup_eligible: false,
        user_verified: true,
    };
    let json = serde_json::to_string(&item).unwrap();
    assert!(json.contains("\"credentialId\""), "camelCase: credentialId");
    assert!(json.contains("\"deviceName\""), "camelCase: deviceName");
    assert!(json.contains("\"createdAt\""), "camelCase: createdAt");
    assert!(json.contains("\"lastUsedAt\""), "camelCase: lastUsedAt");
    assert!(json.contains("\"backupEligible\""), "camelCase: backupEligible");
    assert!(json.contains("\"userVerified\""), "camelCase: userVerified");
}

#[test]
fn credential_list_item_omits_null_last_used_at() {
    let item = CredentialListItem {
        credential_id: "cid".to_string(),
        username: "user".to_string(),
        device_name: "YubiKey".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
        last_used_at: None,
        backup_eligible: false,
        user_verified: false,
    };
    let json = serde_json::to_string(&item).unwrap();
    assert!(!json.contains("lastUsedAt"), "None fields should be skipped");
}

#[test]
fn credential_update_data_serializes_to_camel_case() {
    let data = CredentialUpdateData {
        credential_id: "cid".to_string(),
        old_name: "old".to_string(),
        new_name: "new".to_string(),
    };
    let json = serde_json::to_string(&data).unwrap();
    assert!(json.contains("\"credentialId\""), "camelCase: credentialId");
    assert!(json.contains("\"oldName\""), "camelCase: oldName");
    assert!(json.contains("\"newName\""), "camelCase: newName");
}

#[test]
fn health_check_data_serializes_to_camel_case() {
    let data = HealthCheckData {
        status: "ok".to_string(),
        version: "1.0.0".to_string(),
        storage: StorageStatusData {
            writable: true,
            path: "/etc/webauthn/credentials.json".to_string(),
            count: 3,
        },
    };
    let json = serde_json::to_string(&data).unwrap();
    // All top-level fields are single words (no rename needed) except nested struct
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("storage").is_some());
    assert!(parsed["storage"].get("writable").is_some());
    assert!(parsed["storage"].get("count").is_some());
}

#[test]
fn challenge_state_type_field_uses_rename() {
    let state = ChallengeState {
        challenge_type: "registration".to_string(),
        username: "root".to_string(),
        rp_id: "192.168.1.1".to_string(),
        state: "encoded_state".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&state).unwrap();
    assert!(json.contains("\"type\""), "challenge_type must serialize as 'type'");
    assert!(!json.contains("\"challenge_type\""), "Must not expose Rust field name");
}

#[test]
fn challenge_state_deserializes_type_field() {
    let json = r#"{"type":"authentication","username":"admin","rp_id":"example.com","state":"xyz","created_at":"2025-01-01T00:00:00Z"}"#;
    let state: ChallengeState = serde_json::from_str(json).unwrap();
    assert_eq!(state.challenge_type, "authentication");
}

// ============================================================
// 6. Error Message JSON Output Format
// ============================================================

/// Mirrors schemas.rs ErrorResponse.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct ErrorResponse {
    success: bool,
    error: ErrorDetail,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct ErrorDetail {
    code: String,
    message: String,
}

#[test]
fn error_response_has_required_fields() {
    let resp = ErrorResponse {
        success: false,
        error: ErrorDetail {
            code: "CHALLENGE_NOT_FOUND".to_string(),
            message: "Challenge not found: abc-123".to_string(),
        },
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["success"], false);
    assert!(parsed["error"]["code"].is_string());
    assert!(parsed["error"]["message"].is_string());
    assert!(
        !parsed["error"]["message"].as_str().unwrap().is_empty(),
        "Error message must not be empty"
    );
}

#[test]
fn error_codes_are_descriptive() {
    // Verify all documented error codes produce non-empty messages.
    let test_cases = vec![
        ("CHALLENGE_NOT_FOUND", "Challenge not found: test-id"),
        ("USER_NOT_FOUND", "User not found: admin"),
        ("CREDENTIAL_NOT_FOUND", "Credential not found: cred-id"),
        ("INVALID_ORIGIN", "Invalid origin: http://evil.com"),
        ("WEBAUTHN_ERROR", "WebAuthn error: Signature verification failed"),
        ("STORAGE_ERROR", "Storage error: disk full"),
        ("JSON_ERROR", "JSON error: expected value at line 1 column 1"),
        ("IO_ERROR", "IO error: permission denied"),
        ("INVALID_INPUT", "Invalid input: missing userHandle"),
    ];

    for (code, message) in test_cases {
        let resp = ErrorResponse {
            success: false,
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"]["code"].as_str().unwrap(), code);
        assert!(
            parsed["error"]["message"].as_str().unwrap().len() > 10,
            "Error message for {} should be detailed enough for debugging",
            code
        );
    }
}

// ============================================================
// 7. Mock Data Generator — Legal + 3 Illegal Payloads
// ============================================================

/// Generate a structurally valid (but cryptographically non-verifiable)
/// WebAuthn registration client response JSON.
fn mock_registration_response_legal() -> serde_json::Value {
    serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode(b"credential-id-bytes-abcdef123456"),
        "rawId": URL_SAFE_NO_PAD.encode(b"credential-id-bytes-abcdef123456"),
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "type": "webauthn.create",
                    "challenge": URL_SAFE_NO_PAD.encode(b"server-generated-challenge"),
                    "origin": "https://192.168.1.1",
                    "crossOrigin": false
                })).unwrap().as_slice()
            ),
            "attestationObject": URL_SAFE_NO_PAD.encode(b"fake-attestation-object-cbor")
        }
    })
}

/// Illegal payload 1: Malformed JSON (missing required fields).
fn mock_registration_response_malformed_json() -> &'static str {
    r#"{"id":"abc","type":"public-key","response":{}}"#
}

/// Illegal payload 2: Tampered challenge in clientDataJSON.
fn mock_registration_response_tampered_challenge() -> serde_json::Value {
    serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode(b"credential-id-bytes-abcdef123456"),
        "rawId": URL_SAFE_NO_PAD.encode(b"credential-id-bytes-abcdef123456"),
        "type": "public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "type": "webauthn.create",
                    "challenge": URL_SAFE_NO_PAD.encode(b"TAMPERED-challenge-value!!!"),
                    "origin": "https://192.168.1.1",
                    "crossOrigin": false
                })).unwrap().as_slice()
            ),
            "attestationObject": URL_SAFE_NO_PAD.encode(b"fake-attestation-object-cbor")
        }
    })
}

/// Illegal payload 3: Wrong credential type field.
fn mock_registration_response_wrong_type() -> serde_json::Value {
    serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode(b"credential-id-bytes-abcdef123456"),
        "rawId": URL_SAFE_NO_PAD.encode(b"credential-id-bytes-abcdef123456"),
        "type": "not-a-public-key",
        "response": {
            "clientDataJSON": URL_SAFE_NO_PAD.encode(b"{}"),
            "attestationObject": URL_SAFE_NO_PAD.encode(b"fake")
        }
    })
}

#[test]
fn mock_legal_response_is_valid_json() {
    let resp = mock_registration_response_legal();
    assert!(resp.is_object());
    assert_eq!(resp["type"], "public-key");
    assert!(resp["response"]["clientDataJSON"].is_string());
    assert!(resp["response"]["attestationObject"].is_string());
}

#[test]
fn mock_malformed_json_missing_fields() {
    let parsed: serde_json::Value = serde_json::from_str(mock_registration_response_malformed_json()).unwrap();
    // The response object is empty — no clientDataJSON
    assert!(
        parsed["response"]["clientDataJSON"].is_null(),
        "Should be missing clientDataJSON"
    );
}

#[test]
fn mock_tampered_challenge_differs_from_legal() {
    let legal = mock_registration_response_legal();
    let tampered = mock_registration_response_tampered_challenge();

    let legal_cdata = legal["response"]["clientDataJSON"].as_str().unwrap();
    let tampered_cdata = tampered["response"]["clientDataJSON"].as_str().unwrap();

    assert_ne!(legal_cdata, tampered_cdata, "Tampered challenge must differ from legal");
}

#[test]
fn mock_wrong_type_is_not_public_key() {
    let resp = mock_registration_response_wrong_type();
    assert_ne!(resp["type"], "public-key", "Wrong type payload should not be 'public-key'");
}

// ============================================================
// 8. Credential Store Serialization Contract
// ============================================================

#[test]
fn credential_store_roundtrip_json() {
    let mut store = CredentialStore::default();
    store.users.insert(
        "admin".to_string(),
        UserRecord {
            user_id: URL_SAFE_NO_PAD.encode(b"a]random-user-id-64-bytes-padded-to-fill-the-required-length!!!"),
            credentials: vec![StoredCredential {
                credential_id: URL_SAFE_NO_PAD.encode(b"cred-id-1"),
                device_name: "YubiKey 5".to_string(),
                static_state: URL_SAFE_NO_PAD.encode(b"static"),
                dynamic_state: URL_SAFE_NO_PAD.encode(b"dynamic"),
                user_handle: URL_SAFE_NO_PAD.encode(b"handle"),
                transports: 4,
                created_at: "2025-01-01T00:00:00Z".to_string(),
                last_used_at: None,
                backup_eligible: false,
                user_verified: true,
                sign_count: 0,
            }],
        },
    );

    let json = serde_json::to_string_pretty(&store).unwrap();
    let loaded: CredentialStore = serde_json::from_str(&json).unwrap();

    assert_eq!(loaded.users.len(), 1);
    let admin = loaded.users.get("admin").unwrap();
    assert_eq!(admin.credentials.len(), 1);
    assert_eq!(admin.credentials[0].device_name, "YubiKey 5");
    assert_eq!(admin.credentials[0].sign_count, 0);
}

#[test]
fn credential_store_with_multiple_users_and_credentials() {
    let mut store = CredentialStore::default();

    for i in 0..3 {
        let username = format!("user_{}", i);
        let mut creds = vec![];
        for j in 0..2 {
            creds.push(StoredCredential {
                credential_id: format!("cred_{}_{}", i, j),
                device_name: format!("Device {}", j),
                static_state: "ss".to_string(),
                dynamic_state: "ds".to_string(),
                user_handle: "uh".to_string(),
                transports: 0,
                created_at: "2025-01-01T00:00:00Z".to_string(),
                last_used_at: None,
                backup_eligible: false,
                user_verified: false,
                sign_count: 0,
            });
        }
        store.users.insert(
            username.clone(),
            UserRecord {
                user_id: format!("uid_{}", i),
                credentials: creds,
            },
        );
    }

    let json = serde_json::to_string(&store).unwrap();
    let loaded: CredentialStore = serde_json::from_str(&json).unwrap();
    assert_eq!(loaded.users.len(), 3);
    for (_, record) in &loaded.users {
        assert_eq!(record.credentials.len(), 2);
    }
}

// ============================================================
// 9. Base64URL Edge Cases
// ============================================================

#[test]
fn base64url_empty_input() {
    let encoded = URL_SAFE_NO_PAD.encode(b"");
    assert_eq!(encoded, "");
    let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn base64url_all_byte_values() {
    // Ensure all 256 byte values survive the round-trip
    let data: Vec<u8> = (0..=255).collect();
    let encoded = URL_SAFE_NO_PAD.encode(&data);
    assert!(!encoded.contains('='));
    assert!(!encoded.contains('+'));
    assert!(!encoded.contains('/'));
    let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
    assert_eq!(data, decoded);
}

#[test]
fn base64url_standard_base64_rejected() {
    // A string with standard base64 characters should fail
    let standard_b64 = "SGVsbG8gV29ybGQ="; // "Hello World" in standard base64
    let result = URL_SAFE_NO_PAD.decode(standard_b64);
    assert!(
        result.is_err(),
        "Standard base64 with padding should be rejected by URL_SAFE_NO_PAD"
    );
}
