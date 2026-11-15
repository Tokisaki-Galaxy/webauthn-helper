//! Full registration and login ceremonies against a software authenticator.
//!
//! The authenticator below builds the same attestation and assertion
//! structures a browser hands to the page ("none" attestation, ES256), so
//! these tests exercise the helper exactly as luci-app-webauthn drives it,
//! including the server-side checks a real browser never lets a page get
//! wrong (user verification, replays, origins).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

use crate::commands::{login, register};
use crate::errors::AppError;
use crate::storage::{FileStorage, StorageProvider, MAX_PENDING_CHALLENGES};

const RP_ID: &str = "router.example.com";
const ORIGIN: &str = "https://router.example.com:8443";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

fn cbor_head(major: u8, len: usize) -> Vec<u8> {
    match len {
        0..=23 => vec![(major << 5) | len as u8],
        24..=255 => vec![(major << 5) | 24, len as u8],
        _ => vec![(major << 5) | 25, (len >> 8) as u8, len as u8],
    }
}

fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, data.len());
    out.extend_from_slice(data);
    out
}

fn cbor_text(s: &str) -> Vec<u8> {
    let mut out = cbor_head(3, s.len());
    out.extend_from_slice(s.as_bytes());
    out
}

/// A one-credential authenticator holding a discoverable ES256 key.
struct SoftKey {
    key: SigningKey,
    cred_id: Vec<u8>,
    user_handle: Vec<u8>,
    sign_count: u32,
}

impl SoftKey {
    fn new(seed: u8) -> Self {
        let mut scalar = [0x11u8; 32];
        scalar[31] = seed;
        Self {
            key: SigningKey::from_slice(&scalar).expect("valid scalar"),
            cred_id: vec![seed; 16],
            user_handle: Vec::new(),
            sign_count: 0,
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_encoded_point(false);
        let mut out = vec![0xa5]; // map(5)
        out.extend_from_slice(&[0x01, 0x02]); // kty: EC2
        out.extend_from_slice(&[0x03, 0x26]); // alg: ES256 (-7)
        out.extend_from_slice(&[0x20, 0x01]); // crv: P-256
        out.push(0x21); // x
        out.extend(cbor_bytes(point.x().unwrap()));
        out.push(0x22); // y
        out.extend(cbor_bytes(point.y().unwrap()));
        out
    }

    fn auth_data(&self, flags: u8, attested: bool) -> Vec<u8> {
        let mut out = Sha256::digest(RP_ID.as_bytes()).to_vec();
        out.push(flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());
        if attested {
            out.extend_from_slice(&[0u8; 16]); // AAGUID
            out.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.cred_id);
            out.extend(self.cose_key());
        }
        out
    }

    fn client_data(kind: &str, options: &Value, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": options["challenge"],
            "origin": origin,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    /// navigator.credentials.create() for the given creation options.
    fn create(&mut self, options: &Value, origin: &str) -> String {
        self.user_handle = unb64(options["user"]["id"].as_str().unwrap());
        let mut att = vec![0xa3]; // map(3)
        att.extend(cbor_text("fmt"));
        att.extend(cbor_text("none"));
        att.extend(cbor_text("attStmt"));
        att.push(0xa0);
        att.extend(cbor_text("authData"));
        att.extend(cbor_bytes(&self.auth_data(FLAG_UP | FLAG_UV | FLAG_AT, true)));

        json!({
            "id": b64(&self.cred_id),
            "rawId": b64(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&Self::client_data("webauthn.create", options, origin)),
                "attestationObject": b64(&att),
            },
        })
        .to_string()
    }

    /// navigator.credentials.get() for the given request options.
    fn get(&mut self, options: &Value, origin: &str, flags: u8) -> String {
        self.sign_count += 1;
        let auth_data = self.auth_data(flags, false);
        let client_data = Self::client_data("webauthn.get", options, origin);
        let mut signed = auth_data.clone();
        signed.extend(Sha256::digest(&client_data));
        let sig: DerSignature = self.key.sign(&signed);

        json!({
            "id": b64(&self.cred_id),
            "rawId": b64(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "signature": b64(sig.as_bytes()),
                "userHandle": b64(&self.user_handle),
            },
        })
        .to_string()
    }
}

fn storage() -> (FileStorage, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = FileStorage::with_paths(dir.path().join("etc/credentials.json"), dir.path().join("challenges"));
    (storage, dir)
}

fn data(out: Result<String, AppError>) -> Value {
    let v: Value = serde_json::from_str(&out.expect("command succeeds")).unwrap();
    assert_eq!(v["success"], true);
    v["data"].clone()
}

fn register(storage: &FileStorage, key: &mut SoftKey) {
    let begin = data(register::register_begin(storage, "root", RP_ID, "required"));
    let response = key.create(&begin["publicKey"], ORIGIN);
    data(register::register_finish(
        storage,
        begin["challengeId"].as_str().unwrap(),
        ORIGIN,
        "test key",
        &response,
    ));
}

fn begin_passwordless(storage: &FileStorage) -> Value {
    data(login::login_begin_discoverable(storage, RP_ID))
}

#[test]
fn registration_requires_uv_and_does_not_enforce_cred_protect() {
    let (storage, _dir) = storage();
    let begin = data(register::register_begin(&storage, "root", RP_ID, "required"));
    let pk = &begin["publicKey"];
    assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    assert_eq!(pk["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(pk["extensions"]["enforceCredentialProtectionPolicy"], false);
}

#[test]
fn passwordless_login_identifies_the_user() {
    let (storage, _dir) = storage();
    let mut key = SoftKey::new(1);
    register(&storage, &mut key);

    let begin = begin_passwordless(&storage);
    assert_eq!(begin["publicKey"]["userVerification"], "required");
    assert!(begin["publicKey"]["allowCredentials"].as_array().is_none_or(|a| a.is_empty()));

    let response = key.get(&begin["publicKey"], ORIGIN, FLAG_UP | FLAG_UV);
    let out = data(login::login_finish(
        &storage,
        begin["challengeId"].as_str().unwrap(),
        ORIGIN,
        &response,
    ));
    assert_eq!(out["username"], "root");
    assert_eq!(out["userVerified"], true);

    // The new sign count is stored, in a file only root can read.
    let store = storage.load_credentials().unwrap();
    assert_eq!(store.users["root"].credentials[0].sign_count, 1);
    assert!(store.users["root"].credentials[0].last_used_at.is_some());
    let mode = std::fs::metadata(storage.credentials_path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(!storage.credentials_path().with_extension("json.tmp").exists());
}

#[test]
fn passwordless_login_without_user_verification_is_refused() {
    let (storage, _dir) = storage();
    let mut key = SoftKey::new(2);
    register(&storage, &mut key);

    let begin = begin_passwordless(&storage);
    let response = key.get(&begin["publicKey"], ORIGIN, FLAG_UP);
    let err = login::login_finish(&storage, begin["challengeId"].as_str().unwrap(), ORIGIN, &response).unwrap_err();
    assert!(matches!(err, AppError::WebAuthn(_)), "{err:?}");
}

#[test]
fn replayed_assertion_is_refused() {
    let (storage, _dir) = storage();
    let mut key = SoftKey::new(3);
    register(&storage, &mut key);

    let begin = begin_passwordless(&storage);
    let id = begin["challengeId"].as_str().unwrap();
    let response = key.get(&begin["publicKey"], ORIGIN, FLAG_UP | FLAG_UV);
    data(login::login_finish(&storage, id, ORIGIN, &response));
    let err = login::login_finish(&storage, id, ORIGIN, &response).unwrap_err();
    assert!(matches!(err, AppError::ChallengeNotFound(_)), "{err:?}");
}

#[test]
fn failed_attempt_uses_up_the_challenge() {
    let (storage, _dir) = storage();
    let mut key = SoftKey::new(4);
    register(&storage, &mut key);

    let begin = begin_passwordless(&storage);
    let id = begin["challengeId"].as_str().unwrap();
    let bad = key.get(&begin["publicKey"], ORIGIN, FLAG_UP);
    assert!(login::login_finish(&storage, id, ORIGIN, &bad).is_err());
    let good = key.get(&begin["publicKey"], ORIGIN, FLAG_UP | FLAG_UV);
    let err = login::login_finish(&storage, id, ORIGIN, &good).unwrap_err();
    assert!(matches!(err, AppError::ChallengeNotFound(_)), "{err:?}");
}

#[test]
fn assertion_from_another_origin_is_refused() {
    let (storage, _dir) = storage();
    let mut key = SoftKey::new(5);
    register(&storage, &mut key);

    // The browser signs the page's real origin; the request claims another.
    let begin = begin_passwordless(&storage);
    let response = key.get(&begin["publicKey"], "https://evil.example.com", FLAG_UP | FLAG_UV);
    let err = login::login_finish(&storage, begin["challengeId"].as_str().unwrap(), ORIGIN, &response).unwrap_err();
    assert!(matches!(err, AppError::WebAuthn(_)), "{err:?}");

    let begin = begin_passwordless(&storage);
    let response = key.get(&begin["publicKey"], ORIGIN, FLAG_UP | FLAG_UV);
    let err = login::login_finish(
        &storage,
        begin["challengeId"].as_str().unwrap(),
        "https://evil.example.com",
        &response,
    )
    .unwrap_err();
    assert!(matches!(err, AppError::InvalidOrigin(_)), "{err:?}");
}

#[test]
fn unknown_passkey_is_refused() {
    let (storage, _dir) = storage();
    let mut registered = SoftKey::new(6);
    register(&storage, &mut registered);

    let mut stranger = SoftKey::new(7);
    stranger.user_handle = registered.user_handle.clone();
    let begin = begin_passwordless(&storage);
    let response = stranger.get(&begin["publicKey"], ORIGIN, FLAG_UP | FLAG_UV);
    let err = login::login_finish(&storage, begin["challengeId"].as_str().unwrap(), ORIGIN, &response).unwrap_err();
    assert!(matches!(err, AppError::CredentialNotFound(_)), "{err:?}");
}

#[test]
fn passwordless_begin_needs_a_registered_passkey() {
    let (storage, _dir) = storage();
    let err = login::login_begin_discoverable(&storage, RP_ID).unwrap_err();
    assert!(matches!(err, AppError::CredentialNotFound(_)), "{err:?}");
}

#[test]
fn challenge_ids_never_name_other_files() {
    let (storage, dir) = storage();
    std::fs::create_dir_all(dir.path().join("challenges")).unwrap();
    std::fs::write(dir.path().join("secret.json"), "{}").unwrap();
    for id in ["../secret", "../../etc/passwd", "", "not-a-uuid"] {
        let err = storage.load_challenge(id).unwrap_err();
        assert!(matches!(err, AppError::ChallengeNotFound(_)), "{id}: {err:?}");
    }
    assert!(dir.path().join("secret.json").exists());
}

#[test]
fn pending_challenges_are_capped_by_dropping_the_oldest() {
    let (storage, dir) = storage();
    let mut key = SoftKey::new(8);
    register(&storage, &mut key);

    let first = begin_passwordless(&storage);
    for _ in 0..MAX_PENDING_CHALLENGES + 5 {
        begin_passwordless(&storage);
    }
    let pending = std::fs::read_dir(dir.path().join("challenges")).unwrap().count();
    assert!(pending <= MAX_PENDING_CHALLENGES, "{pending} pending");
    assert!(storage.load_challenge(first["challengeId"].as_str().unwrap()).is_err());

    // The newest challenge still works.
    let begin = begin_passwordless(&storage);
    let response = key.get(&begin["publicKey"], ORIGIN, FLAG_UP | FLAG_UV);
    data(login::login_finish(
        &storage,
        begin["challengeId"].as_str().unwrap(),
        ORIGIN,
        &response,
    ));
}
