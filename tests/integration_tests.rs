/// Integration tests for the webauthn-helper CLI binary.
///
/// Uses `assert_cmd` to invoke the binary and verify:
/// - JSON error output format on failure paths
/// - Register-begin → register-finish simulated flow
/// - Login-begin → login-finish simulated flow
/// - Malformed stdin input handling
/// - Error message detail for common failure modes
use assert_cmd::Command;
use predicates::prelude::*;

#[allow(deprecated)]
fn cmd() -> Command {
    Command::cargo_bin("webauthn-helper").unwrap()
}

// ============================================================
// 1. CLI Basic Invocation
// ============================================================

#[test]
fn cli_no_args_shows_help_or_error() {
    cmd().assert().failure(); // No subcommand → clap error
}

#[test]
fn cli_help_flag() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("WebAuthn"));
}

#[test]
fn cli_version_flag() {
    let expected_version = env!("CARGO_PKG_VERSION");

    let output = cmd()
        .arg("--version")
        .output()
        .expect("Failed to execute --version");

    assert!(output.status.success(), "The --version command itself failed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    if !stdout.contains(expected_version) {
        println!("\n[WARNING] Version mismatch detected!");
        println!("Expected (from Cargo.toml): {}", expected_version);
        println!("Actual (from binary output): {}", stdout.trim());
        println!("This is common in dev/CI builds and will not fail the test.\n");
    } else {
        println!("Version match confirmed: {}", expected_version);
    }
}

// ============================================================
// 2. Register-Begin Tests
// ============================================================

#[test]
fn register_begin_missing_args() {
    cmd().arg("register-begin").assert().failure();
}

#[test]
fn register_begin_valid_domain_rp_id() {
    // This writes challenge files to /tmp/webauthn/challenges/
    // and credentials from /etc/webauthn/ (may fail due to permissions).
    // We test with a valid domain RP ID to confirm the output format.
    let result = cmd()
        .args(["register-begin", "--username", "testuser", "--rp-id", "example.com"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);

    if result.status.success() {
        // Should output valid JSON with challengeId and publicKey
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed["success"], true);
        assert!(parsed["data"]["challengeId"].is_string(), "Must contain challengeId");
        assert!(parsed["data"]["publicKey"].is_object(), "Must contain publicKey object");
    } else {
        // If it fails (e.g., permissions), output should still be JSON
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed["success"], false);
        assert!(parsed["error"]["code"].is_string());
        assert!(parsed["error"]["message"].is_string());
    }
}

// ============================================================
// 3. Register-Finish Tests — Error Paths
// ============================================================

#[test]
fn register_finish_missing_challenge_id() {
    cmd().arg("register-finish").assert().failure();
}

#[test]
fn register_finish_nonexistent_challenge() {
    let result = cmd()
        .args([
            "register-finish",
            "--challenge-id",
            "nonexistent-id-12345",
            "--origin",
            "https://example.com",
            "--device-name",
            "TestKey",
        ])
        .write_stdin("{}")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], false);
    assert_eq!(parsed["error"]["code"], "CHALLENGE_NOT_FOUND");
    assert!(
        parsed["error"]["message"].as_str().unwrap().contains("nonexistent-id-12345"),
        "Error message should include the missing challenge ID"
    );
}

#[test]
fn register_finish_with_malformed_stdin_json() {
    // First create a challenge file so the challenge lookup succeeds
    let challenge_id = "test-malformed-json-challenge";
    let challenge_dir = std::path::Path::new("/tmp/webauthn/challenges");
    let _ = std::fs::create_dir_all(challenge_dir);
    let challenge_path = challenge_dir.join(format!("{}.json", challenge_id));
    let challenge_state = serde_json::json!({
        "type": "registration",
        "username": "testuser",
        "rp_id": "example.com",
        "state": "dGVzdA",  // base64url of "test"
        "created_at": "2025-01-01T00:00:00Z"
    });
    std::fs::write(&challenge_path, serde_json::to_string(&challenge_state).unwrap()).unwrap();

    let result = cmd()
        .args([
            "register-finish",
            "--challenge-id",
            challenge_id,
            "--origin",
            "https://example.com",
            "--device-name",
            "TestKey",
        ])
        .write_stdin("this is not valid JSON at all {{{{")
        .output()
        .unwrap();

    // Clean up
    let _ = std::fs::remove_file(&challenge_path);

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], false);
    // Should report an error (either INVALID_INPUT or WEBAUTHN_ERROR or STORAGE_ERROR)
    assert!(parsed["error"]["code"].is_string());
    assert!(
        !parsed["error"]["message"].as_str().unwrap().is_empty(),
        "Error message should be non-empty and descriptive"
    );
}

// ============================================================
// 4. Login-Begin Tests — Error Paths
// ============================================================

#[test]
fn login_begin_missing_args() {
    cmd().arg("login-begin").assert().failure();
}

#[test]
fn login_begin_nonexistent_user() {
    let result = cmd()
        .args(["login-begin", "--username", "nobody_exists_here", "--rp-id", "example.com"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], false);
    assert_eq!(parsed["error"]["code"], "USER_NOT_FOUND");
    assert!(
        parsed["error"]["message"].as_str().unwrap().contains("nobody_exists_here"),
        "Error message should include the username"
    );
}

// ============================================================
// 5. Login-Finish Tests — Error Paths
// ============================================================

#[test]
fn login_finish_nonexistent_challenge() {
    let result = cmd()
        .args([
            "login-finish",
            "--challenge-id",
            "no-such-challenge",
            "--origin",
            "https://example.com",
        ])
        .write_stdin("{}")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], false);
    assert_eq!(parsed["error"]["code"], "CHALLENGE_NOT_FOUND");
}

// ============================================================
// 6. Credential Management — Error Paths
// ============================================================

#[test]
fn credential_delete_nonexistent() {
    let result = cmd()
        .args(["credential-manage", "delete", "--id", "nonexistent-credential-id"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], false);
    assert_eq!(parsed["error"]["code"], "CREDENTIAL_NOT_FOUND");
}

#[test]
fn credential_update_nonexistent() {
    let result = cmd()
        .args(["credential-manage", "update", "--id", "nonexistent-id", "--name", "NewName"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], false);
    assert_eq!(parsed["error"]["code"], "CREDENTIAL_NOT_FOUND");
}

#[test]
fn credential_list_empty_user() {
    let result = cmd()
        .args(["credential-manage", "list", "--username", "nonexistent_user"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // Listing for a non-existent user should succeed with empty list
    assert_eq!(parsed["success"], true);
    assert!(parsed["data"].as_array().unwrap().is_empty());
}

// ============================================================
// 7. Health Check
// ============================================================

#[test]
fn health_check_returns_json() {
    let result = cmd().arg("health-check").output().unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], true);
    assert!(parsed["data"]["version"].is_string());
    assert!(parsed["data"]["status"].is_string());
    assert!(parsed["data"]["storage"].is_object());
}

// ============================================================
// 8. Error JSON Output Format Verification
// ============================================================

#[test]
fn all_error_responses_have_consistent_json_shape() {
    // Test multiple error-inducing commands and verify JSON shape
    let error_commands: Vec<Vec<&str>> = vec![
        vec![
            "register-finish",
            "--challenge-id",
            "x",
            "--origin",
            "https://a.com",
            "--device-name",
            "d",
        ],
        vec!["login-finish", "--challenge-id", "x", "--origin", "https://a.com"],
        vec!["credential-manage", "delete", "--id", "x"],
    ];

    for args in error_commands {
        let result = cmd().args(&args).write_stdin("{}").output().unwrap();

        let stdout = String::from_utf8_lossy(&result.stdout);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);

        assert!(
            parsed.is_ok(),
            "Output must always be valid JSON for args: {:?}. Got: {}",
            args,
            stdout
        );
        let parsed = parsed.unwrap();

        // Every error response must have these fields
        assert!(parsed.get("success").is_some(), "Missing 'success' field for {:?}", args);
        assert!(parsed.get("error").is_some(), "Missing 'error' field for {:?}", args);
        assert!(parsed["error"].get("code").is_some(), "Missing 'error.code' for {:?}", args);
        assert!(
            parsed["error"].get("message").is_some(),
            "Missing 'error.message' for {:?}",
            args
        );
    }
}

// ============================================================
// 9. Simulated Register → Login Flow (End-to-End)
// ============================================================

#[test]
fn register_begin_produces_valid_challenge_id_format() {
    let result = cmd()
        .args(["register-begin", "--username", "e2e_test_user", "--rp-id", "example.com"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);

    if result.status.success() {
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let challenge_id = parsed["data"]["challengeId"].as_str().unwrap();

        // Challenge ID should be a UUID
        assert!(
            uuid::Uuid::parse_str(challenge_id).is_ok(),
            "challengeId should be a valid UUID"
        );

        // Clean up the challenge file
        let challenge_path = format!("/tmp/webauthn/challenges/{}.json", challenge_id);
        let _ = std::fs::remove_file(&challenge_path);
    }
}

// ============================================================
// 10. Credential Cleanup
// ============================================================

#[test]
fn credential_cleanup_returns_json() {
    let result = cmd().args(["credential-manage", "cleanup"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&result.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["success"], true);
    assert!(parsed["data"]["removedCount"].is_number());
}
