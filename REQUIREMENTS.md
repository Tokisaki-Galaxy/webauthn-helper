# Project Requirements: WebAuthn Helper for OpenWrt (Rust)

**Version**: 1.0
**Target Language**: Rust (2024 Stable)
**Target Platform**: OpenWrt (Linux/musl) - x86_64, aarch64, arm_v7, mips, ...
**Role**: Stateless CLI Utility

## 1. Project Overview

We are building a standalone **CLI tool** in Rust to act as the WebAuthn/FIDO2 backend for OpenWrt routers.
This tool will be invoked by the LuCI web interface (via `ucode` or `luci-base`'s `sys.exec`) to handle Passkey registration, authentication, and credential management.

**Key Constraints:**
*   **Zero Runtime Dependencies**: Must compile to a static binary (musl) to run on bare-bones OpenWrt systems.
*   **Stateless Execution**: The tool runs, executes one command, outputs JSON, and exits. It does NOT run as a daemon.
*   **Parallel Development**: The JSON Input/Output schemas defined below are **strict contracts**. The Frontend is being built simultaneously using these schemas.

## 2. Technical Stack

*   **Core Logic**: `webauthn-rs` (v0.4+).
*   **CLI Parsing**: `clap` (with `derive` feature).
*   **Serialization**: `serde`, `serde_json`.
*   **File Locking**: `fs2` or `fd-lock` (CRITICAL for OpenWrt concurrent access).
*   **Error Handling**: `anyhow` (for main), `thiserror` (for libs).
*   **Encoding**: `base64` (Standard & URL-Safe).
*   **Time**: `chrono`.

## 3. Architecture & Security

### 3.1 Data Flow
1.  **Input**: Arguments via flags + **Sensitive Data via STDIN**.
2.  **Processing**: WebAuthn logic + File I/O.
3.  **State**:
    *   *Challenges*: `/tmp/webauthn/challenges/<uuid>.json` (Ephemeral).
    *   *Credentials*: `/etc/webauthn/credentials.json` (Persistent).
4.  **Output**: Strict JSON to STDOUT.
5.  **Logging**: Logs to **STDERR** only (syslog format preferred).

### 3.2 Security Requirements
*   **Origin Validation**: The CLI MUST accept an `--origin <url>` flag during `finish` steps and verify it matches the RP ID.
*   **File Locking**: All writes to `credentials.json` MUST use an exclusive file lock (`flock`) to prevent corruption during concurrent administrative sessions.
*   **Panic Safety**: The main function must catch all panics (unwinding) and print a valid JSON error object instead of a stack trace, ensuring the calling frontend doesn't crash on parse errors.

## 4. CLI Command Reference

The binary must support the following subcommands.

### 4.1 `register-begin`
Generates a registration challenge.
*   **Args**: `--username <str>`, `--rp-id <str>`, `--user-verification <str>` (default: "preferred").
*   **Action**: Generates `PublicKeyCredentialCreationOptions`. Saves state to `/tmp`.
*   **Output**: JSON Schema A (Section 5).

### 4.2 `register-finish`
Verifies registration and saves the key.
*   **Args**: `--challenge-id <uuid>`, `--origin <url>`, `--device-name <str>`.
*   **STDIN**: Client JSON Response (Schema B).
*   **Action**: Verifies signature + Origin. Locks `/etc/webauthn/`. Atomic write new credential. Deletes challenge.
*   **Output**: JSON Schema B Result.

### 4.3 `login-begin`
Generates a login challenge.
*   **Args**: `--username <str>`, `--rp-id <str>`.
*   **Action**: Loads user's credentials. Generates `PublicKeyCredentialRequestOptions`. Saves state to `/tmp`.
*   **Output**: JSON Schema C.

### 4.4 `login-finish`
Verifies login signature.
*   **Args**: `--challenge-id <uuid>`, `--origin <url>`.
*   **STDIN**: Client JSON Response (Schema D).
*   **Action**: Verifies signature + Origin. Checks **Signature Counter** (warn on clone detection). Updates `counter` and `last_used_at` in storage (using file lock). Deletes challenge.
*   **Output**: JSON Schema D Result.

### 4.5 `credential-manage`
Subcommands for management:
*   `list --username <str>`: Returns array of credentials (Schema E).
*   `delete --id <cred_id>`: Removes specific credential.
*   `update --id <cred_id> --name <new_name>`: Renames a credential (Schema F).
*   `cleanup`: Removes expired challenge files (> 2 minutes old) from `/tmp`.

### 4.6 `health-check`
Used by Frontend UI to determine feature availability.
*   **Action**: Checks if storage directory exists/writable, checks JSON validity.
*   **Output**: Schema G.

## 5. Data Contracts (Strict JSON Schemas)

**Rules:**
1.  **CamelCase**: All output keys must be `camelCase`.
2.  **Base64URL**: All binary data (IDs, Keys, Challenges) must be Base64URL Strings (no padding).

### Schema A: Register Begin Output
```json
{
  "success": true,
  "data": {
    "publicKey": {
      "rp": { "name": "OpenWrt", "id": "192.168.1.1" },
      "user": { "name": "root", "displayName": "root", "id": "dXNlcl9pZF9leGFtcGxl" },
      "challenge": "Y2hhbGxlbmdlX2V4YW1wbGU",
      "pubKeyCredParams": [
        { "type": "public-key", "alg": -7 },
        { "type": "public-key", "alg": -257 }
      ],
      "timeout": 60000,
      "authenticatorSelection": {
        "residentKey": "preferred",
        "userVerification": "preferred"
      },
      "attestation": "none"
    },
    "challengeId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Schema B: Register Finish Input (STDIN) & Output
**Input (STDIN)**:
```json
{
  "id": "Y3JlZGVudGlhbF9pZA",
  "rawId": "Y3JlZGVudGlhbF9pZA",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJjaGFsbGVuZ2UiOiAiLi4uIn0",
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10..."
  }
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "credentialId": "Y3JlZGVudGlhbF9pZA",
    "aaguid": "00000000-0000-0000-0000-000000000000",
    "createdAt": "2023-10-27T10:00:00Z"
  }
}
```

### Schema C: Login Begin Output
```json
{
  "success": true,
  "data": {
    "publicKey": {
      "challenge": "bG9naW5fY2hhbGxlbmdl",
      "timeout": 60000,
      "rpId": "192.168.1.1",
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "Y3JlZGVudGlhbF9pZA",
          "transports": ["usb", "nfc"]
        }
      ],
      "userVerification": "preferred"
    },
    "challengeId": "550e8400-e29b-41d4-a716-446655440001"
  }
}
```

### Schema D: Login Finish Input (STDIN) & Output
**Input (STDIN)**:
```json
{
  "id": "Y3JlZGVudGlhbF9pZA",
  "rawId": "Y3JlZGVudGlhbF9pZA",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ...",
    "authenticatorData": "SZYN...",
    "signature": "MEUC...",
    "userHandle": "dXNlcl9pZF9leGFtcGxl"
  }
}
```
**Output**:
```json
{
  "success": true,
  "data": {
    "username": "root",
    "userVerified": true,
    "counter": 15
  }
}
```

### Schema E: Credential List Output
```json
{
  "success": true,
  "data": [
    {
      "credentialId": "Y3JlZGVudGlhbF9pZA",
      "username": "root",
      "deviceName": "My YubiKey",
      "createdAt": "2023-10-27T10:00:00Z",
      "lastUsedAt": "2023-10-28T14:00:00Z",
      "backupEligible": false,
      "userVerified": true
    }
  ]
}
```

### Schema F: Credential Update Output
```json
{
  "success": true,
  "data": {
    "credentialId": "Y3JlZGVudGlhbF9pZA",
    "oldName": "Unknown Device",
    "newName": "Office Mac"
  }
}
```

### Schema G: Health Check Output
```json
{
  "success": true,
  "data": {
    "status": "ok",
    "version": "1.0.0",
    "storage": {
      "writable": true,
      "path": "/etc/webauthn/credentials.json",
      "count": 2
    }
  }
}
```

### Error Schema (Standard for all failures)
```json
{
  "success": false,
  "error": {
    "code": "INVALID_ORIGIN", 
    "message": "Origin https://fake.com does not match RP ID"
  }
}
```

## 6. Implementation Notes for LLM

1.  **Storage Structs**: Use separate structs for internal storage (Snake Case, Rust Types) and External JSON (Camel Case, Base64 Strings). Implement `From` or `Into` traits for conversion.
2.  **Binary Size**: Add a `Cargo.toml` profile configuration to optimize for size (`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`).
3.  **Permissions**: When creating `/etc/webauthn/credentials.json` if it doesn't exist, ensure mode is `640` or `600`.
4.  **Mocking**: Create a trait `StorageProvider` to allow unit testing the logic without actual disk writes.
5.  **Main Loop**: The `main` function should utilize a top-level `match` on `clap` commands, wrapped in a `Result` handler that always prints the JSON `Error Schema` on failure, never relying on Rust's default panic printer.
