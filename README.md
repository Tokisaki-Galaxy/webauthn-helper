# WebAuthn Helper

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Tokisaki-Galaxy/webauthn-helper/test.yml?branch=master)](https://github.com/Tokisaki-Galaxy/webauthn-helper/actions)
[![GitHub Release](https://img.shields.io/github/v/release/Tokisaki-Galaxy/webauthn-helper)](https://github.com/Tokisaki-Galaxy/webauthn-helper/releases)

**[🇨🇳 切换到中文版](README_CN.md)** | **English**

*A lightweight, stateless WebAuthn/FIDO2 CLI helper designed for OpenWrt routers*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Registration Flow](#registration-flow)
  - [Authentication Flow](#authentication-flow)
  - [Credential Management](#credential-management)
  - [Health Check](#health-check)
- [CLI Reference](#-cli-reference)
- [JSON Schemas](#-json-schemas)
- [Building from Source](#-building-from-source)
- [Testing](#-testing)
- [Security](#-security)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**webauthn-helper** is a standalone CLI tool written in Rust that provides WebAuthn/FIDO2 authentication capabilities for OpenWrt routers. It's designed to be invoked by the LuCI web interface (via `ucode` or `luci-base`) to handle passwordless authentication using security keys, platform authenticators, and passkeys.

### Why WebAuthn Helper?

- **Zero Runtime Dependencies**: Compiles to a static binary (musl) that runs on bare-bones OpenWrt systems
- **Stateless Execution**: No daemon processes - each command runs, outputs JSON, and exits
- **IP-Based RP IDs**: Supports IP addresses as Relying Party IDs, essential for router environments
- **Secure by Design**: File locking, origin validation, panic safety, and comprehensive error handling
- **Multi-Architecture**: Pre-built binaries for x86_64, aarch64, arm_v7, mips, and more

---

## ✨ Features

- 🔐 **Complete WebAuthn Flow**: Registration and authentication with FIDO2 security keys
- 📱 **Multiple Authenticators**: Support for USB, NFC, and platform authenticators
- 🔒 **Secure Storage**: Credentials stored at `/etc/webauthn/credentials.json` with file locking
- ⚡ **Fast & Lightweight**: Optimized for size with `opt-level = "z"` and LTO
- 🌐 **Origin Validation**: Strict origin checking to prevent cross-site attacks
- 🛡️ **Clone Detection**: Signature counter tracking to detect cloned security keys
- 📊 **JSON I/O**: All communication via strict JSON schemas for easy integration
- 🧪 **Well-Tested**: 52+ unit and integration tests with >90% coverage

---

## 🏗️ Architecture

### Data Flow

```
┌─────────────┐
│   LuCI UI   │ (ucode/luci-base)
└──────┬──────┘
       │ sys.exec()
       ▼
┌─────────────────────────────────┐
│    webauthn-helper (CLI)        │
│  ┌───────────────────────────┐  │
│  │  1. Parse Arguments       │  │
│  │  2. Read STDIN (JSON)     │  │
│  │  3. Process WebAuthn      │  │
│  │  4. File I/O + Lock       │  │
│  │  5. Output JSON (STDOUT)  │  │
│  └───────────────────────────┘  │
└────────┬────────────────┬───────┘
         │                │
         ▼                ▼
   /etc/webauthn/    /tmp/webauthn/
   credentials.json  challenges/*.json
   (Persistent)      (Ephemeral, 2min TTL)
```

### Storage Design

- **Credentials**: `/etc/webauthn/credentials.json` - Persistent storage with exclusive file locks (`flock`)
- **Challenges**: `/tmp/webauthn/challenges/<uuid>.json` - Temporary challenge states (auto-cleanup after 2 minutes)
- **Binary Data**: All cryptographic material (keys, challenges, IDs) encoded as Base64URL strings

### WebAuthn Implementation

- Uses **webauthn_rp v0.3.0** (pure Rust, no OpenSSL dependency)
- Features: `serde_relaxed`, `serializable_server_state`
- Direct core API (`WebauthnCore::new_unsafe_experts_only`) to support IP-based RP IDs

---

## 📦 Installation

### Pre-built Binaries

Download pre-compiled binaries for your OpenWrt architecture from [Releases](https://github.com/Tokisaki-Galaxy/webauthn-helper/releases):

```bash
# Example for x86_64
wget https://github.com/Tokisaki-Galaxy/webauthn-helper/releases/latest/download/webauthn-helper-x86_64-unknown-linux-musl
chmod +x webauthn-helper-x86_64-unknown-linux-musl
mv webauthn-helper-x86_64-unknown-linux-musl /usr/bin/webauthn-helper

# Create required directories
mkdir -p /etc/webauthn /tmp/webauthn/challenges
chmod 700 /etc/webauthn
```

### Supported Architectures

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `armv7-unknown-linux-musleabihf`
- `mips-unknown-linux-musl`
- `mipsel-unknown-linux-musl`

---

## 🚀 Usage

All commands follow this pattern:
1. **Input**: Command-line arguments + optional STDIN (JSON)
2. **Output**: JSON response on STDOUT
3. **Errors**: Logged to STDERR, JSON error on STDOUT

### Registration Flow

#### 1. Begin Registration

```bash
webauthn-helper register-begin \
  --username root \
  --rp-id 192.168.1.1 \
  --user-verification preferred
```

**Output** (save `challengeId` for step 2):
```json
{
  "success": true,
  "data": {
    "publicKey": {
      "rp": { "name": "OpenWrt", "id": "192.168.1.1" },
      "user": { "name": "root", "displayName": "root", "id": "..." },
      "challenge": "Y2hhbGxlbmdl...",
      "pubKeyCredParams": [
        { "type": "public-key", "alg": -7 },
        { "type": "public-key", "alg": -257 }
      ],
      "timeout": 60000,
      "authenticatorSelection": {
        "residentKey": "preferred",
        "userVerification": "preferred"
      }
    },
    "challengeId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

#### 2. Finish Registration

```bash
echo '{
  "id": "Y3JlZGVudGlhbF9pZA...",
  "rawId": "Y3JlZGVudGlhbF9pZA...",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJjaGFsbGVuZ2UiOi4uLn0...",
    "attestationObject": "o2NmbXRkbm9uZWdh..."
  }
}' | webauthn-helper register-finish \
  --challenge-id 550e8400-e29b-41d4-a716-446655440000 \
  --origin https://192.168.1.1 \
  --device-name "My YubiKey 5C"
```

**Output**:
```json
{
  "success": true,
  "data": {
    "credentialId": "Y3JlZGVudGlhbF9pZA...",
    "aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "createdAt": "2026-02-07T14:55:33Z"
  }
}
```

### Authentication Flow

#### 1. Begin Login

```bash
webauthn-helper login-begin \
  --username root \
  --rp-id 192.168.1.1
```

**Output**:
```json
{
  "success": true,
  "data": {
    "publicKey": {
      "challenge": "bG9naW5fY2hhbGxlbmdl...",
      "timeout": 60000,
      "rpId": "192.168.1.1",
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "Y3JlZGVudGlhbF9pZA...",
          "transports": ["usb", "nfc"]
        }
      ],
      "userVerification": "preferred"
    },
    "challengeId": "550e8400-e29b-41d4-a716-446655440001"
  }
}
```

#### 2. Finish Login

```bash
echo '{
  "id": "Y3JlZGVudGlhbF9pZA...",
  "rawId": "Y3JlZGVudGlhbF9pZA...",
  "type": "public-key",
  "response": {
    "clientDataJSON": "eyJ...",
    "authenticatorData": "SZYN...",
    "signature": "MEUC...",
    "userHandle": "dXNlcl9pZF9leGFtcGxl..."
  }
}' | webauthn-helper login-finish \
  --challenge-id 550e8400-e29b-41d4-a716-446655440001 \
  --origin https://192.168.1.1
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

### Credential Management

#### List Credentials

```bash
webauthn-helper credential-manage list --username root
```

**Output**:
```json
{
  "success": true,
  "data": [
    {
      "credentialId": "Y3JlZGVudGlhbF9pZA...",
      "username": "root",
      "deviceName": "My YubiKey 5C",
      "createdAt": "2026-02-07T10:00:00Z",
      "lastUsedAt": "2026-02-07T14:30:00Z",
      "backupEligible": false,
      "userVerified": true
    }
  ]
}
```

#### Update Credential Name

```bash
webauthn-helper credential-manage update \
  --id Y3JlZGVudGlhbF9pZA \
  --name "Office YubiKey"
```

#### Delete Credential

```bash
webauthn-helper credential-manage delete \
  --id Y3JlZGVudGlhbF9pZA
```

#### Cleanup Expired Challenges

```bash
webauthn-helper credential-manage cleanup
```

### Health Check

```bash
webauthn-helper health-check
```

**Output**:
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

---

## 📖 CLI Reference

### Global Options

- `--help` - Show help information
- `--version` - Show version information

### Commands

| Command | Description |
|---------|-------------|
| `register-begin` | Generate a registration challenge for new credentials |
| `register-finish` | Verify registration response and save credential |
| `login-begin` | Generate an authentication challenge |
| `login-finish` | Verify authentication response |
| `credential-manage` | Manage stored credentials (list/delete/update/cleanup) |
| `health-check` | Check system health and storage status |

### register-begin

**Arguments**:
- `--username <string>` - Username to register (required)
- `--rp-id <string>` - Relying Party ID (domain or IP, required)
- `--user-verification <string>` - User verification requirement (default: "preferred")
  - Valid values: `required`, `preferred`, `discouraged`

**Output**: Registration challenge + challengeId

### register-finish

**Arguments**:
- `--challenge-id <uuid>` - Challenge ID from register-begin (required)
- `--origin <url>` - Origin URL (must match RP ID, required)
- `--device-name <string>` - Friendly name for the security key (required)

**STDIN**: PublicKeyCredential JSON from browser

**Output**: Credential ID + AAGUID + creation timestamp

### login-begin

**Arguments**:
- `--username <string>` - Username to authenticate (required)
- `--rp-id <string>` - Relying Party ID (required)

**Output**: Authentication challenge + challengeId

### login-finish

**Arguments**:
- `--challenge-id <uuid>` - Challenge ID from login-begin (required)
- `--origin <url>` - Origin URL (must match RP ID, required)

**STDIN**: PublicKeyCredential JSON from browser

**Output**: Username + userVerified + signature counter

### credential-manage

**Subcommands**:

#### list
- `--username <string>` - Username to list credentials for

#### delete
- `--id <string>` - Base64URL-encoded credential ID to delete

#### update
- `--id <string>` - Base64URL-encoded credential ID to update
- `--name <string>` - New friendly name for the credential

#### cleanup
No arguments. Removes expired challenge files (>2 minutes old).

### health-check

No arguments. Returns system status and storage information.

---

## 📝 JSON Schemas

All I/O uses strict JSON schemas with:
- **camelCase** keys (external API)
- **Base64URL** encoding for binary data (no padding)
- **ISO 8601** timestamps

### Success Response Format

```json
{
  "success": true,
  "data": { /* command-specific data */ }
}
```

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message"
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `CHALLENGE_NOT_FOUND` | Challenge ID not found or expired |
| `USER_NOT_FOUND` | No credentials registered for user |
| `CREDENTIAL_NOT_FOUND` | Credential ID not found |
| `INVALID_ORIGIN` | Origin doesn't match RP ID |
| `WEBAUTHN_ERROR` | WebAuthn verification failed |
| `STORAGE_ERROR` | File system I/O error |
| `JSON_ERROR` | Invalid JSON input |
| `IO_ERROR` | Generic I/O error |
| `INVALID_INPUT` | Invalid command arguments |
| `INTERNAL_ERROR` | Unexpected panic or internal error |

For complete schema definitions, see [REQUIREMENTS.md](REQUIREMENTS.md).

---

## 🔨 Building from Source

### Prerequisites

- Rust 1.93+ (2021 edition)
- For cross-compilation: Docker or cross-rs

### Development Build

```bash
# Clone repository
git clone https://github.com/Tokisaki-Galaxy/webauthn-helper.git
cd webauthn-helper

# Build debug binary
cargo build

# Run
./target/debug/webauthn-helper --help
```

### Release Build (Optimized)

```bash
cargo build --release

# Binary at: ./target/release/webauthn-helper
# Size: ~1.5MB (with strip=true, LTO)
```

### Cross-Compilation for OpenWrt

Using the provided build script:

```bash
# Install dependencies
sudo ./install_dependencies.sh

# Build for all architectures
sudo ./build_release.sh

# Outputs to ./release/ directory
```

Manual cross-compilation:

```bash
# Install cross
cargo install cross

# Build for aarch64
cross build --release --target aarch64-unknown-linux-musl

# Build for mips
cross build --release --target mips-unknown-linux-musl
```

### Build Configuration

From `Cargo.toml`:

```toml
[profile.release]
debug = 0
opt-level = "z"      # Optimize for size
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization
panic = "abort"      # Smaller binary
strip = true         # Remove debug symbols
```

---

## 🧪 Testing

### Run All Tests

```bash
cargo test
```

**Test Coverage**:
- 52 total tests
- 5 unit tests (storage module)
- 29 unit tests (various modules)
- 18 integration tests (CLI behavior)

### Test Categories

```bash
# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test '*'

# Specific test file
cargo test --test integration_tests

# With output
cargo test -- --nocapture
```

### Code Quality

```bash
# Format code
cargo fmt

# Linting
cargo clippy

# Check without building
cargo check
```

### CI/CD

The project uses GitHub Actions for continuous testing:

- **test.yml**: Runs `cargo fmt`, `cargo clippy`, `cargo build`, `cargo test`
- **build.yml**: Multi-architecture release builds
- **copilot-setup-steps.yml**: Code quality checks

---

## 🔒 Security

### Security Features

- ✅ **Origin Validation**: Mandatory `--origin` flag with strict RP ID matching
- ✅ **File Locking**: Exclusive `flock` on credential writes prevents race conditions
- ✅ **Panic Safety**: All panics caught and converted to JSON errors
- ✅ **Challenge Expiry**: 2-minute TTL on challenges, automatic cleanup
- ✅ **Signature Counter**: Tracks authenticator usage, detects cloned keys
- ✅ **Secure Permissions**: Credentials stored with restrictive file modes (600/640)
- ✅ **No Secrets in Logs**: Sensitive data only via STDIN, errors to STDERR

### Threat Model

**Protected Against**:
- Cross-site request forgery (origin validation)
- Concurrent file corruption (file locking)
- Challenge replay attacks (single-use with expiry)
- Cloned security keys (signature counter)

**Out of Scope**:
- Physical access to `/etc/webauthn/` (assumed trusted)
- Network-level attacks (TLS required on LuCI layer)
- Side-channel attacks (use hardware security modules if needed)

### Reporting Vulnerabilities

Please report security issues to the repository owner via GitHub Security Advisories.

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the code style
4. Add tests for new functionality
5. Run `cargo fmt` and `cargo clippy`
6. Ensure all tests pass (`cargo test`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Code Style

- Follow Rust standard style (enforced by `cargo fmt`)
- Maximum line width: 140 characters (see `rustfmt.toml`)
- Use meaningful variable names
- Add comments for complex logic
- Write tests for new features

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, Remove, etc.)
- Reference issue numbers when applicable

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 時崎 ギャラクシー

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 Acknowledgments

- [webauthn_rp](https://github.com/AlfredoSequeida/webauthn_rp) - Pure Rust WebAuthn implementation
- [OpenWrt Project](https://openwrt.org/) - Target platform
- [FIDO Alliance](https://fidoalliance.org/) - WebAuthn/FIDO2 specifications

---

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/Tokisaki-Galaxy/webauthn-helper/issues)
- 💡 **Feature Requests**: [GitHub Issues](https://github.com/Tokisaki-Galaxy/webauthn-helper/issues)
- 📖 **Documentation**: [REQUIREMENTS.md](REQUIREMENTS.md)

---

<div align="center">

**Made with ❤️ for the OpenWrt community**

[![GitHub Stars](https://img.shields.io/github/stars/Tokisaki-Galaxy/webauthn-helper?style=social)](https://github.com/Tokisaki-Galaxy/webauthn-helper)
[![GitHub Forks](https://img.shields.io/github/forks/Tokisaki-Galaxy/webauthn-helper?style=social)](https://github.com/Tokisaki-Galaxy/webauthn-helper/fork)

</div>
