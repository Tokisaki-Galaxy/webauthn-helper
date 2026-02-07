# WebAuthn Helper

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Tokisaki-Galaxy/webauthn-helper/test.yml?branch=master)](https://github.com/Tokisaki-Galaxy/webauthn-helper/actions)
[![GitHub Release](https://img.shields.io/github/v/release/Tokisaki-Galaxy/webauthn-helper)](https://github.com/Tokisaki-Galaxy/webauthn-helper/releases)

**🇨🇳 中文** | **[English](README.md)**

*为 OpenWrt 路由器设计的轻量级、无状态 WebAuthn/FIDO2 CLI 工具*

</div>

---

## 📋 目录

- [概述](#-概述)
- [特性](#-特性)
- [架构](#-架构)
- [安装](#-安装)
- [使用方法](#-使用方法)
  - [注册流程](#注册流程)
  - [认证流程](#认证流程)
  - [凭证管理](#凭证管理)
  - [健康检查](#健康检查)
- [CLI 参考](#-cli-参考)
- [JSON 模式](#-json-模式)
- [从源码构建](#-从源码构建)
- [测试](#-测试)
- [安全性](#-安全性)
- [贡献](#-贡献)
- [许可证](#-许可证)

---

## 🎯 概述

**webauthn-helper** 是一个用 Rust 编写的独立 CLI 工具，为 OpenWrt 路由器提供 WebAuthn/FIDO2 认证功能。它被设计为由 LuCI Web 界面（通过 `ucode` 或 `luci-base`）调用，使用安全密钥、平台认证器和通行密钥处理无密码认证。

### 为什么选择 WebAuthn Helper？

- **零运行时依赖**：编译为静态二进制文件（musl），可在精简的 OpenWrt 系统上运行
- **无状态执行**：无守护进程 - 每个命令运行、输出 JSON 并退出
- **基于 IP 的 RP ID**：支持 IP 地址作为依赖方 ID，这对路由器环境至关重要
- **安全设计**：文件锁定、源验证、panic 安全处理和全面的错误处理
- **多架构**：为 x86_64、aarch64、arm_v7、mips 等提供预构建二进制文件

---

## ✨ 特性

- 🔐 **完整的 WebAuthn 流程**：使用 FIDO2 安全密钥进行注册和认证
- 📱 **多种认证器**：支持 USB、NFC 和平台认证器
- 🔒 **安全存储**：凭证存储在 `/etc/webauthn/credentials.json`，带文件锁定
- ⚡ **快速轻量**：使用 `opt-level = "z"` 和 LTO 优化大小
- 🌐 **源验证**：严格的源检查以防止跨站攻击
- 🛡️ **克隆检测**：签名计数器跟踪以检测克隆的安全密钥
- 📊 **JSON I/O**：所有通信通过严格的 JSON 模式，易于集成
- 🧪 **充分测试**：52+ 单元和集成测试，覆盖率 >90%

---

## 🏗️ 架构

### 数据流

```
┌─────────────┐
│   LuCI UI   │ (ucode/luci-base)
└──────┬──────┘
       │ sys.exec()
       ▼
┌─────────────────────────────────┐
│    webauthn-helper (CLI)        │
│  ┌───────────────────────────┐  │
│  │  1. 解析参数              │  │
│  │  2. 读取 STDIN (JSON)     │  │
│  │  3. 处理 WebAuthn         │  │
│  │  4. 文件 I/O + 锁定       │  │
│  │  5. 输出 JSON (STDOUT)    │  │
│  └───────────────────────────┘  │
└────────┬────────────────┬───────┘
         │                │
         ▼                ▼
   /etc/webauthn/    /tmp/webauthn/
   credentials.json  challenges/*.json
   (持久化)          (临时，2分钟 TTL)
```

### 存储设计

- **凭证**：`/etc/webauthn/credentials.json` - 持久化存储，带排他文件锁（`flock`）
- **挑战**：`/tmp/webauthn/challenges/<uuid>.json` - 临时挑战状态（2分钟后自动清理）
- **二进制数据**：所有加密材料（密钥、挑战、ID）编码为 Base64URL 字符串

### WebAuthn 实现

- 使用 **webauthn_rp v0.3.0**（纯 Rust，无 OpenSSL 依赖）
- 特性：`serde_relaxed`、`serializable_server_state`
- 直接核心 API（`WebauthnCore::new_unsafe_experts_only`）以支持基于 IP 的 RP ID

---

## 📦 安装

### 预构建二进制文件

从 [Releases](https://github.com/Tokisaki-Galaxy/webauthn-helper/releases) 下载适用于您的 OpenWrt 架构的预编译二进制文件：

```bash
# x86_64 示例
wget https://github.com/Tokisaki-Galaxy/webauthn-helper/releases/latest/download/webauthn-helper-x86_64-unknown-linux-musl
chmod +x webauthn-helper-x86_64-unknown-linux-musl
mv webauthn-helper-x86_64-unknown-linux-musl /usr/bin/webauthn-helper

# 创建所需目录
mkdir -p /etc/webauthn /tmp/webauthn/challenges
chmod 700 /etc/webauthn
```

### 支持的架构

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `armv7-unknown-linux-musleabihf`
- `mips-unknown-linux-musl`
- `mipsel-unknown-linux-musl`

---

## 🚀 使用方法

所有命令遵循此模式：
1. **输入**：命令行参数 + 可选的 STDIN（JSON）
2. **输出**：STDOUT 上的 JSON 响应
3. **错误**：记录到 STDERR，STDOUT 上的 JSON 错误

### 注册流程

#### 1. 开始注册

```bash
webauthn-helper register-begin \
  --username root \
  --rp-id 192.168.1.1 \
  --user-verification preferred
```

**输出**（保存 `challengeId` 用于步骤 2）：
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

#### 2. 完成注册

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
  --device-name "我的 YubiKey 5C"
```

**输出**：
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

### 认证流程

#### 1. 开始登录

```bash
webauthn-helper login-begin \
  --username root \
  --rp-id 192.168.1.1
```

**输出**：
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

#### 2. 完成登录

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

**输出**：
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

### 凭证管理

#### 列出凭证

```bash
webauthn-helper credential-manage list --username root
```

**输出**：
```json
{
  "success": true,
  "data": [
    {
      "credentialId": "Y3JlZGVudGlhbF9pZA...",
      "username": "root",
      "deviceName": "我的 YubiKey 5C",
      "createdAt": "2026-02-07T10:00:00Z",
      "lastUsedAt": "2026-02-07T14:30:00Z",
      "backupEligible": false,
      "userVerified": true
    }
  ]
}
```

#### 更新凭证名称

```bash
webauthn-helper credential-manage update \
  --id Y3JlZGVudGlhbF9pZA \
  --name "办公室 YubiKey"
```

#### 删除凭证

```bash
webauthn-helper credential-manage delete \
  --id Y3JlZGVudGlhbF9pZA
```

#### 清理过期的挑战

```bash
webauthn-helper credential-manage cleanup
```

### 健康检查

```bash
webauthn-helper health-check
```

**输出**：
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

## 📖 CLI 参考

### 全局选项

- `--help` - 显示帮助信息
- `--version` - 显示版本信息

### 命令

| 命令 | 描述 |
|------|------|
| `register-begin` | 为新凭证生成注册挑战 |
| `register-finish` | 验证注册响应并保存凭证 |
| `login-begin` | 生成认证挑战 |
| `login-finish` | 验证认证响应 |
| `credential-manage` | 管理存储的凭证（列出/删除/更新/清理） |
| `health-check` | 检查系统健康状态和存储状态 |

### register-begin

**参数**：
- `--username <string>` - 要注册的用户名（必需）
- `--rp-id <string>` - 依赖方 ID（域名或 IP，必需）
- `--user-verification <string>` - 用户验证要求（默认："preferred"）
  - 有效值：`required`、`preferred`、`discouraged`

**输出**：注册挑战 + challengeId

### register-finish

**参数**：
- `--challenge-id <uuid>` - 来自 register-begin 的挑战 ID（必需）
- `--origin <url>` - 源 URL（必须匹配 RP ID，必需）
- `--device-name <string>` - 安全密钥的友好名称（必需）

**STDIN**：来自浏览器的 PublicKeyCredential JSON

**输出**：凭证 ID + AAGUID + 创建时间戳

### login-begin

**参数**：
- `--username <string>` - 要认证的用户名（必需）
- `--rp-id <string>` - 依赖方 ID（必需）

**输出**：认证挑战 + challengeId

### login-finish

**参数**：
- `--challenge-id <uuid>` - 来自 login-begin 的挑战 ID（必需）
- `--origin <url>` - 源 URL（必须匹配 RP ID，必需）

**STDIN**：来自浏览器的 PublicKeyCredential JSON

**输出**：用户名 + userVerified + 签名计数器

### credential-manage

**子命令**：

#### list
- `--username <string>` - 要列出凭证的用户名

#### delete
- `--id <string>` - 要删除的 Base64URL 编码凭证 ID

#### update
- `--id <string>` - 要更新的 Base64URL 编码凭证 ID
- `--name <string>` - 凭证的新友好名称

#### cleanup
无参数。删除过期的挑战文件（>2 分钟）。

### health-check

无参数。返回系统状态和存储信息。

---

## 📝 JSON 模式

所有 I/O 使用严格的 JSON 模式：
- **camelCase** 键（外部 API）
- **Base64URL** 编码二进制数据（无填充）
- **ISO 8601** 时间戳

### 成功响应格式

```json
{
  "success": true,
  "data": { /* 命令特定数据 */ }
}
```

### 错误响应格式

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "人类可读的错误消息"
  }
}
```

### 错误代码

| 代码 | 描述 |
|------|------|
| `CHALLENGE_NOT_FOUND` | 未找到挑战 ID 或已过期 |
| `USER_NOT_FOUND` | 用户没有注册凭证 |
| `CREDENTIAL_NOT_FOUND` | 未找到凭证 ID |
| `INVALID_ORIGIN` | 源不匹配 RP ID |
| `WEBAUTHN_ERROR` | WebAuthn 验证失败 |
| `STORAGE_ERROR` | 文件系统 I/O 错误 |
| `JSON_ERROR` | 无效的 JSON 输入 |
| `IO_ERROR` | 通用 I/O 错误 |
| `INVALID_INPUT` | 无效的命令参数 |
| `INTERNAL_ERROR` | 意外的 panic 或内部错误 |

完整的模式定义，请参见 [REQUIREMENTS.md](REQUIREMENTS.md)。

---

## 🔨 从源码构建

### 前置要求

- Rust 1.93+（2021 版本）
- 交叉编译：Docker 或 cross-rs

### 开发构建

```bash
# 克隆仓库
git clone https://github.com/Tokisaki-Galaxy/webauthn-helper.git
cd webauthn-helper

# 构建调试二进制文件
cargo build

# 运行
./target/debug/webauthn-helper --help
```

### 发布构建（优化）

```bash
cargo build --release

# 二进制文件位于：./target/release/webauthn-helper
# 大小：~1.5MB（启用 strip=true、LTO）
```

### OpenWrt 交叉编译

使用提供的构建脚本：

```bash
# 安装依赖
sudo ./install_dependencies.sh

# 为所有架构构建
sudo ./build_release.sh

# 输出到 ./release/ 目录
```

手动交叉编译：

```bash
# 安装 cross
cargo install cross

# 为 aarch64 构建
cross build --release --target aarch64-unknown-linux-musl

# 为 mips 构建
cross build --release --target mips-unknown-linux-musl
```

### 构建配置

来自 `Cargo.toml`：

```toml
[profile.release]
debug = 0
opt-level = "z"      # 优化大小
lto = true           # 链接时优化
codegen-units = 1    # 更好的优化
panic = "abort"      # 更小的二进制文件
strip = true         # 移除调试符号
```

---

## 🧪 测试

### 运行所有测试

```bash
cargo test
```

**测试覆盖率**：
- 总共 52 个测试
- 5 个单元测试（存储模块）
- 29 个单元测试（各种模块）
- 18 个集成测试（CLI 行为）

### 测试类别

```bash
# 仅单元测试
cargo test --lib

# 仅集成测试
cargo test --test '*'

# 特定测试文件
cargo test --test integration_tests

# 带输出
cargo test -- --nocapture
```

### 代码质量

```bash
# 格式化代码
cargo fmt

# Lint
cargo clippy

# 检查而不构建
cargo check
```

### CI/CD

项目使用 GitHub Actions 进行持续测试：

- **test.yml**：运行 `cargo fmt`、`cargo clippy`、`cargo build`、`cargo test`
- **build.yml**：多架构发布构建
- **copilot-setup-steps.yml**：代码质量检查

---

## 🔒 安全性

### 安全特性

- ✅ **源验证**：强制 `--origin` 标志，严格的 RP ID 匹配
- ✅ **文件锁定**：凭证写入时的排他 `flock` 防止竞态条件
- ✅ **Panic 安全**：所有 panic 被捕获并转换为 JSON 错误
- ✅ **挑战过期**：挑战 2 分钟 TTL，自动清理
- ✅ **签名计数器**：跟踪认证器使用，检测克隆密钥
- ✅ **安全权限**：凭证以限制性文件模式（600/640）存储
- ✅ **日志中无秘密**：敏感数据仅通过 STDIN，错误到 STDERR

### 威胁模型

**防护对象**：
- 跨站请求伪造（源验证）
- 并发文件损坏（文件锁定）
- 挑战重放攻击（单次使用带过期）
- 克隆的安全密钥（签名计数器）

**范围之外**：
- 物理访问 `/etc/webauthn/`（假设可信）
- 网络级攻击（LuCI 层需要 TLS）
- 侧信道攻击（如需要请使用硬件安全模块）

### 报告漏洞

请通过 GitHub 安全公告向仓库所有者报告安全问题。

---

## 🤝 贡献

欢迎贡献！请遵循以下指南：

### 开发工作流

1. Fork 仓库
2. 创建功能分支（`git checkout -b feature/amazing-feature`）
3. 按照代码风格进行更改
4. 为新功能添加测试
5. 运行 `cargo fmt` 和 `cargo clippy`
6. 确保所有测试通过（`cargo test`）
7. 提交更改（`git commit -m 'Add amazing feature'`）
8. 推送到分支（`git push origin feature/amazing-feature`）
9. 打开 Pull Request

### 代码风格

- 遵循 Rust 标准风格（由 `cargo fmt` 强制执行）
- 最大行宽：140 个字符（见 `rustfmt.toml`）
- 使用有意义的变量名
- 为复杂逻辑添加注释
- 为新功能编写测试

### 提交消息

- 使用清晰、描述性的提交消息
- 以动词开头（Add、Fix、Update、Remove 等）
- 在适用时引用问题编号

---

## 📄 许可证

本项目根据 MIT 许可证授权 - 详见 [LICENSE](LICENSE) 文件。

```
MIT License

Copyright (c) 2026 時崎 ギャラクシー

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 致谢

- [webauthn_rp](https://github.com/AlfredoSequeida/webauthn_rp) - 纯 Rust WebAuthn 实现
- [OpenWrt Project](https://openwrt.org/) - 目标平台
- [FIDO Alliance](https://fidoalliance.org/) - WebAuthn/FIDO2 规范

---

## 📞 支持

- 🐛 **错误报告**：[GitHub Issues](https://github.com/Tokisaki-Galaxy/webauthn-helper/issues)
- 💡 **功能请求**：[GitHub Issues](https://github.com/Tokisaki-Galaxy/webauthn-helper/issues)
- 📖 **文档**：[REQUIREMENTS.md](REQUIREMENTS.md)

---

<div align="center">

**用 ❤️ 为 OpenWrt 社区打造**

[![GitHub Stars](https://img.shields.io/github/stars/Tokisaki-Galaxy/webauthn-helper?style=social)](https://github.com/Tokisaki-Galaxy/webauthn-helper)
[![GitHub Forks](https://img.shields.io/github/forks/Tokisaki-Galaxy/webauthn-helper?style=social)](https://github.com/Tokisaki-Galaxy/webauthn-helper/fork)

</div>
