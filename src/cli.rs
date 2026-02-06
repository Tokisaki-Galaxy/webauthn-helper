use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "webauthn-helper",
    version,
    about = "WebAuthn/FIDO2 CLI helper for OpenWrt"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a registration challenge
    RegisterBegin {
        #[arg(long)]
        username: String,
        #[arg(long)]
        rp_id: String,
        #[arg(long, default_value = "preferred")]
        user_verification: String,
    },
    /// Verify registration and save credential
    RegisterFinish {
        #[arg(long)]
        challenge_id: String,
        #[arg(long)]
        origin: String,
        #[arg(long)]
        device_name: String,
    },
    /// Generate a login challenge
    LoginBegin {
        #[arg(long)]
        username: String,
        #[arg(long)]
        rp_id: String,
    },
    /// Verify login signature
    LoginFinish {
        #[arg(long)]
        challenge_id: String,
        #[arg(long)]
        origin: String,
    },
    /// Credential management
    CredentialManage {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Health check
    HealthCheck,
}

#[derive(Subcommand)]
pub enum CredentialAction {
    /// List credentials for a user
    List {
        #[arg(long)]
        username: String,
    },
    /// Delete a credential by ID
    Delete {
        #[arg(long)]
        id: String,
    },
    /// Update credential name
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
    },
    /// Remove expired challenge files
    Cleanup,
}
