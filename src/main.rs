mod cli;
mod commands;
mod errors;
mod schemas;
mod storage;

use cli::{Cli, Commands, CredentialAction};
use errors::AppError;
use schemas::ErrorResponse;
use storage::FileStorage;

fn run() -> Result<String, AppError> {
    let cli = Cli::parse();
    let storage = FileStorage::new();

    match cli.command {
        Commands::RegisterBegin {
            username,
            rp_id,
            user_verification,
        } => commands::register::register_begin(&storage, &username, &rp_id, &user_verification),

        Commands::RegisterFinish {
            challenge_id,
            origin,
            device_name,
        } => commands::register::register_finish(&storage, &challenge_id, &origin, &device_name),

        Commands::LoginBegin { username, rp_id } => commands::login::login_begin(&storage, &username, &rp_id),

        Commands::LoginFinish { challenge_id, origin } => commands::login::login_finish(&storage, &challenge_id, &origin),

        Commands::CredentialManage { action } => match action {
            CredentialAction::List { username } => commands::credential::list_credentials(&storage, &username),
            CredentialAction::Delete { id } => commands::credential::delete_credential(&storage, &id),
            CredentialAction::Update { id, name } => commands::credential::update_credential(&storage, &id, &name),
            CredentialAction::Cleanup => commands::credential::cleanup_challenges(&storage),
        },

        Commands::HealthCheck => commands::health::health_check(&storage),
    }
}

fn main() {
    // Catch panics and convert to JSON error output
    let result = std::panic::catch_unwind(run);

    match result {
        Ok(Ok(json)) => {
            println!("{}", json);
        }
        Ok(Err(err)) => {
            let response = ErrorResponse::new(err.error_code(), &err.to_string());
            let json = serde_json::to_string(&response).unwrap_or_else(|_| {
                r#"{"success":false,"error":{"code":"INTERNAL_ERROR","message":"Failed to serialize error response"}}"#.to_string()
            });
            eprintln!("{}", err);
            println!("{}", json);
            std::process::exit(1);
        }
        Err(_panic) => {
            let response = ErrorResponse::new("INTERNAL_ERROR", "An unexpected internal error occurred");
            let json = serde_json::to_string(&response).unwrap_or_else(|_| {
                r#"{"success":false,"error":{"code":"INTERNAL_ERROR","message":"An unexpected internal error occurred"}}"#.to_string()
            });
            println!("{}", json);
            std::process::exit(2);
        }
    }
}
