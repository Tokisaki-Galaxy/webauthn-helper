pub struct Cli {
    pub command: Commands,
}

pub enum Commands {
    RegisterBegin {
        username: String,
        rp_id: String,
        user_verification: String,
    },
    RegisterFinish {
        challenge_id: String,
        origin: String,
        device_name: String,
    },
    LoginBegin {
        username: String,
        rp_id: String,
    },
    LoginFinish {
        challenge_id: String,
        origin: String,
    },
    CredentialManage {
        action: CredentialAction,
    },
    HealthCheck,
}

pub enum CredentialAction {
    List { username: String },
    Delete { id: String },
    Update { id: String, name: String },
    Cleanup,
}

fn print_help() -> ! {
    println!(
        "WebAuthn/FIDO2 CLI helper for OpenWrt\n\n\
         Usage: webauthn-helper <COMMAND>\n\n\
         Commands:\n\
         \x20 register-begin     Generate a registration challenge\n\
         \x20 register-finish    Verify registration and save credential\n\
         \x20 login-begin        Generate a login challenge\n\
         \x20 login-finish       Verify login signature\n\
         \x20 credential-manage  Credential management\n\
         \x20 health-check       Health check\n\n\
         Options:\n\
         \x20 -h, --help     Print help\n\
         \x20 -V, --version  Print version"
    );
    std::process::exit(0);
}

fn print_version() -> ! {
    println!("webauthn-helper {}", env!("CARGO_PKG_VERSION"));
    std::process::exit(0);
}

fn missing_arg(name: &str) -> ! {
    eprintln!("error: the following required argument was not provided: {name}");
    std::process::exit(2);
}

fn take_option(args: &mut Vec<String>, name: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|a| a == name) {
        args.remove(pos);
        if pos < args.len() {
            return Some(args.remove(pos));
        }
    }
    None
}

fn require_option(args: &mut Vec<String>, name: &str) -> String {
    take_option(args, name).unwrap_or_else(|| missing_arg(name))
}

fn parse_credential_manage(args: &mut Vec<String>) -> CredentialAction {
    if args.is_empty() {
        eprintln!("error: a subcommand is required for credential-manage");
        std::process::exit(2);
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "list" => {
            let username = require_option(args, "--username");
            CredentialAction::List { username }
        }
        "delete" => {
            let id = require_option(args, "--id");
            CredentialAction::Delete { id }
        }
        "update" => {
            let id = require_option(args, "--id");
            let name = require_option(args, "--name");
            CredentialAction::Update { id, name }
        }
        "cleanup" => CredentialAction::Cleanup,
        _ => {
            eprintln!("error: unrecognized subcommand '{sub}'");
            std::process::exit(2);
        }
    }
}

impl Cli {
    pub fn parse() -> Self {
        let mut args: Vec<String> = std::env::args().skip(1).collect();

        if args.is_empty() {
            eprintln!(
                "error: a subcommand is required\n\n\
                 Usage: webauthn-helper <COMMAND>\n\n\
                 For more information, try '--help'."
            );
            std::process::exit(2);
        }

        // Check for global flags anywhere in args
        if args.iter().any(|a| a == "--help" || a == "-h") {
            print_help();
        }
        if args.iter().any(|a| a == "--version" || a == "-V") {
            print_version();
        }

        let subcmd = args.remove(0);
        let command = match subcmd.as_str() {
            "register-begin" => {
                let username = require_option(&mut args, "--username");
                let rp_id = require_option(&mut args, "--rp-id");
                let user_verification = take_option(&mut args, "--user-verification").unwrap_or_else(|| "preferred".to_string());
                Commands::RegisterBegin {
                    username,
                    rp_id,
                    user_verification,
                }
            }
            "register-finish" => {
                let challenge_id = require_option(&mut args, "--challenge-id");
                let origin = require_option(&mut args, "--origin");
                let device_name = require_option(&mut args, "--device-name");
                Commands::RegisterFinish {
                    challenge_id,
                    origin,
                    device_name,
                }
            }
            "login-begin" => {
                let username = require_option(&mut args, "--username");
                let rp_id = require_option(&mut args, "--rp-id");
                Commands::LoginBegin { username, rp_id }
            }
            "login-finish" => {
                let challenge_id = require_option(&mut args, "--challenge-id");
                let origin = require_option(&mut args, "--origin");
                Commands::LoginFinish { challenge_id, origin }
            }
            "credential-manage" => {
                let action = parse_credential_manage(&mut args);
                Commands::CredentialManage { action }
            }
            "health-check" => Commands::HealthCheck,
            other => {
                eprintln!("error: unrecognized subcommand '{other}'");
                std::process::exit(2);
            }
        };

        Cli { command }
    }
}
