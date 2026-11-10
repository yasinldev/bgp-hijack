use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use bgp_hijack_core::config::load_config;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Offline configuration validation for isolated BGP research labs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a configuration. Use --static for the currently available checks.
    Validate {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Check the YAML file only; does not verify the live lab or isolation.
        #[arg(long = "static")]
        static_only: bool,
    },
    /// Run a lab scenario (not implemented yet).
    Run {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Re-evaluate saved run artifacts (not implemented yet).
    Report {
        #[arg(long, value_name = "DIR")]
        run: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Validate { config, static_only: true } => {
            let validated = load_config(&config)?;
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, &validated.report())?;
            writeln!(stdout)?;
            Ok(())
        }
        Command::Validate { .. } => Err("live lab validation is not implemented; use validate --config FILE --static for file-only checks".into()),
        Command::Run { .. } => Err("scenario execution is not implemented in Sprint 1".into()),
        Command::Report { .. } => Err("offline artifact reporting is not implemented in Sprint 1".into()),
    }
}
