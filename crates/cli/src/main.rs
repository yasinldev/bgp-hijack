use bgp_hijack_analysis::{
    self as analysis,
    lookup::{LookupClient, Query},
    model::AnalysisLimits,
};
use bgp_hijack_core::{config::load_config, model::CanonicalPrefix};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
#[derive(Debug, Parser)]
#[command(version, about = "Passive BGP analysis and isolated routing lab tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}
#[derive(Debug, Subcommand)]
enum Command {
    /// Query public routing observations using RIPEstat.
    Lookup {
        #[command(subcommand)]
        query: Lookup,
        #[arg(long, value_enum, default_value = "text", global = true)]
        format: Format,
    },
    /// Inspect a local routing data file without network access.
    Inspect {
        #[command(subcommand)]
        input: Inspect,
    },
    /// Record filtered public routing observations.
    Watch {
        #[command(subcommand)]
        stream: Watch,
    },
    /// Re-evaluate a saved passive analysis, or address a legacy lab run.
    Report {
        #[arg(long, required_unless_present = "run", conflicts_with = "run")]
        analysis: Option<PathBuf>,
        #[arg(long)]
        run: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Isolated lab commands. Active scenarios are not implemented yet.
    Lab {
        #[command(subcommand)]
        command: Lab,
    },
    /// Compatibility alias for lab validate.
    Validate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long = "static")]
        static_only: bool,
    },
    /// Compatibility alias for lab run (not implemented yet).
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Debug, Subcommand)]
enum Lab {
    Validate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long = "static")]
        static_only: bool,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Report {
        #[arg(long)]
        run: PathBuf,
    },
}
#[derive(Debug, Subcommand)]
enum Lookup {
    Ip {
        address: std::net::IpAddr,
    },
    Prefix {
        cidr: CanonicalPrefix,
    },
    Asn {
        #[arg(value_parser=parse_asn)]
        asn: u32,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        end: Option<String>,
    },
}
fn parse_asn(s: &str) -> Result<u32, String> {
    s.strip_prefix("AS")
        .or_else(|| s.strip_prefix("as"))
        .unwrap_or(s)
        .parse()
        .map_err(|_| "expected a 32-bit ASN, optionally prefixed by AS".into())
}
#[derive(Debug, Subcommand)]
enum Inspect {
    Mrt {
        file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Pcap {
        file: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        session_context: Option<PathBuf>,
    },
}
#[derive(Debug, Subcommand)]
enum Watch {
    Routes {
        #[arg(long, required = true)]
        prefix: Vec<CanonicalPrefix>,
        #[arg(long, required = true)]
        collector: Vec<String>,
        #[arg(long)]
        duration: u64,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        more_specific: bool,
    },
}
#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err((code, error)) => {
            eprintln!("error: {error}");
            ExitCode::from(code)
        }
    }
}
type CliResult = Result<u8, (u8, String)>;
fn err(e: analysis::Error) -> (u8, String) {
    (
        match e {
            analysis::Error::Invalid(_) => 2,
            _ => 3,
        },
        e.to_string(),
    )
}
fn output(value: serde_json::Value, format: Format) -> CliResult {
    let mut stdout = io::stdout().lock();
    let text = match format {
        Format::Json => serde_json::to_string(&value).map_err(|e| (3, e.to_string()))?,
        Format::Text => render_text(&value),
    };
    writeln!(stdout, "{text}").map_err(|e| (3, e.to_string()))?;
    Ok(0)
}
fn render_text(value: &serde_json::Value) -> String {
    if value.get("provider").is_some() {
        format!(
            "Query: {}\nProvider: {}\nRetrieved: {}\nStatus: {}\nProvider observations (including visibility and source time):\n{}",
            value["query"].as_str().unwrap_or(""),
            value["provider"].as_str().unwrap_or(""),
            value["retrieved_at"].as_str().unwrap_or(""),
            value["status"].as_str().unwrap_or(""),
            serde_json::to_string_pretty(&value["responses"]).unwrap_or_default()
        )
    } else {
        let findings = value["findings"].as_array();
        let mut text = format!(
            "Analysis: {}\nProcessing: {}\nCoverage: {}\nEvents: {}\nFindings: {}",
            value["run_id"].as_str().unwrap_or(""),
            value["processing_status"].as_str().unwrap_or(""),
            value["coverage"].as_str().unwrap_or(""),
            value["events"],
            findings.map_or(0, Vec::len)
        );
        if let Some(findings) = findings {
            for f in findings {
                text.push_str(&format!(
                    "\n- {} {}: {}",
                    f["kind"].as_str().unwrap_or(""),
                    f["prefix"].as_str().unwrap_or(""),
                    f["explanation"].as_str().unwrap_or("")
                ));
            }
        }
        if let Some(gaps) = value["gaps"].as_array() {
            for gap in gaps {
                text.push_str(&format!("\nGap: {}", gap.as_str().unwrap_or("")));
            }
        }
        text
    }
}
fn lab(command: Lab) -> CliResult {
    match command {
    Lab::Validate{config,static_only:true}=>{let v=load_config(&config).map_err(|e|(2,e.to_string()))?;output(serde_json::to_value(v.report()).map_err(|e|(3,e.to_string()))?,Format::Json)},
    Lab::Validate{..}=>Err((2,"live lab validation is not implemented; use validate --config FILE --static for file-only checks".into())),
    Lab::Run{..}=>Err((2,"active lab scenario execution is not implemented".into())),
    Lab::Report{..}=>Err((2,"offline lab artifact reporting is not implemented".into())),
}
}
async fn execute(cli: Cli) -> CliResult {
    match cli.command {
        Command::Lab { command } => lab(command),
        Command::Validate {
            config,
            static_only,
        } => lab(Lab::Validate {
            config,
            static_only,
        }),
        Command::Run { config, output } => lab(Lab::Run { config, output }),
        Command::Lookup { query, format } => {
            let q = match query {
                Lookup::Ip { address } => Query::Ip(address),
                Lookup::Prefix { cidr } => Query::Prefix(cidr),
                Lookup::Asn { asn, start, end } => Query::Asn { asn, start, end },
            };
            let r = LookupClient::new()
                .map_err(err)?
                .lookup(q)
                .await
                .map_err(err)?;
            output(
                serde_json::to_value(r).map_err(|e| (3, e.to_string()))?,
                format,
            )
        }
        Command::Report {
            analysis: Some(dir),
            format,
            ..
        } => {
            let s = analysis::bundle::report(&dir).map_err(err)?;
            let code = if s.coverage == "partial" { 4 } else { 0 };
            output(
                serde_json::to_value(s).map_err(|e| (3, e.to_string()))?,
                format,
            )?;
            Ok(code)
        }
        Command::Report { run: Some(run), .. } => lab(Lab::Report { run }),
        Command::Report { .. } => unreachable!(),
        Command::Inspect { input } => {
            let (file, dir, context) = match &input {
                Inspect::Mrt { file, output } => (file, output, None),
                Inspect::Pcap {
                    file,
                    output,
                    session_context,
                } => (
                    file,
                    output,
                    session_context
                        .as_ref()
                        .map(|p| analysis::pcap::load_context(p))
                        .transpose()
                        .map_err(err)?,
                ),
            };
            // Validate input before creating an output directory.
            std::fs::File::open(file).map_err(|e| (3, format!("{}: {e}", file.display())))?;
            let mut writer = analysis::bundle::BundleWriter::create(
                dir,
                file.display().to_string(),
                serde_json::json!({}),
                AnalysisLimits::default(),
            )
            .map_err(err)?;
            let cancellation = writer.cancellation();
            let signal = tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            });
            let file = file.clone();
            let (summary, code) =
                tokio::task::spawn_blocking(move || -> Result<_, (u8, String)> {
                    let result = match input {
                        Inspect::Mrt { .. } => analysis::mrt::inspect(&file, &mut writer),
                        Inspect::Pcap { .. } => {
                            analysis::pcap::inspect(&file, context.unwrap_or_default(), &mut writer)
                        }
                    };
                    let complete = result.is_ok();
                    let interrupted = matches!(result, Err(analysis::Error::Interrupted));
                    if let Err(error) = result {
                        writer.gap(error.to_string()).map_err(err)?;
                    }
                    let summary = writer.finish(complete).map_err(err)?;
                    let code = if interrupted {
                        130
                    } else if summary.coverage == "partial" {
                        4
                    } else {
                        0
                    };
                    Ok((summary, code))
                })
                .await
                .map_err(|e| (3, e.to_string()))??;
            signal.abort();
            output(
                serde_json::to_value(summary).map_err(|e| (3, e.to_string()))?,
                Format::Json,
            )?;
            Ok(code)
        }
        Command::Watch {
            stream:
                Watch::Routes {
                    prefix,
                    collector,
                    duration,
                    output: dir,
                    more_specific,
                },
        } => {
            let (s, code) = analysis::ris::watch(analysis::ris::WatchOptions {
                prefixes: prefix,
                collectors: collector,
                more_specific,
                duration: Duration::from_secs(duration),
                output: dir,
                limits: AnalysisLimits::default(),
            })
            .await
            .map_err(err)?;
            output(
                serde_json::to_value(s).map_err(|e| (3, e.to_string()))?,
                Format::Json,
            )?;
            Ok(code)
        }
    }
}
