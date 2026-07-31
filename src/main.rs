use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use std::path::PathBuf;

// Modules are declared in the library crate (src/lib.rs).
use cipher_ai::{attack, ci, config, deps, fix, indexer, rag, report, review, sbom, secrets, zeroday};

const NAME: &str = "cipher-ai";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// CipherAI — AI-powered security analysis for your codebase.
///
/// Index your project, ask security questions, and scan for secrets
/// using Groq AI models — all from your terminal.
#[derive(Parser)]
#[command(
    name = NAME,
    version = VERSION,
    about = "AI-powered security analysis",
    long_about = None,
    styles = clap_styles(),
    subcommand_required = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to the project directory (defaults to current directory)
    #[arg(global = true, short = 'p', long = "path")]
    path: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Index a codebase for security analysis
    #[command(visible_alias = "i")]
    Init {
        /// Path to the project to index (defaults to current directory)
        path: Option<PathBuf>,

        /// Force re-index even if already indexed
        #[arg(short = 'f', long = "force")]
        force: bool,
    },

    /// Ask a security question about your codebase
    #[command(visible_alias = "q")]
    Ask {
        /// Your security question
        query: Vec<String>,

        /// Number of code chunks to retrieve for context
        #[arg(short = 'n', long = "top-n", default_value = "10")]
        top_n: usize,

        /// Model to use (defaults to config or groq default)
        #[arg(short = 'm', long = "model")]
        model: Option<String>,
    },

    /// Scan for secrets and credentials
    Secrets {
        /// Path to scan (defaults to current directory)
        path: Option<PathBuf>,

        /// Output format (pretty, json, compact)
        #[arg(short = 'f', long = "format", default_value = "pretty")]
        format: String,

        /// Exit with non-zero code if findings at or above this severity
        #[arg(long = "fail-on")]
        fail_on: Option<String>,

        /// Exit with error code if secrets found (legacy, use --fail-on)
        #[arg(long = "fail-on-secret", hide = true)]
        fail_on_secret: bool,
    },

    /// Show index status and project info
    Status,

    /// Run a comprehensive security review on the codebase
    #[command(visible_alias = "r")]
    Review {
        /// Include AI-powered deep analysis (requires API key)
        #[arg(long = "ai")]
        use_ai: bool,

        /// Model to use for AI analysis
        #[arg(short = 'm', long = "model")]
        model: Option<String>,

        /// Maximum number of findings to display (default: 30, use 0 for no limit)
        #[arg(long = "max-findings", default_value = "30")]
        max_findings: usize,

        /// Minimum severity to show (critical, high, medium, low)
        #[arg(long = "min-severity")]
        min_severity: Option<String>,

        /// Minimum confidence to show (high, medium, low)
        #[arg(long = "min-confidence")]
        min_confidence: Option<String>,

        /// Output format (terminal, json, markdown, sarif)
        #[arg(long = "format", default_value = "terminal")]
        format: String,

        /// Write output to a file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Scan dependencies for known vulnerabilities
    Deps {
        /// Enable online vulnerability database checks (requires internet)
        #[arg(long = "online")]
        online: bool,

        /// Exit with non-zero code if findings at or above this severity
        #[arg(long = "fail-on")]
        fail_on: Option<String>,
    },

    /// Generate a comprehensive security report
    #[command(visible_alias = "rep")]
    Report {
        /// Report type: developer (default), executive, or ci
        #[arg(long = "type", default_value = "developer")]
        report_type: String,

        /// Output format: terminal (default), markdown, or json
        #[arg(long = "format", default_value = "terminal")]
        format: String,

        /// Write output to a file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Analyze attack paths by connecting findings into realistic attack chains
    Attack {
        /// Filter by chain type (privilege-escalation, data-exfiltration, etc.)
        #[arg(long = "chain")]
        chain: Option<String>,

        /// Maximum steps in an attack chain (default: 3)
        #[arg(long = "depth", default_value = "3")]
        depth: usize,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,

        /// Skip AI-powered enrichment for faster results
        #[arg(long = "no-ai")]
        no_ai: bool,
    },

    /// Auto-fix security vulnerabilities using AI
    #[command(visible_alias = "f")]
    Fix {
        /// Fix a specific finding by ID (or UUID prefix)
        #[arg(long = "id")]
        finding_id: Option<String>,

        /// Fix findings with this risk level or higher (critical | high | medium | low)
        #[arg(long = "risk")]
        risk_level: Option<String>,

        /// Fix findings in a specific file (path contains match)
        #[arg(long = "file")]
        target_file: Option<String>,

        /// Fix all fixable findings
        #[arg(long = "all")]
        fix_all: bool,

        /// List fixable findings without fixing
        #[arg(long = "list")]
        list_only: bool,

        /// Show what would be changed without applying (dry run)
        #[arg(long = "dry-run")]
        dry_run: bool,

        /// Auto-apply all fixes without prompting
        #[arg(short = 'y', long = "yes")]
        auto_apply: bool,
    },

    /// Run all security scans with consolidated CI output
    #[command(visible_alias = "c")]
    Ci {
        /// Exit with non-zero code if findings at or above this severity
        #[arg(long = "fail-on", default_value = "high")]
        fail_on: Option<String>,

        /// Include AI-powered deep analysis in review
        #[arg(long = "ai")]
        use_ai: bool,

        /// Output format (terminal, json)
        #[arg(long = "format", default_value = "terminal")]
        format: String,

        /// Write output to a file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Manage configuration settings
    Config {
        /// Action: show (default), set, get
        action: Option<String>,

        /// Config key (groq-api-key, default-model)
        key: Option<String>,

        /// Config value
        value: Option<String>,
    },

    /// Detect zero-day (novel/unknown) vulnerabilities using 3-layer analysis
    ///
    /// Layer 1: Anomaly Detection — finds suspicious code patterns
    /// Layer 2: Taint Flow Analysis — tracks untrusted data to dangerous sinks
    /// Layer 3: AI Zero-Day Hunter — LLM-based novel vulnerability discovery
    #[command(visible_alias = "zd")]
    Zeroday {
        /// Include AI-powered zero-day analysis (requires API key)
        #[arg(long = "ai")]
        use_ai: bool,

        /// Model to use for AI analysis
        #[arg(short = 'm', long = "model")]
        model: Option<String>,

        /// Output format (terminal, json, sarif)
        #[arg(long = "format", default_value = "terminal")]
        format: String,

        /// Write output to a file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<String>,

        /// Only run anomaly detection (skip taint flow and AI analysis)
        #[arg(long = "anomaly-only")]
        anomaly_only: bool,

        /// Skip taint flow analysis
        #[arg(long = "no-flow")]
        no_flow: bool,
    },

    /// Generate a Software Bill of Materials (SBOM) for your project
    ///
    /// Scans all dependency manifests and generates a CycloneDX or SPDX
    /// compliant bill of materials in JSON format.
    #[command(visible_alias = "bom")]
    Sbom {
        /// SBOM format: cyclonedx (default) or spdx
        #[arg(long = "format", default_value = "cyclonedx")]
        format: String,

        /// Write output to a file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(ValueEnum, Clone)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

fn clap_styles() -> clap::builder::Styles {
    use clap::builder::styling;
    styling::Styles::styled()
        .header(styling::AnsiColor::Green.on_default().bold())
        .usage(styling::AnsiColor::Green.on_default().bold())
        .literal(styling::AnsiColor::Cyan.on_default().bold())
        .placeholder(styling::AnsiColor::Yellow.on_default())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::WARN)
        .init();

    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path, force } => {
            let project_path = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            indexer::run_init(&project_path, force).await?;
        }
        Commands::Ask { query, top_n, model } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            let query_str = query.join(" ");
            if query_str.trim().is_empty() {
                eprintln!("{}", "Error: No query provided.".red().bold());
                std::process::exit(1);
            }
            rag::run_ask(&project_path, &query_str, top_n, model.as_deref()).await?;
        }
        Commands::Secrets { path, format, fail_on, fail_on_secret } => {
            let scan_path = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            // Combine legacy --fail-on-secret with new --fail-on
            let fail_level = fail_on.as_deref().or(if fail_on_secret { Some("high") } else { None });
            secrets::run_secrets(&scan_path, &format, fail_level).await?;
        }
        Commands::Status => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            indexer::run_status(&project_path).await?;
        }
        Commands::Review { use_ai, model, max_findings, min_severity, min_confidence, format, output } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            let min_sev = min_severity.as_deref().and_then(review::parse_severity_filter);
            let min_conf = min_confidence.as_deref().and_then(review::parse_confidence_filter);
            let max_f = if max_findings == 0 { None } else { Some(max_findings) };
            review::run_review(&project_path, use_ai, model.as_deref(), max_f, min_sev, min_conf, &format, output.as_deref()).await?;
        }
        Commands::Deps { online, fail_on } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            deps::run_deps(&project_path, online, fail_on.as_deref()).await?;
        }
        Commands::Report { report_type, format, output } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            report::run_report(&project_path, &report_type, &format, output.as_deref()).await?;
        }
        Commands::Attack { chain, depth, json, no_ai } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            attack::run_attack(&project_path, chain.as_deref(), depth, json, !no_ai).await?;
        }
        Commands::Fix { finding_id, risk_level, target_file, fix_all, list_only, dry_run, auto_apply } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            fix::run_fix(&project_path, finding_id.as_deref(), risk_level.as_deref(), target_file.as_deref(), fix_all, list_only, dry_run, auto_apply).await?;
        }
        Commands::Ci { fail_on, use_ai, format, output } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            ci::run_ci(&project_path, fail_on.as_deref(), use_ai, &format, output.as_deref()).await?;
        }
        Commands::Config { action, key, value } => {
            config::run_config(action.as_deref(), key.as_deref(), value.as_deref())?;
        }
        Commands::Sbom { format, output } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            sbom::run_sbom(&project_path, &format, output.as_deref()).await?;
        }
        Commands::Zeroday { use_ai, model, format, output, anomaly_only, no_flow } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            zeroday::run_zeroday(&project_path, use_ai, model.as_deref(), &format, output.as_deref(), anomaly_only, no_flow).await?;
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            let shell_enum = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
                Shell::PowerShell => clap_complete::Shell::PowerShell,
            };
            clap_complete::generate(shell_enum, &mut cmd, "cipher-ai", &mut std::io::stdout());
        }
    }

    Ok(())
}
