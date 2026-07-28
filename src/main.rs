use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

mod attack;
mod deps;
mod finding;
mod fix;
mod groq;
mod indexer;
mod rag;
mod report;
mod review;
mod secrets;

const NAME: &str = "cipher-ai";
const VERSION: &str = "0.1.0";

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
    styles = clap_styles()
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
    ///
    /// Walks the codebase, parses files, chunks code,
    /// and generates embeddings for semantic search.
    Init {
        /// Path to the project to index (defaults to current directory)
        path: Option<PathBuf>,

        /// Force re-index even if already indexed
        #[arg(short = 'f', long = "force")]
        force: bool,
    },

    /// Ask a security question about your codebase
    ///
    /// Uses AI to answer security questions with code-level context.
    ///
    /// Examples:
    ///   cipher-ai ask "Can users become admin?"
    ///   cipher-ai ask "Find authentication bypass vulnerabilities"
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

        /// Exit with error code if secrets found (for CI/CD)
        #[arg(long = "fail-on-secret")]
        fail_on_secret: bool,
    },

    /// Show index status and project info
    Status,

    /// Run a comprehensive security review on the codebase
    ///
    /// Analyzes code for OWASP Top 10 vulnerabilities, hardcoded secrets,
    /// injection flaws, cryptographic weaknesses, and more.
    ///
    /// Examples:
    ///   cipher-ai review
    ///   cipher-ai review --ai          # includes AI-powered deep analysis
    ///   cipher-ai review --ai --model llama-3.3-70b-versatile
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
    },

    /// Scan dependencies for known vulnerabilities
    ///
    /// Parses dependency manifests (Cargo.toml, package.json, requirements.txt)
    /// and checks against known vulnerability databases.
    ///
    /// Examples:
    ///   cipher-ai deps
    ///   cipher-ai deps --online           # queries OSV.dev API
    Deps {
        /// Enable online vulnerability database checks (requires internet)
        #[arg(long = "online")]
        online: bool,
    },

    /// Generate a comprehensive security report
    ///
    /// Aggregates findings from security review, dependency scanning,
    /// and secret detection into a single report.
    ///
    /// Examples:
    ///   cipher-ai report
    ///   cipher-ai report --format json
    ///   cipher-ai report --format markdown --output report.md
    ///   cipher-ai report --type executive     # non-technical summary
    ///   cipher-ai report --type ci            # CI-friendly output
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
    ///
    /// Instead of isolated vulnerability reports, discovers how weaknesses
    /// can combine into practical attack scenarios.
    ///
    /// Examples:
    ///   cipher-ai attack
    ///   cipher-ai attack --chain privilege                  # filter by chain type
    ///   cipher-ai attack --no-ai                             # skip AI enrichment
    ///   cipher-ai attack --json                              # JSON output for CI
    ///   cipher-ai attack --depth 5                           # max chain depth
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
    ///
    /// Scans the codebase for findings, then uses AI to generate
    /// secure patches. Shows a diff before applying.
    ///
    /// Examples:
    ///   cipher fix --list                               # list fixable findings
    ///   cipher fix --id abc12345                        # fix a specific finding
    ///   cipher fix --risk critical                      # fix all critical findings
    ///   cipher fix --risk critical --yes                # auto-apply without prompt
    ///   cipher fix --file src/auth.rs                   # fix findings in a file
    ///   cipher fix --all                                # fix all findings (interactive)
    ///   cipher fix --all --yes                          # auto-fix everything
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

        /// Auto-apply all fixes without prompting
        #[arg(short = 'y', long = "yes")]
        auto_apply: bool,
    },
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
    // Initialize tracing (silent by default, set RUST_LOG=info for verbose)
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::WARN)
        .init();

    // Load .env file if present
    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path, force } => {
            let project_path = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            indexer::run_init(&project_path, force).await?;
        }
        Commands::Ask {
            query,
            top_n,
            model,
        } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            let query_str = query.join(" ");
            if query_str.trim().is_empty() {
                eprintln!("{}", "Error: No query provided.".red().bold());
                std::process::exit(1);
            }
            rag::run_ask(&project_path, &query_str, top_n, model.as_deref()).await?;
        }
        Commands::Secrets {
            path,
            format,
            fail_on_secret,
        } => {
            let scan_path = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            secrets::run_secrets(&scan_path, &format, fail_on_secret).await?;
        }
        Commands::Status => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            indexer::run_status(&project_path).await?;
        }
        Commands::Review {
            use_ai,
            model,
            max_findings,
            min_severity,
            min_confidence,
        } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            let min_sev = min_severity
                .as_deref()
                .and_then(review::parse_severity_filter);
            let min_conf = min_confidence
                .as_deref()
                .and_then(review::parse_confidence_filter);
            let max_f = if max_findings == 0 {
                None
            } else {
                Some(max_findings)
            };
            review::run_review(
                &project_path,
                use_ai,
                model.as_deref(),
                max_f,
                min_sev,
                min_conf,
            )
            .await?;
        }
        Commands::Deps { online } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            deps::run_deps(&project_path, online).await?;
        }
        Commands::Report {
            report_type,
            format,
            output,
        } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            report::run_report(
                &project_path,
                &report_type,
                &format,
                output.as_deref(),
            )
            .await?;
        }
        Commands::Attack {
            chain,
            depth,
            json,
            no_ai,
        } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            attack::run_attack(
                &project_path,
                chain.as_deref(),
                depth,
                json,
                !no_ai,
            )
            .await?;
        }
        Commands::Fix {
            finding_id,
            risk_level,
            target_file,
            fix_all,
            list_only,
            auto_apply,
        } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            fix::run_fix(
                &project_path,
                finding_id.as_deref(),
                risk_level.as_deref(),
                target_file.as_deref(),
                fix_all,
                list_only,
                auto_apply,
            )
            .await?;
        }
    }

    Ok(())
}
