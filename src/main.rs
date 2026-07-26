use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

mod deps;
mod finding;
mod groq;
mod indexer;
mod rag;
mod review;
mod secrets;

const NAME: &str = "cipher";
const VERSION: &str = "0.1.0";

/// Cipher — AI-powered security analysis for your codebase.
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
    ///   cipher ask "Can users become admin?"
    ///   cipher ask "Find authentication bypass vulnerabilities"
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
    ///   cipher review
    ///   cipher review --ai          # includes AI-powered deep analysis
    ///   cipher review --ai --model llama-3.3-70b-versatile
    Review {
        /// Include AI-powered deep analysis (requires API key)
        #[arg(long = "ai")]
        use_ai: bool,

        /// Model to use for AI analysis
        #[arg(short = 'm', long = "model")]
        model: Option<String>,
    },

    /// Scan dependencies for known vulnerabilities
    ///
    /// Parses dependency manifests (Cargo.toml, package.json, requirements.txt)
    /// and checks against known vulnerability databases.
    ///
    /// Examples:
    ///   cipher deps
    ///   cipher deps --online           # queries OSV.dev API
    Deps {
        /// Enable online vulnerability database checks (requires internet)
        #[arg(long = "online")]
        online: bool,
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
        Commands::Review { use_ai, model } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            review::run_review(&project_path, use_ai, model.as_deref()).await?;
        }
        Commands::Deps { online } => {
            let project_path = cli.path.unwrap_or_else(|| std::env::current_dir().unwrap());
            deps::run_deps(&project_path, online).await?;
        }
    }

    Ok(())
}
