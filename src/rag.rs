use crate::groq::GroqClient;
use crate::indexer::{self, CodeChunk};
use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;

const DEFAULT_TOP_N: usize = 10;
const MAX_CONTEXT_CHARS: usize = 25_000;

/// Security-focused system prompt for the AI
const SECURITY_SYSTEM_PROMPT: &str = r#"You are CipherAI, an expert application security engineer AI assistant.

Your role is to analyze code and answer security-related questions with precision and clarity.

Follow these guidelines:
1. Be specific and reference actual code patterns, file names, and line numbers from the provided context.
2. If you find potential vulnerabilities, explain:
   - What the issue is
   - Where it is located (file, line)
   - Why it matters (impact)
   - How to fix it
3. If you're not confident about a finding, say so. Honesty builds trust.
4. Consider: OWASP Top 10, authentication flaws, authorization bypasses, injection attacks, business logic vulnerabilities, secret exposure, and insecure configurations.
5. Format your response with clear sections and code examples where helpful.
6. When suggesting fixes, provide actual code snippets.
7. If the provided code context doesn't contain enough information to answer definitively, say so and suggest what additional code would help.

Remember: You are looking at real code from the user's project. Ground every answer in the provided code context."#;

/// Run the `cipher-ai ask` command
pub async fn run_ask(
    project_path: &Path,
    query: &str,
    top_n: usize,
    model: Option<&str>,
) -> Result<()> {
    let top_n = if top_n == 0 { DEFAULT_TOP_N } else { top_n };

    let canonical_path = std::fs::canonicalize(project_path)?;

    // Load the index with spinner
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Loading index...")
            .unwrap(),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let index = match indexer::load_index(&canonical_path)? {
        Some(idx) => idx,
        None => {
            spinner.finish_and_clear();
            println!(
                "{} Project not indexed. Run {} first.",
                "[-]".bright_blue(),
                "cipher-ai init".yellow().bold()
            );
            return Ok(());
        }
    };

    // Search for relevant chunks using keyword search
    spinner.set_message("Searching codebase...");
    let results = indexer::search_index(&index, query, top_n);

    if results.is_empty() {
        spinner.finish_and_clear();
        println!(
            "{} No relevant code found for your query. Try rephrasing or use more specific terms.",
            "[*]".yellow()
        );
        return Ok(());
    }

    // Build context from retrieved chunks
    let mut context = String::new();
    let mut chunk_files: Vec<&CodeChunk> = Vec::new();

    for chunk in &results {
        let chunk_text = format!(
            "--- {}:{}:{} ({}) ---\n{}\n\n",
            chunk.relative_path,
            chunk.start_line,
            chunk.end_line,
            chunk.language,
            chunk.content
        );

        if context.len() + chunk_text.len() > MAX_CONTEXT_CHARS {
            break;
        }

        context.push_str(&chunk_text);
        chunk_files.push(chunk);
    }

    // Initialize Groq client
    spinner.set_message("Connecting to Groq...");
    let client = match GroqClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            spinner.finish_and_clear();
            eprintln!("{} {}", "✗".red().bold(), e);
            return Ok(());
        }
    };

    spinner.finish_and_clear();

    // Show what we found
    println!();
    println!(
        "{} {}",
        "[*]".bright_blue(),
        "Relevant Code Context".bold()
    );
    println!("  {}", "-".repeat(40).dimmed());

    let mut file_set: Vec<&str> = Vec::new();
    for chunk in &chunk_files {
        let path_str = chunk.relative_path.as_str();
        if !file_set.contains(&path_str) {
            file_set.push(path_str);
            println!(
                "  {}  {}:{}",
                "[FILE]".cyan(),
                path_str,
                format!("{}-{}", chunk.start_line, chunk.end_line).dimmed()
            );
        }
    }
    println!(
        "  {} {}",
        format!("Found {} relevant code chunks", chunk_files.len())
            .cyan()
            .bold(),
        format!("(~{} tokens)", context.len() / 4).dimmed()
    );
    println!();

    // Build the user prompt
    let user_prompt = format!(
        r#"I need to analyze my codebase for security issues.

## Question
{query}

## Code Context
Here are the relevant code files from my project:

{context}

Please analyze the code above and answer my security question thoroughly.
Focus on actionable insights and reference specific lines of code.
"#
    );

    // Show thinking indicator
    let model_name = model.unwrap_or("llama-3.3-70b-versatile");
    println!(
        "{} {}",
        "[AI]".bright_green(),
        format!("Thinking with {}...", model_name).bold()
    );

    // Query the LLM
    let response = client
        .chat(SECURITY_SYSTEM_PROMPT, &user_prompt, model)
        .await
        .map_err(|e| {
            eprintln!(
                "\n{} Groq API error: {}",
                "✗".red().bold(),
                e
            );
            e
        })?;

    // Print the response
    println!();
    println!("{}", "-".repeat(60).green());
    println!("{}", response.trim());
    println!("{}", "-".repeat(60).green());
    println!();

    Ok(())
}
