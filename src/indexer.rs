use anyhow::{Context, Result};
use colored::*;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Supported file extensions for indexing
const SUPPORTED_EXTENSIONS: &[&str] = &[
    "rs", "js", "jsx", "ts", "tsx", "py", "go", "rb", "java", "kt", "swift",
    "c", "cpp", "h", "hpp", "cs", "php", "sh", "bash", "zsh", "yaml", "yml",
    "json", "toml", "dockerfile", "sql", "graphql", "proto", "vue", "svelte",
];

/// A single chunk of code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChunk {
    pub id: String,
    pub file_path: String,
    pub relative_path: String,
    pub language: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
}

/// TF-IDF term frequency for a single chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermFreq {
    /// Term -> frequency in this chunk
    pub terms: HashMap<String, usize>,
    /// Total number of terms in this chunk
    pub total_terms: usize,
}

/// Summary of the indexed project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSummary {
    pub project_path: String,
    pub indexed_at: String,
    pub total_files: usize,
    pub total_chunks: usize,
    pub languages: HashMap<String, usize>,
}

/// The full index stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeIndex {
    pub summary: IndexSummary,
    pub chunks: Vec<CodeChunk>,
    /// TF-IDF term frequencies for each chunk (parallel to chunks)
    pub term_freqs: Vec<TermFreq>,
    /// Inverse document frequency for each term across all chunks
    pub idf: HashMap<String, f64>,
}

/// Detect programming language from file extension
fn detect_language(path: &Path) -> Option<&'static str> {
    let ext = path
        .extension()
        .map(|e| e.to_str().unwrap_or("").to_lowercase())
        .unwrap_or_default();

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_lowercase())
        .unwrap_or_default();

    let by_ext = match ext.as_str() {
        "rs" => Some("rust"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        "ts" | "tsx" | "mts" | "cts" => Some("typescript"),
        "py" | "pyw" => Some("python"),
        "go" => Some("go"),
        "rb" => Some("ruby"),
        "java" => Some("java"),
        "kt" | "kts" => Some("kotlin"),
        "swift" => Some("swift"),
        "c" | "h" => Some("c"),
        "cpp" | "hpp" | "cc" | "cxx" | "hh" => Some("cpp"),
        "cs" => Some("csharp"),
        "php" => Some("php"),
        "sh" | "bash" | "zsh" | "fish" => Some("shell"),
        "yaml" | "yml" => Some("yaml"),
        "json" => Some("json"),
        "toml" => Some("toml"),
        "sql" => Some("sql"),
        "graphql" | "gql" => Some("graphql"),
        "proto" => Some("protobuf"),
        "vue" => Some("vue"),
        "svelte" => Some("svelte"),
        "html" | "htm" => Some("html"),
        "css" | "scss" | "less" => Some("css"),
        "dart" => Some("dart"),
        "scala" => Some("scala"),
        "lua" => Some("lua"),
        "r" | "rdata" => Some("r"),
        _ => None,
    };

    if by_ext.is_some() {
        return by_ext;
    }

    match file_name.as_str() {
        n if n == "dockerfile" || n.starts_with("dockerfile.") => Some("dockerfile"),
        n if n == "makefile" => Some("makefile"),
        n if n.ends_with(".env") || n == ".env" => Some("env"),
        _ => None,
    }
}

/// Check if a file should be indexed
fn is_supported(path: &Path) -> bool {
    detect_language(path).is_some()
}

/// Estimate token count (rough approximation: ~4 chars per token)
#[allow(dead_code)]
fn estimate_tokens(text: &str) -> usize {
    text.len() / 4 + 1
}

/// Smart chunking: try to split at natural boundaries
fn chunk_code(content: &str, max_chunk_tokens: usize) -> Vec<(usize, usize, String)> {
    let max_chars = max_chunk_tokens * 4;
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    let mut chunks = Vec::new();
    let mut start = 0;

    if total_lines == 0 {
        return chunks;
    }

    while start < total_lines {
        let mut end = start;
        let mut char_count = 0;

        while end < total_lines && char_count < max_chars {
            char_count += lines[end].len() + 1;
            end += 1;

            if char_count >= max_chars / 2 {
                let line = lines[end - 1].trim();
                if end < total_lines && (line.is_empty() || line == "}" || line == "```")
                {
                    break;
                }
            }
        }

        if end == start {
            end = start + 1;
        }

        let chunk_content = lines[start..end].join("\n");
        if !chunk_content.trim().is_empty() {
            chunks.push((start + 1, end, chunk_content));
        }

        let overlap = 3;
        if end + overlap < total_lines {
            start = if end > overlap { end - overlap } else { end };
        } else {
            start = end;
        }
    }

    chunks
}

/// Tokenize text into lowercase terms
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty() && s.len() > 1)
        .map(|s| s.to_string())
        .collect()
}

/// Common English/security words to ignore in search
fn is_stopword(term: &str) -> bool {
    matches!(
        term,
        "the" | "is" | "at" | "which" | "on" | "a" | "an" | "and" | "or" | "but"
            | "in" | "with" | "to" | "for" | "of" | "by" | "from" | "as" | "are"
            | "was" | "were" | "been" | "be" | "has" | "have" | "had" | "do" | "does"
            | "did" | "will" | "would" | "could" | "should" | "may" | "might" | "can"
            | "shall" | "this" | "that" | "these" | "those" | "it" | "its" | "not"
            | "no" | "nor" | "if" | "else" | "then" | "than" | "so" | "such" | "only"
            | "just" | "also" | "very" | "too" | "about" | "above" | "after" | "again"
            | "all" | "any" | "both" | "each" | "few" | "more" | "most" | "other"
            | "some" | "into" | "over" | "under" | "up" | "out" | "off" | "down"
            | "here" | "there" | "when" | "where" | "why" | "how" | "what" | "who"
            | "whom" | "while" | "during" | "before" | "between"
            | "through" | "using" | "use" | "get" | "set" | "put" | "let" | "make"
            | "run" | "new" | "return" | "void" | "null" | "true" | "false" | "none"
            | "self" | "super" | "base" | "class" | "struct" | "enum" | "trait"
            | "impl" | "type" | "fn" | "fun" | "def" | "function" | "var" | "const"
            | "static" | "public" | "private" | "protected" | "internal" | "override"
            | "virtual" | "abstract" | "sealed" | "readonly" | "async" | "await"
            | "import" | "export" | "require" | "include" | "package" | "module"
            | "namespace" | "default" | "case" | "switch" | "match" | "break"
            | "continue" | "loop" | "for" | "try" | "catch"
            | "finally" | "throw" | "throws" | "raise" | "except" | "with"
            | "yield" | "println" | "print" | "console" | "log" | "debug"
            | "info" | "warn" | "error" | "assert" | "expect" | "unwrap" | "panic"
            | "todo" | "fixme" | "hack" | "xxx" | "note" | "warning"
    )
}

/// Compute term frequency for a single chunk
fn compute_term_freq(content: &str) -> TermFreq {
    let tokens = tokenize(content);
    let mut terms: HashMap<String, usize> = HashMap::new();
    let mut total_terms = 0;

    for token in tokens {
        if !is_stopword(&token) && token.len() >= 2 {
            *terms.entry(token).or_insert(0) += 1;
            total_terms += 1;
        }
    }

    TermFreq { terms, total_terms }
}

/// Compute IDF for all terms across all chunks
fn compute_idf(chunks: &[CodeChunk]) -> HashMap<String, f64> {
    let total_chunks = chunks.len() as f64;
    let mut doc_count: HashMap<String, usize> = HashMap::new();

    for chunk in chunks {
        let terms: HashSet<String> = tokenize(&chunk.content)
            .into_iter()
            .filter(|t| !is_stopword(t) && t.len() >= 2)
            .collect();

        for term in terms {
            *doc_count.entry(term).or_insert(0) += 1;
        }
    }

    doc_count
        .into_iter()
        .map(|(term, count)| {
            let idf = (total_chunks / (count as f64 + 1.0)).ln() + 1.0;
            (term, idf)
        })
        .collect()
}

/// Get the .cipher data directory path
fn data_dir(project_path: &Path) -> PathBuf {
    project_path.join(".cipher")
}

/// Initialize the index for a project
pub async fn run_init(project_path: &Path, force: bool) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)
        .with_context(|| format!("Cannot access path: {}", project_path.display()))?;

    let sec_dir = data_dir(&canonical_path);
    let index_path = sec_dir.join("index.json");

    if index_path.exists() && !force {
        println!(
            "{} Project already indexed at {}",
            "✓".green().bold(),
            sec_dir.display()
        );
        println!("  Run {} to re-index", "cipher init --force".yellow());
        return Ok(());
    }

    println!(
        "{} {}",
        "🔍".bright_blue(),
        format!("Indexing {}...", canonical_path.display()).bold()
    );

    // Collect supported files
    let mut files: Vec<PathBuf> = Vec::new();
    let walker = WalkBuilder::new(&canonical_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .build();

    for result in walker {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() && is_supported(path) {
                    files.push(path.to_path_buf());
                }
            }
            Err(e) => {
                eprintln!("  {} {}", "⚠".yellow(), e);
            }
        }
    }

    if files.is_empty() {
        println!("  {} No supported source files found.", "⚠".yellow());
        println!("  Supported: {}", SUPPORTED_EXTENSIONS.join(", "));
        return Ok(());
    }

    println!(
        "  {} Found {} supported files",
        "📁".cyan(),
        files.len().to_string().bold()
    );

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut all_chunks: Vec<CodeChunk> = Vec::new();
    let mut language_counts: HashMap<String, usize> = HashMap::new();
    let max_chunk_tokens = 500;

    for file_path in &files {
        pb.set_message(format!("{}", file_path.display()));
        let relative = file_path
            .strip_prefix(&canonical_path)
            .unwrap_or(file_path)
            .to_path_buf();

        let language = detect_language(file_path).unwrap_or("unknown").to_string();
        *language_counts.entry(language.clone()).or_insert(0) += 1;

        match std::fs::read_to_string(file_path) {
            Ok(content) => {
                if content.trim().is_empty() || content.len() > 500_000 {
                    pb.inc(1);
                    continue;
                }

                let file_chunks = chunk_code(&content, max_chunk_tokens);
                for (start_line, end_line, text) in file_chunks {
                    let id = format!("{}:{}", relative.display(), all_chunks.len() + 1);
                    all_chunks.push(CodeChunk {
                        id,
                        file_path: file_path.to_string_lossy().to_string(),
                        relative_path: relative.to_string_lossy().to_string(),
                        language: language.clone(),
                        start_line,
                        end_line,
                        content: text,
                    });
                }
            }
            Err(e) => {
                eprintln!(
                    "\n  {} Could not read {}: {}",
                    "⚠".yellow(),
                    relative.display(),
                    e
                );
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message(format!("{} files processed", files.len()));
    println!(
        "  {} Created {} code chunks",
        "🧩".cyan(),
        all_chunks.len().to_string().bold()
    );

    // Compute TF-IDF indices
    println!("  {} Building search index...", "📊".cyan());

    let term_freqs: Vec<TermFreq> = all_chunks
        .iter()
        .map(|c| compute_term_freq(&c.content))
        .collect();

    let idf = compute_idf(&all_chunks);

    let summary = IndexSummary {
        project_path: canonical_path.to_string_lossy().to_string(),
        indexed_at: chrono::Utc::now().to_rfc3339(),
        total_files: files.len(),
        total_chunks: all_chunks.len(),
        languages: language_counts,
    };

    let index = CodeIndex {
        summary,
        chunks: all_chunks,
        term_freqs,
        idf,
    };

    // Save to disk
    std::fs::create_dir_all(&sec_dir)?;
    let json = serde_json::to_string_pretty(&index)?;
    std::fs::write(&index_path, &json)?;

    // Save API key to config if not already saved
    let config_path = sec_dir.join("config.json");
    if !config_path.exists() {
        if let Ok(key) = std::env::var("GROQ_API_KEY") {
            let config = serde_json::json!({
                "groq_api_key": key
            });
            std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
        }
    }

    println!();
    println!(
        "{} Indexing complete! {}",
        "✅".green(),
        format!("{} chunks indexed", index.summary.total_chunks)
            .green()
            .bold()
    );
    println!(
        "  {} Run {} to ask questions about your codebase",
        "💬".cyan(),
        "sec ask \"your question\"".yellow()
    );

    Ok(())
}

/// Show index status
pub async fn run_status(project_path: &Path) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)
        .with_context(|| format!("Cannot access path: {}", project_path.display()))?;

    let index_path = data_dir(&canonical_path).join("index.json");

    if !index_path.exists() {
        println!("{} Project not indexed yet.", "📭".bright_blue());
        println!("  Run {} to index this codebase", "cipher init".yellow().bold());
        return Ok(());
    }

    let content = std::fs::read_to_string(&index_path)?;
    let index: CodeIndex = serde_json::from_str(&content)?;

    println!("{} {}", "📊".bright_blue(), "Index Status".bold());
    println!("  {}", "─".repeat(40).dimmed());
    println!(
        "  {} {}",
        "Project:".bold(),
        index.summary.project_path
    );
    println!(
        "  {} {}",
        "Indexed:".bold(),
        index.summary.indexed_at
    );
    println!(
        "  {} {} files across {} languages",
        "Files:".bold(),
        index.summary.total_files.to_string().cyan().bold(),
        index.summary.languages.len().to_string().cyan()
    );
    println!(
        "  {} {} code chunks",
        "Chunks:".bold(),
        index.summary.total_chunks.to_string().cyan().bold()
    );

    if !index.summary.languages.is_empty() {
        println!(
            "  {} {}",
            "Languages:".bold(),
            index
                .summary
                .languages
                .iter()
                .map(|(lang, count)| format!("{} ({} files)", lang.cyan(), count))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Check if GROQ_API_KEY is set
    match std::env::var("GROQ_API_KEY") {
        Ok(_) => println!("  {} Groq API key: {}", "🔑".bold(), "configured ✓".green()),
        Err(_) => println!(
            "  {} Groq API key: {} (set GROQ_API_KEY env var)",
            "🔑".bold(),
            "not set".red()
        ),
    }

    Ok(())
}

/// Load the index from disk
pub fn load_index(project_path: &Path) -> Result<Option<CodeIndex>> {
    let index_path = data_dir(project_path).join("index.json");
    if !index_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&index_path)?;
    let index: CodeIndex = serde_json::from_str(&content)?;
    Ok(Some(index))
}

/// Search the index for chunks relevant to a query using TF-IDF scoring
pub fn search_index<'a>(index: &'a CodeIndex, query: &str, top_n: usize) -> Vec<&'a CodeChunk> {
    let query_terms = tokenize(query);

    if query_terms.is_empty() {
        return Vec::new();
    }

    // Score each chunk against the query
    let mut scored: Vec<(f64, usize)> = Vec::new();

    for (i, tf) in index.term_freqs.iter().enumerate() {
        let mut score = 0.0;

        for qterm in &query_terms {
            let idf = index.idf.get(qterm).copied().unwrap_or(0.0);
            if idf <= 0.0 {
                continue;
            }

            // Term frequency in this chunk (normalized)
            let tf_val = tf.terms.get(qterm).copied().unwrap_or(0) as f64;
            if tf_val > 0.0 {
                let normalized_tf = (1.0 + tf_val.ln()).max(0.0);
                score += normalized_tf * idf;
            }

            // Bonus: if the query term appears in the file name or as a bigram
            let chunk = &index.chunks[i];
            let path_lower = chunk.relative_path.to_lowercase();
            if path_lower.contains(qterm) {
                score += idf * 0.5; // file name match bonus
            }
        }

        if score > 0.0 {
            scored.push((score, i));
        }
    }

    // Sort by score descending
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    // Return top N
    scored
        .into_iter()
        .take(top_n)
        .map(|(_, i)| &index.chunks[i])
        .collect()
}
