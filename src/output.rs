// ── CipherAI Unified Styled Output ──────────────────────────────────
//
// Provides consistent, beautiful formatting for all command output.
// Every command should use these helpers instead of raw println! calls.

use colored::*;
use std::fmt::Write;

// ── Box-Drawing Characters ─────────────────────────────────────────

const H: &str = "─";
const V: &str = "│";
const TL: &str = "┌";
const TR: &str = "┐";
const BL: &str = "└";
const BR: &str = "┘";
const LT: &str = "├";
const RT: &str = "┤";

// ── Section / Header ────────────────────────────────────────────────

/// Print a prominent command header with a title and optional subtitle
/// Example output:
///   ┌─ CipherAI Security Review ─────────────────────────────────┐
///   │  Scanning /path/to/project ...                              │
///   └────────────────────────────────────────────────────────────┘
pub fn print_header(title: &str, subtitle: Option<&str>) {
    let full = if let Some(sub) = subtitle {
        format!("{} — {}", title, sub)
    } else {
        title.to_string()
    };
    let line_len = full.len().min(70) + 4;
    let sep = H.repeat(line_len);
    println!("{} {} {}", TL.bright_blue().bold(), full.bold().white(), sep.bright_blue().bold());
    if let Some(sub) = subtitle {
        let pad = line_len.saturating_sub(sub.len().min(70));
        println!("{} {} {}", V.bright_blue(), sub.cyan(), " ".repeat(pad).bright_blue());
    }
}

/// Print a section header within the command
/// ── Section Name ──────────────────────────────────────────────
pub fn print_section(name: &str) {
    let sep = H.repeat(50);
    println!();
    println!("  {} {} {}", LT.dimmed(), name.bold().white(), sep.dimmed());
}

/// Print a closing footer
pub fn print_footer() {
    let sep = H.repeat(50);
    println!("  {}", format!("{}{}{}", BL, sep, BR).dimmed());
    println!();
}

// ── Progress Steps ────────────────────────────────────────────────

/// Print a numbered step header: [1/5] Running security review...
pub fn print_step(current: usize, total: usize, label: &str) {
    let tag = format!("[{}/{}]", current, total);
    println!("  {} {}...", tag.bright_cyan().bold(), label.bold());
}

/// Print a step result (success): ✓ Review: 2 critical, 5 high, 30 total
pub fn print_ok(tag: &str, detail: &str) {
    println!("  {} {} {}",
        "✓".green().bold(),
        format!("{}:", tag).bold(),
        detail,
    );
}

/// Print a step result (warning)
pub fn print_warn(tag: &str, detail: &str) {
    println!("  {} {} {}",
        "⚠".yellow().bold(),
        format!("{}:", tag).bold(),
        detail,
    );
}

/// Print a step result (error)
pub fn print_fail(tag: &str, detail: &str) {
    println!("  {} {} {}",
        "✗".red().bold(),
        format!("{}:", tag).bold(),
        detail,
    );
}

/// Print an informational note
pub fn print_info(tag: &str, msg: &str) {
    println!("  {} {} {}",
        "●".cyan().bold(),
        format!("{}:", tag).bold(),
        msg,
    );
}

/// Print a subtle/hint message
pub fn print_hint(msg: &str) {
    println!("    {} {}", "↳".dimmed(), msg.dimmed());
}

// ── Summary Box ────────────────────────────────────────────────────

/// Print a bordered summary box with title and labeled rows
/// ┌─── Security Review Results ────────────────────────────────┐
/// │  Files scanned:    42                                     │
/// │  Critical:          2                                     │
/// │  High:              5                                     │
/// │  Total findings:   30                                     │
/// └───────────────────────────────────────────────────────────┘
pub fn print_summary_box(title: &str, rows: &[(&str, &str)]) {
    let left_w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(20).max(10);
    let title_line = format!(" {} ", title);
    let box_w = (left_w + 30).max(title_line.len() + 4);

    println!();
    println!("  {}",
        format!("{}{}{}", TL.bright_blue(), H.repeat(box_w - 2), TR.bright_blue())
    );
    println!("  {} {:^width$} {}",
        V.bright_blue().bold(), title.bold().white(), V.bright_blue(),
        width = box_w.saturating_sub(2)
    );
    println!("  {}",
        format!("{}{}{}", LT.bright_blue(), H.repeat(box_w - 2), RT.bright_blue())
    );
    for (key, val) in rows {
        let pad = box_w.saturating_sub(2 + 2 + key.len() + val.len()).saturating_sub(1);
        println!("  {} {}:{} {}{}",
            V.bright_blue(),
            key.bold(),
            " ".repeat(left_w.saturating_sub(key.len())).dimmed(),
            val,
            " ".repeat(pad.saturating_sub(1)).dimmed(),
            // V is not needed at far-right for aesthetic simplicity
        );
    }
    println!("  {}",
        format!("{}{}{}", BL.bright_blue(), H.repeat(box_w - 2), BR.bright_blue())
    );
    println!();
}

// ── Findings Table ─────────────────────────────────────────────────

/// Print a findings summary in compact table form
pub fn print_findings_table(
    header: &str,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    total: usize,
) {
    let bar_critical = if total > 0 { (critical as f64 / total as f64 * 20.0).round() as usize } else { 0 };
    let bar_high = if total > 0 { (high as f64 / total as f64 * 20.0).round() as usize } else { 0 };
    let bar_med = if total > 0 { (medium as f64 / total as f64 * 20.0).round() as usize } else { 0 };
    let bar_low = if total > 0 { (low as f64 / total as f64 * 20.0).round() as usize } else { 0 };

    let bar = format!(
        "{}{}{}{}",
        "█".repeat(bar_critical).red().to_string(),
        "█".repeat(bar_high).yellow().to_string(),
        "█".repeat(bar_med).cyan().to_string(),
        "█".repeat(bar_low).dimmed().to_string(),
    );

    println!("  {}", header.bold().white());
    println!("    {} {}   {} {}   {} {}   {} {}  ({})",
        "CRITICAL".red().bold(),
        format!("{:>4}", critical).red().bold(),
        "HIGH".yellow().bold(),
        format!("{:>4}", high).yellow().bold(),
        "MEDIUM".cyan(),
        format!("{:>4}", medium).cyan(),
        "LOW".dimmed(),
        format!("{:>4}", low).dimmed(),
        format!("{} total", total).bold(),
    );
    if !bar.trim().is_empty() {
        println!("    {} {}", bar.dimmed(), "risk distribution".dimmed());
    }
}

// ── Recommendations ────────────────────────────────────────────────

/// Print a recommendations section with bullet points
pub fn print_recommendations(items: &[&str]) {
    println!("  {} {}", "💡".bold(), "Recommendations".bold().white());
    println!("  {}", H.repeat(40).dimmed());
    for item in items {
        println!("    {} {}", "•".cyan(), item);
    }
    println!();
}

// ── Separator ──────────────────────────────────────────────────────

/// Print a subtle horizontal separator
pub fn print_separator() {
    println!("  {}", H.repeat(50).dimmed());
}

// ── Status Badge ───────────────────────────────────────────────────

/// Generate a colored status badge string
pub fn status_badge(status: &str, success: bool) -> String {
    if success {
        format!("{} {}", "●".green(), status.green())
    } else {
        format!("{} {}", "●".red(), status.red())
    }
}

// ── Finding Severity Badge ─────────────────────────────────────────

/// Generate a colored severity badge for display in tables
pub fn severity_badge(severity: &str) -> colored::ColoredString {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => severity.red().bold(),
        "HIGH" => severity.yellow().bold(),
        "MEDIUM" => severity.cyan(),
        "LOW" => severity.dimmed(),
        _ => severity.normal(),
    }
}

// ── Large Banner ───────────────────────────────────────────────────

/// Print the CipherAI ASCII banner
pub fn print_banner() {
    let banner = r#"
    ╔══════════════════════════════════════════╗
    ║   ██████  ██ ██████  ██   ██ ███████  ║
    ║  ██      ██ ██   ██ ██   ██ ██       ║
    ║  ██      ██ ██████  ███████ █████    ║
    ║  ██      ██ ██      ██   ██ ██       ║
    ║   ██████ ██ ██      ██   ██ ███████  ║
    ║                                       ║
    ║      AI-Powered Security Analysis      ║
    ╚══════════════════════════════════════════╝
    "#;
    println!("{}", banner.bright_blue());
}

// ── Key-Value Line ─────────────────────────────────────────────────

/// Print a key-value pair with aligned values
pub fn print_kv(key: &str, value: &str, align: usize) {
    let a = align.max(15);
    println!("  {}:{}{}",
        key.bold(),
        " ".repeat(a.saturating_sub(key.len())),
        value
    );
}

// ── Error message ──────────────────────────────────────────────────

/// Print a formatted error message
pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗ Error:".red().bold(), msg);
}

/// Print a formatted success message
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg.green().bold());
}
