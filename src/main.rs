#![deny(unused)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use dialoguer::Select;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::sinks::UTF8;
use grep_searcher::Searcher;
use ignore::WalkBuilder;
use owo_colors::OwoColorize;
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "find-unused-pub",
    about = "Find pub items that are unused or only used within their crate",
    version
)]
struct Args {
    /// Crate paths to scan (defaults to all crates/*)
    crate_paths: Vec<PathBuf>,

    /// Auto-fix crate-internal items → pub(crate)
    #[arg(long)]
    fix_crate_internal: bool,

    /// Auto-fix unused items → remove pub (lets rustc warn dead_code)
    #[arg(long)]
    fix_unused: bool,

    /// Alias for --fix-crate-internal
    #[arg(long)]
    fix: bool,

    /// Interactively review unused items (fix / whitelist / skip)
    #[arg(long)]
    review_unused: bool,

    /// Interactively review crate-internal items (fix / whitelist / skip)
    #[arg(long)]
    review_crate_internal: bool,

    /// Alias for --review-unused
    #[arg(long)]
    review: bool,

    /// Clear the whitelist database
    #[arg(long)]
    nuke_whitelist: bool,
}

impl Args {
    fn should_fix_crate_internal(&self) -> bool {
        self.fix_crate_internal || self.fix
    }

    fn should_review_unused(&self) -> bool {
        self.review_unused || self.review
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PubSymbol {
    name: String,
    file: PathBuf,
    line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    UnusedAnywhere,
    CrateInternalOnly { refs: usize },
}

#[derive(Debug, Clone)]
struct UnusedSymbol {
    symbol: PubSymbol,
    kind: SymbolKind,
    crate_name: String,
}

struct CrateResult {
    crate_name: String,
    items_found: usize,
    unused: Vec<UnusedSymbol>,
}

// ---------------------------------------------------------------------------
// Symbol collection
// ---------------------------------------------------------------------------

/// Skipped ORM-derived symbols that are always used implicitly.
const SKIP_SYMBOLS: &[&str] = &[
    "ActiveModel",
    "Model",
    "Relation",
    "Entity",
    "Column",
    "ActiveModelBehavior",
];

fn collect_pub_symbols(crate_path: &Path) -> Result<Vec<PubSymbol>> {
    let src = crate_path.join("src");
    if !src.is_dir() {
        return Ok(vec![]);
    }

    let pattern = r"^\s*pub\s+(?:async\s+)?(?:fn|struct|enum|trait|type|const|static)\s+([A-Za-z_][A-Za-z0-9_]*)";
    let matcher = RegexMatcherBuilder::new()
        .build(pattern)
        .context("building pub-definition regex")?;

    let extract_re =
        regex::Regex::new(r"^\s*pub\s+(?:async\s+)?(?:fn|struct|enum|trait|type|const|static)\s+([A-Za-z_][A-Za-z0-9_]*)")
            .unwrap();

    let results: Mutex<Vec<PubSymbol>> = Mutex::new(vec![]);
    let mut searcher = Searcher::new();

    for entry in WalkBuilder::new(&src)
        .types(
            ignore::types::TypesBuilder::new()
                .add_defaults()
                .select("rust")
                .build()
                .unwrap(),
        )
        .build()
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Skip generated files
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map_or(false, |n| n.contains(".generated."))
        {
            continue;
        }

        searcher.search_path(
            &matcher,
            path,
            UTF8(|line_num, line| {
                // Filter out pub(crate), pub(super), pub(in ...)
                let trimmed = line.trim_start();
                if trimmed.starts_with("pub(crate)")
                    || trimmed.starts_with("pub(super)")
                    || trimmed.starts_with("pub(in ")
                {
                    return Ok(true);
                }

                if let Some(caps) = extract_re.captures(line) {
                    let name = caps[1].to_string();
                    if name.len() >= 2 && !SKIP_SYMBOLS.contains(&name.as_str()) {
                        results.lock().unwrap().push(PubSymbol {
                            name,
                            file: path.to_path_buf(),
                            line: line_num as usize,
                        });
                    }
                }
                Ok(true)
            }),
        )?;
    }

    // Deduplicate by name, keeping first occurrence
    let all = results.into_inner().unwrap();
    let mut seen = HashSet::new();
    let mut deduped = vec![];
    for sym in all {
        if seen.insert(sym.name.clone()) {
            deduped.push(sym);
        }
    }

    Ok(deduped)
}

// ---------------------------------------------------------------------------
// Symbol searching
// ---------------------------------------------------------------------------

/// Count occurrences of each symbol name in the given directories.
/// Returns a map of symbol_name → hit count.
fn count_symbol_hits(
    symbol_names: &[String],
    search_dirs: &[PathBuf],
) -> Result<HashMap<String, usize>> {
    if symbol_names.is_empty() || search_dirs.is_empty() {
        return Ok(HashMap::new());
    }

    // Build a word-bounded alternation: \b(sym1|sym2|...)\b
    let alt = symbol_names.join("|");
    let pattern = format!(r"\b({})\b", alt);

    let matcher = RegexMatcherBuilder::new()
        .build(&pattern)
        .context("building symbol search regex")?;

    let word_re = regex::Regex::new(&pattern).unwrap();
    let counts: Mutex<HashMap<String, usize>> = Mutex::new(HashMap::new());

    let mut walker = WalkBuilder::new(&search_dirs[0]);
    for dir in &search_dirs[1..] {
        walker.add(dir);
    }
    let walker = walker
        .types(
            ignore::types::TypesBuilder::new()
                .add_defaults()
                .select("rust")
                .build()
                .unwrap(),
        )
        .build();

    let mut searcher = Searcher::new();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        searcher.search_path(
            &matcher,
            path,
            UTF8(|_line_num, line| {
                for m in word_re.find_iter(line) {
                    let sym = m.as_str().to_string();
                    *counts.lock().unwrap().entry(sym).or_insert(0) += 1;
                }
                Ok(true)
            }),
        )?;
    }

    Ok(counts.into_inner().unwrap())
}

// ---------------------------------------------------------------------------
// Crate analysis
// ---------------------------------------------------------------------------

fn analyze_crate(
    crate_path: &Path,
    all_crate_src_dirs: &[PathBuf],
    whitelist: &HashSet<(String, String)>,
) -> Result<CrateResult> {
    let crate_name = crate_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let crate_src = crate_path.join("src");

    eprint!(
        "  {} {}...",
        "scanning".dimmed(),
        crate_name.cyan(),
    );

    let symbols = collect_pub_symbols(crate_path)?;
    let items_found = symbols.len();

    if symbols.is_empty() {
        eprintln!(" {}", "0 pub items".dimmed());
        return Ok(CrateResult {
            crate_name,
            items_found: 0,
            unused: vec![],
        });
    }

    // External search: all other crate src dirs
    let external_dirs: Vec<PathBuf> = all_crate_src_dirs
        .iter()
        .filter(|d| **d != crate_src)
        .cloned()
        .collect();

    let symbol_names: Vec<String> = symbols.iter().map(|s| s.name.clone()).collect();
    let external_counts = count_symbol_hits(&symbol_names, &external_dirs)?;

    // Find symbols with zero external hits
    let no_external: Vec<&PubSymbol> = symbols
        .iter()
        .filter(|s| external_counts.get(&s.name).copied().unwrap_or(0) == 0)
        .collect();

    // Internal search for those symbols
    let internal_names: Vec<String> = no_external.iter().map(|s| s.name.clone()).collect();
    let internal_counts = count_symbol_hits(&internal_names, &[crate_src])?;

    // Classify
    let mut unused = vec![];
    for sym in no_external {
        // Check whitelist
        if whitelist.contains(&(sym.name.clone(), crate_name.clone())) {
            continue;
        }

        let internal_hits = internal_counts.get(&sym.name).copied().unwrap_or(0);
        let kind = if internal_hits <= 1 {
            SymbolKind::UnusedAnywhere
        } else {
            SymbolKind::CrateInternalOnly {
                refs: internal_hits,
            }
        };

        unused.push(UnusedSymbol {
            symbol: sym.clone(),
            kind,
            crate_name: crate_name.clone(),
        });
    }

    eprintln!(
        " {} found, {} unused",
        items_found.to_string().dimmed(),
        if unused.is_empty() {
            "0".green().to_string()
        } else {
            unused.len().to_string().yellow().to_string()
        }
    );

    Ok(CrateResult {
        crate_name,
        items_found,
        unused,
    })
}

// ---------------------------------------------------------------------------
// Whitelist DB
// ---------------------------------------------------------------------------

fn open_db(workspace_root: &Path) -> Result<Connection> {
    let path = workspace_root.join(".find-unused-pub.db");
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS whitelist (
            symbol TEXT NOT NULL,
            crate_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (symbol, crate_name)
        );",
    )?;
    Ok(conn)
}

fn load_whitelist(conn: &Connection) -> Result<HashSet<(String, String)>> {
    let mut stmt = conn.prepare("SELECT symbol, crate_name FROM whitelist")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut set = HashSet::new();
    for row in rows {
        set.insert(row?);
    }
    Ok(set)
}

fn add_to_whitelist(
    conn: &Connection,
    symbol: &str,
    crate_name: &str,
    file_path: &str,
    reason: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO whitelist (symbol, crate_name, file_path, reason) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![symbol, crate_name, file_path, reason],
    )?;
    Ok(())
}

fn nuke_whitelist(conn: &Connection) -> Result<()> {
    conn.execute_batch("DROP TABLE IF EXISTS whitelist;")?;
    conn.execute_batch(
        "CREATE TABLE whitelist (
            symbol TEXT NOT NULL,
            crate_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (symbol, crate_name)
        );",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixing
// ---------------------------------------------------------------------------

fn apply_fix_crate_internal(symbol: &UnusedSymbol) -> Result<()> {
    let content = fs::read_to_string(&symbol.symbol.file)?;
    let lines: Vec<&str> = content.lines().collect();
    let line_idx = symbol.symbol.line - 1;

    if line_idx >= lines.len() {
        anyhow::bail!(
            "line {} out of range in {}",
            symbol.symbol.line,
            symbol.symbol.file.display()
        );
    }

    let new_line = lines[line_idx].replacen("pub ", "pub(crate) ", 1);
    let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    new_lines[line_idx] = new_line;

    let mut result = new_lines.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    fs::write(&symbol.symbol.file, result)?;
    Ok(())
}

/// Find the full span of a Rust item starting at `start_line` (0-indexed).
/// Returns (inclusive_start, exclusive_end) line indices.
/// Uses tree-sitter for accurate parsing with fallback to brace-counting.
fn find_item_span(source: &str, start_line: usize) -> (usize, usize) {
    if let Some(span) = find_item_span_ts(source, start_line) {
        return span;
    }
    find_item_span_fallback(source, start_line)
}

const ITEM_KINDS: &[&str] = &[
    "function_item",
    "struct_item",
    "enum_item",
    "trait_item",
    "type_item",
    "const_item",
    "static_item",
];

fn find_item_span_ts(source: &str, start_line: usize) -> Option<(usize, usize)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    let item = find_item_at_line(root, start_line)?;

    // Attributes are children of the item in tree-sitter-rust,
    // so start_position() already includes them.
    let mut first_line = item.start_position().row;
    let last_line = item.end_position().row;

    // Doc comments and attributes are separate sibling nodes — walk back to include them.
    let mut prev = item.prev_sibling();
    while let Some(sibling) = prev {
        match sibling.kind() {
            "line_comment" | "block_comment" => {
                let text = &source[sibling.start_byte()..sibling.end_byte()];
                if text.starts_with("///") || text.starts_with("//!") || text.starts_with("/**") {
                    first_line = sibling.start_position().row;
                    prev = sibling.prev_sibling();
                } else {
                    break;
                }
            }
            "attribute_item" => {
                first_line = sibling.start_position().row;
                prev = sibling.prev_sibling();
            }
            _ => break,
        }
    }

    let mut end = last_line + 1;
    let lines: Vec<&str> = source.lines().collect();
    if end < lines.len() && lines[end].trim().is_empty() {
        end += 1;
    }

    Some((first_line, end))
}

fn find_item_at_line<'a>(
    node: tree_sitter::Node<'a>,
    line: usize,
) -> Option<tree_sitter::Node<'a>> {
    if ITEM_KINDS.contains(&node.kind()) {
        let start = node.start_position().row;
        let end = node.end_position().row;
        if line >= start && line <= end {
            return Some(node);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_item_at_line(child, line) {
            return Some(found);
        }
    }
    None
}

/// Fallback: brace-counting heuristic when tree-sitter fails to parse.
fn find_item_span_fallback(source: &str, start_line: usize) -> (usize, usize) {
    let lines: Vec<&str> = source.lines().collect();
    let mut first = start_line;
    while first > 0 {
        let prev = lines[first - 1].trim();
        if prev.starts_with('#')
            || prev.starts_with("///")
            || prev.starts_with("//!")
            || prev.is_empty()
        {
            first -= 1;
        } else {
            break;
        }
    }
    while first < start_line && lines[first].trim().is_empty() {
        first += 1;
    }

    let def_line = lines[start_line];
    let is_semicolon_item = {
        let trimmed = def_line.trim_start();
        trimmed.starts_with("pub const ")
            || trimmed.starts_with("pub static ")
            || trimmed.starts_with("pub type ")
            || trimmed.starts_with("const ")
            || trimmed.starts_with("static ")
            || trimmed.starts_with("type ")
    };

    let mut end = start_line;
    if is_semicolon_item {
        while end < lines.len() {
            if lines[end].contains(';') {
                end += 1;
                break;
            }
            end += 1;
        }
    } else {
        let mut depth: i32 = 0;
        let mut found_open = false;
        while end < lines.len() {
            for ch in lines[end].chars() {
                if ch == '{' {
                    depth += 1;
                    found_open = true;
                } else if ch == '}' {
                    depth -= 1;
                }
            }
            end += 1;
            if found_open && depth <= 0 {
                break;
            }
        }
    }

    if end < lines.len() && lines[end].trim().is_empty() {
        end += 1;
    }

    (first, end)
}

fn apply_fix_unused(symbol: &UnusedSymbol) -> Result<String> {
    let content = fs::read_to_string(&symbol.symbol.file)?;
    let lines: Vec<&str> = content.lines().collect();
    let line_idx = symbol.symbol.line - 1;

    if line_idx >= lines.len() {
        anyhow::bail!(
            "line {} out of range in {}",
            symbol.symbol.line,
            symbol.symbol.file.display()
        );
    }

    let (span_start, span_end) = find_item_span(&content, line_idx);

    // Build the removed text for display
    let removed: Vec<&str> = lines[span_start..span_end].to_vec();
    let preview = if removed.len() <= 3 {
        removed.join("\n")
    } else {
        format!(
            "{}\n  ... ({} more lines)\n{}",
            removed[0],
            removed.len() - 2,
            removed.last().unwrap()
        )
    };

    let mut new_lines: Vec<&str> = Vec::with_capacity(lines.len());
    new_lines.extend_from_slice(&lines[..span_start]);
    new_lines.extend_from_slice(&lines[span_end..]);

    let mut result = new_lines.join("\n");
    if content.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    fs::write(&symbol.symbol.file, result)?;

    Ok(preview)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn print_results(results: &[CrateResult], workspace_root: &Path) {
    for result in results {
        if result.unused.is_empty() {
            continue;
        }

        println!(
            "{} {}",
            result.crate_name.bold().cyan(),
            format!("({}/{})", result.unused.len(), result.items_found).dimmed(),
        );

        for item in &result.unused {
            match item.kind {
                SymbolKind::UnusedAnywhere => {
                    println!(
                        "  {} {}",
                        item.symbol.name.red(),
                        "unused anywhere".dimmed(),
                    );
                }
                SymbolKind::CrateInternalOnly { refs } => {
                    println!(
                        "  {} {}",
                        item.symbol.name.yellow(),
                        format!("crate-internal only ({} refs) → consider pub(crate)", refs)
                            .dimmed(),
                    );
                }
            }
            let rel_path = item
                .symbol
                .file
                .strip_prefix(workspace_root)
                .unwrap_or(&item.symbol.file);
            println!(
                "    {}",
                format!("{}:{}", rel_path.display(), item.symbol.line).dimmed(),
            );
        }
        println!();
    }
}

// ---------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------

fn review_item(item: &UnusedSymbol, conn: &Connection) -> Result<()> {
    let kind_label = match item.kind {
        SymbolKind::UnusedAnywhere => "unused anywhere".red().to_string(),
        SymbolKind::CrateInternalOnly { refs } => {
            format!("crate-internal only ({refs} refs)").yellow().to_string()
        }
    };

    println!(
        "\n  {} {} in {}",
        item.symbol.name.bold(),
        kind_label,
        item.crate_name.cyan(),
    );
    println!(
        "    {}",
        format!("{}:{}", item.symbol.file.display(), item.symbol.line).dimmed(),
    );

    let fix_label = match item.kind {
        SymbolKind::UnusedAnywhere => "Fix (delete item)",
        SymbolKind::CrateInternalOnly { .. } => "Fix (→ pub(crate))",
    };

    let selection = Select::new()
        .with_prompt("  Action")
        .items(&[fix_label, "Whitelist (skip in future)", "Skip"])
        .default(2)
        .interact()?;

    match selection {
        0 => match item.kind {
            SymbolKind::CrateInternalOnly { .. } => {
                apply_fix_crate_internal(item)?;
                println!("    {}", "fixed → pub(crate)".green());
            }
            SymbolKind::UnusedAnywhere => {
                let preview = apply_fix_unused(item)?;
                println!("    {} {}", "deleted:".green(), preview.dimmed());
            }
        },
        1 => {
            let reason: String = dialoguer::Input::new()
                .with_prompt("    Reason (optional)")
                .allow_empty(true)
                .interact_text()?;
            let reason = if reason.is_empty() {
                None
            } else {
                Some(reason.as_str())
            };
            add_to_whitelist(
                conn,
                &item.symbol.name,
                &item.crate_name,
                &item.symbol.file.to_string_lossy(),
                reason,
            )?;
            println!("    {}", "whitelisted".green());
        }
        _ => {
            println!("    {}", "skipped".dimmed());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let start = Instant::now();

    // Find workspace root (look for root Cargo.toml with [workspace])
    let workspace_root = find_workspace_root()?;
    let crates_dir = workspace_root.join("crates");

    // Handle --nuke-whitelist
    let conn = open_db(&workspace_root)?;
    if args.nuke_whitelist {
        nuke_whitelist(&conn)?;
        println!("{}", "Whitelist cleared.".green());
        if args.crate_paths.is_empty()
            && !args.should_fix_crate_internal()
            && !args.fix_unused
            && !args.should_review_unused()
            && !args.review_crate_internal
        {
            return Ok(());
        }
    }

    let whitelist = load_whitelist(&conn)?;

    // Resolve crate paths
    let target_crates: Vec<PathBuf> = if args.crate_paths.is_empty() {
        let mut crates = vec![];
        for entry in fs::read_dir(&crates_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                crates.push(entry.path());
            }
        }
        crates.sort();
        crates
    } else {
        args.crate_paths
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    workspace_root.join(p)
                }
            })
            .collect()
    };

    // Build list of all crate src dirs (for external search)
    let all_crate_src_dirs: Vec<PathBuf> = fs::read_dir(&crates_dir)?
        .flatten()
        .filter(|e| e.file_type().map_or(false, |t| t.is_dir()))
        .map(|e| e.path().join("src"))
        .filter(|p| p.is_dir())
        .collect();

    eprintln!(
        "{} {} crates",
        "Scanning".bold(),
        target_crates.len(),
    );

    // Scan crates in parallel using tokio tasks
    let mut handles = vec![];
    for crate_path in &target_crates {
        let crate_path = crate_path.clone();
        let all_dirs = all_crate_src_dirs.clone();
        let wl = whitelist.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            analyze_crate(&crate_path, &all_dirs, &wl)
        }));
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.await??);
    }

    // Print results
    eprintln!();
    print_results(&results, &workspace_root);

    let total_unused: usize = results.iter().map(|r| r.unused.len()).sum();
    println!(
        "{}",
        format!("Total: {} potentially unused pub items", total_unused).bold(),
    );

    let elapsed = start.elapsed();
    eprintln!(
        "{}",
        format!("Done in {:.1}s", elapsed.as_secs_f64()).dimmed(),
    );

    // Collect all unused items for fix/review
    let all_unused: Vec<UnusedSymbol> = results
        .into_iter()
        .flat_map(|r| r.unused)
        .collect();

    // Auto-fix
    let mut fixed = 0;
    if args.should_fix_crate_internal() || args.fix_unused {
        for item in &all_unused {
            let should_fix = match item.kind {
                SymbolKind::CrateInternalOnly { .. } => args.should_fix_crate_internal(),
                SymbolKind::UnusedAnywhere => args.fix_unused,
            };
            if should_fix {
                let label = match item.kind {
                    SymbolKind::CrateInternalOnly { .. } => {
                        apply_fix_crate_internal(item)?;
                        "→ pub(crate)"
                    }
                    SymbolKind::UnusedAnywhere => {
                        let _preview = apply_fix_unused(item)?;
                        "→ deleted"
                    }
                };
                println!(
                    "  {} {} {}",
                    "fixed".green(),
                    item.symbol.name.bold(),
                    label.dimmed(),
                );
                fixed += 1;
            }
        }
        if fixed > 0 {
            println!("{}", format!("Fixed {fixed} items").bold().green());
        }
    }

    // Interactive review
    if args.should_review_unused() || args.review_crate_internal {
        for item in &all_unused {
            let should_review = match item.kind {
                SymbolKind::UnusedAnywhere => args.should_review_unused(),
                SymbolKind::CrateInternalOnly { .. } => args.review_crate_internal,
            };
            // Skip items that were already auto-fixed
            let already_fixed = match item.kind {
                SymbolKind::CrateInternalOnly { .. } => args.should_fix_crate_internal(),
                SymbolKind::UnusedAnywhere => args.fix_unused,
            };
            if should_review && !already_fixed {
                review_item(item, &conn)?;
            }
        }
    }

    Ok(())
}

fn find_workspace_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            anyhow::bail!("Could not find workspace root (no Cargo.toml with [workspace] found)");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a mini workspace under a temp dir.
    /// `crates` is a slice of (crate_name, &[(filename, source_content)]).
    fn create_workspace(crates: &[(&str, &[(&str, &str)])]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let crates_dir = tmp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        for (name, files) in crates {
            let src_dir = crates_dir.join(name).join("src");
            fs::create_dir_all(&src_dir).unwrap();
            for (filename, content) in *files {
                fs::write(src_dir.join(filename), content).unwrap();
            }
        }
        tmp
    }

    fn crate_src_dirs(tmp: &TempDir) -> Vec<PathBuf> {
        let crates_dir = tmp.path().join("crates");
        fs::read_dir(&crates_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().map_or(false, |t| t.is_dir()))
            .map(|e| e.path().join("src"))
            .filter(|p| p.is_dir())
            .collect()
    }

    // -- find_item_span (tree-sitter) ----------------------------------------

    #[test]
    fn item_span_ts_function() {
        let source = "\
fn private() {}

pub fn hello() {
    println!(\"hello\");
}

fn other() {}
";
        // pub fn hello is on line 2 (0-indexed)
        // lines 2-4, plus trailing blank → end = 6
        let span = find_item_span_ts(source, 2);
        assert_eq!(span, Some((2, 6)));
    }

    #[test]
    fn item_span_ts_with_doc_comment() {
        let source = "\
/// Does something
/// cool
pub fn documented() {
    todo!()
}
";
        // pub fn is on line 2, doc comments on lines 0-1
        let span = find_item_span_ts(source, 2);
        assert_eq!(span, Some((0, 5)));
    }

    #[test]
    fn item_span_ts_with_attribute() {
        let source = "\
#[derive(Debug)]
pub struct Foo {
    bar: i32,
}
";
        // attribute is sibling, struct_item starts at line 1
        let span = find_item_span_ts(source, 1);
        assert_eq!(span, Some((0, 4)));
    }

    #[test]
    fn item_span_ts_const() {
        let source = "\
pub const MAX: usize = 100;

pub fn other() {}
";
        // const on line 0, trailing blank on line 1 → end = 2
        let span = find_item_span_ts(source, 0);
        assert_eq!(span, Some((0, 2)));
    }

    #[test]
    fn item_span_ts_struct_with_doc_and_attr() {
        let source = "\
use std::fmt;

/// A point in 2D space
#[derive(Debug, Clone)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

pub fn other() {}
";
        // pub struct Point on line 4, doc on line 2, attr on line 3
        let span = find_item_span_ts(source, 4);
        assert_eq!(span, Some((2, 9)));
    }

    // -- collect_pub_symbols -------------------------------------------------

    #[test]
    fn collect_finds_pub_items() {
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                "pub fn foo() {}\npub struct Bar {}\nfn private() {}\npub(crate) fn scoped() {}\n",
            )],
        )]);
        let symbols = collect_pub_symbols(&ws.path().join("crates/alpha")).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"Bar"));
        assert!(!names.contains(&"private"));
        assert!(!names.contains(&"scoped"));
    }

    #[test]
    fn collect_skips_orm_symbols() {
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                "pub struct Model {}\npub struct Entity {}\npub fn real_thing() {}\n",
            )],
        )]);
        let symbols = collect_pub_symbols(&ws.path().join("crates/alpha")).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(!names.contains(&"Model"));
        assert!(!names.contains(&"Entity"));
        assert!(names.contains(&"real_thing"));
    }

    // -- count_symbol_hits ---------------------------------------------------

    #[test]
    fn count_hits_correctly() {
        let ws = create_workspace(&[
            ("alpha", &[("lib.rs", "pub fn shared() {}\npub fn lonely() {}\n")]),
            (
                "beta",
                &[("lib.rs", "fn consumer() {\n    shared();\n    shared();\n}\n")],
            ),
        ]);
        let beta_src = ws.path().join("crates/beta/src");
        let names = vec!["shared".to_string(), "lonely".to_string()];
        let counts = count_symbol_hits(&names, &[beta_src]).unwrap();
        assert_eq!(counts.get("shared").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("lonely").copied().unwrap_or(0), 0);
    }

    // -- analyze_crate -------------------------------------------------------

    #[test]
    fn analyze_classifies_unused_and_internal() {
        let ws = create_workspace(&[
            (
                "alpha",
                &[(
                    "lib.rs",
                    concat!(
                        "pub fn used_externally() {}\n",
                        "pub fn used_internally() { used_internally_helper(); }\n",
                        "fn used_internally_helper() { used_internally(); }\n",
                        "pub fn dead_code() {}\n",
                    ),
                )],
            ),
            (
                "beta",
                &[("lib.rs", "fn consumer() { used_externally(); }\n")],
            ),
        ]);
        let crate_path = ws.path().join("crates/alpha");
        let src_dirs = crate_src_dirs(&ws);
        let whitelist = HashSet::new();
        let result = analyze_crate(&crate_path, &src_dirs, &whitelist).unwrap();

        let find = |name: &str| result.unused.iter().find(|u| u.symbol.name == name);

        // used_externally: has external hits → not reported
        assert!(find("used_externally").is_none());

        // dead_code: no refs anywhere → UnusedAnywhere
        let dead = find("dead_code").unwrap();
        assert_eq!(dead.kind, SymbolKind::UnusedAnywhere);

        // used_internally: internal refs only → CrateInternalOnly
        let internal = find("used_internally").unwrap();
        assert!(matches!(internal.kind, SymbolKind::CrateInternalOnly { .. }));
    }

    #[test]
    fn analyze_respects_whitelist() {
        let ws = create_workspace(&[(
            "alpha",
            &[("lib.rs", "pub fn whitelisted_fn() {}\n")],
        )]);
        let src_dirs = crate_src_dirs(&ws);
        let mut whitelist = HashSet::new();
        whitelist.insert(("whitelisted_fn".to_string(), "alpha".to_string()));

        let result =
            analyze_crate(&ws.path().join("crates/alpha"), &src_dirs, &whitelist).unwrap();
        assert!(result.unused.is_empty());
    }

    // -- apply_fix_crate_internal --------------------------------------------

    #[test]
    fn fix_crate_internal_changes_pub_to_pub_crate() {
        let ws = create_workspace(&[(
            "alpha",
            &[("lib.rs", "pub fn internal_only() {\n    todo!()\n}\n")],
        )]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "internal_only".to_string(),
                file: file.clone(),
                line: 1,
            },
            kind: SymbolKind::CrateInternalOnly { refs: 3 },
            crate_name: "alpha".to_string(),
        };
        apply_fix_crate_internal(&sym).unwrap();

        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("pub(crate) fn internal_only()"));
        assert!(!result.starts_with("pub fn"));
    }

    // -- apply_fix_unused ----------------------------------------------------

    #[test]
    fn fix_unused_deletes_entire_function() {
        let source = "\
pub fn keep_me() {}

pub fn delete_me() {
    println!(\"bye\");
}

pub fn also_keep() {}
";
        let ws = create_workspace(&[("alpha", &[("lib.rs", source)])]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "delete_me".to_string(),
                file: file.clone(),
                line: 3, // 1-indexed
            },
            kind: SymbolKind::UnusedAnywhere,
            crate_name: "alpha".to_string(),
        };

        let _preview = apply_fix_unused(&sym).unwrap();
        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("keep_me"));
        assert!(!result.contains("delete_me"));
        assert!(result.contains("also_keep"));
    }

    #[test]
    fn fix_unused_deletes_struct_with_doc_and_attr() {
        let source = "\
pub fn keep() {}

/// Old struct
#[derive(Debug)]
pub struct Dead {
    field: i32,
}

pub fn also_keep() {}
";
        let ws = create_workspace(&[("alpha", &[("lib.rs", source)])]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "Dead".to_string(),
                file: file.clone(),
                line: 5, // 1-indexed: the `pub struct Dead` line
            },
            kind: SymbolKind::UnusedAnywhere,
            crate_name: "alpha".to_string(),
        };

        let _preview = apply_fix_unused(&sym).unwrap();
        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("keep"));
        assert!(!result.contains("Dead"));
        assert!(!result.contains("Old struct")); // doc comment deleted too
        assert!(result.contains("also_keep"));
    }

    #[test]
    fn fix_unused_deletes_const() {
        let source = "\
pub const UNUSED_CONST: &str = \"hello\";

pub fn keep() {}
";
        let ws = create_workspace(&[("alpha", &[("lib.rs", source)])]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "UNUSED_CONST".to_string(),
                file: file.clone(),
                line: 1,
            },
            kind: SymbolKind::UnusedAnywhere,
            crate_name: "alpha".to_string(),
        };

        let _preview = apply_fix_unused(&sym).unwrap();
        let result = fs::read_to_string(&file).unwrap();
        assert!(!result.contains("UNUSED_CONST"));
        assert!(result.contains("keep"));
    }
}
