# find-unused-pub

Find `pub` items in a Rust workspace that are either unused entirely or only used within their own crate.

## Install

```bash
cargo install --git https://github.com/Bolognafingers/find-unused-pub
```

Or build from source:

```bash
cargo build --release
```

## Usage

Run from anywhere inside a Rust workspace (it walks up to find the root `Cargo.toml` with `[workspace]`):

```bash
# Scan all crates
find-unused-pub

# Scan specific crates
find-unused-pub crates/auth crates/core

# Auto-fix crate-internal items → pub(crate)
find-unused-pub --fix crates/auth

# Auto-fix unused items (deletes the entire item)
find-unused-pub --fix-unused

# Fix both categories at once
find-unused-pub --fix --fix-unused

# Interactively review unused items (fix / whitelist / skip)
find-unused-pub --review

# Interactively review crate-internal items
find-unused-pub --review-crate-internal

# Clear the whitelist database
find-unused-pub --nuke-whitelist
```

## Flags

| Flag | Description |
|------|-------------|
| `--fix` | Alias for `--fix-crate-internal` |
| `--fix-crate-internal` | Auto-fix crate-internal items to `pub(crate)` |
| `--fix-unused` | Auto-fix unused items by deleting them entirely |
| `--review` | Alias for `--review-unused` |
| `--review-unused` | Interactively review unused items |
| `--review-crate-internal` | Interactively review crate-internal items |
| `--nuke-whitelist` | Clear the SQLite whitelist database |

Flags compose: `--fix --fix-unused` fixes both categories.

## How it works

1. Scans each crate's `src/` for `pub fn|struct|enum|trait|type|const|static` definitions
2. Batch-searches all other crates for word-bounded matches (using ripgrep as a library)
3. For symbols with zero external hits, checks internal usage within the same crate
4. Classifies each symbol:
   - **unused anywhere** (red) - no references beyond the definition itself
   - **crate-internal only** (yellow) - used inside the crate but never externally

Uses [tree-sitter-rust](https://github.com/tree-sitter/tree-sitter-rust) for accurate item span detection when deleting items (includes doc comments, attributes, and the full item body).

## Whitelist

False positives can be whitelisted during `--review` mode. The whitelist is stored in a SQLite database at `.find-unused-pub.db` in the workspace root (gitignored).

## Caveats

- Text-based search: will miss re-exports, derive macros generating references, etc.
- May false-positive on items used only via trait impls or proc macros
- Skips `pub(crate)`, `pub(super)`, and `pub(in ...)` (already scoped)
- Skips `pub mod` (modules are structural)
- Skips ORM-derived symbols (`Model`, `Entity`, `Column`, `Relation`, `ActiveModel`, `ActiveModelBehavior`)

## Tests

```bash
cargo nextest run
```
