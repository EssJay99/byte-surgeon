# Contributing to Data Doctor

Thank you for your interest in contributing to Data Doctor. This guide covers everything you need to know to make a successful contribution.

---

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment (OS, Rust version, hardware)
   - Logs or screenshots if applicable

### Requesting Features

1. Check existing issues and the roadmap
2. Open a feature request issue
3. Describe the use case and expected behavior
4. Discuss with maintainers before implementing

### Submitting Code

1. Fork the repository
2. Create a feature branch from `main`
3. Write code following the style guide
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

---

## Development Setup

### Prerequisites

- Rust 1.70+ (`rustup install stable`)
- Node.js 18+ (for GUI)
- Platform-specific dependencies:

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install libudev-dev libusb-1.0-0-dev pkg-config
```

**macOS:**
```bash
xcode-select --install
```

**Windows:**
```
Install Visual Studio Build Tools with C++ workload
```

### Building

```bash
# Clone the repository
git clone https://github.com/yourorg/datadoctor.git
cd datadoctor

# Build the workspace
cargo build

# Build release
cargo build --release

# Build CLI only
cargo build -p datadoctor-cli

# Build GUI
cd gui
npm install
npm run tauri dev
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p datadoctor-core
cargo test -p tle-plugins

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_threat_scanner_creation
```

### Linting and Formatting

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Check without building
cargo check
```

---

## Code Style Guide

### General Principles

- Follow standard Rust conventions (`rustfmt` default style)
- Prefer readability over cleverness
- Keep functions small and focused
- Use descriptive variable names
- Document public APIs with `///` doc comments

### Formatting

All code must be formatted with `cargo fmt`. The project uses default `rustfmt` settings.

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Types | `PascalCase` | `RecoveryEngine`, `FileInfo` |
| Functions | `snake_case` | `scan_file()`, `get_progress()` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_FILE_SIZE`, `BLOCK_SIZE` |
| Modules | `snake_case` | `threat_scanner`, `file_carver` |
| Traits | `PascalCase` | `Plugin`, `FileSystem` |
| Enums | `PascalCase` | `ScanType`, `DeviceType` |
| Enum variants | `PascalCase` | `ScanType::Deep`, `DeviceType::SSD` |
| Lifetimes | Short lowercase | `'a`, `'ctx` |

### Error Handling

Use `thiserror` for library errors and `anyhow` for application code:

```rust
// Library error (core, filesystem, etc.)
#[derive(Error, Debug)]
pub enum MyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, MyError>;
```

### Imports

Group imports in this order:

```rust
// 1. Standard library
use std::path::Path;
use std::io::Read;

// 2. External crates
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// 3. Internal modules
use crate::models::DeviceInfo;
use crate::error::{Error, Result};
```

### Documentation

- Document all public items with `///` comments
- Include code examples in doc comments
- Use `# Errors` section to document when functions fail

```rust
/// Scans a device for recoverable files using signature matching.
///
/// # Examples
///
/// ```rust
/// let scanner = DiskScanner::new("/dev/sda");
/// let matches = scanner.find_signatures()?;
/// ```
///
/// # Errors
///
/// Returns `Error::Io` if the device cannot be opened.
/// Returns `Error::Cancelled` if the scan is cancelled.
pub fn find_signatures(&self) -> Result<Vec<SignatureMatch>> {
```

### Unsafe Code

- Minimize `unsafe` usage
- Every `unsafe` block must have a `// SAFETY:` comment
- Prefer safe abstractions

```rust
// SAFETY: The pointer is guaranteed to be non-null by the plugin contract,
// and the plugin is guaranteed to outlive this call.
let plugin = &*loaded.instance;
```

### Concurrency

- Prefer `Arc<Mutex<T>>` for shared mutable state
- Use `Arc<AtomicBool>` for cancellation flags
- Use Rayon for data parallelism
- Use Tokio for async I/O

---

## Testing Requirements

### Unit Tests

Every module must have unit tests. Place tests in a `#[cfg(test)] mod tests` block at the bottom of each file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert!(result.is_ok());
    }
}
```

### Coverage Expectations

| Area | Minimum Coverage |
|------|-----------------|
| Core engine | 80% |
| File system parsers | 70% |
| Security modules | 90% |
| Plugin system | 80% |
| CLI | 60% |

### Test Types

1. **Unit tests** - Test individual functions in isolation
2. **Integration tests** - Test module interactions (in `tests/` directory)
3. **Property tests** - Test invariants with random inputs (consider `proptest`)
4. **Fuzz tests** - Test parsers with malformed inputs

### Running Tests in CI

All tests must pass before merging:

```bash
cargo test --workspace
cargo clippy -- -D warnings
cargo fmt --check
```

---

## Pull Request Process

### Before Submitting

1. **Rebase on main**: `git rebase main`
2. **Run tests**: `cargo test --workspace`
3. **Run linter**: `cargo clippy -- -D warnings`
4. **Format code**: `cargo fmt`
5. **Check formatting**: `cargo fmt --check`

### PR Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Added unit tests
- [ ] All existing tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows the style guide
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new clippy warnings
- [ ] No new compiler warnings
```

### Review Process

1. **Automated checks** run on every PR:
   - `cargo test --workspace`
   - `cargo clippy -- -D warnings`
   - `cargo fmt --check`
   - `cargo audit`

2. **Peer review** requires at least one approval from a maintainer

3. **Security review** required for changes to:
   - `core/src/security.rs`
   - `core/src/writeprotect.rs`
   - `core/src/tamper_proof_audit.rs`
   - `core/src/evidence_hash.rs`
   - `crypto/` module
   - Plugin loading code

4. **Merge** is done via squash merge to keep history clean

### Commit Messages

Follow conventional commits:

```
feat(core): add parallel file carving support
fix(scanner): handle zero-byte files gracefully
docs(api): update RecoveryEngine examples
test(carver): add PNG carving tests
refactor(security): extract threat patterns to config
chore(deps): update rusqlite to 0.31
```

Format: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `style`

---

## Project Structure

```
datadoctor/
├── core/               # Core recovery engine
│   └── src/
│       ├── lib.rs      # Public API exports
│       ├── recovery.rs # RecoveryEngine
│       ├── scanner.rs  # DiskScanner, MmapScanner
│       ├── carver.rs   # FileCarver
│       ├── models.rs   # Data types
│       ├── error.rs    # Error types
│       ├── security.rs # ThreatScanner, AuditLogger
│       └── ...
├── filesystem/         # File system parsers
├── devices/            # Device detection
├── network/            # Network scanning
├── mobile/             # Mobile device support
├── security/           # Compliance checking
├── crypto/             # Decryption engine
├── encryption/         # Volume encryption
├── enterprise/         # Case management, batch, API
├── forensic/           # Forensic analysis
├── raid/               # RAID reconstruction
├── chat/               # Chat message extraction
├── ml/                 # Machine learning
├── plugins/            # Plugin system
├── cli/                # CLI application
├── gui/                # GUI application (Tauri)
├── i18n/               # Internationalization
└── templates/          # Report templates
```

---

## Architecture Decisions

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Rust | Memory safety, performance, cross-platform |
| SQLite | Embedded database, no external dependencies |
| Tauri | Lightweight GUI, native performance |
| Rayon | Ergonomic data parallelism |
| Tokio | Async I/O for network operations |
| serde + JSON | Flexible data interchange for plugins |
| libloading | Dynamic plugin loading without FFI codegen |
| thiserror | Type-safe error handling |
| tracing | Structured logging with multiple backends |

### Adding a New Module

1. Create the crate in the workspace:
   ```bash
   cargo new --lib my_module
   ```

2. Add to `Cargo.toml` workspace members:
   ```toml
   [workspace]
   members = [
       # ...
       "my_module",
   ]
   ```

3. Add workspace dependencies:
   ```toml
   [dependencies]
   datadoctor-core = { path = "../core" }
   serde = { workspace = true }
   thiserror = { workspace = true }
   tracing = { workspace = true }
   ```

4. Create `src/lib.rs` with public API
5. Add tests
6. Update documentation

---

## Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and design discussions
- **Email**: support@datadoctor.com

---

## Code of Conduct

- Be respectful and constructive
- Focus on the technical merits
- Accept constructive criticism
- Acknowledge mistakes
- Prioritize the community's well-being

---

## License

By contributing, you agree that your contributions will be licensed under the project's proprietary license.
