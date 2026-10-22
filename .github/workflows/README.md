# CI/CD Pipeline - Byte Surgeon

## Overview

Byte Surgeon uses GitHub Actions for continuous integration and deployment. The CI/CD pipeline ensures code quality, security, and performance across all supported platforms.

## Workflows

### 1. CI (`ci.yml`)

**Triggers**: Push and pull requests to `main` and `develop` branches.

**Jobs**:

| Job | Description |
|-----|-------------|
| **check** | Runs `cargo fmt --check`, `cargo clippy`, and `cargo build` on Linux, macOS, and Windows |
| **test** | Runs `cargo test --workspace --all-features` on all platforms |
| **release-build** | Builds release binaries on all platforms |
| **fuzz** | Runs fuzz tests for 60 seconds per target |
| **docs** | Builds documentation with `cargo doc` and uploads as artifact |

**Coverage**: Code coverage is generated on Linux using `cargo-tarpaulin` and uploaded as an artifact.

### 2. Release (`release.yml`)

**Triggers**: Push of version tags matching `v*` (e.g., `v1.0.0`).

**Build targets**:

| Platform | Target |
|----------|--------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS x86_64 | `x86_64-apple-darwin` |
| macOS ARM64 | `aarch64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

**Process**:
1. Builds release binaries for all platforms
2. Generates changelog from commits since last tag
3. Creates GitHub release with:
   - Release notes with changelog
   - Binary archives (`.tar.gz` for Unix, `.zip` for Windows)
   - SHA256 checksums

### 3. Security Audit (`security-audit.yml`)

**Triggers**: Weekly schedule (Monday 6 AM UTC), or on changes to `Cargo.toml`/`Cargo.lock`.

**Jobs**:

| Job | Description |
|-----|-------------|
| **audit** | Runs `cargo audit` to check for known vulnerabilities |
| **deny** | Runs `cargo deny` to check license compliance and dependency policies |
| **sbom** | Generates Software Bill of Materials (SBOM) |

### 4. Performance Benchmarks (`performance-bench.yml`)

**Triggers**: Pull requests to `main`/`develop`, pushes to `main`, or manual dispatch.

**Process**:
1. Runs `cargo bench` on the current branch
2. On pull requests: compares results against `main` branch
3. Generates comparison table showing:
   - Benchmark names
   - Execution times (ns/iter)
   - Percentage change
   - Status (OK, IMPROVED, REGRESSION)
4. Comments comparison results directly on the PR
5. Flags regressions greater than 10%

## Caching Strategy

All workflows cache the following directories to speed up builds:
- `~/.cargo/registry` - Downloaded crate dependencies
- `~/.cargo/git` - Git-based dependencies
- `target/` - Build artifacts

Cache keys are based on the OS and `Cargo.lock` hash.

## Artifacts

| Artifact | Retention | Workflow |
|----------|-----------|----------|
| Coverage report | 30 days | CI |
| Documentation | 14 days | CI |
| Release binaries | 7 days | Release |
| Benchmark results | 30 days | Benchmarks |
| SBOM | 90 days | Security Audit |

## Adding a New Workspace Crate

When adding a new crate to the workspace:

1. Add it to `Cargo.toml` workspace members
2. Add benchmark targets if applicable:
   ```toml
   [[bench]]
   name = "my_benchmark"
   harness = false
   ```
3. Add fuzz targets in a `fuzz/` directory if applicable
4. The CI will automatically pick up the new crate

## Required Secrets

| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | Automatically provided; used for creating releases |

## Local Testing

Run CI checks locally before pushing:

```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Tests
cargo test --workspace --all-features

# Release build
cargo build --workspace --release

# Benchmarks
cargo bench --workspace --all-features

# Security audit
cargo install cargo-audit && cargo audit
```
