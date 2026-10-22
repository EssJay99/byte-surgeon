# Build Instructions

## Quick Start

### Build CLI Only
```bash
cargo build --release --bin datadoctor
```

### Build GUI Application
```bash
cd gui
npm install
npm run tauri build
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

1. Install dependencies:
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    curl \
    wget \
    file \
    libssl-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libudev-dev \
    libusb-1.0-0-dev
```

2. Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

3. Install Node.js (for GUI):
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

4. Build:
```bash
cargo build --release
```

### macOS

1. Install Xcode Command Line Tools:
```bash
xcode-select --install
```

2. Install Homebrew (if not installed):
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

3. Install dependencies:
```bash
brew install rust node libusb
```

4. Build:
```bash
cargo build --release
```

### Windows

1. Install Visual Studio Build Tools:
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Select "Desktop development with C++"
   - Ensure "Windows 10 SDK" is selected

2. Install Rust:
   - Download from: https://rustup.rs/
   - Run the installer

3. Install Node.js:
   - Download from: https://nodejs.org/
   - Install LTS version

4. Install dependencies:
```powershell
# Install additional tools
cargo install cargo-audit
cargo install cargo-outdated
```

5. Build:
```powershell
cargo build --release
```

## Build Options

### Debug Build
```bash
cargo build
```

### Release Build (Optimized)
```bash
cargo build --release
```

### Build with Specific Features
```bash
cargo build --features "network,mobile"
```

### Cross-Compilation

#### Build for Linux from macOS
```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

#### Build for Windows from Linux
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

## Testing

### Run All Tests
```bash
cargo test
```

### Run Specific Tests
```bash
cargo test --package datadoctor-core
```

### Run with Output
```bash
cargo test -- --nocapture
```

### Coverage Report
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

## Linting and Formatting

### Format Code
```bash
cargo fmt
```

### Check Formatting
```bash
cargo fmt -- --check
```

### Run Clippy
```bash
cargo clippy -- -D warnings
```

### Auto-fix Clippy Warnings
```bash
cargo clippy --fix
```

## Documentation

### Generate Documentation
```bash
cargo doc --no-deps --open
```

### Build Documentation
```bash
cargo doc --no-deps
```

## GUI Build

### Development Mode
```bash
cd gui
npm install
npm run tauri dev
```

### Production Build
```bash
cd gui
npm install
npm run tauri build
```

### Platform-Specific Builds

#### macOS DMG
```bash
cd gui
npm run tauri build -- --target universal-apple-darwin
```

#### Windows Installer
```bash
cd gui
npm run tauri build -- --bundles msi
```

#### Linux AppImage
```bash
cd gui
npm run tauri build -- --bundles appimage
```

## Troubleshooting

### Rust Toolchain Issues

Update Rust:
```bash
rustup update
```

Reset toolchain:
```bash
rustup default stable
rustup update stable
```

### Permission Errors

Linux/macOS:
```bash
sudo chown -R $USER ~/.cargo
```

Windows:
- Run as Administrator
- Check antivirus exclusions

### Build Failures

Clean build:
```bash
cargo clean
cargo build --release
```

Clear Cargo cache:
```bash
rm -rf ~/.cargo/registry
rm -rf target/
cargo build --release
```

### Node.js Issues

Clear npm cache:
```bash
npm cache clean --force
rm -rf node_modules
npm install
```

## Performance Optimization

### Release Profile
Edit `Cargo.toml`:
```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
panic = 'abort'
strip = true
```

### Build Parallelism
```bash
CARGO_BUILD_JOBS=8 cargo build --release
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Build
on: [push, pull_request]
jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo build --release
      - run: cargo test
```

## Distribution

### Create Release Package
```bash
# Build
cargo build --release

# Package CLI
mkdir -p dist
cp target/release/datadoctor dist/
cp README.md dist/
cp LICENSE dist/
tar -czf datadoctor-1.0.0.tar.gz dist/
```

### Docker Build
```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
COPY --from=builder /app/target/release/datadoctor /usr/local/bin/
CMD ["datadoctor"]
```

Build Docker image:
```bash
docker build -t datadoctor:latest .
```

## Support

For build issues:
- GitHub Issues: https://github.com/yourorg/datadoctor/issues
- Discord: https://discord.gg/datadoctor
- Email: support@datadoctor.com

---

**Last Updated**: October 20, 2026
