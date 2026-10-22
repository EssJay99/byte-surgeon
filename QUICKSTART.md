# Data Doctor - Quick Start Guide

## Installation

### Prerequisites
- Rust 1.70+ (install from https://rustup.rs)
- Node.js 18+ (for GUI, from https://nodejs.org)

### Build the CLI
```bash
# Clone or navigate to the project
cd /Users/ted/TLE

# Build in release mode
cargo build --release

# The binary will be at: target/release/datadoctor
```

### Build the GUI
```bash
cd gui
npm install
npm run tauri dev
```

## First Steps

### 1. Scan for Devices
```bash
./target/release/datadoctor scan
```
This will detect all connected storage devices.

### 2. Start a Recovery Session
```bash
# Create output directory
mkdir -p recovered_files

# Start recovery (example for Linux/macOS)
./target/release/datadoctor recover \
  --device /dev/sda \
  --mode signature \
  --output ./recovered_files
```

**Recovery Modes:**
- `signature` - Fast file signature scanning (recommended to start)
- `quick` - Quick file system scan
- `deep` - Thorough deep scan (slower but more complete)
- `filesystem` - File system metadata scan
- `raw` - Raw sector-by-sector recovery

### 3. View Recovery Sessions
```bash
./target/release/datadoctor sessions
```

### 4. List Recovered Files
```bash
./target/release/datadoctor files --session <session-id>
```

### 5. Scan for Threats
```bash
./target/release/datadoctor threat-scan --path ./recovered_files
```

## Common Use Cases

### Recover from USB Drive
```bash
# Find the USB device
./target/release/datadoctor scan

# Recover files (adjust device path as needed)
./target/release/datadoctor recover \
  --device /dev/sdb1 \
  --mode signature \
  --output ./usb_recovery
```

### Deep Scan a Hard Drive
```bash
./target/release/datadoctor recover \
  --device /dev/sda \
  --mode deep \
  --output ./deep_recovery
```

### Scan Network for Devices
```bash
./target/release/datadoctor network-scan --subnet 192.168.1
```

### Check System Compliance
```bash
./target/release/datadoctor compliance
```

## Windows Users

Device paths are different on Windows:
```powershell
# Scan devices
.\target\release\datadoctor.exe scan

# Recover from D: drive
.\target\release\datadoctor.exe recover --device \\.\D: --mode signature --output .\recovered
```

## macOS Users

You may need to grant disk access:
```bash
# Give Full Disk Access in System Preferences > Security & Privacy
# Then run:
sudo ./target/release/datadoctor scan
```

## Troubleshooting

### "Permission denied" errors
- Linux/macOS: Use `sudo` or run as root
- Windows: Run as Administrator

### Device not detected
- Check device is properly connected
- Verify device appears in system (lsblk on Linux, diskutil on macOS)
- Check system logs for hardware issues

### Slow recovery
- Use `signature` mode for faster results
- Close other applications
- Ensure adequate disk space

## Next Steps

1. Read the full README.md for comprehensive documentation
2. Review SECURITY.md for security features and compliance
3. Check BUILD.md for detailed build instructions
4. Explore the GUI for a visual interface

## Need Help?

- Documentation: See README.md
- Security: See SECURITY.md
- Build issues: See BUILD.md
- GitHub Issues: https://github.com/yourorg/datadoctor/issues

---

**Happy Recovering!** 🔥
