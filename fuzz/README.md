# Fuzz Testing for TLE (Data Doctor)

Fuzz testing infrastructure targeting parsers and recovery engines to find edge cases, crashes, and panics.

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Description |
|--------|-------------|
| `filesystem_parser` | Fuzzes NTFS, FAT32, ext4, and APFS boot sector / superblock parsing |
| `signature_scanner` | Fuzzes `SignatureDatabase::identify` and `identify_all` with arbitrary byte sequences |
| `registry_parser` | Fuzzes Windows registry hive parsing (`parse_hive_data`, `load_from_data`) |
| `email_parser` | Fuzzes PST, MBOX, and EML email parsing via `EmailRecoverer` |
| `chat_recoverer` | Fuzzes WhatsApp/iMessage SQLite recovery, `SqliteCarver`, and iMessage date parsing |

## Quick Start

```bash
# Fuzz a single target for 5 minutes (default)
./run_fuzz.sh signature_scanner

# Fuzz all targets for 5 minutes each
./run_fuzz.sh --all

# Custom duration (60 seconds)
./run_fuzz.sh --max-time 60 registry_parser

# List available targets
./run_fuzz.sh --list
```

## Manual Execution

```bash
cd fuzz

# Build and run a target
cargo +nightly fuzz run signature_scanner

# Run with a specific corpus directory
cargo +nightly fuzz run filesystem_parser ./corpus/filesystem_parser

# Reproduce a crash
cargo +nightly fuzz run <target> <artifact_file>
```

## Directory Structure

```
fuzz/
  Cargo.toml              # Fuzz crate config with libfuzzer-sys + arbitrary
  fuzz_targets/
    filesystem_parser.rs  # NTFS/FAT32/ext4/APFS fuzzing
    signature_scanner.rs  # Signature matching fuzzing
    registry_parser.rs    # Windows registry hive fuzzing
    email_parser.rs       # PST/MBOX/EML fuzzing
    chat_recoverer.rs     # WhatsApp/iMessage fuzzing
  corpus/                 # Auto-generated inputs that increase coverage
  artifacts/              # Crash inputs and slow-unit reports
  run_fuzz.sh             # Runner script
```

## How It Works

Each fuzz target:

1. Receives arbitrary byte sequences from libFuzzer
2. Feeds the bytes to parser/recovery functions (via temp files or direct `&[u8]`)
3. Wraps calls in `catch_unwind` to detect panics
4. Returns normally on success or error; libFuzzer tracks code coverage

The fuzzer mutates inputs to maximize coverage, naturally discovering edge cases like:
- Truncated headers
- Integer overflow in size fields
- Invalid UTF-16 sequences
- Corrupt B-tree nodes
- Malformed SQLite databases

## Interpreting Results

- **Crash found**: An artifact file is written to `artifacts/<target>/`. Reproduce with:
  ```bash
  cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>
  ```
- **Timeout**: Slow inputs are saved. Investigate and optimize the parser.
- **No crashes**: Coverage still increases over time; longer runs find deeper bugs.

## CI Integration

```bash
# Short smoke test (30s per target)
MAX_TOTAL_TIME=30 ./run_fuzz.sh --all
```

## Adding New Targets

1. Add a new file in `fuzz_targets/`
2. Register it in `fuzz/Cargo.toml` as a `[[bin]]` entry
3. Add the target name to the `TARGETS` array in `run_fuzz.sh`
