# Security Documentation

## Overview

Byte Surgeon is built with security as a foundational principle. The entire codebase is written in Rust, providing memory safety without garbage collection, and implements defense-in-depth across all layers.

This document covers the security architecture, threat model, best practices, and vulnerability reporting procedures.

---

## Security Features

### Memory Safety

- **No buffer overflows**: Rust's bounds checking prevents out-of-bounds access
- **No use-after-free**: Ownership model eliminates dangling pointers
- **No data races**: `Send`/`Sync` traits prevent concurrent data access violations
- **No null pointer dereferences**: `Option<T>` replaces null pointers
- **No uninitialized memory**: Variables must be initialized before use

### Cryptographic Primitives

| Algorithm | Usage | Crate |
|-----------|-------|-------|
| AES-256-GCM | Symmetric encryption | `aes-gcm` |
| Argon2 | Password hashing | `argon2` |
| SHA-256 | Integrity verification | `sha2` |
| CRC32 | Checksum verification | `crc32fast` |

### Threat Detection

The `ThreatScanner` engine performs multi-layer analysis:

```rust
use bytesurgeon_core::ThreatScanner;

let scanner = ThreatScanner::new();
```

**Detection Methods:**

1. **Pattern Matching** - Scans for known malicious patterns:
   - EICAR test string
   - Shell commands (`eval(`, `exec(`, `base64_decode`, `shell_exec`)
   - System access (`powershell`, `cmd.exe`, `/bin/sh`, `/bin/bash`)
   - Windows scripting (`WScript.Shell`, `AutoRun`)
   - Registry access (`HKEY_`)

2. **Executable Header Analysis** - Detects PE (`MZ`) and ELF (`\x7fELF`) binaries

3. **Suspicious API Detection** - Scans executable headers for:
   - `CreateRemoteThread`
   - `VirtualAllocEx`
   - `WriteProcessMemory`
   - `NtUnmapViewOfSection`
   - `SetWindowsHookEx`

### Integrity Verification

```rust
use bytesurgeon_core::ThreatScanner;
use std::path::Path;

let scanner = ThreatScanner::new();

// Calculate file hash
let hash = scanner.calculate_file_hash(Path::new("/recovered/file.jpg"))?;

// Verify integrity
let valid = scanner.verify_file_integrity(Path::new("/recovered/file.jpg"), &hash)?;
```

Every recovered file receives a SHA-256 hash stored in `RecoveredFile.signature`.

### Audit Logging

All operations are logged with timestamps via `AuditLogger`:

```rust
use bytesurgeon_core::AuditLogger;

let logger = AuditLogger::new(Path::new("/var/log/bytesurgeon/audit.log"));
logger.log_operation("RECOVERY_START", "Device: /dev/sda, Type: Signature")?;
logger.log_security_event("THREAT_DETECTED", "File: /tmp/suspicious.exe")?;
logger.log_threat_detection(Path::new("/tmp/suspicious.exe"), "malware")?;
```

### Tamper-Proof Audit Trail

```rust
use bytesurgeon_core::tamper_proof_audit;
```

Hash-chained audit entries prevent log tampering.

### Evidence Chain of Custody

```rust
use bytesurgeon_core::{EvidenceHasher, EvidenceChain, HashChainEntry, VerificationResult};

let hasher = EvidenceHasher::new();
```

Cryptographic hash chains verify the integrity of evidence throughout the recovery process.

### Write Protection

```rust
use bytesurgeon_core::{WriteProtector, WriteProtectionStatus, AuditEntry};

let protector = WriteProtector::new("/dev/sda");
```

Hardware and software write-blocking prevents accidental modification of source media.

### Security Policy Enforcement

```rust
use bytesurgeon_core::SecurityPolicy;

let policy = SecurityPolicy {
    allow_network_recovery: true,
    allow_mobile_recovery: true,
    require_threat_scan: true,       // Force threat scan on all recovered files
    max_concurrent_operations: 4,     // Limit resource usage
    audit_logging: true,              // Enable full audit trail
};
```

---

## Threat Model

### Assets

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| Recovered files | High | Integrity verification, threat scanning |
| Audit logs | High | Tamper-proof hashing, append-only writes |
| Session data | Medium | SQLite storage with access controls |
| Encryption keys | Critical | Argon2 hashing, memory-only storage |
| Device metadata | Medium | Access-controlled database |

### Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Malicious files | Pattern exploitation | Infect recovery system |
| Insider threat | Database access | Data exfiltration |
| Supply chain | Dependency compromise | Backdoor injection |
| Network attacker | MITM on network recovery | Data interception |

### Attack Surfaces

| Surface | Risk | Mitigation |
|---------|------|------------|
| Device I/O | Malformed data | Rust memory safety, bounds checking |
| File carving | Corrupted signatures | Size validation, hash verification |
| Network scanning | Untrusted responses | Input validation, TLS encryption |
| Plugin loading | Arbitrary code execution | Signed plugins, sandboxing |
| Database access | SQL injection | Parameterized queries (rusqlite) |
| CLI input | Command injection | Clap argument parsing, input sanitization |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                               │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐│
│  │  Core Engine (Rust, memory-safe)                         ││
│  │  - RecoveryEngine, DiskScanner, FileCarver               ││
│  │  - ThreatScanner, AuditLogger                            ││
│  │  - Database (parameterized queries)                      ││
│  └──────────────────────────────────────────────────────────┘│
│                          │                                    │
│              ─────── Trust Boundary ───────                   │
│                          │                                    │
│  ┌───────────────────────▼──────────────────────────────────┐│
│  │  INPUT ZONE (untrusted data)                             ││
│  │  - Raw disk data (malformed sectors, corrupted files)    ││
│  │  - Device responses (potentially hostile firmware)       ││
│  │  - Network packets (untrusted remote devices)            ││
│  │  - User input (CLI arguments, GUI fields)                ││
│  └──────────────────────────────────────────────────────────┘│
│                          │                                    │
│              ─────── Trust Boundary ───────                   │
│                          │                                    │
│  ┌───────────────────────▼──────────────────────────────────┐│
│  │  PLUGIN ZONE (dynamically loaded code)                   ││
│  │  - External .so/.dylib/.dll files                        ││
│  │  - Executed via unsafe FFI                               ││
│  │  - Isolated by process boundaries                        ││
│  └──────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Security Best Practices

### For Operators

1. **Run with minimum privileges**
   - Only use `sudo`/admin when accessing raw devices
   - Use a dedicated recovery user account
   - Restrict output directory permissions

2. **Verify recovered files**
   - Always scan recovered files for threats
   - Check SHA-256 hashes against known-good values
   - Open files in isolated environments

3. **Maintain audit logs**
   - Review audit logs after every operation
   - Store logs on separate, protected media
   - Verify log integrity with hash chains

4. **Protect source media**
   - Use write-blocking hardware when possible
   - Create forensic images before recovery
   - Document chain of custody

5. **Secure the environment**
   - Use encrypted storage for recovered data
   - Enable full-disk encryption on recovery workstations
   - Restrict network access during sensitive operations

### For Developers

1. **Input validation**
   - Validate all file paths before use
   - Canonicalize paths to prevent traversal attacks
   - Check file sizes before allocating buffers

2. **Error handling**
   - Never expose internal paths in error messages
   - Use typed errors (`thiserror`) instead of stringly-typed errors
   - Log errors with context but sanitize sensitive data

3. **Dependency management**
   - Run `cargo audit` regularly
   - Pin dependency versions in `Cargo.lock`
   - Review new dependencies before adding

4. **Unsafe code**
   - Minimize `unsafe` blocks (currently only in plugin FFI and mmap)
   - Document safety invariants for every `unsafe` block
   - Prefer safe abstractions over raw pointers

5. **Testing**
   - Write unit tests for all security-critical functions
   - Fuzz test input parsers
   - Test error paths, not just happy paths

### For Enterprise Deployments

1. **Access control**
   - Integrate with LDAP/AD for authentication
   - Implement role-based access control
   - Require multi-factor authentication for sensitive operations

2. **Network security**
   - Use TLS 1.3 for all API communications
   - Implement API key rotation
   - Rate-limit API endpoints

3. **Compliance**
   - Run compliance checks regularly: `bytesurgeon compliance`
   - Maintain evidence chain of custody
   - Generate court-ready reports with `CourtReportGenerator`

4. **Monitoring**
   - Monitor audit logs in real-time
   - Set up alerts for threat detections
   - Track resource usage patterns

---

## Compliance Standards

### NIST SP 800-53 Rev 5

Byte Surgeon aligns with the following control families:

| Control Family | Implementation |
|---------------|----------------|
| **AC** - Access Control | Device permissions, security policy enforcement |
| **AU** - Audit and Accountability | Complete operation logging with timestamps |
| **CA** - Assessment and Authorization | Compliance checker, security testing |
| **CM** - Configuration Management | Secure defaults, version-controlled config |
| **IA** - Identification and Authentication | GUI authentication, examiner roles |
| **IR** - Incident Response | Threat detection, automatic quarantine |
| **RA** - Risk Assessment | Risk level estimation in dry-run mode |
| **SA** - System and Services Acquisition | Secure development practices |
| **SC** - System and Communications Protection | AES-256-GCM encryption, TLS |
| **SI** - System and Information Integrity | Threat scanning, integrity verification |

### Other Standards

- **ISO 27001** - Information security management aligned
- **SOC 2 Type II** - Service organization controls compliant
- **GDPR** - Data protection and privacy compliant
- **CCPA** - California Consumer Privacy Act compliant

### Compliance Checking

```rust
use bytesurgeon_security::compliance::ComplianceChecker;

let checker = ComplianceChecker::new();
let report = checker.check_nist_compliance()?;

println!("Standard: {}", report.standard);
println!("Passed: {}", report.passed);
for finding in &report.findings {
    println!("Finding: {}", finding);
}
for rec in &report.recommendations {
    println!("Recommendation: {}", rec);
}
```

---

## Data Protection

### At Rest

- Recovered files written with secure I/O
- Temporary files securely deleted after use
- SQLite database with access controls
- Audit logs protected from tampering (hash-chained)

### In Transit

- Network recovery uses TLS 1.3
- API calls authenticated with bearer tokens
- Session tokens are cryptographically random
- No data transmitted without encryption

### Destruction

- Temporary files overwritten before deletion
- Sensitive buffers zeroed after use (`Vec<u8>` cleared)
- Compliant with NIST SP 800-88 media sanitization guidelines

---

## Vulnerability Reporting

### Process

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email **security@bytesurgeon.com** with details
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Phase | Timeframe |
|-------|-----------|
| Acknowledgment | Within 24 hours |
| Initial assessment | Within 72 hours |
| Progress updates | Weekly |
| Public disclosure | After fix is released |

### Patch Policy

| Severity | Patch Timeline |
|----------|---------------|
| Critical | Within 7 days |
| High | Within 30 days |
| Medium | Within 90 days |
| Low | Next scheduled release |

### Security Contacts

| Role | Contact |
|------|---------|
| Security Team | security@bytesurgeon.com |
| CISO | ciso@bytesurgeon.com |
| Emergency | emergency@bytesurgeon.com |

---

## Security Checklist

Before deploying Byte Surgeon:

- [ ] Latest version installed with all security patches
- [ ] Audit logging enabled and reviewed
- [ ] Threat scanning active for all recovered files
- [ ] Access controls configured (minimum privilege)
- [ ] Network security reviewed (TLS, API keys)
- [ ] Backup procedures tested
- [ ] Incident response plan documented
- [ ] Compliance check passed (`bytesurgeon compliance`)
- [ ] Write protection enabled for source media
- [ ] Evidence chain of custody established

---

## Secure Development Lifecycle

### Code Review

- All changes require peer review
- Security-critical modules require security-focused review
- Automated scanning in CI/CD pipeline

### Testing

- Unit tests for all security functions
- Integration tests for security workflows
- Fuzz testing for parsers (file system, network, device)
- Quarterly penetration testing

### Dependencies

- `cargo audit` runs in CI on every PR
- Dependencies updated monthly
- Minimal dependency footprint
- Verified package sources

### Release Process

- Security review before each release
- Changelog includes security fixes
- Signed release artifacts
- SBOM (Software Bill of Materials) generated

---

**Last Updated**: October 20, 2026
**Next Review**: January 20, 2027
