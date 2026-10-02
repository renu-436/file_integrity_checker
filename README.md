# Authenticated File Integrity Checker (FIM)

A lightweight, enterprise-ready File Integrity Monitoring utility built with Python. It tracks directory changes using SHA-256 cryptographic hashing and secures baseline snapshots against tampering using HMAC-SHA256 signatures.

## Features
- **Cryptographic Hashing:** Uses streaming SHA-256 chunking to monitor file integrity without memory overhead.
- **Tamper-Proof Baseline:** Verifies baseline authenticity via HMAC-SHA256 signatures to prevent unauthorized rewriting.
- **Forensic Metadata:** Audits byte size differences and filesystem modification timestamps (`mtime`).
- **Zero External Dependencies:** Built entirely on Python standard libraries (`hashlib`, `hmac`, `json`, `argparse`).

## Usage

### 1. Initialize Baseline
Generate a signed baseline of the target directory:
```bash
python fim.py -d monitored_files --baseline
```

### 2. Audit Integrity
Verify directory state against the signed baseline:
```bash
python fim.py -d monitored_files --check
```

## Security Model
- **Change Detection:** Flags modified, added, or deleted files based on cryptographic hash mismatches.
- **Integrity Validation:** Fails closed if `baseline.json` or its signature is modified without the valid HMAC secret key.