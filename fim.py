import argparse
import getpass
import hashlib
import hmac
import json
import sys
from datetime import datetime
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 hash of a file using buffered reading."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        print(f"[!] Warning: Cannot read {file_path}: {e}")
        return ""


def calculate_hmac(file_path: Path, secret_key: str) -> str:
    """Calculates the HMAC-SHA256 signature for a file using a secret key."""
    key_bytes = secret_key.encode("utf-8")
    mac = hmac.new(key_bytes, digestmod=hashlib.sha256)
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            mac.update(chunk)
    return mac.hexdigest()


def collect_directory_state(target_dir: Path) -> dict:
    """Recursively collects relative file paths and their SHA-256 hashes."""
    state = {}
    for item in target_dir.rglob("*"):
        if item.is_file():
            rel_path = str(item.relative_to(target_dir))
            file_hash = compute_sha256(item)
            if file_hash:
                state[rel_path] = file_hash
    return state


def create_baseline(target_dir: Path, baseline_file: Path, secret_key: str):
    print(f"[*] Scanning '{target_dir}' to generate baseline...")
    current_state = collect_directory_state(target_dir)

    metadata = {
        "timestamp": datetime.now().isoformat(),
        "target_directory": str(target_dir.resolve()),
        "file_count": len(current_state),
        "hashes": current_state,
    }

    # 1. Write the baseline JSON
    with open(baseline_file, "w") as f:
        json.dump(metadata, f, indent=4)

    # 2. Generate and save the HMAC signature
    sig_file = Path(f"{baseline_file}.sig")
    signature = calculate_hmac(baseline_file, secret_key)
    with open(sig_file, "w") as f:
        f.write(signature)

    print(f"[+] Baseline successfully saved to '{baseline_file}'")
    print(f"[+] HMAC Signature saved to '{sig_file}'")
    print(f"[+] Total files tracked: {len(current_state)}")


def verify_integrity(target_dir: Path, baseline_file: Path, secret_key: str):
    sig_file = Path(f"{baseline_file}.sig")

    # Step 1: Check existence of both baseline and its signature
    if not baseline_file.exists():
        print(f"[-] Error: Baseline file '{baseline_file}' does not exist.")
        sys.exit(1)
    if not sig_file.exists():
        print(f"[-] Error: Signature file '{sig_file}' is missing!")
        print("    The baseline is untrusted and cannot be verified.")
        sys.exit(1)

    # Step 2: Verify Baseline Authenticity using HMAC
    print("[*] Verifying baseline authenticity against cryptographic signature...")
    current_sig = calculate_hmac(baseline_file, secret_key)
    with open(sig_file, "r") as f:
        stored_sig = f.read().strip()

    # Use constant-time comparison to protect against timing attacks
    if not hmac.compare_digest(current_sig, stored_sig):
        print("\n" + "!" * 60)
        print(" [CRITICAL ALERT] BASELINE TAMPERING DETECTED!")
        print(" The baseline file or signature does not match your secret key.")
        print(" Either someone modified 'baseline.json' or the wrong key was entered.")
        print(" Audit aborted to prevent spoofed checks.")
        print("!" * 60 + "\n")
        sys.exit(1)

    print("[+] Baseline verification passed: Baseline is authentic and untampered.\n")

    # Step 3: Run standard file integrity verification
    with open(baseline_file, "r") as f:
        baseline_data = json.load(f)

    stored_hashes = baseline_data.get("hashes", {})
    print(f"[*] Checking directory '{target_dir}' against baseline created on {baseline_data.get('timestamp')}...")

    current_hashes = collect_directory_state(target_dir)

    stored_set = set(stored_hashes.keys())
    current_set = set(current_hashes.keys())

    added_files = current_set - stored_set
    deleted_files = stored_set - current_set

    modified_files = []
    common_files = stored_set & current_set
    for file_rel in common_files:
        if stored_hashes[file_rel] != current_hashes[file_rel]:
            modified_files.append(file_rel)

    # Print Audit Report
    print("\n" + "=" * 55)
    print("              INTEGRITY AUDIT REPORT")
    print("=" * 55)

    tampering_detected = False

    if modified_files:
        tampering_detected = True
        print(f"\n[!] MODIFIED FILES ({len(modified_files)}):")
        for f in sorted(modified_files):
            print(f"    - {f}")

    if added_files:
        tampering_detected = True
        print(f"\n[+] NEW / UNTRACKED FILES ({len(added_files)}):")
        for f in sorted(added_files):
            print(f"    - {f}")

    if deleted_files:
        tampering_detected = True
        print(f"\n[-] DELETED FILES ({len(deleted_files)}):")
        for f in sorted(deleted_files):
            print(f"    - {f}")

    if not tampering_detected:
        print("\n[OK] Integrity Verified: All files match baseline. No tampering detected.")

    print("=" * 55 + "\n")


def get_secret(args_key: str) -> str:
    """Gets the secret key from flags or via interactive secure prompt."""
    if args_key:
        return args_key
    # getpass hides the password as you type in the terminal
    key = getpass.getpass("Enter HMAC Secret Key: ")
    if not key:
        print("[-] Error: A secret key is required.")
        sys.exit(1)
    return key


def main():
    parser = argparse.ArgumentParser(description="Authenticated File Integrity Checker (FIM with HMAC)")
    parser.add_argument("-d", "--dir", required=True, help="Target directory to monitor")
    parser.add_argument("-b", "--baseline", action="store_true", help="Generate a new signed baseline file")
    parser.add_argument("-c", "--check", action="store_true", help="Audit directory integrity against signed baseline")
    parser.add_argument("--db", default="baseline.json", help="Path to baseline file (default: baseline.json)")
    parser.add_argument("-k", "--key", default=None, help="HMAC secret key (optional; prompted securely if omitted)")

    args = parser.parse_args()
    target_path = Path(args.dir)
    baseline_path = Path(args.db)

    if not target_path.exists() or not target_path.is_dir():
        print(f"[-] Error: '{target_path}' is not a valid directory.")
        sys.exit(1)

    if args.baseline:
        secret_key = get_secret(args.key)
        create_baseline(target_path, baseline_path, secret_key)
    elif args.check:
        secret_key = get_secret(args.key)
        verify_integrity(target_path, baseline_path, secret_key)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()