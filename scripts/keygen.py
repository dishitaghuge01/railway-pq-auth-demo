"""
scripts/keygen.py

Standalone key generation script for the Railway PQ Auth Demo.
Simulates the one-time HSM keypair initialisation at CRIS headquarters.

Usage:
    python scripts/keygen.py               # generate keys (warns if overwriting)
    python scripts/keygen.py --force       # overwrite without prompting
    python scripts/keygen.py --rotate      # rotate: current → old, generate new current

What it does:
    1. If keys/public_key.bin already exists:
         --rotate : moves public_key.bin → old_public_key.bin
         default  : warns and asks for confirmation before overwriting
    2. Generates a new Dilithium2 keypair via liboqs
    3. Writes private_key.bin (mode 0o600, gitignored) and public_key.bin
    4. Prints key sizes, fingerprint, and next steps

Key rotation model (from the proposal):
    - Key rotation every 6 months
    - New public key embedded in app updates 14 days before rotation date
    - Old key remains in apps for 4 months after rotation to cover
      advance-booked tickets issued before the rotation date
    - Two keys always embedded in HHT/IRCTC/RailOne apps simultaneously:
      current and previous

This script handles the key file management side of rotation.
The app-embedding side is done by rebuilding the apps with the new public key.

Security note:
    In production, the private key is generated inside the HSM and never
    exported. This script generates it in software and writes it to disk,
    which is only acceptable for a demo environment.
    private_key.bin is in .gitignore and must never be committed.
"""

import argparse
import os
import sys
import time

# ---------------------------------------------------------------------------
# Path resolution — run from repo root: python scripts/keygen.py
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.config import settings
from shared.crypto_utils import (
    DILITHIUM2_PRIVATE_KEY_BYTES,
    DILITHIUM2_PUBLIC_KEY_BYTES,
    generate_keypair,
    get_public_key_fingerprint,
    save_private_key,
    save_public_key,
)

# ANSI colour helpers — degrade gracefully on Windows
def _green(s):  return f"\033[32m{s}\033[0m"
def _yellow(s): return f"\033[33m{s}\033[0m"
def _red(s):    return f"\033[31m{s}\033[0m"
def _bold(s):   return f"\033[1m{s}\033[0m"
def _cyan(s):   return f"\033[36m{s}\033[0m"


def _path(filename: str) -> str:
    """Resolve a key filename to its full path under KEYS_DIR."""
    return os.path.join(settings.KEYS_DIR, filename)


def _confirm(prompt: str) -> bool:
    """Ask yes/no question. Returns True if user typed 'y' or 'yes'."""
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def _print_separator():
    print("─" * 60)


def run_keygen(force: bool = False, rotate: bool = False) -> None:
    """
    Main key generation logic.

    Args:
        force  : Skip confirmation prompt when overwriting existing keys.
        rotate : Move existing current key to old before generating new one.
    """
    private_key_path     = _path("private_key.bin")
    public_key_path      = _path("public_key.bin")
    old_public_key_path  = _path("old_public_key.bin")

    _print_separator()
    print(_bold("Railway PQ Auth Demo — Dilithium2 Key Generation"))
    print(_bold("Simulates one-time HSM keypair initialisation at CRIS HQ"))
    _print_separator()

    # -----------------------------------------------------------------------
    # Handle existing keys
    # -----------------------------------------------------------------------
    current_key_exists = os.path.exists(public_key_path)

    if current_key_exists:
        if rotate:
            # Key rotation path: current → old, then generate new current
            if os.path.exists(old_public_key_path):
                print(_yellow(
                    f"Warning: old_public_key.bin already exists at {old_public_key_path}.\n"
                    "It will be overwritten with the current public key.\n"
                    "This means tickets signed with the key that is currently 'old' will\n"
                    "no longer be verifiable after this rotation."
                ))
                if not force and not _confirm("Continue with rotation?"):
                    print("Rotation cancelled.")
                    sys.exit(0)

            print(f"\n{_cyan('Key rotation:')} moving current public key → old_public_key.bin")
            # Read current public key
            with open(public_key_path, "rb") as f:
                current_pub_bytes = f.read()
            # Write it as the old key
            save_public_key(current_pub_bytes, old_public_key_path)
            old_fp = get_public_key_fingerprint(current_pub_bytes)
            print(f"  Old public key saved.  Fingerprint: {_yellow(old_fp)}")
            print(f"  Path: {old_public_key_path}")

            # Also move private key to a timestamped backup (don't delete — may be needed
            # for re-signing edge cases, but gitignored)
            if os.path.exists(private_key_path):
                backup_path = _path(f"private_key_retired_{int(time.time())}.bin")
                os.rename(private_key_path, backup_path)
                print(f"  Old private key backed up to: {backup_path}")
                print(_yellow(f"  (This backup is gitignored but should be deleted after confirming the rotation.)"))

        else:
            # Non-rotation overwrite — warn loudly
            print(_yellow(
                f"\nWarning: Key files already exist:\n"
                f"  {public_key_path}\n"
                f"  {private_key_path}\n\n"
                "Generating new keys will invalidate ALL previously issued tickets.\n"
                "TTEs will get FORGED results for every ticket issued before this moment.\n\n"
                "If you meant to rotate keys (keep old key for grace period), use --rotate.\n"
            ))
            if not force and not _confirm("Overwrite existing keys? (All existing tickets will become unverifiable)"):
                print("Key generation cancelled.")
                sys.exit(0)

            # Clean up old key files if present
            for path in [old_public_key_path]:
                if os.path.exists(path):
                    os.remove(path)
                    print(f"Removed: {path}")
    else:
        print(f"\nNo existing keys found. Generating fresh keypair.")

    # -----------------------------------------------------------------------
    # Generate keypair
    # -----------------------------------------------------------------------
    print(f"\n{_cyan('Generating Dilithium2 keypair...')} (this may take 1–3 seconds)")
    t_start = time.perf_counter()

    private_key_bytes, public_key_bytes = generate_keypair()

    elapsed = time.perf_counter() - t_start
    print(f"Keypair generated in {elapsed:.2f}s")

    # Verify sizes before writing anything
    assert len(private_key_bytes) == DILITHIUM2_PRIVATE_KEY_BYTES
    assert len(public_key_bytes) == DILITHIUM2_PUBLIC_KEY_BYTES

    # -----------------------------------------------------------------------
    # Write key files
    # -----------------------------------------------------------------------
    save_private_key(private_key_bytes, private_key_path)
    save_public_key(public_key_bytes, public_key_path)

    fingerprint = get_public_key_fingerprint(public_key_bytes)

    # -----------------------------------------------------------------------
    # Summary output
    # -----------------------------------------------------------------------
    _print_separator()
    print(_green("✓ Keys generated successfully"))
    _print_separator()
    print(f"  Algorithm      : Dilithium2 (FIPS 204 / CRYSTALS-Dilithium, level 2)")
    print(f"  Security level : 128-bit post-quantum (resistant to Shor's algorithm)")
    print(f"  Private key    : {len(private_key_bytes)} bytes → {private_key_path}")
    print(f"  Public key     : {len(public_key_bytes)} bytes → {public_key_path}")
    print(f"  Fingerprint    : {_bold(fingerprint)}")

    if rotate and os.path.exists(old_public_key_path):
        with open(old_public_key_path, "rb") as f:
            old_bytes = f.read()
        old_fp = get_public_key_fingerprint(old_bytes)
        print(f"  Old key fp     : {_yellow(old_fp)} (grace period active)")

    _print_separator()
    print(_yellow("Security reminders:"))
    print(f"  • private_key.bin is in .gitignore — confirm it is never committed")
    print(f"  • In production, the private key is generated inside the HSM")
    print(f"    and never exported. This file simulates that boundary.")
    print(f"  • The public key fingerprint above should be announced to TTE")
    print(f"    app maintainers for embedding in the next app build.")
    _print_separator()

    print(f"\n{_green('Next steps:')}")
    print(f"  1. Start all services:    honcho start")
    print(f"  2. Verify signer health:  curl http://localhost:{settings.CRIS_SIGNER_PORT}/health")
    print(f"  3. View public key:       curl http://localhost:{settings.CRIS_SIGNER_PORT}/public-key")
    print(f"  4. Book a test ticket:    python -m cli book")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate or rotate Dilithium2 keys for the Railway PQ Auth Demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompts. Use in CI or scripted environments.",
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help=(
            "Key rotation mode: move current key to old_public_key.bin "
            "before generating a new current key. "
            "Use this for scheduled 6-month key rotations."
        ),
    )
    args = parser.parse_args()

    try:
        run_keygen(force=args.force, rotate=args.rotate)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)
    except Exception as exc:
        print(_red(f"\nKey generation failed: {exc}"))
        sys.exit(1)


if __name__ == "__main__":
    main()