"""
shared/crypto_utils.py

Post-quantum cryptographic utilities for the Railway PQ Auth Demo.
Uses Falcon (FIPS 204 / NIST ML-DSA-44) via liboqs-python.

Key sizes (Falcon):
    Private key : 1281 bytes
    Public key  : 897 bytes
    Signature   : 809 bytes

Unlike the v1 ECDSA implementation, keys are stored as raw bytes (.bin files),
not PEM-encoded strings, because Falcon keys have no standardised PEM format
in mainstream tooling. All sign/verify functions accept and return raw bytes.
"""

import hashlib
import os
import struct

import oqs  # liboqs-python

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM = "Falcon-padded-512"  # liboqs name for Falcon-512, FIPS 204 level 2 signature scheme

# Fixed sizes defined by the Falcon parameter set (FIPS 204, security level 2).
# These are checked at runtime to catch misuse early.
FALCON_PRIVATE_KEY_BYTES = 1281
FALCON_PUBLIC_KEY_BYTES = 897
FALCON_SIGNATURE_BYTES = 666


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a new Falcon keypair.

    Returns:
        (private_key_bytes, public_key_bytes)
        private_key_bytes : 2528 raw bytes
        public_key_bytes  : 1312 raw bytes

    The caller is responsible for saving the keys securely.
    In the real system the private key never leaves the HSM.
    In this demo it is written to keys/private_key.bin which is gitignored.
    """
    with oqs.Signature(ALGORITHM) as signer:
        public_key_bytes = signer.generate_keypair()
        private_key_bytes = signer.export_secret_key()

    assert len(private_key_bytes) == FALCON_PRIVATE_KEY_BYTES, (
        f"Expected private key of {FALCON_PRIVATE_KEY_BYTES} bytes, "
        f"got {len(private_key_bytes)}"
    )
    assert len(public_key_bytes) == FALCON_PUBLIC_KEY_BYTES, (
        f"Expected public key of {FALCON_PUBLIC_KEY_BYTES} bytes, "
        f"got {len(public_key_bytes)}"
    )

    return private_key_bytes, public_key_bytes


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------

def save_private_key(key_bytes: bytes, path: str) -> None:
    """
    Write raw private key bytes to a .bin file.

    The file is created with mode 0o600 (owner read/write only).
    Raises ValueError if key_bytes is not the expected length.
    """
    if len(key_bytes) != FALCON_PRIVATE_KEY_BYTES:
        raise ValueError(
            f"Private key must be {FALCON_PRIVATE_KEY_BYTES} bytes, "
            f"got {len(key_bytes)}"
        )
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key_bytes)
    os.chmod(path, 0o600)


def save_public_key(key_bytes: bytes, path: str) -> None:
    """
    Write raw public key bytes to a .bin file.

    Raises ValueError if key_bytes is not the expected length.
    """
    if len(key_bytes) != FALCON_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Public key must be {FALCON_PUBLIC_KEY_BYTES} bytes, "
            f"got {len(key_bytes)}"
        )
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key_bytes)


def load_private_key(path: str) -> bytes:
    """
    Load raw private key bytes from a .bin file.

    Returns:
        2528 raw bytes

    Raises:
        FileNotFoundError : if the file does not exist
        ValueError        : if the file length is wrong
    """
    with open(path, "rb") as f:
        key_bytes = f.read()
    if len(key_bytes) != FALCON_PRIVATE_KEY_BYTES:
        raise ValueError(
            f"Private key file {path!r} contains {len(key_bytes)} bytes, "
            f"expected {FALCON_PRIVATE_KEY_BYTES}. File may be corrupt."
        )
    return key_bytes


def load_public_key(path: str) -> bytes:
    """
    Load raw public key bytes from a .bin file.

    Returns:
        1312 raw bytes

    Raises:
        FileNotFoundError : if the file does not exist
        ValueError        : if the file length is wrong
    """
    with open(path, "rb") as f:
        key_bytes = f.read()
    if len(key_bytes) != FALCON_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Public key file {path!r} contains {len(key_bytes)} bytes, "
            f"expected {FALCON_PUBLIC_KEY_BYTES}. File may be corrupt."
        )
    return key_bytes


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign_payload(payload_bytes: bytes, private_key_bytes: bytes) -> bytes:
    """
    Sign payload_bytes using Falcon.

    Args:
        payload_bytes    : The raw bytes of the serialised ticket payload JSON.
        private_key_bytes: 2528-byte Falcon private key.

    Returns:
        2420-byte raw Falcon signature.

    Raises:
        ValueError : if private_key_bytes is the wrong length.
        RuntimeError : if the liboqs signing operation fails.

    Note:
        In the real system this function is never called directly — the HSM
        handles signing via PKCS#11 and the private key bytes are never
        accessible to application code. In this demo the private key is loaded
        from disk and passed in, simulating the HSM signing API.
    """
    if len(private_key_bytes) != FALCON_PRIVATE_KEY_BYTES:
        raise ValueError(
            f"Private key must be {FALCON_PRIVATE_KEY_BYTES} bytes, "
            f"got {len(private_key_bytes)}"
        )

    try:
        with oqs.Signature(ALGORITHM, secret_key=private_key_bytes) as signer:
            sig_bytes = signer.sign(payload_bytes)
    except Exception as exc:
        raise RuntimeError(f"Falcon signing failed: {exc}") from exc

    if len(sig_bytes) != FALCON_SIGNATURE_BYTES:
        raise RuntimeError(
            f"Falcon produced signature of {len(sig_bytes)} bytes, "
            f"expected {FALCON_SIGNATURE_BYTES}. This is a bug."
        )

    return sig_bytes


def verify_signature(
    payload_bytes: bytes,
    sig_bytes: bytes,
    public_key_bytes: bytes,
) -> bool:
    """
    Verify a Falcon signature against payload_bytes.

    Args:
        payload_bytes   : The raw bytes that were originally signed.
        sig_bytes       : 2420-byte Falcon signature to verify.
        public_key_bytes: 1312-byte Falcon public key.

    Returns:
        True if the signature is valid, False for any other reason
        (wrong key, tampered payload, tampered signature, wrong lengths,
        malformed input, library error — everything returns False).

    This function never raises. All exceptions are caught and return False.
    This is intentional: the HHT app treats any non-True result as FORGED.
    """
    try:
        if len(public_key_bytes) != FALCON_PUBLIC_KEY_BYTES:
            return False
        if len(sig_bytes) != FALCON_SIGNATURE_BYTES:
            return False
        if not payload_bytes:
            return False

        with oqs.Signature(ALGORITHM) as verifier:
            return verifier.verify(payload_bytes, sig_bytes, public_key_bytes)

    except Exception:
        return False


# ---------------------------------------------------------------------------
# Identity hash
# ---------------------------------------------------------------------------

def compute_identity_hash(aadhaar: str, dob: str) -> str:
    """
    Compute the one-way identity hash stored in each pax entry.

    Formula: SHA256(aadhaar.strip() + "|" + dob)

    The pipe separator is mandatory. Without it:
        aadhaar="123456", dob="789"  →  concat "123456789"
        aadhaar="1234567", dob="89" →  concat "123456789"
    These two distinct passengers would produce the same hash.
    The separator makes the input to SHA256 unambiguously partitioned.

    Args:
        aadhaar : 12-digit Aadhaar number as a string. Leading/trailing
                  whitespace is stripped. Hyphens or spaces within the
                  number are NOT stripped — callers must normalise first.
        dob     : Date of birth in YYYY-MM-DD format.

    Returns:
        Lowercase hex SHA256 digest string (64 characters).
    """
    raw = aadhaar.strip() + "|" + dob
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Key fingerprint
# ---------------------------------------------------------------------------

def get_public_key_fingerprint(public_key_bytes: bytes) -> str:
    """
    Produce a short human-readable fingerprint of a public key.

    Used for logging and display — not for cryptographic purposes.

    Returns:
        First 16 hex characters of the SHA256 digest of the key bytes.
        Example: "a3f2e1c9d2b4f5e6"
    """
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]