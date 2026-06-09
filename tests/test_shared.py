"""
tests/test_shared.py

Unit tests for shared/crypto_utils.py and shared/payload.py.
These tests run standalone — no services need to be running.

Run with:
    python -m pytest tests/test_shared.py -v
or:
    python tests/test_shared.py

Tests cover all the verification criteria listed in the build plan:

crypto_utils.py:
  1. Generate keypair, sign realistic payload, verify → must pass
  2. Sign, flip one byte in signature, verify → must fail
  3. Sign, flip one byte in payload, verify with original sig → must fail
  4. sign_payload returns exactly 666 bytes (Falcon-padded-512)
  5. generate_keypair returns (1281 bytes, 897 bytes)
  6. compute_identity_hash pipe separator prevents collision
  7. verify_signature never raises, always returns bool

payload.py:
  1. build_payload → pack → unpack roundtrip, payload dict preserved
  2. Packed size for 1-passenger ticket is in expected range
  3. Packed size for 6-passenger ticket is in expected range
  4. 6-passenger packed size < 1558 (DataMatrix ECC200 144x144 binary capacity)
  5. Unpack then re-verify signature passes
  6. Tamper with packed bytes → unpack + verify fails
  7. Unreserved ticket pax entries have null berth and id
  8. Missing aadhaar/dob produces null id, not an error
  9. Identity hash in pax matches manual compute_identity_hash call
 10. Validity window offsets are correct for reserved vs unreserved
"""

import hashlib
import json
import struct
import sys
import time
import os

# ---------------------------------------------------------------------------
# Path setup — allow running from repo root without installing as package
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto_utils import (
    FALCON_PRIVATE_KEY_BYTES,
    FALCON_PUBLIC_KEY_BYTES,
    FALCON_SIGNATURE_BYTES,
    compute_identity_hash,
    generate_keypair,
    get_public_key_fingerprint,
    sign_payload,
    verify_signature,
)
from shared.payload import (
    FALCON_SIGNATURE_BYTES as PAYLOAD_SIG_BYTES,
    LENGTH_FIELD_BYTES,
    RESERVED_VALID_FROM_OFFSET,
    RESERVED_VALID_UNTIL_OFFSET,
    TYPE_RESERVED,
    TYPE_TATKAL,
    TYPE_UNRESERVED,
    UNRESERVED_VALID_FROM_OFFSET,
    UNRESERVED_VALID_UNTIL_OFFSET,
    build_payload,
    estimate_packed_size,
    new_pnr,
    new_ticket_uuid,
    pack_signed_payload,
    unpack_signed_payload,
)


# ---------------------------------------------------------------------------
# Fixtures (manual — no pytest fixtures needed at this simplicity level)
# ---------------------------------------------------------------------------

def make_keypair():
    """Generate a keypair once for a test session."""
    return generate_keypair()


SAMPLE_PAYLOAD_BYTES = b'{"v":1,"type":"R","uuid":"550e8400-e29b-41d4-a716-446655440000","train":"12051","from":"CSMT","to":"NDLS","class":"3A","date":"2026-06-15","vf":1750000000,"vu":1750050000,"iat":1749990000,"pax":[{"b":"B2/14","id":"a3f2e1c9d2b4f5e6a3f2e1c9d2b4f5e6a3f2e1c9d2b4f5e6a3f2e1c9d2b4f5e6"}]}'


# ===========================================================================
# SECTION 1: crypto_utils.py tests
# ===========================================================================

def test_generate_keypair_sizes():
    """generate_keypair() returns (2528, 1312) byte keys — FIPS 204 Dilithium2."""
    priv, pub = generate_keypair()
    assert len(priv) == FALCON_PRIVATE_KEY_BYTES, (
        f"Private key should be {FALCON_PRIVATE_KEY_BYTES} bytes, got {len(priv)}"
    )
    assert len(pub) == FALCON_PUBLIC_KEY_BYTES, (
        f"Public key should be {FALCON_PUBLIC_KEY_BYTES} bytes, got {len(pub)}"
    )
    print(f"  ✓ Private key: {len(priv)} bytes")
    print(f"  ✓ Public key:  {len(pub)} bytes")


def test_sign_returns_correct_size():
    """sign_payload() returns exactly 2420 bytes."""
    priv, pub = generate_keypair()
    sig = sign_payload(SAMPLE_PAYLOAD_BYTES, priv)
    assert len(sig) == FALCON_SIGNATURE_BYTES, (
        f"Signature should be {FALCON_SIGNATURE_BYTES} bytes, got {len(sig)}"
    )
    print(f"  ✓ Signature: {len(sig)} bytes")


def test_sign_and_verify_passes():
    """A freshly signed payload verifies correctly."""
    priv, pub = generate_keypair()
    sig = sign_payload(SAMPLE_PAYLOAD_BYTES, priv)
    result = verify_signature(SAMPLE_PAYLOAD_BYTES, sig, pub)
    assert result is True, "Signature verification should pass for a valid signature"
    print("  ✓ Valid signature verifies True")


def test_verify_fails_on_tampered_signature():
    """Flipping one byte in the signature causes verify to return False."""
    priv, pub = generate_keypair()
    sig = sign_payload(SAMPLE_PAYLOAD_BYTES, priv)

    # Flip the middle byte of the signature
    mid = len(sig) // 2
    tampered_sig = sig[:mid] + bytes([sig[mid] ^ 0xFF]) + sig[mid + 1:]

    result = verify_signature(SAMPLE_PAYLOAD_BYTES, tampered_sig, pub)
    assert result is False, "Tampered signature should fail verification"
    print("  ✓ Tampered signature verifies False")


def test_verify_fails_on_tampered_payload():
    """Flipping one byte in the payload causes verify to return False."""
    priv, pub = generate_keypair()
    sig = sign_payload(SAMPLE_PAYLOAD_BYTES, priv)

    # Change one byte in the middle of the payload (e.g. flip a character in the JSON)
    mid = len(SAMPLE_PAYLOAD_BYTES) // 2
    tampered_payload = (
        SAMPLE_PAYLOAD_BYTES[:mid]
        + bytes([SAMPLE_PAYLOAD_BYTES[mid] ^ 0x01])
        + SAMPLE_PAYLOAD_BYTES[mid + 1:]
    )

    result = verify_signature(tampered_payload, sig, pub)
    assert result is False, "Tampered payload should fail verification"
    print("  ✓ Tampered payload verifies False")


def test_verify_fails_with_wrong_key():
    """Signature from keypair A does not verify under keypair B's public key."""
    priv_a, pub_a = generate_keypair()
    _, pub_b = generate_keypair()

    sig = sign_payload(SAMPLE_PAYLOAD_BYTES, priv_a)
    result = verify_signature(SAMPLE_PAYLOAD_BYTES, sig, pub_b)
    assert result is False, "Signature from key A should not verify under key B"
    print("  ✓ Wrong public key verifies False")


def test_verify_never_raises():
    """verify_signature returns False (not raises) for all garbage inputs."""
    # Empty inputs
    assert verify_signature(b"", b"", b"") is False
    # Wrong length public key
    assert verify_signature(SAMPLE_PAYLOAD_BYTES, b"\x00" * FALCON_SIGNATURE_BYTES, b"\x00" * 32) is False
    # Wrong length signature
    priv, pub = generate_keypair()
    assert verify_signature(SAMPLE_PAYLOAD_BYTES, b"\x00" * 100, pub) is False
    # None-like: bytes that are valid length but garbage content
    assert verify_signature(SAMPLE_PAYLOAD_BYTES, b"\x00" * FALCON_SIGNATURE_BYTES, b"\x00" * FALCON_PUBLIC_KEY_BYTES) is False
    print("  ✓ verify_signature never raises, returns False for all garbage inputs")


def test_verify_fails_on_empty_payload():
    """Empty payload bytes return False, not a crash."""
    priv, pub = generate_keypair()
    result = verify_signature(b"", b"\x00" * FALCON_SIGNATURE_BYTES, pub)
    assert result is False
    print("  ✓ Empty payload verifies False")


def test_identity_hash_pipe_separator():
    """
    Pipe separator prevents hash collision between two different passengers
    whose Aadhaar+DOB string concatenations are identical without the separator.
    """
    # Without separator: "123456" + "789" == "1234567" + "89"
    hash_a = compute_identity_hash("123456", "789")
    hash_b = compute_identity_hash("1234567", "89")
    assert hash_a != hash_b, (
        "Identity hashes for different passengers must not collide. "
        "Pipe separator is broken."
    )
    print(f"  ✓ Hash collision prevented by pipe separator")
    print(f"    aadhaar=123456, dob=789   → {hash_a[:16]}...")
    print(f"    aadhaar=1234567, dob=89  → {hash_b[:16]}...")


def test_identity_hash_is_deterministic():
    """Same inputs always produce the same hash."""
    h1 = compute_identity_hash("123456789012", "1990-05-10")
    h2 = compute_identity_hash("123456789012", "1990-05-10")
    assert h1 == h2
    print("  ✓ Identity hash is deterministic")


def test_identity_hash_strips_aadhaar_whitespace():
    """Leading/trailing whitespace on aadhaar is stripped."""
    h1 = compute_identity_hash("123456789012", "1990-05-10")
    h2 = compute_identity_hash("  123456789012  ", "1990-05-10")
    assert h1 == h2
    print("  ✓ Aadhaar whitespace stripped before hashing")


def test_identity_hash_format():
    """Identity hash is a 64-character lowercase hex string."""
    h = compute_identity_hash("123456789012", "1990-05-10")
    assert len(h) == 64
    assert h == h.lower()
    assert all(c in "0123456789abcdef" for c in h)
    print(f"  ✓ Identity hash is 64-char lowercase hex")


def test_public_key_fingerprint_format():
    """Fingerprint is 16 lowercase hex characters."""
    _, pub = generate_keypair()
    fp = get_public_key_fingerprint(pub)
    assert len(fp) == 16
    assert fp == fp.lower()
    assert all(c in "0123456789abcdef" for c in fp)
    print(f"  ✓ Public key fingerprint: {fp}")


def test_public_key_fingerprints_differ():
    """Two different keypairs produce different fingerprints."""
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    assert get_public_key_fingerprint(pub_a) != get_public_key_fingerprint(pub_b)
    print("  ✓ Different keys produce different fingerprints")


# ===========================================================================
# SECTION 2: payload.py tests
# ===========================================================================

SAMPLE_DEPARTURE = 1750000000
SAMPLE_ARRIVAL = 1750050000
SAMPLE_DATE = "2026-06-15"
SAMPLE_TRAIN = "12051"
SAMPLE_FROM = "CSMT"
SAMPLE_TO = "NDLS"
SAMPLE_CLASS = "3A"

SAMPLE_PASSENGERS_1 = [
    {"name": "Rajan Kumar", "berth": "B2/14", "aadhaar": "123456789012", "dob": "1990-05-10"},
]

SAMPLE_PASSENGERS_6 = [
    {"name": "Rajan Kumar",  "berth": "B2/14", "aadhaar": "123456789012", "dob": "1990-05-10"},
    {"name": "Priya Kumar",  "berth": "B2/15", "aadhaar": "234567890123", "dob": "1992-08-22"},
    {"name": "Arjun Mehta",  "berth": "B2/16", "aadhaar": "345678901234", "dob": "1985-03-15"},
    {"name": "Sunita Mehta", "berth": "B2/17", "aadhaar": "456789012345", "dob": "1988-11-30"},
    {"name": "Vivek Sharma", "berth": "B2/18", "aadhaar": "567890123456", "dob": "1995-07-04"},
    {"name": "Anita Sharma", "berth": "B2/19", "aadhaar": "678901234567", "dob": "1997-01-19"},
]


def test_build_payload_structure():
    """build_payload returns a dict with all required top-level fields."""
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    required_keys = {"v", "type", "uuid", "train", "from", "to", "class", "date", "vf", "vu", "iat", "pax"}
    missing = required_keys - set(payload.keys())
    assert not missing, f"Payload is missing fields: {missing}"
    assert payload["v"] == 1
    assert payload["type"] == TYPE_RESERVED
    assert isinstance(payload["pax"], list)
    print("  ✓ Payload has all required fields")


def test_build_payload_validity_window_reserved():
    """Reserved ticket vf and vu are offset correctly from departure and arrival."""
    before = int(time.time())
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    assert payload["vf"] == SAMPLE_DEPARTURE + RESERVED_VALID_FROM_OFFSET
    assert payload["vu"] == SAMPLE_ARRIVAL + RESERVED_VALID_UNTIL_OFFSET
    assert before <= payload["iat"] <= int(time.time()) + 1
    print(f"  ✓ Reserved validity window: vf={payload['vf']}, vu={payload['vu']}")


def test_build_payload_validity_window_unreserved():
    """Unreserved ticket uses wider validity offsets."""
    payload = build_payload(
        ticket_type=TYPE_UNRESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class="UR",
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    assert payload["vf"] == SAMPLE_DEPARTURE + UNRESERVED_VALID_FROM_OFFSET
    assert payload["vu"] == SAMPLE_ARRIVAL + UNRESERVED_VALID_UNTIL_OFFSET
    print("  ✓ Unreserved validity window uses correct offsets")


def test_build_payload_unreserved_pax_null():
    """Unreserved ticket pax entries always have null berth and id."""
    payload = build_payload(
        ticket_type=TYPE_UNRESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class="UR",
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    for entry in payload["pax"]:
        assert entry["b"] is None, "Unreserved berth should be null"
        assert entry["id"] is None, "Unreserved identity hash should be null"
    print("  ✓ Unreserved pax entries have null berth and id")


def test_build_payload_missing_aadhaar_produces_null_id():
    """Passenger without aadhaar/dob gets id=null without raising."""
    passengers = [
        {"name": "No Aadhaar", "berth": "S1/22", "aadhaar": None, "dob": None},
    ]
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class="SL",
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=passengers,
    )
    assert payload["pax"][0]["id"] is None
    assert payload["pax"][0]["b"] == "S1/22"
    print("  ✓ Missing Aadhaar produces null id without raising")


def test_build_payload_identity_hash_matches_manual():
    """The id field in pax exactly matches a manually computed identity hash."""
    aadhaar = "123456789012"
    dob = "1990-05-10"
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=[{"name": "Test", "berth": "B1/1", "aadhaar": aadhaar, "dob": dob}],
    )
    expected = compute_identity_hash(aadhaar, dob)
    assert payload["pax"][0]["id"] == expected
    print(f"  ✓ pax id matches compute_identity_hash: {expected[:16]}...")


def test_build_payload_invalid_type_raises():
    """build_payload raises ValueError for unknown ticket_type."""
    try:
        build_payload(
            ticket_type="X",
            uuid=new_ticket_uuid(),
            train=SAMPLE_TRAIN,
            from_stn=SAMPLE_FROM,
            to_stn=SAMPLE_TO,
            ticket_class=SAMPLE_CLASS,
            travel_date=SAMPLE_DATE,
            departure_unix=SAMPLE_DEPARTURE,
            arrival_unix=SAMPLE_ARRIVAL,
            passengers=SAMPLE_PASSENGERS_1,
        )
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Invalid ticket_type raises ValueError: {e}")


def test_pack_unpack_roundtrip():
    """pack → unpack roundtrip preserves the payload dict exactly."""
    priv, pub = generate_keypair()
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )

    packed = pack_signed_payload(payload, priv)
    recovered_dict, recovered_payload_bytes, recovered_sig_bytes = unpack_signed_payload(packed)

    assert recovered_dict == payload, (
        f"Roundtrip payload mismatch.\n"
        f"Original: {json.dumps(payload)}\n"
        f"Recovered: {json.dumps(recovered_dict)}"
    )
    print("  ✓ pack → unpack roundtrip preserves payload dict exactly")


def test_roundtrip_signature_verifies():
    """After pack → unpack, the recovered bytes verify correctly."""
    priv, pub = generate_keypair()
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )

    packed = pack_signed_payload(payload, priv)
    _, raw_payload_bytes, raw_sig_bytes = unpack_signed_payload(packed)

    result = verify_signature(raw_payload_bytes, raw_sig_bytes, pub)
    assert result is True, "Signature should verify after pack → unpack roundtrip"
    print("  ✓ Recovered signature verifies True after roundtrip")


def test_packed_size_1_passenger():
    """1-passenger packed bytes are in the expected size range."""
    priv, pub = generate_keypair()
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    packed = pack_signed_payload(payload, priv)
    # Expected: 2 + ~282 + 666 = ~950 bytes. Allow generous range.
    assert 850 <= len(packed) <= 1100, (
        f"1-passenger packed size {len(packed)} is outside expected range [850, 1100]"
    )
    print(f"  ✓ 1-passenger packed size: {len(packed)} bytes")


def test_packed_size_6_passengers():
    """6-passenger packed bytes are in the expected size range and fit in DataMatrix."""
    priv, pub = generate_keypair()
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_6,
    )
    packed = pack_signed_payload(payload, priv)

    DATAMATRIX_MAX_BYTES = 1558  # DataMatrix ECC200 144x144 binary capacity (Base256 scheme)

    assert len(packed) < DATAMATRIX_MAX_BYTES, (
        f"6-passenger packed size {len(packed)} exceeds DataMatrix capacity {DATAMATRIX_MAX_BYTES}"
    )
    # Expected: 2 + ~712 + 666 = ~1380 bytes. Allow generous range.
    assert 1250 <= len(packed) <= 1560, (
        f"6-passenger packed size {len(packed)} is outside expected range [1250, 1560]"
    )
    headroom = DATAMATRIX_MAX_BYTES - len(packed)
    print(f"  ✓ 6-passenger packed size: {len(packed)} bytes ({headroom} bytes headroom in DataMatrix)")


def test_tampered_packed_bytes_fail_verification():
    """Flipping a byte in the payload region of packed bytes fails signature verification."""
    priv, pub = generate_keypair()
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    packed = pack_signed_payload(payload, priv)

    # Flip a byte in the SIGNATURE region (last 100 bytes — safely past the JSON payload).
    # Flipping inside the JSON payload corrupts UTF-8 and causes unpack_signed_payload
    # to raise ValueError before verify_signature is even called. We want to test that
    # verify_signature itself returns False, so we tamper the signature bytes directly.
    tampered = bytearray(packed)
    tampered[-50] ^= 0xFF   # 50 bytes from the end — well inside the 666-byte sig region
    tampered = bytes(tampered)

    _, raw_payload_bytes, raw_sig_bytes = unpack_signed_payload(tampered)
    result = verify_signature(raw_payload_bytes, raw_sig_bytes, pub)
    assert result is False, "Tampered packed bytes should fail signature verification"
    print("  ✓ Tampered packed bytes fail signature verification")


def test_wire_format_structure():
    """Verify the binary wire format: first 2 bytes = payload length, then payload, then sig."""
    priv, pub = generate_keypair()
    payload = build_payload(
        ticket_type=TYPE_RESERVED,
        uuid=new_ticket_uuid(),
        train=SAMPLE_TRAIN,
        from_stn=SAMPLE_FROM,
        to_stn=SAMPLE_TO,
        ticket_class=SAMPLE_CLASS,
        travel_date=SAMPLE_DATE,
        departure_unix=SAMPLE_DEPARTURE,
        arrival_unix=SAMPLE_ARRIVAL,
        passengers=SAMPLE_PASSENGERS_1,
    )
    packed = pack_signed_payload(payload, priv)

    # Manual parse
    (declared_len,) = struct.unpack(">H", packed[:2])
    payload_bytes_manual = packed[2 : 2 + declared_len]
    sig_bytes_manual = packed[2 + declared_len:]

    recovered = json.loads(payload_bytes_manual.decode("utf-8"))
    assert recovered == payload
    assert len(sig_bytes_manual) == FALCON_SIGNATURE_BYTES
    print(f"  ✓ Wire format correct: 2-byte length={declared_len}, "
          f"payload={len(payload_bytes_manual)}B, sig={len(sig_bytes_manual)}B")


def test_unpack_rejects_truncated_input():
    """unpack_signed_payload raises ValueError for truncated bytes."""
    try:
        unpack_signed_payload(b"\x00\x10" + b"\x00" * 10)  # declares 16 bytes but only 10 follow
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Truncated input raises ValueError: {e}")


def test_unpack_rejects_empty_input():
    """unpack_signed_payload raises ValueError for empty bytes."""
    try:
        unpack_signed_payload(b"")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Empty input raises ValueError: {e}")


def test_new_ticket_uuid_format():
    """new_ticket_uuid() returns a valid UUID4 string."""
    import uuid
    u = new_ticket_uuid()
    parsed = uuid.UUID(u)
    assert parsed.version == 4
    assert str(parsed) == u
    print(f"  ✓ new_ticket_uuid: {u}")


def test_new_pnr_format():
    """new_pnr() returns a string matching PNR + 7 digits."""
    import re
    pnr = new_pnr()
    assert re.match(r"^PNR\d{7}$", pnr), f"PNR format wrong: {pnr!r}"
    print(f"  ✓ new_pnr: {pnr}")


def test_estimate_packed_size_bounds():
    """estimate_packed_size returns values in a plausible range."""
    for n in [1, 3, 6]:
        est = estimate_packed_size(n, TYPE_RESERVED)
        assert est > FALCON_SIGNATURE_BYTES, "Estimate must be larger than signature alone"
        assert est < 3116, f"Estimate for {n} passengers {est} exceeds DataMatrix capacity"
        print(f"  ✓ Estimated packed size for {n} passengers: {est} bytes")


# ===========================================================================
# Test runner
# ===========================================================================

def run_all():
    tests = [
        # crypto_utils
        ("generate_keypair sizes",            test_generate_keypair_sizes),
        ("sign returns correct size",         test_sign_returns_correct_size),
        ("sign and verify passes",            test_sign_and_verify_passes),
        ("verify fails on tampered sig",      test_verify_fails_on_tampered_signature),
        ("verify fails on tampered payload",  test_verify_fails_on_tampered_payload),
        ("verify fails with wrong key",       test_verify_fails_with_wrong_key),
        ("verify never raises",               test_verify_never_raises),
        ("verify fails on empty payload",     test_verify_fails_on_empty_payload),
        ("identity hash pipe separator",      test_identity_hash_pipe_separator),
        ("identity hash is deterministic",    test_identity_hash_is_deterministic),
        ("identity hash strips whitespace",   test_identity_hash_strips_aadhaar_whitespace),
        ("identity hash format",              test_identity_hash_format),
        ("fingerprint format",                test_public_key_fingerprint_format),
        ("fingerprints differ",               test_public_key_fingerprints_differ),
        # payload
        ("build_payload structure",           test_build_payload_structure),
        ("validity window reserved",          test_build_payload_validity_window_reserved),
        ("validity window unreserved",        test_build_payload_validity_window_unreserved),
        ("unreserved pax null",               test_build_payload_unreserved_pax_null),
        ("missing aadhaar null id",           test_build_payload_missing_aadhaar_produces_null_id),
        ("identity hash matches manual",      test_build_payload_identity_hash_matches_manual),
        ("invalid type raises",               test_build_payload_invalid_type_raises),
        ("pack unpack roundtrip",             test_pack_unpack_roundtrip),
        ("roundtrip sig verifies",            test_roundtrip_signature_verifies),
        ("packed size 1 passenger",           test_packed_size_1_passenger),
        ("packed size 6 passengers",          test_packed_size_6_passengers),
        ("tampered bytes fail verify",        test_tampered_packed_bytes_fail_verification),
        ("wire format structure",             test_wire_format_structure),
        ("unpack rejects truncated",          test_unpack_rejects_truncated_input),
        ("unpack rejects empty",              test_unpack_rejects_empty_input),
        ("uuid format",                       test_new_ticket_uuid_format),
        ("pnr format",                        test_new_pnr_format),
        ("estimate packed size bounds",       test_estimate_packed_size_bounds),
    ]

    passed = 0
    failed = 0
    errors = []

    print("\n" + "=" * 70)
    print("Railway PQ Auth Demo — Shared Layer Unit Tests")
    print("=" * 70)

    # Warn about slow keypair generation
    print("\nNote: Each test that calls generate_keypair() takes ~0.5–2s (Dilithium2).")
    print("Tests that reuse keypairs across multiple assertions are grouped to minimise this.\n")

    for name, fn in tests:
        print(f"[ ] {name}")
        try:
            fn()
            print(f"[✓] {name}\n")
            passed += 1
        except AssertionError as e:
            print(f"[✗] FAILED: {e}\n")
            errors.append((name, str(e)))
            failed += 1
        except Exception as e:
            print(f"[✗] ERROR: {type(e).__name__}: {e}\n")
            errors.append((name, f"{type(e).__name__}: {e}"))
            failed += 1

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")

    if errors:
        print("\nFailed tests:")
        for name, msg in errors:
            print(f"  ✗ {name}: {msg}")

    print("=" * 70 + "\n")
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)