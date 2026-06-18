"""
shared/payload.py

Ticket payload construction and binary serialisation for the Railway PQ Auth Demo.

Wire format
-----------
The v1 (ECDSA) implementation used a JWT-inspired text format:

    <base64url(payload_json)>.<base64url(signature)>

This worked because an ECDSA P-256 signature is 71–72 bytes, which after
base64url encoding adds ~96 bytes to the QR payload — acceptable for a QR code.

The Falcon signature is 666 bytes. Base64url-encoding it produces ~3227
bytes for the signature alone. The full JWT-style string would be ~3800 bytes,
which exceeds the 3116-byte binary capacity of a maximum-size DataMatrix ECC200.

Instead, v2 uses a compact binary format:

    [ 2 bytes big-endian uint16 : payload_len ]
    [ payload_len bytes         : UTF-8 JSON  ]
    [ 666 bytes                : Falcon raw signature ]

Total for a 6-passenger ticket: 2 + ~570 + 666 = ~1238 bytes.
DataMatrix ECC200 max capacity: 3116 bytes.
Headroom: ~124 bytes. Fits with margin.

No base64 encoding is applied to the barcode content itself — raw bytes go
directly into the DataMatrix barcode, avoiding the ~33% base64 size penalty.

HTTP transport
--------------
When packed bytes need to travel over JSON HTTP APIs between services, they are
base64-encoded (standard alphabet) with the field name "barcode_b64". This is
only a transport layer concern and is transparent to the barcode/crypto logic.

Database storage
----------------
The issued_tickets.jwt_string column (name kept from v1 for schema compatibility)
stores the base64-encoded packed bytes.
"""

import hashlib
import json
import struct
import time
import uuid as uuid_module
from typing import Optional

from shared.crypto_utils import (
    FALCON_SIGNATURE_BYTES,
    compute_identity_hash,
    sign_payload,
    verify_signature,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAYLOAD_VERSION = 1

# Validity window offsets (seconds)
RESERVED_VALID_FROM_OFFSET = -2 * 3600    # 2 hours before departure
RESERVED_VALID_UNTIL_OFFSET = 4 * 3600    # 4 hours after scheduled arrival
UNRESERVED_VALID_FROM_OFFSET = -1 * 3600  # 1 hour before departure
UNRESERVED_VALID_UNTIL_OFFSET = 6 * 3600  # 6 hours after scheduled arrival

# Ticket type codes
TYPE_RESERVED = "R"
TYPE_UNRESERVED = "U"
TYPE_TATKAL = "T"

VALID_TYPES = {TYPE_RESERVED, TYPE_UNRESERVED, TYPE_TATKAL}

# Length field is a big-endian unsigned 16-bit integer.
# This caps JSON payload at 65535 bytes, which is far beyond any realistic ticket.
LENGTH_STRUCT_FORMAT = ">H"
LENGTH_FIELD_BYTES = 2  # struct.calcsize(">H") == 2


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------

def build_payload(
    ticket_type: str,
    uuid: str,
    train: str,
    from_stn: str,
    to_stn: str,
    ticket_class: str,
    travel_date: str,
    departure_unix: int,
    arrival_unix: int,
    passengers: list[dict],
) -> dict:
    """
    Build the structured ticket payload dict.

    Args:
        ticket_type    : "R" (reserved), "U" (unreserved), or "T" (Tatkal).
        uuid           : UUID4 string for this ticket. Caller generates this.
        train          : Train number string, e.g. "12051".
        from_stn       : Origin station code, e.g. "CSMT".
        to_stn         : Destination station code, e.g. "NDLS".
        ticket_class   : Class code: "1A", "2A", "3A", "SL", "UR".
        travel_date    : Journey date in "YYYY-MM-DD" format.
        departure_unix : Scheduled departure as Unix timestamp (int).
        arrival_unix   : Scheduled arrival as Unix timestamp (int).
        passengers     : List of passenger dicts. Each dict may contain:
                           "name"    : str  (display only, not in payload)
                           "berth"   : str | None  e.g. "B2/14"
                           "aadhaar" : str | None  12-digit number
                           "dob"     : str | None  "YYYY-MM-DD"

    Returns:
        Payload dict exactly matching the spec schema. Suitable for JSON
        serialisation and signing.

    Raises:
        ValueError : if ticket_type is not one of the three valid codes.

    Payload schema:
        {
          "v":     1,
          "type":  "R" | "U" | "T",
          "uuid":  "<uuid4>",
          "train": "12051",
          "from":  "CSMT",
          "to":    "NDLS",
          "class": "3A",
          "date":  "2026-05-30",
          "vf":    <unix timestamp>,   # valid-from
          "vu":    <unix timestamp>,   # valid-until
          "iat":   <unix timestamp>,   # issued-at
          "pax": [
            { "b": "B2/14", "id": "<sha256 hex | null>" },
            ...
          ]
        }

    Identity hash rules:
        - Computed only if both aadhaar and dob are non-null and non-empty.
        - For unreserved tickets: berth and id are always null.
        - For Sleeper where Aadhaar was not provided: id is null.
        - For Tatkal: Aadhaar is mandatory at booking, so id should always
          be non-null (enforced by the booking service, not here).
    """
    if ticket_type not in VALID_TYPES:
        raise ValueError(
            f"ticket_type must be one of {VALID_TYPES}, got {ticket_type!r}"
        )

    # Validity window
    if ticket_type == TYPE_UNRESERVED:
        vf = departure_unix + UNRESERVED_VALID_FROM_OFFSET
        vu = arrival_unix + UNRESERVED_VALID_UNTIL_OFFSET
    else:
        vf = departure_unix + RESERVED_VALID_FROM_OFFSET
        vu = arrival_unix + RESERVED_VALID_UNTIL_OFFSET

    iat = int(time.time())

    # Build pax array
    pax = []
    for p in passengers:
        if ticket_type == TYPE_UNRESERVED:
            # Unreserved: no berth assignment, no identity binding
            pax.append({"b": None, "id": None})
        else:
            berth = p.get("berth") or None

            aadhaar = p.get("aadhaar")
            dob = p.get("dob")
            if aadhaar and dob:
                identity_hash = compute_identity_hash(str(aadhaar), str(dob))
            else:
                identity_hash = None

            pax.append({"b": berth, "id": identity_hash})

    payload = {
        "v":     PAYLOAD_VERSION,
        "type":  ticket_type,
        "uuid":  uuid,
        "train": train,
        "from":  from_stn,
        "to":    to_stn,
        "class": ticket_class,
        "date":  travel_date,
        "vf":    vf,
        "vu":    vu,
        "iat":   iat,
        "pax":   pax,
    }

    return payload


# ---------------------------------------------------------------------------
# Binary pack / unpack
# ---------------------------------------------------------------------------

def pack_signed_payload(payload_dict: dict, private_key_bytes: bytes) -> bytes:
    """
    Serialise the payload dict, sign it, and pack everything into the binary
    wire format for DataMatrix encoding.

    Wire format:
        Bytes 0–1           : big-endian uint16, length of the JSON payload
        Bytes 2 – 2+len-1   : UTF-8 encoded compact JSON of payload_dict
        Bytes 2+len – end   : raw Falcon signature (666 bytes)

    Args:
        payload_dict      : Dict as returned by build_payload().
        private_key_bytes : 2528-byte Falcon private key.

    Returns:
        Raw bytes ready to be encoded into a DataMatrix barcode.
        For a 6-passenger ticket: approximately 2992 bytes.

    Raises:
        ValueError   : if the JSON payload exceeds 65535 bytes (impossible
                       in practice but checked defensively).
        RuntimeError : if signing fails.

    JSON serialisation note:
        We use separators=(',', ':') to produce compact JSON with no
        whitespace. sort_keys=False preserves field insertion order, which
        matches the spec schema. The payload_bytes produced here are the
        exact bytes that get signed and that the verifier reconstructs —
        they must be byte-for-byte identical on both ends.
    """
    # 1. Compact JSON serialisation
    payload_json = json.dumps(payload_dict, separators=(",", ":"), sort_keys=False)
    payload_bytes = payload_json.encode("utf-8")

    payload_len = len(payload_bytes)
    if payload_len > 65535:
        raise ValueError(
            f"Payload JSON is {payload_len} bytes, exceeds uint16 max (65535). "
            "This should never happen with a real ticket."
        )

    # 2. Sign the payload bytes
    sig_bytes = sign_payload(payload_bytes, private_key_bytes)

    # 3. Pack: [2-byte length][payload bytes][signature bytes]
    length_prefix = struct.pack(LENGTH_STRUCT_FORMAT, payload_len)
    packed = length_prefix + payload_bytes + sig_bytes

    return packed


def unpack_signed_payload(packed_bytes: bytes) -> tuple[dict, bytes, bytes]:
    """
    Parse packed bytes back into (payload_dict, raw_payload_bytes, raw_sig_bytes).

    This is the inverse of pack_signed_payload. The raw_payload_bytes returned
    here are the exact bytes that were signed — pass them directly to
    verify_signature() without any re-serialisation.

    Args:
        packed_bytes : Raw bytes decoded from a DataMatrix barcode.

    Returns:
        (payload_dict, raw_payload_bytes, raw_sig_bytes)

        payload_dict      : Parsed ticket payload as a Python dict.
        raw_payload_bytes : The original UTF-8 JSON bytes (not re-serialised).
        raw_sig_bytes     : 666-byte Falcon signature.

    Raises:
        ValueError : for any structural problem:
                     - packed_bytes too short to contain the length field
                     - declared payload_len would overrun the buffer
                     - remaining bytes after payload are not 666 bytes
                     - payload JSON is not valid UTF-8
                     - payload JSON is not a valid JSON object
    """
    min_bytes = LENGTH_FIELD_BYTES + 1 + FALCON_SIGNATURE_BYTES
    if len(packed_bytes) < min_bytes:
        raise ValueError(
            f"packed_bytes is {len(packed_bytes)} bytes, minimum is {min_bytes}. "
            "Input is too short to be a valid signed payload."
        )

    # 1. Read payload length from the first 2 bytes
    (payload_len,) = struct.unpack(
        LENGTH_STRUCT_FORMAT,
        packed_bytes[:LENGTH_FIELD_BYTES],
    )

    # 2. Validate length makes sense given the total buffer
    expected_total = LENGTH_FIELD_BYTES + payload_len + FALCON_SIGNATURE_BYTES
    if len(packed_bytes) != expected_total:
        raise ValueError(
            f"Length field declares payload of {payload_len} bytes. "
            f"Expected total {expected_total} bytes "
            f"({LENGTH_FIELD_BYTES} + {payload_len} + {FALCON_SIGNATURE_BYTES}), "
            f"but got {len(packed_bytes)} bytes. "
            "Barcode data may be truncated or corrupt."
        )

    # 3. Slice payload bytes
    payload_start = LENGTH_FIELD_BYTES
    payload_end = LENGTH_FIELD_BYTES + payload_len
    raw_payload_bytes = packed_bytes[payload_start:payload_end]

    # 4. Slice signature bytes
    raw_sig_bytes = packed_bytes[payload_end:]

    if len(raw_sig_bytes) != FALCON_SIGNATURE_BYTES:
        # Should be unreachable given the length check above, but be explicit.
        raise ValueError(
            f"Signature is {len(raw_sig_bytes)} bytes, "
            f"expected {FALCON_SIGNATURE_BYTES}."
        )

    # 5. Parse payload JSON
    try:
        payload_json = raw_payload_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Payload bytes are not valid UTF-8: {exc}") from exc

    try:
        payload_dict = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Payload is not valid JSON: {exc}") from exc

    if not isinstance(payload_dict, dict):
        raise ValueError(
            f"Payload JSON must be an object, got {type(payload_dict).__name__}"
        )

    return payload_dict, raw_payload_bytes, raw_sig_bytes


# ---------------------------------------------------------------------------
# Convenience: generate UUID for new tickets
# ---------------------------------------------------------------------------

def new_ticket_uuid() -> str:
    """
    Generate a new UUID4 string for a ticket.
    Centralised here so all services use the same format.
    """
    return str(uuid_module.uuid4())


# ---------------------------------------------------------------------------
# Convenience: generate PNR for new tickets
# ---------------------------------------------------------------------------

def new_pnr() -> str:
    """
    Generate a human-readable PNR string.
    Format: "PNR" followed by 7 random decimal digits.
    Example: "PNR8472910"

    Not cryptographically significant — used as a booking reference only.
    The UUID is the canonical ticket identifier for cryptographic purposes.
    """
    import random
    digits = "".join(str(random.randint(0, 9)) for _ in range(7))
    return f"PNR{digits}"


# ---------------------------------------------------------------------------
# Packed bytes size estimator (for testing and documentation)
# ---------------------------------------------------------------------------

def estimate_packed_size(num_passengers: int, ticket_type: str = TYPE_RESERVED) -> int:
    """
    Estimate the packed byte size for a ticket without actually signing it.

    Useful for capacity planning and unit tests. Based on a realistic
    average JSON payload size per passenger count.

    Returns approximate total bytes. The actual size depends on the lengths
    of station codes, train numbers, and whether identity hashes are present.
    """
    # Rough JSON size per passenger entry (with identity hash):
    #   {"b":"B2/14","id":"<64-char hex>"}  ≈ 87 bytes
    # Without identity hash:
    #   {"b":"B2/14","id":null}             ≈ 24 bytes
    per_pax_with_hash = 87
    per_pax_no_hash = 24

    # Fixed overhead: all non-pax fields ≈ 210 bytes
    base_overhead = 210

    if ticket_type == TYPE_UNRESERVED:
        pax_size = num_passengers * per_pax_no_hash
    else:
        pax_size = num_passengers * per_pax_with_hash

    json_size = base_overhead + pax_size
    return LENGTH_FIELD_BYTES + json_size + FALCON_SIGNATURE_BYTES
