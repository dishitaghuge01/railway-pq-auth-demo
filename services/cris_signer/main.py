"""
services/cris_signer/main.py

CRIS Signing Microservice — Port 8001

Mirrors: CRIS HSM signing API (PKCS#11 endpoint in production)

This is the only service that ever touches private_key.bin.
No other service imports or loads the private key.

In the real system, the private key bytes never leave the HSM. The HSM
exposes a PKCS#11 signing API that receives payload bytes and returns a
signature. The raw key material is physically inaccessible to software.

In this demo, private_key.bin on disk simulates the HSM. The key is loaded
once at startup into process memory and held in app.state. It is never
returned in any HTTP response, never logged, never written anywhere else.

Endpoints
---------
POST /sign          — Sign a ticket payload, return barcode_b64 + uuid + pnr
GET  /public-key    — Return current and previous public keys (base64) + fingerprint
GET  /health        — Liveness check

Flow
----
PRS Booking Service  →  POST /sign  →  CRIS Signer  →  HSM (simulated)
                                           ↓
                                    Returns barcode_b64
                                           ↓
PRS Booking Service generates DataMatrix barcode from decoded bytes
"""

import base64
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Path resolution — allow running from repo root or from this directory
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.config import settings
from shared.crypto_utils import (
    FALCON_PRIVATE_KEY_BYTES,
    FALCON_PUBLIC_KEY_BYTES,
    get_public_key_fingerprint,
    load_private_key,
    load_public_key,
)
from shared.payload import (
    build_payload,
    new_pnr,
    new_ticket_uuid,
    pack_signed_payload,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [cris_signer] %(levelname)s %(message)s",
)
log = logging.getLogger("cris_signer")


# ---------------------------------------------------------------------------
# Lifespan — key loading at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Load keys at startup. Fail hard if private key is missing.
    Keys are stored in app.state and never leave this process.
    """
    private_key_path = os.path.join(settings.KEYS_DIR, "private_key.bin")
    public_key_path = os.path.join(settings.KEYS_DIR, "public_key.bin")
    old_public_key_path = os.path.join(settings.KEYS_DIR, "old_public_key.bin")

    # Private key — mandatory
    if not os.path.exists(private_key_path):
        log.error(
            "Private key not found at %s. "
            "Run 'python scripts/keygen.py' first.",
            private_key_path,
        )
        raise RuntimeError(
            f"Private key not found at {private_key_path!r}. "
            "Run 'python scripts/keygen.py' first."
        )

    try:
        app.state.private_key_bytes = load_private_key(private_key_path)
        log.info("Private key loaded (%d bytes)", len(app.state.private_key_bytes))
    except ValueError as exc:
        log.error("Private key file is corrupt: %s", exc)
        raise RuntimeError(f"Private key file is corrupt: {exc}") from exc

    # Current public key — mandatory (keygen writes both)
    if not os.path.exists(public_key_path):
        log.error("Public key not found at %s.", public_key_path)
        raise RuntimeError(f"Public key not found at {public_key_path!r}.")

    try:
        app.state.public_key_bytes = load_public_key(public_key_path)
        fp = get_public_key_fingerprint(app.state.public_key_bytes)
        log.info("Public key loaded (%d bytes), fingerprint: %s", len(app.state.public_key_bytes), fp)
    except ValueError as exc:
        log.error("Public key file is corrupt: %s", exc)
        raise RuntimeError(f"Public key file is corrupt: {exc}") from exc

    # Previous public key — optional (only present after first rotation)
    app.state.old_public_key_bytes = None
    if os.path.exists(old_public_key_path):
        try:
            app.state.old_public_key_bytes = load_public_key(old_public_key_path)
            old_fp = get_public_key_fingerprint(app.state.old_public_key_bytes)
            log.info("Old public key loaded (%d bytes), fingerprint: %s", len(app.state.old_public_key_bytes), old_fp)
        except ValueError as exc:
            # Corrupt old key is a warning, not a fatal error — current key still works
            log.warning("Old public key file is corrupt and will be ignored: %s", exc)
            app.state.old_public_key_bytes = None

    log.info("CRIS Signer ready. HSM (simulated) loaded.")
    yield

    # Shutdown — zero out key material from memory as best-effort
    if hasattr(app.state, "private_key_bytes") and app.state.private_key_bytes:
        app.state.private_key_bytes = bytes(FALCON_PRIVATE_KEY_BYTES)
    log.info("CRIS Signer shutdown. Key material cleared.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CRIS Signing Service",
    description=(
        "Simulates the CRIS HSM signing microservice. "
        "Signs ticket payloads using CRYSTALS-Falcon (FIPS 204). "
        "This is the only service with access to the private key."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:4173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class PassengerInput(BaseModel):
    """One passenger's booking details."""
    name: str = Field(..., description="Passenger's full name (display only, not in signed payload)")
    berth: Optional[str] = Field(None, description="Berth string e.g. 'B2/14'. Null for unreserved.")
    aadhaar: Optional[str] = Field(None, description="12-digit Aadhaar number. Null if not provided.")
    dob: Optional[str] = Field(None, description="Date of birth in YYYY-MM-DD format. Null if not provided.")

    @field_validator("aadhaar")
    @classmethod
    def validate_aadhaar(cls, v):
        if v is None:
            return v
        stripped = v.strip()
        if not stripped.isdigit() or len(stripped) != 12:
            raise ValueError("Aadhaar must be exactly 12 digits")
        return stripped

    @field_validator("dob")
    @classmethod
    def validate_dob(cls, v):
        if v is None:
            return v
        # Basic format check — YYYY-MM-DD
        parts = v.split("-")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError("Date of birth must be in YYYY-MM-DD format")
        return v


class SignRequest(BaseModel):
    """
    Request body for POST /sign.
    Sent by the PRS Booking Service when a ticket is issued.
    """
    ticket_type: str = Field(
        ...,
        description="Ticket type: 'R' (reserved), 'U' (unreserved), 'T' (Tatkal)",
    )
    train: str = Field(..., description="Train number, e.g. '12051'")
    from_stn: str = Field(..., description="Origin station code, e.g. 'CSMT'")
    to_stn: str = Field(..., description="Destination station code, e.g. 'NDLS'")
    ticket_class: str = Field(..., description="Class code: '1A', '2A', '3A', 'SL', 'UR'")
    travel_date: str = Field(..., description="Journey date in YYYY-MM-DD format")
    departure_unix: int = Field(..., description="Scheduled departure as Unix timestamp")
    arrival_unix: int = Field(..., description="Scheduled arrival as Unix timestamp")
    passengers: list[PassengerInput] = Field(
        ...,
        min_length=1,
        description="List of passengers. At least one required.",
    )

    @field_validator("ticket_type")
    @classmethod
    def validate_ticket_type(cls, v):
        valid = {"R", "U", "T"}
        if v not in valid:
            raise ValueError(f"ticket_type must be one of {valid}, got {v!r}")
        return v

    @field_validator("ticket_class")
    @classmethod
    def validate_ticket_class(cls, v):
        valid = {"1A", "2A", "3A", "SL", "UR"}
        if v not in valid:
            raise ValueError(f"ticket_class must be one of {valid}, got {v!r}")
        return v

    @field_validator("travel_date")
    @classmethod
    def validate_travel_date(cls, v):
        parts = v.split("-")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError("travel_date must be in YYYY-MM-DD format")
        return v

    @field_validator("passengers")
    @classmethod
    def validate_tatkal_aadhaar(cls, v, info):
        # Access ticket_type from already-validated data
        # Pydantic v2: info.data contains previously validated fields
        ticket_type = info.data.get("ticket_type")
        if ticket_type == "T":
            for i, p in enumerate(v):
                if not p.aadhaar or not p.dob:
                    raise ValueError(
                        f"Tatkal tickets require Aadhaar and DOB for all passengers. "
                        f"Passenger {i+1} ({p.name!r}) is missing one or both."
                    )
        return v


class SignResponse(BaseModel):
    """Response from POST /sign."""
    uuid: str = Field(..., description="UUID4 string — canonical ticket identifier")
    pnr: str = Field(..., description="Human-readable booking reference, e.g. 'PNR8472910'")
    barcode_b64: str = Field(
        ...,
        description=(
            "Base64-encoded packed bytes ready for DataMatrix encoding. "
            "Decode to raw bytes, then pass to DataMatrix generator. "
            "Format: [2-byte BE uint16 payload_len][payload JSON][Falcon sig]"
        ),
    )
    packed_size_bytes: int = Field(
        ...,
        description="Byte length of the decoded barcode content. Must be ≤ 3116 for DataMatrix ECC200.",
    )
    payload_preview: dict = Field(
        ...,
        description=(
            "Full payload dict for logging and debugging. "
            "Contains no private key material. "
            "The 'id' fields are SHA256 hashes — not raw Aadhaar numbers."
        ),
    )


class PublicKeyResponse(BaseModel):
    """Response from GET /public-key."""
    current_b64: str = Field(..., description="Base64-encoded current Falcon public key (1312 bytes)")
    previous_b64: Optional[str] = Field(None, description="Base64-encoded previous public key, or null if no rotation has occurred")
    fingerprint_current: str = Field(..., description="First 16 hex chars of SHA256(current public key)")
    fingerprint_previous: Optional[str] = Field(None, description="Fingerprint of previous key, or null")
    key_size_bytes: int = Field(..., description="Public key size in bytes (always 1312 for Falcon)")
    algorithm: str = Field(..., description="Signing algorithm identifier")


class HealthResponse(BaseModel):
    """Response from GET /health."""
    status: str
    hsm_loaded: bool
    algorithm: str
    private_key_size_bytes: int
    public_key_fingerprint: str
    old_key_present: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/sign",
    response_model=SignResponse,
    summary="Sign a ticket payload",
    description=(
        "Called by PRS Booking Service and IRCTC at ticket generation. "
        "Builds the canonical payload, signs it with Falcon via the simulated HSM, "
        "and returns the packed bytes base64-encoded for DataMatrix generation."
    ),
)
async def sign_ticket(request: Request, body: SignRequest) -> SignResponse:
    """
    Core signing endpoint. This is the only place signing happens.

    Steps:
      1. Generate UUID and PNR for this ticket
      2. Build payload dict from request fields
      3. Sign + pack via pack_signed_payload (HSM simulated)
      4. Base64-encode packed bytes for JSON transport
      5. Return uuid, pnr, barcode_b64, size, payload_preview

    The private key never appears in the response. The payload_preview
    contains the pax[].id fields (SHA256 hashes) but not raw Aadhaar numbers.
    """
    private_key_bytes: bytes = request.app.state.private_key_bytes

    # Generate identifiers
    ticket_uuid = new_ticket_uuid()
    ticket_pnr = new_pnr()

    log.info(
        "Signing ticket: uuid=%s pnr=%s type=%s train=%s class=%s date=%s passengers=%d",
        ticket_uuid,
        ticket_pnr,
        body.ticket_type,
        body.train,
        body.ticket_class,
        body.travel_date,
        len(body.passengers),
    )

    # Build payload
    try:
        passengers_dicts = [p.model_dump() for p in body.passengers]
        payload_dict = build_payload(
            ticket_type=body.ticket_type,
            uuid=ticket_uuid,
            train=body.train,
            from_stn=body.from_stn,
            to_stn=body.to_stn,
            ticket_class=body.ticket_class,
            travel_date=body.travel_date,
            departure_unix=body.departure_unix,
            arrival_unix=body.arrival_unix,
            passengers=passengers_dicts,
        )
    except ValueError as exc:
        log.error("Payload construction failed for uuid=%s: %s", ticket_uuid, exc)
        raise HTTPException(status_code=422, detail=f"Payload construction error: {exc}")

    # Sign and pack (simulates HSM PKCS#11 call)
    try:
        packed_bytes = pack_signed_payload(payload_dict, private_key_bytes)
    except (ValueError, RuntimeError) as exc:
        log.error("HSM signing failed for uuid=%s: %s", ticket_uuid, exc)
        raise HTTPException(status_code=500, detail=f"HSM signing failure: {exc}")

    packed_size = len(packed_bytes)
    barcode_b64 = base64.b64encode(packed_bytes).decode("ascii")

    # Warn if approaching DataMatrix capacity (should never happen with realistic tickets)
    datamatrix_max = 3116
    if packed_size > datamatrix_max:
        log.error(
            "CRITICAL: Packed size %d bytes exceeds DataMatrix ECC200 max capacity %d bytes. "
            "uuid=%s passengers=%d",
            packed_size, datamatrix_max, ticket_uuid, len(body.passengers),
        )
        raise HTTPException(
            status_code=500,
            detail=(
                f"Packed payload size {packed_size} bytes exceeds DataMatrix ECC200 "
                f"maximum capacity of {datamatrix_max} bytes. "
                f"Reduce the number of passengers or shorten field values."
            ),
        )

    log.info(
        "Signed successfully: uuid=%s pnr=%s packed_size=%d bytes (DataMatrix capacity: %d bytes, headroom: %d bytes)",
        ticket_uuid,
        ticket_pnr,
        packed_size,
        datamatrix_max,
        datamatrix_max - packed_size,
    )

    return SignResponse(
        uuid=ticket_uuid,
        pnr=ticket_pnr,
        barcode_b64=barcode_b64,
        packed_size_bytes=packed_size,
        payload_preview=payload_dict,
    )


@app.get(
    "/public-key",
    response_model=PublicKeyResponse,
    summary="Get current and previous public keys",
    description=(
        "Returns the Falcon public keys embedded in all HHT, IRCTC, and RailOne apps. "
        "Both the current key and the previous key (if a rotation has occurred) are returned. "
        "HHT apps try current key first, then previous key, for tickets issued around rotation time."
    ),
)
async def get_public_key(request: Request) -> PublicKeyResponse:
    public_key_bytes: bytes = request.app.state.public_key_bytes
    old_public_key_bytes: Optional[bytes] = request.app.state.old_public_key_bytes

    current_b64 = base64.b64encode(public_key_bytes).decode("ascii")
    fp_current = get_public_key_fingerprint(public_key_bytes)

    previous_b64 = None
    fp_previous = None
    if old_public_key_bytes is not None:
        previous_b64 = base64.b64encode(old_public_key_bytes).decode("ascii")
        fp_previous = get_public_key_fingerprint(old_public_key_bytes)

    return PublicKeyResponse(
        current_b64=current_b64,
        previous_b64=previous_b64,
        fingerprint_current=fp_current,
        fingerprint_previous=fp_previous,
        key_size_bytes=len(public_key_bytes),
        algorithm="Falcon-padded-512 (FIPS 206 / FN-DSA, level 1)",
    )


@app.get(
    "/health",
    summary="Service liveness check",
)
async def health(request: Request) -> dict:
    return {
        "status": "ok",
        "service": "cris_signing",
    }


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler.
    Returns a structured error response and logs the full traceback.
    Never exposes private key material or internal stack traces to the client.
    """
    log.exception("Unhandled exception in CRIS signer: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal signing service error. Check server logs."},
    )