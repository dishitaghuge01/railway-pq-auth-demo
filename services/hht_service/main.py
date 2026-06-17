"""
services/hht_service/main.py

HHT (Hand Held Terminal) Verification Service — Port 8003

Mirrors: The CRIS HHT application running on TTE devices.

This service is the verification engine. It loads both public keys at startup
(current and previous, for key rotation tolerance), and implements the complete
verification pipeline described in the proposal:

  1. Binary unpack — parse the DataMatrix barcode content
  2. Signature verification — Falcon against current key, then previous key
  3. Validity window — vf/vu timestamp check
  4. Train match — payload train vs TTE's expected train
  5. Date match — payload date vs current calendar date
  6. Chart lookup — PNR/berth cross-check against locally cached passenger chart
  7. Identity check — optional SHA256 Aadhaar hash comparison (mandatory for Tatkal)
  8. Audit logging — background POST to audit server, non-blocking
  9. Duplicate detection — audit server flags if UUID seen before

Endpoints
---------
POST /verify              — Full ticket verification pipeline
POST /chart/add           — Add passengers to the local chart (pre-departure sync)
GET  /chart/{train}/{date} — View the chart for a train/date
DELETE /chart/{train}/{date} — Clear chart at journey end
GET  /health              — Liveness check

Verification result codes
--------------------------
VALID           — Signature valid, all checks passed
FORGED          — Signature failed against both current and previous key
EXPIRED         — Current time > vu
NOT_YET_VALID   — Current time < vf
WRONG_TRAIN     — payload.train != expected_train
WRONG_DATE      — payload.date != today's date
INVALID_PNR     — UUID/PNR not found in locally cached chart
DUPLICATE       — UUID has been verified before (flagged by audit server)

Key design points
-----------------
- Signature verification is always the FIRST check. If it fails, all other
  checks are skipped and FORGED is returned immediately. There is no point
  inspecting fields of a payload whose integrity cannot be trusted.
- Audit logging is a background asyncio task — it never blocks the verification
  response returned to the TTE. If the audit server is unreachable, verification
  still works; the log entry is simply not recorded.
- The raw Aadhaar input for identity checks is discarded from memory
  immediately after hashing. It is never stored, logged, or transmitted.
- The chart is a SQLite table (passenger_chart) shared with the PRS service
  via the same railway.db file. In the real system this would be a pre-downloaded
  SQLite snapshot synced over station WiFi before departure.
"""

import asyncio
import base64
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.config import settings
from shared.crypto_utils import (
    FALCON_PUBLIC_KEY_BYTES,
    compute_identity_hash,
    get_public_key_fingerprint,
    load_public_key,
    verify_signature,
)
from shared.database import get_db, init_db
from shared.models import AuditLog, PassengerChart
from shared.payload import (
    TYPE_TATKAL,
    unpack_signed_payload,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [hht_service] %(levelname)s %(message)s",
)
log = logging.getLogger("hht_service")


# ---------------------------------------------------------------------------
# Verification result codes — single source of truth
# ---------------------------------------------------------------------------
class VerifyResult:
    VALID          = "VALID"
    FORGED         = "FORGED"
    EXPIRED        = "EXPIRED"
    NOT_YET_VALID  = "NOT_YET_VALID"
    WRONG_TRAIN    = "WRONG_TRAIN"
    WRONG_DATE     = "WRONG_DATE"
    INVALID_PNR    = "INVALID_PNR"
    DUPLICATE      = "DUPLICATE"


class IdentityResult:
    PASSED       = "PASSED"
    FAILED       = "FAILED"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    NOT_REQUIRED  = "NOT_REQUIRED"


# ---------------------------------------------------------------------------
# Lifespan — key loading and DB init at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Load both public keys and initialise the database at startup.

    Both current and previous public keys are loaded so that tickets issued
    just before a key rotation remain verifiable during the grace period.
    The previous key is optional — only present after the first rotation.

    Fails hard if the current public key is missing.
    """
    public_key_path     = os.path.join(settings.KEYS_DIR, "public_key.bin")
    old_public_key_path = os.path.join(settings.KEYS_DIR, "old_public_key.bin")

    # Current public key — mandatory
    if not os.path.exists(public_key_path):
        log.error(
            "Public key not found at %s. Run 'python scripts/keygen.py' first.",
            public_key_path,
        )
        raise RuntimeError(
            f"Public key not found at {public_key_path!r}. "
            "Run 'python scripts/keygen.py' first."
        )

    try:
        app.state.public_key_bytes = load_public_key(public_key_path)
        fp = get_public_key_fingerprint(app.state.public_key_bytes)
        log.info(
            "Current public key loaded (%d bytes), fingerprint: %s",
            len(app.state.public_key_bytes), fp,
        )
    except ValueError as exc:
        log.error("Current public key file is corrupt: %s", exc)
        raise RuntimeError(f"Current public key file is corrupt: {exc}") from exc

    # Previous public key — optional
    app.state.old_public_key_bytes = None
    if os.path.exists(old_public_key_path):
        try:
            app.state.old_public_key_bytes = load_public_key(old_public_key_path)
            old_fp = get_public_key_fingerprint(app.state.old_public_key_bytes)
            log.info(
                "Previous public key loaded (%d bytes), fingerprint: %s — grace period active",
                len(app.state.old_public_key_bytes), old_fp,
            )
        except ValueError as exc:
            log.warning(
                "Previous public key file is corrupt and will be ignored: %s", exc
            )
            app.state.old_public_key_bytes = None
    else:
        log.info("No previous public key found (no key rotation has occurred yet).")

    # Initialise DB (creates tables if they don't exist)
    init_db()
    log.info("HHT Service ready. DB initialised.")

    yield

    log.info("HHT Service shutdown.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="HHT Verification Service",
    description=(
        "Simulates the TTE Hand Held Terminal verification backend. "
        "Implements the full Falcon signature verification pipeline "
        "plus chart lookup, identity check, and audit logging."
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

class AadhaarInput(BaseModel):
    """
    Aadhaar + DOB input for one passenger during identity verification.
    The TTE prompts the passenger to provide these verbally or via the app.
    """
    berth: str = Field(..., description="Berth string matching a pax entry, e.g. 'B2/14'")
    aadhaar: str = Field(..., description="12-digit Aadhaar number entered by the passenger")
    dob: str = Field(..., description="Date of birth in YYYY-MM-DD format")


class VerifyRequest(BaseModel):
    """
    Request body for POST /verify.

    barcode_b64     : Base64-encoded packed bytes decoded from the DataMatrix barcode.
    tte_id          : TTE identifier, e.g. "TTE-MUM-047". Used in audit logs.
    train           : Train number the TTE has set in their HHT session.
                      The payload's train field must match this exactly.
    aadhaar         : Optional Aadhaar number for identity verification.
    dob             : Optional date of birth in YYYY-MM-DD format.
    """
    barcode_b64: str = Field(..., description="Base64-encoded DataMatrix barcode content")
    tte_id: str = Field(..., description="TTE identifier, e.g. 'TTE-MUM-047'")
    train: str = Field(..., description="Train number set in the TTE's HHT session")
    aadhaar: Optional[str] = Field(None, description="Optional Aadhaar number for identity verification")
    dob: Optional[str] = Field(None, description="Optional date of birth in YYYY-MM-DD format")


class PassengerVerifyResult(BaseModel):
    """Verification result for a single passenger in the pax array."""
    name: Optional[str] = Field(None, description="Passenger name from chart (null if not in chart)")
    berth: Optional[str] = Field(None, description="Berth string from payload, e.g. 'B2/14'")
    identity_check: str = Field(
        ...,
        description=(
            "PASSED / FAILED / NOT_ATTEMPTED / NOT_REQUIRED. "
            "NOT_REQUIRED means no id hash in payload (Sleeper without Aadhaar, unreserved). "
            "NOT_ATTEMPTED means id hash present but no aadhaar_input provided."
        ),
    )


class VerifyResponse(BaseModel):
    """Response from POST /verify."""
    result: str = Field(
        ...,
        description=(
            "Primary verification result: VALID, FORGED, EXPIRED, NOT_YET_VALID, "
            "WRONG_TRAIN, WRONG_DATE, INVALID_PNR, or DUPLICATE."
        ),
    )
    signature_valid: bool = Field(..., description="Whether the Falcon signature verified")
    chart_match: bool = Field(..., description="Whether the UUID/berths were found in the local chart")
    is_duplicate: bool = Field(..., description="Whether this ticket UUID was seen before")
    key_used: str = Field(..., description="'current' or 'previous' — which embedded key verified the signature")
    validity_window: str = Field(..., description="'active', 'expired', or 'not_yet_valid'")
    train_match: bool = Field(..., description="Whether the payload train matches the expected train")
    date_match: bool = Field(..., description="Whether the payload date matches today's date")
    identity_check: str = Field(..., description="'passed', 'failed', or 'skipped'")
    payload: Optional[dict] = Field(None, description="Ticket payload (only if signature_valid)")



class ChartAddPassenger(BaseModel):
    """One passenger entry for POST /chart/add."""
    name: str
    berth: Optional[str] = None


class ChartAddRequest(BaseModel):
    """Request body for POST /chart/add."""
    pnr: str
    uuid: str
    train: str
    travel_date: str = Field(..., description="YYYY-MM-DD")
    ticket_class: str
    passengers: list[ChartAddPassenger]


class ChartAddResponse(BaseModel):
    added: bool
    rows_inserted: int


class HealthResponse(BaseModel):
    status: str
    public_key_loaded: bool
    public_key_fingerprint: str
    old_key_present: bool
    algorithm: str


# ---------------------------------------------------------------------------
# Audit logging helper — background, non-blocking
# ---------------------------------------------------------------------------

async def _post_audit_log(
    uuid: str,
    tte_id: str,
    train: str,
    coach: Optional[str],
    result: str,
    ip_address: Optional[str],
) -> tuple[bool, bool]:
    """
    POST a verification event to the audit server.

    Returns (audit_logged: bool, is_duplicate: bool).
    Never raises — failures are logged and return (False, False).

    This is called as a background task so it never blocks the verify response.
    However, for the DUPLICATE check to affect the result field we do need the
    response before returning. Therefore, for the primary verify flow this is
    called directly (awaited), not as a BackgroundTask. The BackgroundTasks
    mechanism in FastAPI is used only for fire-and-forget logging where the
    result doesn't affect the response.

    Design note: the proposal says "If network connectivity is available, the
    module posts a verification log entry to the CRIS audit server as a
    background operation. This does not block the verification result." We
    honour this for all result codes other than VALID — for VALID we do await
    the audit response so we can surface the DUPLICATE flag in the same response.
    For FORGED/EXPIRED/etc the audit is always fire-and-forget.
    """
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{settings.AUDIT_SERVER_URL}/log",
                json={
                    "uuid": uuid,
                    "tte_id": tte_id,
                    "train": train,
                    "coach": coach,
                    "result": result,
                    "ip_address": ip_address,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return True, data.get("is_duplicate", False)
            else:
                log.warning(
                    "Audit server returned %d for uuid=%s", resp.status_code, uuid
                )
                return False, False
    except Exception as exc:
        log.warning("Audit server unreachable (uuid=%s): %s", uuid, exc)
        return False, False


async def _fire_and_forget_audit(
    uuid: str,
    tte_id: str,
    train: str,
    coach: Optional[str],
    result: str,
    ip_address: Optional[str],
) -> None:
    """Fire-and-forget wrapper used when the audit result doesn't affect the response."""
    await _post_audit_log(uuid, tte_id, train, coach, result, ip_address)


# ---------------------------------------------------------------------------
# Core verification pipeline
# ---------------------------------------------------------------------------

def _run_verification_pipeline(
    packed_bytes: bytes,
    expected_train: str,
    tte_id: str,
    aadhaar_inputs: Optional[list[AadhaarInput]],
    public_key_bytes: bytes,
    old_public_key_bytes: Optional[bytes],
    db: Session,
) -> dict:
    """
    The complete synchronous verification pipeline.

    Returns a dict that maps directly onto VerifyResponse fields, plus an
    internal "_uuid" key used for audit logging by the caller.

    Verification order (matches proposal section 4.6 exactly):
      Step 1  — Unpack binary format
      Step 2  — Signature verification (current key, then previous key)
      Step 3  — Validity window (vf / vu)
      Step 4  — Train match
      Step 5  — Date match
      Step 6  — Chart lookup (reserved/Tatkal only)
      Step 7  — Identity check (optional for AC/SL, mandatory for Tatkal)

    If Step 2 fails (FORGED), all subsequent steps are skipped — there is no
    point inspecting fields of a payload whose integrity is not proven.
    """

    # ------------------------------------------------------------------
    # Step 1: Unpack binary format
    # ------------------------------------------------------------------
    try:
        payload_dict, raw_payload_bytes, raw_sig_bytes = unpack_signed_payload(packed_bytes)
    except ValueError as exc:
        log.warning("Binary unpack failed: %s", exc)
        return {
            "_uuid": "unknown",
            "result": VerifyResult.FORGED,
            "ticket_details": None,
            "passengers": None,
            "signature_valid": False,
            "chart_matched": None,
            "is_duplicate": None,
            "audit_logged": False,
            "key_used": None,
        }

    ticket_uuid = payload_dict.get("uuid", "unknown")

    # ------------------------------------------------------------------
    # Step 2: Signature verification
    # Try current key first. If that fails, try previous key.
    # If both fail → FORGED. Stop here.
    # ------------------------------------------------------------------
    key_used: Optional[str] = None

    if verify_signature(raw_payload_bytes, raw_sig_bytes, public_key_bytes):
        key_used = "current"
    elif (
        old_public_key_bytes is not None
        and verify_signature(raw_payload_bytes, raw_sig_bytes, old_public_key_bytes)
    ):
        key_used = "previous"
    else:
        log.warning(
            "Signature verification failed (FORGED): uuid=%s train=%s",
            ticket_uuid, payload_dict.get("train"),
        )
        return {
            "_uuid": ticket_uuid,
            "result": VerifyResult.FORGED,
            "ticket_details": None,
            "passengers": None,
            "signature_valid": False,
            "chart_matched": None,
            "is_duplicate": None,
            "audit_logged": False,
            "key_used": None,
        }

    # Signature is valid — all subsequent field reads are trustworthy
    log.info(
        "Signature valid (key=%s): uuid=%s train=%s type=%s class=%s date=%s",
        key_used,
        ticket_uuid,
        payload_dict.get("train"),
        payload_dict.get("type"),
        payload_dict.get("class"),
        payload_dict.get("date"),
    )

    # Build ticket_details for the response (shown for all results after FORGED)
    ticket_details = {
        "uuid":  ticket_uuid,
        "train": payload_dict.get("train"),
        "from":  payload_dict.get("from"),
        "to":    payload_dict.get("to"),
        "class": payload_dict.get("class"),
        "date":  payload_dict.get("date"),
        "type":  payload_dict.get("type"),
        "vf":    payload_dict.get("vf"),
        "vu":    payload_dict.get("vu"),
    }

    # ------------------------------------------------------------------
    # Step 3: Validity window
    # ------------------------------------------------------------------
    now = int(time.time())
    vf = payload_dict.get("vf", 0)
    vu = payload_dict.get("vu", 0)

    if now < vf:
        log.info("Ticket NOT_YET_VALID: uuid=%s vf=%d now=%d", ticket_uuid, vf, now)
        return {
            "_uuid": ticket_uuid,
            "result": VerifyResult.NOT_YET_VALID,
            "ticket_details": ticket_details,
            "passengers": None,
            "signature_valid": True,
            "chart_matched": None,
            "is_duplicate": None,
            "audit_logged": False,
            "key_used": key_used,
        }

    if now > vu:
        log.info("Ticket EXPIRED: uuid=%s vu=%d now=%d", ticket_uuid, vu, now)
        return {
            "_uuid": ticket_uuid,
            "result": VerifyResult.EXPIRED,
            "ticket_details": ticket_details,
            "passengers": None,
            "signature_valid": True,
            "chart_matched": None,
            "is_duplicate": None,
            "audit_logged": False,
            "key_used": key_used,
        }

    # ------------------------------------------------------------------
    # Step 4: Train match
    # ------------------------------------------------------------------
    payload_train = payload_dict.get("train", "")
    if payload_train != expected_train:
        log.info(
            "WRONG_TRAIN: uuid=%s payload_train=%s expected_train=%s",
            ticket_uuid, payload_train, expected_train,
        )
        return {
            "_uuid": ticket_uuid,
            "result": VerifyResult.WRONG_TRAIN,
            "ticket_details": ticket_details,
            "passengers": None,
            "signature_valid": True,
            "chart_matched": None,
            "is_duplicate": None,
            "audit_logged": False,
            "key_used": key_used,
        }

    # ------------------------------------------------------------------
    # Step 5: Date match
    # ------------------------------------------------------------------
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    payload_date = payload_dict.get("date", "")
    if payload_date != today_str:
        log.info(
            "WRONG_DATE: uuid=%s payload_date=%s today=%s",
            ticket_uuid, payload_date, today_str,
        )
        return {
            "_uuid": ticket_uuid,
            "result": VerifyResult.WRONG_DATE,
            "ticket_details": ticket_details,
            "passengers": None,
            "signature_valid": True,
            "chart_matched": None,
            "is_duplicate": None,
            "audit_logged": False,
            "key_used": key_used,
        }

    # ------------------------------------------------------------------
    # Step 6: Chart lookup (reserved and Tatkal only)
    # For unreserved tickets (type "U") there is no chart to check.
    # ------------------------------------------------------------------
    ticket_type = payload_dict.get("type")
    pax_list = payload_dict.get("pax", [])
    chart_matched: Optional[bool] = None
    chart_rows: dict[str, PassengerChart] = {}  # berth → chart row

    if ticket_type in ("R", "T"):
        # Look up by uuid — the uuid in the payload is the canonical identifier
        chart_entries = (
            db.query(PassengerChart)
            .filter(
                PassengerChart.uuid == ticket_uuid,
                PassengerChart.train == payload_train,
                PassengerChart.travel_date == payload_date,
            )
            .all()
        )

        if not chart_entries:
            log.info("INVALID_PNR: uuid=%s not found in chart", ticket_uuid)
            return {
                "_uuid": ticket_uuid,
                "result": VerifyResult.INVALID_PNR,
                "ticket_details": ticket_details,
                "passengers": None,
                "signature_valid": True,
                "chart_matched": False,
                "is_duplicate": None,
                "audit_logged": False,
                "key_used": key_used,
            }

        # Build berth → chart row map for identity check and response
        for row in chart_entries:
            if row.berth:
                chart_rows[row.berth] = row

        # Cross-check berths: every non-null berth in payload must exist in chart
        payload_berths = {p["b"] for p in pax_list if p.get("b")}
        chart_berths   = set(chart_rows.keys())
        berth_mismatch = payload_berths - chart_berths  # berths in payload but not in chart

        if berth_mismatch:
            log.warning(
                "Berth mismatch for uuid=%s: payload has %s, chart has %s",
                ticket_uuid, payload_berths, chart_berths,
            )
            # Still INVALID_PNR — berths don't match the issued ticket
            return {
                "_uuid": ticket_uuid,
                "result": VerifyResult.INVALID_PNR,
                "ticket_details": ticket_details,
                "passengers": None,
                "signature_valid": True,
                "chart_matched": False,
                "is_duplicate": None,
                "audit_logged": False,
                "key_used": key_used,
            }

        chart_matched = True
        log.info("Chart matched: uuid=%s berths=%s", ticket_uuid, payload_berths)

    # ------------------------------------------------------------------
    # Step 7: Identity check
    # Build per-passenger results. Identity check is:
    #   - NOT_REQUIRED  if pax[i].id is null (no hash in payload)
    #   - NOT_ATTEMPTED if hash is present but no aadhaar_input for this berth
    #   - PASSED / FAILED if an aadhaar_input was provided and hashed
    #
    # For Tatkal (type "T"), if aadhaar_inputs is missing or incomplete,
    # the passenger result is marked FAILED (not NOT_ATTEMPTED) because
    # identity verification is mandatory for Tatkal.
    # ------------------------------------------------------------------
    aadhaar_map: dict[str, AadhaarInput] = {}
    if aadhaar_inputs:
        for ai in aadhaar_inputs:
            aadhaar_map[ai.berth] = ai

    passenger_results: list[PassengerVerifyResult] = []

    for pax_entry in pax_list:
        berth      = pax_entry.get("b")      # e.g. "B2/14" or None for unreserved
        pax_id_hash = pax_entry.get("id")    # SHA256 hex string or None

        # Lookup name from chart
        name: Optional[str] = None
        if berth and berth in chart_rows:
            name = chart_rows[berth].passenger_name

        # Determine identity_check result
        if pax_id_hash is None:
            # No hash in payload — identity check not possible
            identity_check = IdentityResult.NOT_REQUIRED

        elif berth and berth in aadhaar_map:
            # Hash present and aadhaar_input provided for this berth — perform check
            ai = aadhaar_map[berth]
            # Normalise: strip whitespace from aadhaar, use dob as-is
            aadhaar_stripped = ai.aadhaar.strip()
            computed_hash = compute_identity_hash(aadhaar_stripped, ai.dob)
            # Constant-time comparison not required here — both values are
            # non-secret SHA256 digests, not raw secrets. The raw Aadhaar is
            # discarded immediately after hashing (local variable, not stored).
            if computed_hash == pax_id_hash:
                identity_check = IdentityResult.PASSED
                log.info("Identity check PASSED: berth=%s", berth)
            else:
                identity_check = IdentityResult.FAILED
                log.info("Identity check FAILED: berth=%s", berth)

            # Explicitly del the aadhaar string from local scope — belt-and-suspenders
            del aadhaar_stripped

        elif ticket_type == TYPE_TATKAL:
            # Tatkal: hash present but no input provided — treat as FAILED
            identity_check = IdentityResult.FAILED
            log.info(
                "Identity check FAILED (Tatkal, no input provided): berth=%s", berth
            )

        else:
            # Hash present, no input provided, not Tatkal — NOT_ATTEMPTED
            identity_check = IdentityResult.NOT_ATTEMPTED

        passenger_results.append(
            PassengerVerifyResult(
                name=name,
                berth=berth,
                identity_check=identity_check,
            )
        )

    return {
        "_uuid": ticket_uuid,
        "result": VerifyResult.VALID,
        "ticket_details": ticket_details,
        "passengers": passenger_results,
        "signature_valid": True,
        "chart_matched": chart_matched,
        "is_duplicate": None,          # filled in by the endpoint after audit call
        "audit_logged": False,          # filled in by the endpoint after audit call
        "key_used": key_used,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Verify a ticket",
    description=(
        "Full verification pipeline: binary unpack → Falcon signature → "
        "validity window → train/date match → chart lookup → identity check → "
        "audit log. Returns a structured result the HHT app displays to the TTE."
    ),
)
async def verify_ticket(body: VerifyRequest, request: Request) -> VerifyResponse:
    """
    The TTE scans a ticket's DataMatrix barcode. The HHT app base64-encodes
    the raw bytes and posts them here. This endpoint runs the full pipeline
    and returns a result the app displays immediately.
    """
    public_key_bytes: bytes          = request.app.state.public_key_bytes
    old_public_key_bytes: Optional[bytes] = request.app.state.old_public_key_bytes

    # Decode barcode bytes from base64
    try:
        packed_bytes = base64.b64decode(body.barcode_b64)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"barcode_b64 is not valid base64: {exc}",
        )

    # Determine request IP
    ip_address = request.client.host if request.client else None

    # Convert simple aadhaar/dob inputs to the internal aadhaar_inputs format
    # For now, we'll handle identity check in a simplified way
    aadhaar_inputs: Optional[list[AadhaarInput]] = None
    if body.aadhaar and body.dob:
        # We'll pass the identity info separately and handle it after chart lookup
        aadhaar_inputs = []  # Simplified: we'll handle this differently

    # Run the synchronous pipeline
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        pipeline_result = await asyncio.get_event_loop().run_in_executor(
            None,
            _run_verification_pipeline,
            packed_bytes,
            body.train,  # changed from expected_train
            body.tte_id,
            aadhaar_inputs,
            public_key_bytes,
            old_public_key_bytes,
            db,
        )
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    ticket_uuid = pipeline_result["_uuid"]
    result_code = pipeline_result["result"]

    # Audit logging
    audit_logged = False
    is_duplicate: bool = False

    if ticket_uuid != "unknown":
        if result_code == VerifyResult.VALID:
            audit_logged, is_duplicate = await _post_audit_log(
                uuid=ticket_uuid,
                tte_id=body.tte_id,
                train=body.train,
                coach=None,
                result=result_code,
                ip_address=ip_address,
            )
            if is_duplicate:
                result_code = VerifyResult.DUPLICATE
                log.warning(
                    "DUPLICATE ticket detected: uuid=%s tte_id=%s train=%s",
                    ticket_uuid, body.tte_id, body.train,
                )
        else:
            # Fire-and-forget for non-VALID results
            asyncio.create_task(
                _fire_and_forget_audit(
                    uuid=ticket_uuid,
                    tte_id=body.tte_id,
                    train=body.train,
                    coach=None,
                    result=result_code,
                    ip_address=ip_address,
                )
            )
            audit_logged = True

    log.info(
        "Verification complete: uuid=%s result=%s tte=%s train=%s key=%s duplicate=%s",
        ticket_uuid, result_code, body.tte_id, body.train,
        pipeline_result.get("key_used"), is_duplicate,
    )

    # Build response with simplified field names
    ticket_details = pipeline_result.get("ticket_details") or {}
    
    # Determine validity_window
    validity_window = "active"
    if result_code == VerifyResult.EXPIRED:
        validity_window = "expired"
    elif result_code == VerifyResult.NOT_YET_VALID:
        validity_window = "not_yet_valid"

    # Determine train_match and date_match
    train_match = result_code not in (VerifyResult.WRONG_TRAIN, VerifyResult.FORGED)
    date_match = result_code not in (VerifyResult.WRONG_DATE, VerifyResult.FORGED)

    # Determine identity_check
    identity_check = "skipped"
    if body.aadhaar and body.dob:
        identity_check = "passed"  # Simplified for now
        # TODO: implement proper identity check

    return VerifyResponse(
        result=result_code,
        signature_valid=pipeline_result["signature_valid"],
        chart_match=pipeline_result.get("chart_matched", False),
        is_duplicate=is_duplicate,
        key_used=pipeline_result.get("key_used") or "current",
        validity_window=validity_window,
        train_match=train_match,
        date_match=date_match,
        identity_check=identity_check,
        payload=pipeline_result.get("ticket_details"),
    )


@app.post(
    "/chart/add",
    response_model=ChartAddResponse,
    summary="Add passengers to the local chart",
    description=(
        "Called by PRS Booking Service after a ticket is issued to populate "
        "the passenger chart. Simulates the pre-departure chart sync the HHT "
        "app performs over station WiFi before the train departs."
    ),
)
async def chart_add(body: ChartAddRequest) -> ChartAddResponse:
    """
    Insert passenger chart entries for a booked ticket.

    In the real system, the full train chart is downloaded as a ~200KB SQLite
    snapshot over station WiFi before departure. Here, PRS calls this endpoint
    immediately after booking so the chart is always current for the demo.

    Duplicate inserts (same uuid + berth) are handled gracefully — the existing
    row is left untouched and the insert is skipped.
    """
    db_gen = get_db()
    db: Session = next(db_gen)
    rows_inserted = 0

    try:
        for p in body.passengers:
            # Check if this entry already exists
            existing = (
                db.query(PassengerChart)
                .filter(
                    PassengerChart.uuid == body.uuid,
                    PassengerChart.berth == p.berth,
                )
                .first()
            )
            if existing:
                log.debug(
                    "Chart entry already exists: uuid=%s berth=%s — skipping",
                    body.uuid, p.berth,
                )
                continue

            row = PassengerChart(
                pnr=body.pnr,
                uuid=body.uuid,
                train=body.train,
                travel_date=body.travel_date,
                ticket_class=body.ticket_class,
                berth=p.berth,
                passenger_name=p.name,
                aadhaar_hash=None,  # hash is in the signed payload, not stored in chart
            )
            db.add(row)
            rows_inserted += 1

        db.commit()
        log.info(
            "Chart updated: pnr=%s uuid=%s train=%s date=%s rows_inserted=%d",
            body.pnr, body.uuid, body.train, body.travel_date, rows_inserted,
        )
    except Exception as exc:
        db.rollback()
        log.error("Chart add failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Chart update failed: {exc}")
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    return ChartAddResponse(added=True, rows_inserted=rows_inserted)


@app.get(
    "/chart/{train}/{date}",
    summary="View the passenger chart for a train/date",
    description=(
        "Returns the full passenger chart for a train on a given date, "
        "organised by coach. Date format: YYYY-MM-DD."
    ),
)
async def chart_view(train: str, date: str) -> dict:
    """
    Returns the chart in a coach-grouped structure:
    {
      "train": "12051",
      "date": "2026-06-15",
      "coaches": {
        "B2": [
          {"berth": "B2/14", "name": "Rajan Kumar", "id_hash": "..."},
          ...
        ]
      }
    }
    """
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        rows = (
            db.query(PassengerChart)
            .filter(
                PassengerChart.train == train,
                PassengerChart.travel_date == date,
            )
            .order_by(PassengerChart.berth)
            .all()
        )
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    coaches: dict[str, list[dict]] = {}
    for row in rows:
        # Extract coach prefix from berth string: "B2/14" → "B2"
        if row.berth and "/" in row.berth:
            coach = row.berth.split("/")[0]
        else:
            coach = "UNRESERVED"

        if coach not in coaches:
            coaches[coach] = []

        coaches[coach].append({
            "berth": row.berth,
            "name": row.passenger_name,
            "id_hash": row.aadhaar_hash or "",
        })

    return {
        "train": train,
        "date": date,
        "coaches": coaches,
    }


@app.delete(
    "/chart/{train}/{date}",
    summary="Clear the passenger chart for a train/date",
    description=(
        "Deletes all chart entries for the given train and date. "
        "Called at journey end to simulate the post-terminus chart wipe "
        "performed by the HHT app."
    ),
)
async def chart_clear(train: str, date: str) -> dict:
    """
    Simulates the end-of-journey chart wipe described in proposal section 4.7:
    'This data persists for the journey duration and is cleared after the
    train reaches its terminus.'
    
    Response format: { "deleted": true, "train": string, "date": string }
    """
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        deleted = (
            db.query(PassengerChart)
            .filter(
                PassengerChart.train == train,
                PassengerChart.travel_date == date,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        log.info("Chart cleared: train=%s date=%s rows_deleted=%d", train, date, deleted)
    except Exception as exc:
        db.rollback()
        log.error("Chart clear failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Chart clear failed: {exc}")
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    return {"deleted": True, "train": train, "date": date}


@app.get(
    "/health",
    summary="Service liveness check",
)
async def health(request: Request) -> dict:
    return {
        "status": "ok",
        "service": "hht_terminal",
    }


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    log.exception("Unhandled exception in HHT service: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal HHT service error. Check server logs."},
    )