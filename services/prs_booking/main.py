"""
services/prs_booking/main.py

PRS (Passenger Reservation System) Booking Service — Port 8000

Mirrors: IRCTC online booking and PRS counter booking systems.

This is the user-facing service. It orchestrates ticket issuance by:
  1. Accepting a booking request from the client (CLI, browser, or phone)
  2. Calling CRIS Signer (POST :8001/sign) to get the signed barcode payload
  3. Generating a DataMatrix ECC200 barcode PNG from the raw packed bytes
  4. Storing the issued ticket in the database (issued_tickets table)
  5. Calling HHT Service (POST :8003/chart/add) to pre-populate the chart
  6. Returning the PNR, ticket URL, and QR URL to the caller

The "QR URL" naming in URL paths is kept as /ticket/{pnr}/qr for URL
compatibility with v1 and the existing ticket.html template. The image
served at that URL is a DataMatrix barcode, not a QR code.

Endpoints
---------
POST /book                  — Issue a new ticket
GET  /ticket/{pnr}          — Human-readable ticket page (HTML, phone-viewable)
GET  /ticket/{pnr}/qr       — DataMatrix barcode PNG (for scanning)
GET  /ticket/{pnr}/raw      — Full ticket data including barcode_b64 (for CLI/debug)
GET  /tickets               — List all issued tickets (summary, no barcode data)
GET  /health                — Liveness check

DataMatrix generation
---------------------
pylibdmtx is used for both generation (encode) and decoding (decode).
The barcode encodes raw binary bytes directly using the Base256 encoding
scheme, which is the correct scheme for arbitrary binary data. ASCII
encoding (the pylibdmtx default) expands binary bytes and would cause
capacity errors. Base256 encodes each byte as-is, maximising capacity.

Falcon-padded-512 (FIPS 206) signatures are 666 bytes. A 6-passenger
ticket payload is approximately 712 bytes. Total packed size including
the 2-byte length header is approximately 1380 bytes, which fits within
the DataMatrix ECC200 144×144 binary capacity of 1558 bytes.

pylibdmtx.encode() returns a named tuple with fields:
    .pixels  : bytes  (raw RGB pixel data)
    .width   : int
    .height  : int

The pixel data is converted to a PIL Image, scaled up for legibility,
and saved as a PNG.

Departure/arrival time handling
--------------------------------
The booking API accepts departure_time and arrival_time as "HH:MM" strings
combined with travel_date to produce Unix timestamps. If arrival_time is
earlier than departure_time on the same date (overnight journey), arrival
is automatically placed on the next day.
"""

import base64
import io
import logging
import os
import socket
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from PIL import Image
from pydantic import BaseModel, Field, field_validator
from pylibdmtx.pylibdmtx import encode as dm_encode
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.config import settings
from shared.database import get_db, init_db
from shared.models import IssuedTicket
from shared.payload import unpack_signed_payload

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [prs_booking] %(levelname)s %(message)s",
)
log = logging.getLogger("prs_booking")

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
_templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=_templates_dir)

# ---------------------------------------------------------------------------
# DataMatrix barcode settings
# ---------------------------------------------------------------------------
# Minimum module size in pixels before upscaling.
# pylibdmtx generates very small bitmaps by default.
# We scale up so the barcode is scannable on a phone screen.
DM_SCALE_FACTOR = 4       # multiply each module pixel by this factor
DM_MIN_SIZE_PX  = 300     # minimum output image dimension in pixels
DM_QUIET_ZONE   = 10      # extra white border padding in pixels


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialise the database and ensure output directories exist at startup.
    No keys are loaded here — PRS only calls CRIS signer over HTTP.
    """
    init_db()
    os.makedirs(settings.TICKETS_DIR, exist_ok=True)

    # Determine network-accessible IP for phone access instructions
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    app.state.local_ip = local_ip
    log.info("PRS Booking Service ready.")
    log.info("Local:   http://localhost:%d", settings.PRS_PORT)
    log.info("Network: http://%s:%d  ← use this on phone (same WiFi)", local_ip, settings.PRS_PORT)

    yield

    log.info("PRS Booking Service shutdown.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PRS Booking Service",
    description=(
        "Simulates the IRCTC / PRS counter booking system. "
        "Issues tickets, generates DataMatrix barcodes, and serves "
        "phone-viewable ticket pages."
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

class PassengerBooking(BaseModel):
    """One passenger in a booking request."""
    name: str = Field(..., description="Passenger full name")
    berth: Optional[str] = Field(None, description="Berth assignment, e.g. 'B2/14'. Null for unreserved.")
    aadhaar: Optional[str] = Field(None, description="12-digit Aadhaar. Null for Sleeper/unreserved.")
    dob: Optional[str] = Field(None, description="Date of birth YYYY-MM-DD. Required if aadhaar provided.")

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
        parts = v.split("-")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError("DOB must be in YYYY-MM-DD format")
        return v


class BookRequest(BaseModel):
    """
    Request body for POST /book.

    departure_time and arrival_time are "HH:MM" strings (24-hour).
    They are combined with travel_date to produce Unix timestamps.
    If arrival_time < departure_time on the same date, arrival is
    automatically placed on the next calendar day (overnight journey).
    """
    ticket_type: str = Field(
        ...,
        description="'R' (reserved), 'U' (unreserved), 'T' (Tatkal)",
    )
    train: str = Field(..., description="Train number, e.g. '12051'")
    from_stn: str = Field(..., description="Origin station code, e.g. 'CSMT'")
    to_stn: str = Field(..., description="Destination station code, e.g. 'NDLS'")
    ticket_class: str = Field(..., description="'1A', '2A', '3A', 'SL', 'UR'")
    travel_date: str = Field(..., description="Journey date YYYY-MM-DD")
    departure_time: str = Field(..., description="Departure time HH:MM (24-hour)")
    arrival_time: str = Field(..., description="Arrival time HH:MM (24-hour). Next day handled automatically.")
    passengers: list[PassengerBooking] = Field(..., min_length=1)

    @field_validator("ticket_type")
    @classmethod
    def validate_ticket_type(cls, v):
        if v not in {"R", "U", "T"}:
            raise ValueError("ticket_type must be 'R', 'U', or 'T'")
        return v

    @field_validator("ticket_class")
    @classmethod
    def validate_ticket_class(cls, v):
        if v not in {"1A", "2A", "3A", "SL", "UR"}:
            raise ValueError("ticket_class must be one of: 1A, 2A, 3A, SL, UR")
        return v

    @field_validator("travel_date")
    @classmethod
    def validate_travel_date(cls, v):
        parts = v.split("-")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError("travel_date must be YYYY-MM-DD")
        return v

    @field_validator("departure_time", "arrival_time")
    @classmethod
    def validate_time(cls, v):
        parts = v.split(":")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            raise ValueError("Time must be HH:MM (24-hour)")
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError("Time must be HH:MM (24-hour, valid range)")
        return v


class BookResponse(BaseModel):
    """Response from POST /book."""
    pnr: str
    uuid: str
    ticket_url: str
    qr_url: str
    barcode_size_bytes: int = Field(..., description="Size of the DataMatrix barcode content in bytes")
    message: str = "Booking confirmed"


class TicketSummary(BaseModel):
    """One entry in GET /tickets response."""
    pnr: str
    uuid: str
    train: str
    from_stn: str
    to_stn: str
    ticket_class: str
    travel_date: str
    ticket_type: str
    issued_at: int
    passenger_names: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_datetime_unix(date_str: str, time_str: str) -> int:
    """
    Convert a YYYY-MM-DD date string and HH:MM time string to a UTC Unix timestamp.
    Treats the input as IST (UTC+5:30) since Indian Railways operates on IST.
    """
    IST_OFFSET = timedelta(hours=5, minutes=30)
    dt_naive = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    dt_ist = dt_naive - IST_OFFSET          # convert IST → UTC
    return int(dt_ist.replace(tzinfo=timezone.utc).timestamp())


def _resolve_arrival_unix(
    travel_date: str,
    departure_time: str,
    arrival_time: str,
) -> int:
    """
    Compute arrival Unix timestamp, advancing to the next day if arrival
    time is earlier than departure time (overnight journey).

    Example:
        departure_time = "22:00", arrival_time = "06:00"
        → arrival is the next calendar day at 06:00 IST
    """
    dep_h, dep_m = (int(x) for x in departure_time.split(":"))
    arr_h, arr_m = (int(x) for x in arrival_time.split(":"))

    departure_minutes = dep_h * 60 + dep_m
    arrival_minutes   = arr_h * 60 + arr_m

    arrival_date = travel_date
    if arrival_minutes <= departure_minutes:
        # Overnight: arrival is next day
        date_obj = datetime.strptime(travel_date, "%Y-%m-%d") + timedelta(days=1)
        arrival_date = date_obj.strftime("%Y-%m-%d")
        log.debug(
            "Overnight journey detected: dep=%s arr=%s → arrival_date=%s",
            departure_time, arrival_time, arrival_date,
        )

    return _parse_datetime_unix(arrival_date, arrival_time)


def _generate_datamatrix_png(packed_bytes: bytes, output_path: str) -> None:
    """
    Generate a DataMatrix ECC200 barcode PNG from raw packed bytes.

    The barcode encodes the raw binary content using the Base256 encoding
    scheme, which is required for arbitrary binary data. The default ASCII
    scheme would expand binary bytes and exceed the barcode capacity.

    Capacity (144×144, Base256): 1558 bytes.
    Falcon-padded-512 packed payload (6 passengers): ~1380 bytes. Fits.

    The output image is scaled up to DM_MIN_SIZE_PX minimum dimension so
    it is legible on screen and scannable by phone cameras.

    Args:
        packed_bytes : Raw signed payload bytes (2-byte length + JSON + sig).
        output_path  : File path to write the PNG.

    Raises:
        RuntimeError : if pylibdmtx fails to encode the data.
    """
    try:
        encoded = dm_encode(packed_bytes, size="144x144", scheme="Base256")
    except Exception as exc:
        raise RuntimeError(
            f"DataMatrix encoding failed ({len(packed_bytes)} bytes): {exc}"
        ) from exc

    if not encoded:
        raise RuntimeError(
            f"pylibdmtx returned empty result for {len(packed_bytes)}-byte input. "
            "Check that libdmtx system library is installed."
        )

    # pylibdmtx returns pixels as a flat bytes object in RGB format
    # width and height include the quiet zone pylibdmtx adds automatically
    raw_width  = encoded.width
    raw_height = encoded.height
    raw_pixels = encoded.pixels

    # Build PIL image from raw RGB bytes
    img = Image.frombytes("RGB", (raw_width, raw_height), raw_pixels)

    # Scale up for legibility — the raw output is tiny (e.g. 154×154 px)
    scale = max(DM_SCALE_FACTOR, DM_MIN_SIZE_PX // min(raw_width, raw_height))
    if scale > 1:
        new_w = raw_width  * scale
        new_h = raw_height * scale
        img = img.resize((new_w, new_h), Image.NEAREST)  # NEAREST preserves sharp edges

    # Add quiet zone border
    if DM_QUIET_ZONE > 0:
        bordered_w = img.width  + 2 * DM_QUIET_ZONE
        bordered_h = img.height + 2 * DM_QUIET_ZONE
        bordered = Image.new("RGB", (bordered_w, bordered_h), (255, 255, 255))
        bordered.paste(img, (DM_QUIET_ZONE, DM_QUIET_ZONE))
        img = bordered

    img.save(output_path, format="PNG")
    log.info(
        "DataMatrix PNG saved: %s (%dx%d px, %d bytes input, scale=%d)",
        output_path, img.width, img.height, len(packed_bytes), scale,
    )


async def _call_cris_signer(body: BookRequest) -> dict:
    """
    Call CRIS Signer POST /sign and return the response dict.

    Raises HTTPException on network failure or non-200 response.
    """
    sign_payload = {
        "ticket_type":    body.ticket_type,
        "train":          body.train,
        "from_stn":       body.from_stn,
        "to_stn":         body.to_stn,
        "ticket_class":   body.ticket_class,
        "travel_date":    body.travel_date,
        "departure_unix": _parse_datetime_unix(body.travel_date, body.departure_time),
        "arrival_unix":   _resolve_arrival_unix(
                              body.travel_date, body.departure_time, body.arrival_time
                          ),
        "passengers": [
            {
                "name":    p.name,
                "berth":   p.berth,
                "aadhaar": p.aadhaar,
                "dob":     p.dob,
            }
            for p in body.passengers
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{settings.CRIS_SIGNER_URL}/sign",
                json=sign_payload,
            )
    except httpx.ConnectError:
        log.error("Cannot reach CRIS Signer at %s", settings.CRIS_SIGNER_URL)
        raise HTTPException(
            status_code=503,
            detail=(
                f"CRIS Signer service is not reachable at {settings.CRIS_SIGNER_URL}. "
                "Ensure it is running: honcho start (or uvicorn services.cris_signer.main:app --port 8001)"
            ),
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="CRIS Signer timed out. The signing operation took too long.",
        )

    if resp.status_code != 200:
        log.error("CRIS Signer returned %d: %s", resp.status_code, resp.text)
        raise HTTPException(
            status_code=502,
            detail=f"CRIS Signer error ({resp.status_code}): {resp.text}",
        )

    return resp.json()


async def _call_hht_chart_add(
    pnr: str,
    uuid: str,
    body: BookRequest,
    passengers: list[PassengerBooking],
) -> None:
    """
    Call HHT Service POST /chart/add to pre-populate the passenger chart.

    Failure is logged as a warning but does not abort the booking.
    The ticket is already issued and signed at this point — the chart
    entry is supplementary. In a real deployment, chart sync happens
    separately over station WiFi before departure.
    """
    chart_payload = {
        "pnr":          pnr,
        "uuid":         uuid,
        "train":        body.train,
        "travel_date":  body.travel_date,
        "ticket_class": body.ticket_class,
        "passengers": [
            {"name": p.name, "berth": p.berth}
            for p in passengers
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{settings.HHT_SERVICE_URL}/chart/add",
                json=chart_payload,
            )
        if resp.status_code == 200:
            data = resp.json()
            log.info(
                "Chart populated: pnr=%s uuid=%s rows_inserted=%d",
                pnr, uuid, data.get("rows_inserted", 0),
            )
        else:
            log.warning(
                "HHT chart/add returned %d for pnr=%s: %s",
                resp.status_code, pnr, resp.text,
            )
    except Exception as exc:
        log.warning(
            "Could not reach HHT Service for chart/add (pnr=%s): %s. "
            "Ticket is still issued — chart sync can be done manually.",
            pnr, exc,
        )


def _build_ticket_url(request: Request, pnr: str) -> tuple[str, str]:
    """
    Build the ticket_url and qr_url for a given PNR.

    Uses the Host header from the request so the URLs work when accessed
    from both localhost and a phone on the same LAN.
    """
    base = str(request.base_url).rstrip("/")
    ticket_url = f"{base}/ticket/{pnr}"
    qr_url     = f"{base}/ticket/{pnr}/qr"
    return ticket_url, qr_url


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/book",
    response_model=BookResponse,
    summary="Issue a new ticket",
    description=(
        "Books a ticket, calls CRIS Signer for signing, generates a DataMatrix "
        "barcode PNG, stores the ticket in the database, and populates the "
        "HHT passenger chart. Returns PNR and URLs for viewing the ticket."
    ),
)
async def book_ticket(body: BookRequest, request: Request) -> BookResponse:
    """
    Full booking pipeline:
      1. Call CRIS Signer → get barcode_b64, uuid, pnr, payload_preview
      2. Decode barcode_b64 → raw packed_bytes
      3. Generate DataMatrix PNG from packed_bytes → save to tickets/
      4. Store IssuedTicket row in DB
      5. Call HHT chart/add (best-effort, non-blocking failure)
      6. Return PNR + URLs
    """
    # ------------------------------------------------------------------
    # Step 1: Call CRIS Signer
    # ------------------------------------------------------------------
    sign_resp = await _call_cris_signer(body)

    ticket_uuid  = sign_resp["uuid"]
    ticket_pnr   = sign_resp["pnr"]
    barcode_b64  = sign_resp["barcode_b64"]
    payload_prev = sign_resp["payload_preview"]

    log.info(
        "Received signed ticket from CRIS: pnr=%s uuid=%s packed_size=%d bytes",
        ticket_pnr, ticket_uuid, sign_resp.get("packed_size_bytes", 0),
    )

    # ------------------------------------------------------------------
    # Step 2: Decode barcode bytes
    # ------------------------------------------------------------------
    try:
        packed_bytes = base64.b64decode(barcode_b64)
    except Exception as exc:
        log.error("Failed to decode barcode_b64 from CRIS signer: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: CRIS signer returned invalid barcode_b64: {exc}",
        )

    # ------------------------------------------------------------------
    # Step 3: Generate DataMatrix PNG
    # ------------------------------------------------------------------
    dm_filename = f"{ticket_uuid}_dm.png"
    dm_path     = os.path.join(settings.TICKETS_DIR, dm_filename)

    try:
        _generate_datamatrix_png(packed_bytes, dm_path)
    except RuntimeError as exc:
        log.error("DataMatrix generation failed for uuid=%s: %s", ticket_uuid, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Barcode generation failed: {exc}",
        )

    # ------------------------------------------------------------------
    # Step 4: Store in database
    # ------------------------------------------------------------------
    passenger_names = ", ".join(p.name for p in body.passengers)

    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        existing = db.query(IssuedTicket).filter(IssuedTicket.pnr == ticket_pnr).first()
        if existing:
            log.warning("PNR collision detected: %s — this is extremely unlikely", ticket_pnr)
            raise HTTPException(
                status_code=500,
                detail=f"PNR collision: {ticket_pnr} already exists. Please retry.",
            )

        ticket_row = IssuedTicket(
            uuid=ticket_uuid,
            pnr=ticket_pnr,
            jwt_string=barcode_b64,      # column name kept from v1; stores barcode_b64
            train=body.train,
            from_stn=body.from_stn,
            to_stn=body.to_stn,
            ticket_class=body.ticket_class,
            travel_date=body.travel_date,
            ticket_type=body.ticket_type,
            issued_at=int(time.time()),
            passenger_names=passenger_names,
        )
        db.add(ticket_row)
        db.commit()
        log.info(
            "Ticket stored in DB: pnr=%s uuid=%s train=%s date=%s class=%s type=%s",
            ticket_pnr, ticket_uuid, body.train, body.travel_date,
            body.ticket_class, body.ticket_type,
        )
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        log.error("DB insert failed for uuid=%s: %s", ticket_uuid, exc)
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    # ------------------------------------------------------------------
    # Step 5: Populate HHT passenger chart (best-effort)
    # ------------------------------------------------------------------
    await _call_hht_chart_add(ticket_pnr, ticket_uuid, body, body.passengers)

    # ------------------------------------------------------------------
    # Step 6: Build and return response
    # ------------------------------------------------------------------
    ticket_url, qr_url = _build_ticket_url(request, ticket_pnr)

    log.info(
        "Booking complete: pnr=%s uuid=%s ticket_url=%s",
        ticket_pnr, ticket_uuid, ticket_url,
    )

    return BookResponse(
        pnr=ticket_pnr,
        uuid=ticket_uuid,
        ticket_url=ticket_url,
        qr_url=qr_url,
        barcode_size_bytes=len(packed_bytes),
        message="Booking confirmed",
    )


@app.get(
    "/ticket/{pnr}",
    response_class=HTMLResponse,
    summary="Phone-viewable ticket page",
    description=(
        "Renders the full ticket as an HTML page. Embeds the DataMatrix barcode "
        "image. Designed to be opened on a phone browser and scanned directly."
    ),
)
async def ticket_page(pnr: str, request: Request):
    """
    Renders ticket.html with all ticket details and the DataMatrix barcode image.
    The page is intentionally minimal — plain HTML, inline styles, no JS framework.
    """
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        ticket = db.query(IssuedTicket).filter(IssuedTicket.pnr == pnr).first()
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    if not ticket:
        raise HTTPException(status_code=404, detail=f"Ticket with PNR {pnr!r} not found")

    _, qr_url = _build_ticket_url(request, pnr)

    passenger_name_list = [n.strip() for n in ticket.passenger_names.split(",") if n.strip()]

    issued_dt = datetime.fromtimestamp(ticket.issued_at, tz=timezone.utc)
    issued_at_str = issued_dt.strftime("%d %b %Y %H:%M UTC")

    type_display = {
        "R": "Reserved",
        "U": "Unreserved",
        "T": "Tatkal Reserved",
    }.get(ticket.ticket_type, ticket.ticket_type)

    return templates.TemplateResponse(
        "ticket.html",
        {
            "request":         request,
            "pnr":             ticket.pnr,
            "train":           ticket.train,
            "from_stn":        ticket.from_stn,
            "to_stn":          ticket.to_stn,
            "ticket_class":    ticket.ticket_class,
            "travel_date":     ticket.travel_date,
            "ticket_type":     ticket.ticket_type,
            "type_display":    type_display,
            "passengers":      passenger_name_list,
            "issued_at":       issued_at_str,
            "qr_url":          qr_url,
        },
    )


@app.get(
    "/ticket/{pnr}/qr",
    summary="DataMatrix barcode PNG",
    description=(
        "Returns the DataMatrix barcode PNG for the ticket. "
        "This is the image embedded in the ticket.html page. "
        "Phone cameras and 2D barcode scanner apps can scan this image directly."
    ),
)
async def ticket_barcode(pnr: str) -> FileResponse:
    """
    Serves the DataMatrix PNG file for the given PNR.

    The barcode encodes the raw binary signed payload — the same bytes that
    the HHT scanner reads when a physical ticket is scanned.
    """
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        ticket = db.query(IssuedTicket).filter(IssuedTicket.pnr == pnr).first()
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    if not ticket:
        raise HTTPException(status_code=404, detail=f"Ticket with PNR {pnr!r} not found")

    dm_filename = f"{ticket.uuid}_dm.png"
    dm_path     = os.path.join(settings.TICKETS_DIR, dm_filename)

    if not os.path.exists(dm_path):
        log.warning("DataMatrix PNG missing for pnr=%s, regenerating.", pnr)
        try:
            packed_bytes = base64.b64decode(ticket.jwt_string)
            _generate_datamatrix_png(packed_bytes, dm_path)
        except Exception as exc:
            log.error("Barcode regeneration failed for pnr=%s: %s", pnr, exc)
            raise HTTPException(
                status_code=500,
                detail=f"Barcode file missing and regeneration failed: {exc}",
            )

    return FileResponse(dm_path, media_type="image/png")


@app.get(
    "/ticket/{pnr}/raw",
    summary="Full ticket data (CLI/debug use)",
    description=(
        "Returns the full ticket record including barcode_b64. "
        "Intended for the CLI and debugging — not shown to end users."
    ),
)
async def ticket_raw(pnr: str) -> dict:
    """
    Returns the full ticket data including barcode_b64 (base64-encoded packed bytes).
    The CLI uses this to fetch the barcode for verification with the HHT service.
    
    Response format:
    {
      "pnr": string,
      "barcode_b64": string,
      "payload": object (decoded from the packed bytes)
    }
    """
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        ticket = db.query(IssuedTicket).filter(IssuedTicket.pnr == pnr).first()
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    if not ticket:
        raise HTTPException(status_code=404, detail=f"Ticket with PNR {pnr!r} not found")

    # Decode the barcode to extract the payload
    try:
        packed_bytes = base64.b64decode(ticket.jwt_string)
        payload_dict, _, _ = unpack_signed_payload(packed_bytes)
    except Exception as exc:
        log.error("Failed to decode payload for pnr=%s: %s", pnr, exc)
        payload_dict = {}

    return {
        "pnr": ticket.pnr,
        "barcode_b64": ticket.jwt_string,
        "payload": payload_dict,
    }


@app.get(
    "/tickets",
    summary="List all issued tickets",
    description="Returns a summary list of all issued tickets. Does not include barcode data.",
)
async def list_tickets() -> dict:
    """Returns all tickets in summary form — suitable for display in the CLI."""
    db_gen = get_db()
    db: Session = next(db_gen)
    try:
        tickets = (
            db.query(IssuedTicket)
            .order_by(IssuedTicket.issued_at.desc())
            .all()
        )
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
        db.close()

    return {
        "total": len(tickets),
        "tickets": [
            {
                "pnr":             t.pnr,
                "uuid":            t.uuid,
                "train":           t.train,
                "from_stn":        t.from_stn,
                "to_stn":          t.to_stn,
                "ticket_class":    t.ticket_class,
                "travel_date":     t.travel_date,
                "ticket_type":     t.ticket_type,
                "issued_at":       t.issued_at,
                "passenger_names": t.passenger_names,
            }
            for t in tickets
        ],
    }


@app.get(
    "/health",
    summary="Service liveness check",
)
async def health(request: Request) -> dict:
    return {
        "status": "ok",
        "service": "prs_booking",
    }


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    log.exception("Unhandled exception in PRS booking service: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal PRS booking error. Check server logs."},
    )
