"""
cli/main.py

Railway PQ Auth Demo — Management CLI

All commands talk to the four services over HTTP. The CLI is a thin client
over the REST APIs — no crypto or DB logic lives here directly.

Commands
--------
  keygen                  Generate / rotate falcon keypair (.bin files)
  book                    Issue a new ticket (interactive or --json)
  verify                  Verify a ticket via HHT service
  audit stats             Aggregated verification statistics
  audit duplicates        List all duplicate-UUID events
  audit log <uuid>        All events for a specific UUID
  chart show              Display passenger chart for a train/date
  chart clear             Wipe chart at journey end
  clone                   DEMO ATTACK — clone a ticket (DataMatrix, same packed bytes)
  forge                   DEMO ATTACK — tamper with a payload field (binary format)

v1 → v2 changes in this file
------------------------------
  keygen   : keys saved as .bin (raw bytes) not .pem
             uses save_private_key / save_public_key from crypto_utils
             reports key sizes in bytes (2528 / 1312)

  verify   : fetches "barcode_b64" from /raw endpoint (was "jwt")
             posts "barcode_b64" to HHT /verify (was "jwt")
             --jwt flag renamed to --barcode, --jwt kept as hidden alias
             --image: decodes DataMatrix with pylibdmtx (was pyzbar QR)
             Aadhaar prompting uses unpack_signed_payload (was parse_jwt)

  clone    : generates DataMatrix PNG from raw packed bytes (was QR from JWT string)

  forge    : binary struct unpack/repack (was base64url split/rejoin)
             repacks [2-byte len][modified payload][original sig bytes]
             generates DataMatrix PNG (was QR)
"""

import base64
import json
import os
import shutil
import struct
import sys
import time
from datetime import datetime
from typing import Optional

import typer
import httpx

# ---------------------------------------------------------------------------
# Path resolution — allow running as: python -m cli
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.config import settings
from shared.crypto_utils import (
    FALCON_PRIVATE_KEY_BYTES,
    FALCON_PUBLIC_KEY_BYTES,
    FALCON_SIGNATURE_BYTES,
    generate_keypair,
    get_public_key_fingerprint,
    save_private_key,
    save_public_key,
)
from shared.payload import (
    LENGTH_FIELD_BYTES,
    LENGTH_STRUCT_FORMAT,
    unpack_signed_payload,
)


# ── App + sub-apps ─────────────────────────────────────────────────────────────

app = typer.Typer(
    name="railway-pq-cli",
    help="Railway PQ Auth Demo — Post-Quantum Ticket Authentication CLI",
    no_args_is_help=True,
)

audit_app = typer.Typer(help="Audit server commands.", no_args_is_help=True)
chart_app = typer.Typer(help="Passenger chart commands.", no_args_is_help=True)

app.add_typer(audit_app, name="audit")
app.add_typer(chart_app, name="chart")


@app.callback()
def root():
    """Railway PQ Auth Demo — Falcon / FIPS 204 / DataMatrix ECC200."""
    pass


# ── Shared HTTP helpers ─────────────────────────────────────────────────────────

def _svc(url: str) -> str:
    return url.rstrip("/")


def _http_get(url: str) -> dict:
    try:
        r = httpx.get(url, timeout=8.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        typer.secho(f"\n  ✗ Could not connect to {url}", fg=typer.colors.RED)
        typer.secho(
            "    Make sure all services are running: honcho start",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        typer.secho(
            f"\n  ✗ HTTP {e.response.status_code}: {e.response.text}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)


def _http_post(url: str, body: dict) -> dict:
    try:
        r = httpx.post(url, json=body, timeout=30.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        typer.secho(f"\n  ✗ Could not connect to {url}", fg=typer.colors.RED)
        typer.secho(
            "    Make sure all services are running: honcho start",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        typer.secho(
            f"\n  ✗ HTTP {e.response.status_code}: {e.response.text}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)


def _http_delete(url: str) -> dict:
    try:
        r = httpx.delete(url, timeout=8.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        typer.secho(f"\n  ✗ Could not connect to {url}", fg=typer.colors.RED)
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        typer.secho(
            f"\n  ✗ HTTP {e.response.status_code}: {e.response.text}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)


# ── Display helpers ─────────────────────────────────────────────────────────────

def _result_color(result: str) -> str:
    return {
        "VALID":         typer.colors.GREEN,
        "DUPLICATE":     typer.colors.YELLOW,
        "FORGED":        typer.colors.RED,
        "EXPIRED":       typer.colors.RED,
        "NOT_YET_VALID": typer.colors.YELLOW,
        "WRONG_TRAIN":   typer.colors.RED,
        "WRONG_DATE":    typer.colors.RED,
        "INVALID_PNR":   typer.colors.RED,
    }.get(result, typer.colors.WHITE)


def _print_section(title: str):
    typer.echo("")
    typer.secho(f"  {'─' * 52}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"  {title}", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.secho(f"  {'─' * 52}", fg=typer.colors.BRIGHT_BLACK)


def _print_kv(label: str, value: str, color=None):
    label_str = typer.style(f"  {label:<24}", fg=typer.colors.BRIGHT_BLACK)
    value_str = typer.style(str(value), fg=color) if color else str(value)
    typer.echo(label_str + value_str)


# ── Barcode helpers ─────────────────────────────────────────────────────────────

def _fetch_barcode_b64_for_pnr(pnr: str) -> str:
    """
    Fetch barcode_b64 from PRS /ticket/{pnr}/raw for a given PNR.
    barcode_b64 is the base64-encoded packed bytes (the DataMatrix content).
    """
    data = _http_get(f"{_svc(settings.PRS_URL)}/ticket/{pnr}/raw")
    barcode_b64 = data.get("barcode_b64")
    if not barcode_b64:
        typer.secho(
            f"  ✗ No barcode_b64 found for PNR {pnr}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    return barcode_b64


def _decode_datamatrix_image(image_path: str) -> str:
    """
    Decode a DataMatrix barcode from a PNG image file using pylibdmtx.

    Returns the barcode content base64-encoded (barcode_b64) so it can
    be transported in the JSON body of the HHT /verify request.

    The DataMatrix encodes raw binary bytes (the packed signed payload).
    pylibdmtx returns them as bytes — we base64-encode for JSON transport.
    """
    try:
        from pylibdmtx.pylibdmtx import decode as dm_decode
        from PIL import Image
    except ImportError:
        typer.secho(
            "  ✗ pylibdmtx / Pillow not installed.\n"
            "    Run: pip install pylibdmtx Pillow",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if not os.path.exists(image_path):
        typer.secho(
            f"  ✗ Image file not found: {image_path}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    try:
        img = Image.open(image_path)
        # Convert to RGB — pylibdmtx can fail on RGBA or palette images
        img = img.convert("RGB")
        decoded = dm_decode(img)
    except Exception as exc:
        typer.secho(
            f"  ✗ DataMatrix decode error: {exc}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if not decoded:
        typer.secho(
            f"  ✗ No DataMatrix barcode found in: {image_path}\n"
            "    Make sure the image contains a valid DataMatrix ECC200 barcode.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    packed_bytes = decoded[0].data     # raw binary bytes from barcode
    barcode_b64  = base64.b64encode(packed_bytes).decode("ascii")

    typer.secho(
        f"  ✓ DataMatrix decoded: {len(packed_bytes)} bytes from {image_path}",
        fg=typer.colors.CYAN,
    )
    return barcode_b64


def _generate_datamatrix_png(packed_bytes: bytes, output_path: str) -> None:
    """
    Generate a DataMatrix ECC200 barcode PNG from raw packed bytes.
    Used by clone and forge commands.

    Identical logic to prs_booking/main.py _generate_datamatrix_png —
    kept local here so CLI commands have no service dependency for
    demo artifact generation.
    """
    from pylibdmtx.pylibdmtx import encode as dm_encode
    from PIL import Image

    try:
        encoded = dm_encode(packed_bytes, size="144x144")
    except Exception as exc:
        typer.secho(
            f"  ✗ DataMatrix encode failed ({len(packed_bytes)} bytes): {exc}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if not encoded:
        typer.secho(
            "  ✗ pylibdmtx returned empty result. "
            "Check libdmtx system library is installed.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    img = Image.frombytes("RGB", (encoded.width, encoded.height), encoded.pixels)

    # Scale up 4× with NEAREST to keep module edges sharp
    scale = max(4, 300 // min(encoded.width, encoded.height))
    img   = img.resize((encoded.width * scale, encoded.height * scale), Image.NEAREST)

    # Add quiet zone border
    border = 10
    padded = Image.new("RGB", (img.width + 2 * border, img.height + 2 * border), (255, 255, 255))
    padded.paste(img, (border, border))

    padded.save(output_path, format="PNG")


# ── Verify result printer ───────────────────────────────────────────────────────

def _print_verify_result(data: dict):
    """Pretty-print a full HHT /verify response."""
    result = data.get("result", "UNKNOWN")

    _print_section("VERIFICATION RESULT")
    typer.echo("")
    typer.secho(
        f"  {'RESULT':<24}{result}",
        fg=_result_color(result),
        bold=True,
    )
    typer.echo("")

    # Ticket details
    td = data.get("ticket_details") or {}
    if td:
        _print_section("Ticket Details")
        _print_kv("Train",       td.get("train", "—"))
        _print_kv("From → To",   f"{td.get('from', '—')} → {td.get('to', '—')}")
        _print_kv("Class",       td.get("class", "—"))
        _print_kv("Date",        td.get("date", "—"))
        _print_kv("Type",        td.get("type", "—"))
        _print_kv("UUID",        td.get("uuid", "—"))

    # Security checks
    _print_section("Security Checks")
    sig_ok   = data.get("signature_valid", False)
    chart_ok = data.get("chart_matched",   False)
    is_dup   = data.get("is_duplicate",    False)
    key_used = data.get("key_used",        "—")

    _print_kv(
        "Falcon Signature",
        "✓ VALID" if sig_ok else "✗ INVALID",
        typer.colors.GREEN if sig_ok else typer.colors.RED,
    )
    _print_kv(
        "Chart Match",
        "✓ MATCHED" if chart_ok else "✗ NOT FOUND",
        typer.colors.GREEN if chart_ok else typer.colors.RED,
    )
    _print_kv(
        "Duplicate",
        "⚠ YES — FLAGGED" if is_dup else "✓ NO",
        typer.colors.YELLOW if is_dup else typer.colors.GREEN,
    )
    _print_kv("Key Used", key_used or "—")

    # Passengers
    passengers = data.get("passengers", [])
    if passengers:
        _print_section("Passengers")
        for i, p in enumerate(passengers, 1):
            name   = p.get("name",           "—")
            berth  = p.get("berth",          "—")
            id_chk = p.get("identity_check", "NOT_REQUIRED")

            id_color = {
                "PASSED":        typer.colors.GREEN,
                "FAILED":        typer.colors.RED,
                "NOT_ATTEMPTED": typer.colors.YELLOW,
                "NOT_REQUIRED":  typer.colors.BRIGHT_BLACK,
            }.get(id_chk, typer.colors.WHITE)

            typer.echo(
                typer.style(f"  {i}. {name:<22}", bold=True)
                + typer.style(f"Berth: {berth:<10}", fg=typer.colors.BRIGHT_BLACK)
                + typer.style(f"Identity: {id_chk}", fg=id_color)
            )

    typer.echo("")


# ===========================================================================
# 6.1  keygen
# ===========================================================================

@app.command("keygen")
def keygen(
    force: bool = typer.Option(
        False, "--force", "-f",
        help="Overwrite existing keys without prompting.",
    ),
    rotate: bool = typer.Option(
        False, "--rotate", "-r",
        help=(
            "Key rotation mode: move current public key → old_public_key.bin "
            "before generating a new keypair. Use for scheduled 6-month rotations."
        ),
    ),
):
    """
    Generate a Falcon keypair (FIPS 204) and write to the keys/ directory.

    Keys are stored as raw bytes in .bin files (not PEM — Falcon keys have
    no standardised PEM format). private_key.bin simulates the HSM private key.

    Key sizes:
      Private key : 2528 bytes
      Public key  : 1312 bytes
    """
    private_path    = os.path.join(settings.KEYS_DIR, "private_key.bin")
    public_path     = os.path.join(settings.KEYS_DIR, "public_key.bin")
    old_public_path = os.path.join(settings.KEYS_DIR, "old_public_key.bin")

    os.makedirs(settings.KEYS_DIR, exist_ok=True)

    keys_exist = os.path.exists(private_path) or os.path.exists(public_path)

    if keys_exist:
        if rotate:
            # Rotation path: current public key → old, generate new
            if os.path.exists(old_public_path) and not force:
                typer.echo("")
                typer.secho(
                    "  ⚠  old_public_key.bin already exists. It will be overwritten.",
                    fg=typer.colors.YELLOW,
                )
                typer.secho(
                    "     Tickets signed with the current-old key will no longer verify "
                    "after this rotation.",
                    fg=typer.colors.YELLOW,
                )
                if not typer.confirm("\n  Continue with rotation?", default=False):
                    typer.secho("  Rotation cancelled.", fg=typer.colors.YELLOW)
                    raise typer.Exit(0)

            if os.path.exists(public_path):
                shutil.copy2(public_path, old_public_path)
                typer.secho(
                    f"  ↳ Current public key rotated → {old_public_path}",
                    fg=typer.colors.CYAN,
                )

            # Back up old private key with timestamp (gitignored)
            if os.path.exists(private_path):
                backup = os.path.join(
                    settings.KEYS_DIR,
                    f"private_key_retired_{int(time.time())}.bin",
                )
                os.rename(private_path, backup)
                typer.secho(
                    f"  ↳ Old private key backed up to: {backup}",
                    fg=typer.colors.BRIGHT_BLACK,
                )
                typer.secho(
                    "     (Gitignored. Delete after confirming rotation is stable.)",
                    fg=typer.colors.BRIGHT_BLACK,
                )

        else:
            # Plain overwrite — warn loudly
            if not force:
                typer.echo("")
                typer.secho(
                    "  ⚠  Key files already exist:",
                    fg=typer.colors.YELLOW, bold=True,
                )
                typer.echo(f"     {private_path}")
                typer.echo(f"     {public_path}")
                typer.echo("")
                typer.secho(
                    "  Generating new keys will INVALIDATE ALL previously issued tickets.\n"
                    "  TTEs will get FORGED on every ticket issued before this moment.\n\n"
                    "  If you want to keep the old key for a grace period, use --rotate.",
                    fg=typer.colors.YELLOW,
                )
                if not typer.confirm(
                    "\n  Overwrite? (all existing tickets become unverifiable)",
                    default=False,
                ):
                    typer.secho("  Aborted. No changes made.", fg=typer.colors.RED)
                    raise typer.Exit(0)

            # Clean up old key file when doing a full overwrite
            for p in [old_public_path]:
                if os.path.exists(p):
                    os.remove(p)

    # Generate
    typer.echo("")
    typer.secho(
        "  Generating Falcon keypair (FIPS 204)...",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.secho(
        "  (This may take 1–3 seconds on first run.)",
        fg=typer.colors.BRIGHT_BLACK,
    )

    t0 = time.perf_counter()
    private_key_bytes, public_key_bytes = generate_keypair()
    elapsed = time.perf_counter() - t0

    # Save using crypto_utils helpers (enforces correct lengths, sets file permissions)
    save_private_key(private_key_bytes, private_path)
    save_public_key(public_key_bytes, public_path)

    fingerprint = get_public_key_fingerprint(public_key_bytes)

    # Summary
    typer.echo("")
    typer.secho("  ✓ Keypair generated successfully.", fg=typer.colors.GREEN, bold=True)
    _print_section("Key Details")
    _print_kv("Algorithm",    "Falcon (FIPS 204 / CRYSTALS-Falcon, level 2)")
    _print_kv("Security",     "128-bit post-quantum (resistant to Shor's algorithm)")
    _print_kv("Generated in", f"{elapsed:.2f}s")
    _print_kv("Private key",  f"{private_path}  ({len(private_key_bytes)} bytes, chmod 600)")
    _print_kv("Public key",   f"{public_path}  ({len(public_key_bytes)} bytes)")
    if rotate and os.path.exists(old_public_path):
        with open(old_public_path, "rb") as f:
            old_bytes = f.read()
        old_fp = get_public_key_fingerprint(old_bytes)
        _print_kv("Old key fp",   f"{old_fp}  (grace period active)", typer.colors.YELLOW)
    typer.echo("")
    typer.secho(
        f"  Fingerprint (new) : {fingerprint}",
        fg=typer.colors.BRIGHT_WHITE, bold=True,
    )
    typer.echo("")
    typer.secho(
        "  ⚠  private_key.bin simulates the HSM. In production the private key\n"
        "     is generated inside the HSM and never exported as a file.",
        fg=typer.colors.YELLOW,
    )
    typer.echo("")
    typer.secho("  Next steps:", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.echo("    1. Start all services:   honcho start")
    typer.echo(f"   2. Verify CRIS health:   curl http://localhost:{settings.CRIS_SIGNER_PORT}/health")
    typer.echo(f"   3. Book a test ticket:   python -m cli book")
    typer.echo("")


# ===========================================================================
# 6.2  book
# ===========================================================================

TICKET_TYPES   = ["R", "U", "T"]
TICKET_CLASSES = ["1A", "2A", "3A", "SL", "UR"]


@app.command("book")
def book(
    json_file: Optional[str] = typer.Option(
        None, "--json", "-j",
        help="Path to a JSON file containing the full booking request body.",
    ),
):
    """
    Book a new ticket.

    Run interactively (no flags) or pass --json <file> for scripted/demo use.
    """
    if json_file:
        if not os.path.exists(json_file):
            typer.secho(f"  ✗ File not found: {json_file}", fg=typer.colors.RED)
            raise typer.Exit(1)
        with open(json_file) as f:
            body = json.load(f)
        typer.echo(f"\n  Booking from file: {json_file}")

    else:
        typer.echo("")
        typer.secho("  ╔════════════════════════════════╗", fg=typer.colors.BRIGHT_WHITE)
        typer.secho("  ║   NEW TICKET BOOKING           ║", fg=typer.colors.BRIGHT_WHITE, bold=True)
        typer.secho("  ╚════════════════════════════════╝", fg=typer.colors.BRIGHT_WHITE)
        typer.echo("")

        ticket_type = typer.prompt(
            "  Ticket type [R=Reserved, U=Unreserved, T=Tatkal]",
            default="R",
        ).strip().upper()
        if ticket_type not in TICKET_TYPES:
            typer.secho(
                f"  ✗ Invalid type. Choose from: {TICKET_TYPES}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        train          = typer.prompt("  Train number").strip()
        from_stn       = typer.prompt("  From station code (e.g. CSMT)").strip().upper()
        to_stn         = typer.prompt("  To station code (e.g. NDLS)").strip().upper()
        ticket_class   = typer.prompt(
            "  Class [1A / 2A / 3A / SL / UR]", default="3A"
        ).strip().upper()
        if ticket_class not in TICKET_CLASSES:
            typer.secho(
                f"  ✗ Invalid class. Choose from: {TICKET_CLASSES}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        travel_date    = typer.prompt("  Travel date (YYYY-MM-DD)").strip()
        departure_time = typer.prompt("  Departure time (HH:MM, 24h)").strip()
        arrival_time   = typer.prompt("  Arrival time  (HH:MM, 24h)").strip()

        passengers = []
        typer.echo("")
        typer.secho(
            "  Add passengers (Aadhaar optional for SL / unreserved):",
            fg=typer.colors.BRIGHT_BLACK,
        )

        while True:
            typer.echo("")
            name  = typer.prompt(f"  Passenger {len(passengers)+1} — Full name").strip()
            berth = None
            if ticket_type != "U":
                berth = typer.prompt("  Berth (e.g. B2/14)").strip() or None

            aadhaar, dob = None, None

            if ticket_type == "T":
                # Tatkal: mandatory
                typer.secho(
                    "  ⚠  Tatkal requires Aadhaar for identity check at boarding.",
                    fg=typer.colors.YELLOW,
                )
                aadhaar = typer.prompt("  Aadhaar number (12 digits)").strip()
                dob     = typer.prompt("  Date of birth (YYYY-MM-DD)").strip()

            elif ticket_type == "R" and ticket_class in ("1A", "2A", "3A"):
                # AC reserved: optional
                if typer.confirm("  Add Aadhaar for identity check?", default=False):
                    aadhaar = typer.prompt("  Aadhaar number (12 digits)").strip()
                    dob     = typer.prompt("  Date of birth (YYYY-MM-DD)").strip()

            passengers.append({
                "name":    name,
                "berth":   berth,
                "aadhaar": aadhaar,
                "dob":     dob,
            })

            if not typer.confirm("\n  Add another passenger?", default=False):
                break

        body = {
            "ticket_type":    ticket_type,
            "train":          train,
            "from_stn":       from_stn,
            "to_stn":         to_stn,
            "ticket_class":   ticket_class,
            "travel_date":    travel_date,
            "departure_time": departure_time,
            "arrival_time":   arrival_time,
            "passengers":     passengers,
        }

    typer.echo("")
    typer.secho("  Sending booking request...", fg=typer.colors.BRIGHT_BLACK)
    data = _http_post(f"{_svc(settings.PRS_URL)}/book", body)

    _print_section("BOOKING CONFIRMED")
    typer.echo("")
    _print_kv("PNR",              data["pnr"],              typer.colors.GREEN)
    _print_kv("UUID",             data["uuid"])
    _print_kv("Barcode size",     f"{data.get('barcode_size_bytes', '?')} bytes  "
                                  f"(DataMatrix ECC200, Falcon signed)")
    _print_kv("Ticket URL",       data["ticket_url"],       typer.colors.CYAN)
    _print_kv("Barcode URL",      data["qr_url"],           typer.colors.CYAN)
    typer.echo("")
    typer.secho(
        "  Open the Ticket URL on your phone to view and scan the DataMatrix barcode.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")


# ===========================================================================
# 6.3  verify
# ===========================================================================

@app.command("verify")
def verify(
    pnr: Optional[str] = typer.Option(
        None, "--pnr", "-p",
        help="PNR number. Fetches barcode from PRS service automatically.",
    ),
    barcode: Optional[str] = typer.Option(
        None, "--barcode",
        help="Base64-encoded packed bytes (barcode_b64) to verify directly.",
    ),
    # --jwt kept as hidden alias for backward compatibility
    jwt_str: Optional[str] = typer.Option(
        None, "--jwt",
        hidden=True,
        help="Alias for --barcode (v1 compatibility).",
    ),
    image: Optional[str] = typer.Option(
        None, "--image", "-i",
        help="Path to a DataMatrix barcode PNG image.",
    ),
    tte: str = typer.Option(
        ..., "--tte",
        help="TTE ID, e.g. TTE-MUM-047",
    ),
    train: str = typer.Option(
        ..., "--train",
        help="Expected train number, e.g. 12051",
    ),
    aadhaar: bool = typer.Option(
        False, "--aadhaar", "-a",
        help="Prompt for Aadhaar+DOB for each passenger that has an identity hash.",
    ),
):
    """
    Verify a ticket via the HHT service.

    Provide exactly one of: --pnr, --barcode, or --image.

    --pnr    : fetches barcode_b64 from PRS service for the given PNR
    --barcode: pass base64-encoded packed bytes directly (barcode_b64)
    --image  : decode DataMatrix PNG, extract packed bytes, verify
    --jwt    : alias for --barcode (v1 compatibility)
    """
    # Resolve the barcode source
    provided = sum([
        pnr     is not None,
        barcode is not None,
        jwt_str is not None,
        image   is not None,
    ])
    if provided == 0:
        typer.secho(
            "  ✗ Provide one of: --pnr, --barcode, or --image",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if provided > 1:
        typer.secho(
            "  ✗ Provide only one of: --pnr, --barcode, or --image",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if pnr:
        typer.echo(f"\n  Fetching barcode for PNR {pnr}...")
        barcode_b64 = _fetch_barcode_b64_for_pnr(pnr)
    elif image:
        barcode_b64 = _decode_datamatrix_image(image)
    elif barcode:
        barcode_b64 = barcode.strip()
    else:
        # --jwt alias
        barcode_b64 = jwt_str.strip()

    # Optionally collect Aadhaar inputs
    aadhaar_inputs = []
    if aadhaar:
        try:
            packed_bytes = base64.b64decode(barcode_b64)
            payload_dict, _, _ = unpack_signed_payload(packed_bytes)
        except Exception as e:
            typer.secho(
                f"  ✗ Cannot unpack barcode for Aadhaar prompting: {e}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        pax_list = payload_dict.get("pax", [])
        typer.echo("")
        typer.secho(
            "  Identity check requested. Enter details for each passenger.",
            fg=typer.colors.BRIGHT_BLACK,
        )

        for i, pax in enumerate(pax_list):
            berth   = pax.get("b", f"PAX-{i+1}")
            id_hash = pax.get("id")
            if not id_hash:
                continue  # no hash in payload — identity check not applicable
            typer.echo(f"\n  Passenger at berth {berth}:")
            adh = typer.prompt("    Aadhaar number (12 digits)").strip()
            dob = typer.prompt("    Date of birth (YYYY-MM-DD)").strip()
            aadhaar_inputs.append({"berth": berth, "aadhaar": adh, "dob": dob})

        if not aadhaar_inputs:
            typer.secho(
                "  ℹ  No passengers with identity hashes found in this ticket.",
                fg=typer.colors.BRIGHT_BLACK,
            )

    # POST to HHT service
    typer.echo("\n  Verifying with HHT service...")

    body = {
        "barcode_b64":    barcode_b64,
        "tte_id":         tte,
        "expected_train": train,
        "aadhaar_inputs": aadhaar_inputs if aadhaar_inputs else None,
    }
    data = _http_post(f"{_svc(settings.HHT_SERVICE_URL)}/verify", body)
    _print_verify_result(data)


# ===========================================================================
# 6.4  audit
# ===========================================================================

@audit_app.callback()
def audit_root():
    """Audit server commands."""
    pass


@audit_app.command("stats")
def audit_stats():
    """Show aggregated verification statistics from the audit server."""
    data = _http_get(f"{_svc(settings.AUDIT_SERVER_URL)}/stats")

    _print_section("AUDIT SERVER STATS")
    typer.echo("")
    _print_kv("Total verifications", data.get("total_verifications", 0))
    _print_kv("Valid",               data.get("valid",               0), typer.colors.GREEN)
    _print_kv("Forged",              data.get("forged",              0), typer.colors.RED)
    _print_kv("Expired",             data.get("expired",             0), typer.colors.YELLOW)
    _print_kv("Duplicate UUIDs",     data.get("duplicate_uuids",     0), typer.colors.YELLOW)
    _print_kv("Wrong train",         data.get("wrong_train",         0), typer.colors.YELLOW)
    _print_kv("Wrong date",          data.get("wrong_date",          0), typer.colors.YELLOW)
    _print_kv("Invalid PNR",         data.get("invalid_pnr",         0), typer.colors.YELLOW)
    typer.echo("")


@audit_app.command("duplicates")
def audit_duplicates():
    """List all duplicate ticket scan events flagged by the audit server."""
    data  = _http_get(f"{_svc(settings.AUDIT_SERVER_URL)}/duplicates")
    dupes = data.get("duplicates", [])

    _print_section("DUPLICATE TICKET REPORT")
    typer.echo("")

    if not dupes:
        typer.secho("  ✓ No duplicate ticket scans detected.", fg=typer.colors.GREEN)
        typer.echo("")
        return

    typer.secho(
        f"  ⚠  {len(dupes)} duplicate UUID(s) detected!",
        fg=typer.colors.YELLOW, bold=True,
    )

    for d in dupes:
        typer.echo("")
        typer.secho(f"  UUID: {d['uuid']}", fg=typer.colors.BRIGHT_WHITE, bold=True)
        _print_kv("Occurrences", d.get("occurrences", "—"), typer.colors.RED)

        first = d.get("first_seen", {})
        _print_kv("First seen — TTE",   first.get("tte_id",  "—"))
        _print_kv("First seen — Train", first.get("train",   "—"))
        ts = first.get("timestamp")
        if ts:
            _print_kv(
                "First seen — Time",
                datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            )

        events = d.get("all_events", [])
        if events:
            typer.echo("")
            typer.secho("  All scan events:", fg=typer.colors.BRIGHT_BLACK)
            for ev in events:
                ts_str = datetime.fromtimestamp(ev["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                typer.echo(
                    typer.style(f"    [{ts_str}]", fg=typer.colors.BRIGHT_BLACK)
                    + f"  TTE: {ev.get('tte_id','—'):<16}"
                    + f"  Train: {ev.get('train','—'):<8}"
                    + f"  Result: "
                    + typer.style(
                        ev.get("result", "—"),
                        fg=_result_color(ev.get("result", "")),
                    )
                )
    typer.echo("")


@audit_app.command("log")
def audit_log(
    uuid: str = typer.Argument(..., help="UUID to look up in the audit log."),
):
    """Show all audit log events for a specific ticket UUID."""
    data   = _http_get(f"{_svc(settings.AUDIT_SERVER_URL)}/log/{uuid}")
    events = data.get("events", [])

    _print_section(f"AUDIT LOG — {uuid}")
    typer.echo("")

    if not events:
        typer.secho("  No events found for this UUID.", fg=typer.colors.YELLOW)
        typer.echo("")
        return

    for ev in events:
        ts_str  = datetime.fromtimestamp(ev["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        is_dup  = ev.get("is_duplicate", 0)
        dup_mrk = typer.style(" ⚠ DUPLICATE", fg=typer.colors.YELLOW) if is_dup else ""

        typer.echo(
            typer.style(f"  [{ts_str}]", fg=typer.colors.BRIGHT_BLACK)
            + f"  TTE: {ev.get('tte_id','—'):<16}"
            + f"  Train: {ev.get('train','—'):<8}"
            + f"  Coach: {ev.get('coach') or '—':<6}"
            + f"  Result: "
            + typer.style(ev.get("result", "—"), fg=_result_color(ev.get("result", "")))
            + dup_mrk
        )
    typer.echo("")


# ===========================================================================
# 6.5  chart
# ===========================================================================

@chart_app.callback()
def chart_root():
    """Passenger chart commands."""
    pass


@chart_app.command("show")
def chart_show(
    train: str = typer.Option(..., "--train", "-t", help="Train number."),
    date:  str = typer.Option(..., "--date",  "-d", help="Travel date YYYY-MM-DD."),
):
    """Display the passenger chart for a train and date."""
    data = _http_get(f"{_svc(settings.HHT_SERVICE_URL)}/chart/{train}/{date}")

    _print_section(f"PASSENGER CHART — Train {train}  |  {date}")
    typer.echo("")
    _print_kv("Total passengers", data.get("total_passengers", 0))
    typer.echo("")

    coaches = data.get("coaches", {})
    if not coaches:
        typer.secho(
            "  No passengers found for this train/date.",
            fg=typer.colors.YELLOW,
        )
        typer.echo("")
        return

    for coach, rows in sorted(coaches.items()):
        typer.secho(f"  Coach {coach}", fg=typer.colors.BRIGHT_WHITE, bold=True)
        typer.secho(
            f"  {'Berth':<10} {'Name':<26} {'PNR':<14} {'Class':<6}",
            fg=typer.colors.BRIGHT_BLACK,
        )
        typer.secho(f"  {'─' * 56}", fg=typer.colors.BRIGHT_BLACK)
        for row in rows:
            typer.echo(
                f"  {(row.get('berth') or '—'):<10}"
                f" {row.get('name','—'):<26}"
                f" {row.get('pnr','—'):<14}"
                f" {row.get('class','—'):<6}"
            )
        typer.echo("")


@chart_app.command("clear")
def chart_clear(
    train: str = typer.Option(..., "--train", "-t", help="Train number."),
    date:  str = typer.Option(..., "--date",  "-d", help="Travel date YYYY-MM-DD."),
):
    """Clear the passenger chart for a train (simulates end-of-journey wipe)."""
    if not typer.confirm(
        f"\n  Clear chart for train {train} on {date}?", default=False
    ):
        typer.secho("  Aborted.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    data = _http_delete(
        f"{_svc(settings.HHT_SERVICE_URL)}/chart/{train}/{date}"
    )
    typer.echo("")
    typer.secho(
        f"  ✓ Chart cleared. {data.get('rows_deleted', 0)} row(s) deleted.",
        fg=typer.colors.GREEN,
    )
    typer.echo("")


# ===========================================================================
# 6.6  clone — DEMO ATTACK
# ===========================================================================

@app.command("clone")
def clone(
    pnr: str = typer.Option(..., "--pnr", "-p", help="PNR of the ticket to clone."),
):
    """
    DEMO ATTACK: Clone a ticket.

    Copies a real ticket's packed bytes to a new DataMatrix barcode image.
    The barcode content is byte-for-byte identical — same UUID, same valid
    Falcon signature. When the clone is verified after the original,
    the audit server flags it as DUPLICATE.

    This demonstrates that cloning the physical barcode does not help an
    attacker: the UUID duplicate check catches it even offline-first
    (once both events reach the audit server).
    """
    typer.echo("")
    typer.secho("  ╔══════════════════════════════════════╗", fg=typer.colors.RED)
    typer.secho("  ║  DEMO ATTACK: TICKET CLONING         ║", fg=typer.colors.RED, bold=True)
    typer.secho("  ╚══════════════════════════════════════╝", fg=typer.colors.RED)
    typer.echo("")
    typer.secho(
        "  Simulates an attacker scanning a legitimate DataMatrix barcode\n"
        "  and re-printing it on a second piece of paper.\n"
        "  The packed bytes are identical — same UUID, same valid signature.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")

    # Fetch barcode_b64 for real ticket
    typer.echo(f"  Fetching barcode for PNR {pnr}...")
    barcode_b64 = _fetch_barcode_b64_for_pnr(pnr)

    # Decode to inspect the payload
    try:
        packed_bytes = base64.b64decode(barcode_b64)
        payload_dict, _, _ = unpack_signed_payload(packed_bytes)
    except Exception as exc:
        typer.secho(f"  ✗ Failed to unpack barcode: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.secho("  ✓ Barcode fetched. Creating clone...", fg=typer.colors.YELLOW)
    _print_kv("UUID being cloned",  payload_dict.get("uuid",  "—"), typer.colors.YELLOW)
    _print_kv("Train",              payload_dict.get("train", "—"))
    _print_kv("Class",              payload_dict.get("class", "—"))
    _print_kv("Packed bytes",       f"{len(packed_bytes)} bytes (Falcon sig included)")

    # Generate clone DataMatrix PNG — same packed bytes, new file name
    os.makedirs(settings.TICKETS_DIR, exist_ok=True)
    clone_path = os.path.join(settings.TICKETS_DIR, f"CLONED_{pnr}_dm.png")
    _generate_datamatrix_png(packed_bytes, clone_path)

    typer.echo("")
    typer.secho("  ✓ Clone DataMatrix created.", fg=typer.colors.YELLOW, bold=True)
    _print_kv("Clone saved to", clone_path, typer.colors.YELLOW)
    typer.echo("")
    typer.secho("  What to do next:", fg=typer.colors.BRIGHT_WHITE, bold=True)
    train = payload_dict.get("train", "?")
    typer.echo(
        f"\n  1. Verify the original:\n"
        f"       python -m cli verify --pnr {pnr} --tte TTE-001 --train {train}\n"
        f"\n  2. Verify the clone:\n"
        f"       python -m cli verify --image {clone_path} --tte TTE-002 --train {train}\n"
        f"\n  3. Check audit:\n"
        f"       python -m cli audit duplicates\n"
    )
    typer.secho(
        "  The second scan returns DUPLICATE. Both events are flagged\n"
        "  in the audit log with the same UUID.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")


# ===========================================================================
# 6.7  forge — DEMO ATTACK
# ===========================================================================

FORGEABLE_FIELDS = ["class", "date", "from", "to", "train"]


@app.command("forge")
def forge(
    pnr: str = typer.Option(
        ..., "--pnr", "-p", help="PNR of the real ticket to forge from."
    ),
    field: str = typer.Option(
        "class", "--field",
        help=f"Payload field to tamper with. One of: {FORGEABLE_FIELDS}",
    ),
    value: str = typer.Option(
        ..., "--value", "-v",
        help="New value to substitute into the chosen field.",
    ),
):
    """
    DEMO ATTACK: Forge a ticket by tampering with a payload field.

    Modifies a field in the binary-packed payload and reassembles the
    packed bytes WITHOUT re-signing. The original Falcon signature
    is kept but now covers the ORIGINAL payload bytes — not the modified
    ones — so signature verification FAILS → result: FORGED.

    Binary forge process (v2 wire format):
      1. Fetch packed bytes (barcode_b64) from PRS
      2. Parse:  [2-byte length][payload JSON][2420-byte signature]
      3. Decode payload JSON, modify the chosen field
      4. Re-encode modified payload JSON
      5. Repack: [2-byte new length][modified JSON][ORIGINAL signature]
      6. Generate DataMatrix PNG from forged packed bytes
    """
    typer.echo("")
    typer.secho("  ╔══════════════════════════════════════╗", fg=typer.colors.RED)
    typer.secho("  ║  DEMO ATTACK: TICKET FORGERY         ║", fg=typer.colors.RED, bold=True)
    typer.secho("  ╚══════════════════════════════════════╝", fg=typer.colors.RED)
    typer.echo("")
    typer.secho(
        "  Simulates an attacker who intercepts a legitimate ticket and\n"
        "  modifies a field (e.g. upgrades class SL → 1A).\n"
        "  The Falcon signature still exists but now covers DIFFERENT\n"
        "  payload bytes, so cryptographic verification fails.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")

    if field not in FORGEABLE_FIELDS:
        typer.secho(
            f"  ✗ Invalid field '{field}'. Choose from: {FORGEABLE_FIELDS}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    # Fetch barcode_b64
    typer.echo(f"  Fetching barcode for PNR {pnr}...")
    barcode_b64 = _fetch_barcode_b64_for_pnr(pnr)

    # Decode and parse binary format
    try:
        packed_bytes = base64.b64decode(barcode_b64)
    except Exception as exc:
        typer.secho(f"  ✗ base64 decode failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        payload_dict, raw_payload_bytes, raw_sig_bytes = unpack_signed_payload(packed_bytes)
    except ValueError as exc:
        typer.secho(f"  ✗ Binary unpack failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1)

    original_value = payload_dict.get(field, "—")

    typer.secho(
        f"  Tampering field '{field}':  {original_value!r}  →  {value!r}",
        fg=typer.colors.YELLOW, bold=True,
    )

    # Modify the payload dict
    forged_dict = dict(payload_dict)
    forged_dict[field] = value

    # Re-serialise with the same compact format used by pack_signed_payload
    # sort_keys=False, separators=(',',':') — must match exactly
    forged_json  = json.dumps(forged_dict, separators=(",", ":"), sort_keys=False)
    forged_payload_bytes = forged_json.encode("utf-8")

    forged_payload_len = len(forged_payload_bytes)
    if forged_payload_len > 65535:
        typer.secho(
            f"  ✗ Forged payload too large: {forged_payload_len} bytes",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    # Repack: [2-byte big-endian length][modified payload][ORIGINAL signature]
    # The original signature is kept unchanged — it now covers the WRONG bytes.
    length_prefix       = struct.pack(LENGTH_STRUCT_FORMAT, forged_payload_len)
    forged_packed_bytes = length_prefix + forged_payload_bytes + raw_sig_bytes

    typer.secho(
        f"\n  Original packed size : {len(packed_bytes)} bytes",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.secho(
        f"  Forged packed size   : {len(forged_packed_bytes)} bytes",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.secho(
        f"  Signature bytes kept : {len(raw_sig_bytes)} bytes (ORIGINAL — now INVALID)",
        fg=typer.colors.YELLOW,
    )

    # Generate DataMatrix from forged packed bytes
    os.makedirs(settings.TICKETS_DIR, exist_ok=True)
    forged_path = os.path.join(
        settings.TICKETS_DIR, f"FORGED_{pnr}_{field}_dm.png"
    )
    _generate_datamatrix_png(forged_packed_bytes, forged_path)

    typer.echo("")
    typer.secho("  ✓ Forged DataMatrix created.", fg=typer.colors.RED, bold=True)
    _print_kv("Original value",  str(original_value))
    _print_kv("Forged value",    value,       typer.colors.RED)
    _print_kv("Forged DM saved", forged_path, typer.colors.YELLOW)
    typer.echo("")
    typer.secho("  What to do next:", fg=typer.colors.BRIGHT_WHITE, bold=True)
    train = payload_dict.get("train", "?")
    typer.echo(
        f"\n  Verify the forged ticket:\n"
        f"    python -m cli verify --image {forged_path} --tte TTE-001 --train {train}\n"
    )
    typer.secho(
        "  Expected result: FORGED\n"
        "  The Falcon signature check fails because the payload bytes\n"
        "  no longer match what was signed by the CRIS HSM.\n"
        "  This is true even though the signature bytes are present and\n"
        "  structurally valid — the cryptographic binding is broken.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")


# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()