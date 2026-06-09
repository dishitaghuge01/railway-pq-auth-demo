# railway-pq-auth-demo

A post-quantum cryptographic authentication and anti-forgery framework for printed Indian Railway tickets, implemented as a Python microservices demo.

This is the v2 successor to [railway-auth-demo](https://github.com/dishitaghuge01/railway-auth-demo), which used ECDSA P-256. This version replaces ECDSA with **Falcon-padded-512 (FIPS 206 / FN-DSA)**, a lattice-based post-quantum digital signature scheme standardised by NIST in 2024. It is designed to remain secure against both classical and quantum adversaries through the expected operational lifetime of the ticketing infrastructure.

---

## The Problem

Indian Railways issues approximately 12 million tickets every day. The QR codes printed on those tickets encode plain text with no digital signature. Anyone with a QR generator and a printer can produce a ticket that is visually and electronically indistinguishable from a genuine one. A TTE doing a manual check has no device-assisted way to verify that the ticket in front of them was actually issued by Indian Railways rather than fabricated or cloned.

Specific attacks this system addresses:

- **Fabrication** — creating a ticket from scratch using publicly available PNR data from NTES
- **Cloning** — scanning a legitimate barcode and reprinting it on a second piece of paper
- **Physical tampering** — altering printed fields (date, class, berth) after the ticket is issued
- **Impersonation** — using a cloned ticket paired with a forged identity document

---

## The Solution

Every ticket is cryptographically signed at the point of issuance using a private key held in a simulated HSM. The signed payload is encoded into a **DataMatrix ECC200** barcode printed on the ticket. A TTE scanning the barcode with their HHT (Hand Held Terminal) device verifies the Falcon-padded-512 signature offline in milliseconds. No network connection is needed for the core verification.

Security layers from the proposal:

| Layer | Mechanism | Offline? |
|---|---|---|
| Signature verification | Falcon-padded-512 (FIPS 206) | ✓ Yes |
| Validity window | `vf` / `vu` Unix timestamps in payload | ✓ Yes |
| Train and date match | Payload fields vs TTE session | ✓ Yes |
| Chart lookup | Pre-downloaded SQLite passenger manifest | ✓ Yes |
| Identity binding | SHA256(Aadhaar \| DOB) hash in payload | ✓ Yes |
| Duplicate detection | UUID audit log on CRIS server | Network required |

---

## Why Falcon-padded-512, Not ML-DSA-44

The original proposal specified CRYSTALS-Dilithium (ML-DSA-44, FIPS 204) as the signing algorithm. During implementation a hard capacity constraint was discovered that rules it out.

**The numbers:**

| | Size |
|---|---|
| ML-DSA-44 signature | 2420 bytes |
| DataMatrix ECC200 144×144 binary capacity (Base256 scheme) | 1558 bytes |
| ML-DSA-44 signature alone | **exceeds barcode capacity** |

The 3116-byte figure cited in the original proposal was the *ASCII text character* capacity of DataMatrix 144×144 — not the *binary byte* capacity. For raw binary data (which a cryptographic signature is), the correct figure is 1558 bytes. An ML-DSA-44 signature of 2420 bytes is larger than the entire barcode, so the offline-first signed barcode architecture is not achievable with that algorithm regardless of compression or encoding strategy.

Falcon-padded-512 (FIPS 206, FN-DSA security level 1) solves this directly. Its signatures are fixed at **666 bytes** in our liboqs 0.15.0 build. A 6-passenger ticket packs to approximately 1380 bytes, which fits within the 1558-byte capacity with 178 bytes of headroom.

| Algorithm | Signature | Fits in DataMatrix 144×144? |
|---|---|---|
| ECDSA P-256 (v1) | 64–72 bytes | ✓ Yes (QR code) |
| ML-DSA-44 / Dilithium2 | 2420 bytes | ✗ No |
| Falcon-padded-512 | 666 bytes (fixed) | ✓ Yes |

Both ML-DSA-44 and Falcon-padded-512 are NIST-standardised post-quantum schemes providing 128-bit post-quantum security. The switch is algorithm-only — key infrastructure, verification pipeline, physical security layers, and all operational procedures are identical.

---

## Architecture

Four services run simultaneously. Each mirrors a real component of the Indian Railways ticketing infrastructure.

```
┌─────────────────────────────────────────────────────────────┐
│                       Local Machine                          │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │ CRIS Signing │    │ Audit Server │    │  HHT Service  │  │
│  │ Microservice │    │   Service    │    │  (TTE API)    │  │
│  │   :8001      │    │   :8002      │    │   :8003       │  │
│  └──────────────┘    └──────────────┘    └───────────────┘  │
│         │                   │                   │            │
│  ┌──────────────┐    ┌──────────────┐           │            │
│  │ PRS Booking  │    │   SQLite DB  │           │            │
│  │   Service    │◄──►│  railway.db  │◄──────────┘            │
│  │   :8000      │    └──────────────┘                        │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

| Service | Port | Mirrors | Responsibility |
|---|---|---|---|
| PRS Booking Service | 8000 | IRCTC / PRS counter | Accept bookings, call CRIS signer, generate DataMatrix barcode, serve ticket page |
| CRIS Signing Service | 8001 | CRIS HSM microservice | Sign payload with Falcon-padded-512. Only service that holds the private key. |
| Audit Server | 8002 | CRIS audit server | Log verifications, detect duplicate UUIDs |
| HHT Service | 8003 | TTE Hand Held Terminal | Verify ticket barcode, check chart, return structured result |

### Data flow — booking

```
CLI / Browser
     │
     ▼
PRS :8000  POST /book
     │
     ├──► CRIS Signer :8001  POST /sign
     │         │  Falcon-padded-512 sign
     │         │  Returns barcode_b64 (base64 packed bytes)
     │         ▼
     │    PRS decodes → generates DataMatrix PNG → saves to tickets/
     │
     ├──► SQLite  (store IssuedTicket row)
     │
     └──► HHT :8003  POST /chart/add  (populate passenger chart)
```

### Data flow — verification

```
TTE scans DataMatrix barcode
     │
     ▼
HHT :8003  POST /verify
     │
     ├── 1. Binary unpack (2-byte length + JSON payload + 666-byte sig)
     ├── 2. Falcon signature verify (current key, then previous key)
     ├── 3. Validity window check (vf / vu timestamps)
     ├── 4. Train match
     ├── 5. Date match
     ├── 6. Chart lookup (SQLite, offline)
     ├── 7. Identity check (SHA256 Aadhaar hash, if provided)
     │
     └──► Audit :8002  POST /log  (background, non-blocking)
               │
               └── Duplicate UUID detection
```

---

## Wire Format

The DataMatrix barcode encodes raw binary bytes directly using the Base256 encoding scheme. No base64 layer is applied at the barcode level.

```
┌──────────────────────────────────────────────────────────┐
│  2 bytes  │  payload_len bytes  │  666 bytes             │
│  BE uint16│  UTF-8 JSON payload │  Falcon-padded-512 sig │
│  (length) │                     │                        │
└──────────────────────────────────────────────────────────┘
```

The 2-byte big-endian length prefix allows the parser to slice the variable-length JSON payload from the fixed-length signature without any delimiter. For HTTP transport between services, packed bytes are base64-encoded with the field name `barcode_b64`.

### Payload schema

```json
{
  "v":     1,
  "type":  "R",
  "uuid":  "550e8400-e29b-41d4-a716-446655440000",
  "train": "12051",
  "from":  "CSMT",
  "to":    "NDLS",
  "class": "3A",
  "date":  "2026-05-30",
  "vf":    1748578200,
  "vu":    1748671800,
  "iat":   1748491800,
  "pax": [
    { "b": "B2/14", "id": "a3f2e1c9d2b4f5e6..." },
    { "b": "B2/15", "id": null }
  ]
}
```

| Field | Description |
|---|---|
| `v` | Payload version (always 1) |
| `type` | `R` reserved, `U` unreserved, `T` Tatkal |
| `uuid` | UUID4 — canonical ticket identifier for audit deduplication |
| `vf` | Valid-from Unix timestamp (2h before departure for reserved) |
| `vu` | Valid-until Unix timestamp (4h after arrival for reserved) |
| `iat` | Issued-at Unix timestamp |
| `pax[].b` | Berth string e.g. `"B2/14"` (null for unreserved) |
| `pax[].id` | `SHA256(aadhaar \| dob)` hex string, or null if not provided |

The `id` field uses a pipe separator: `SHA256(aadhaar + "|" + dob)`. Without it, Aadhaar `"123456"` + DOB `"789"` would hash identically to Aadhaar `"1234567"` + DOB `"89"`. The payload is not encrypted — the security guarantee is integrity (the signature proves the data was issued by CRIS and has not been tampered with), not confidentiality. All fields except the Aadhaar hash are already printed on the physical ticket.

---

## Prerequisites

### System dependencies

**Arch Linux:**
```bash
sudo pacman -S libdmtx
```

**Ubuntu / Debian:**
```bash
sudo apt install libdmtx-dev libdmtx0b
```

**macOS:**
```bash
brew install libdmtx
```

liboqs C library (required by liboqs-python):

```bash
# Ubuntu / Debian
sudo apt install cmake ninja-build libssl-dev

git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig
```

On Arch Linux, liboqs may be available via AUR: `yay -S liboqs`.

### Python version

Python 3.11 or later. The project uses Python 3.14 in development.

**Note on SQLAlchemy and Python 3.12+:** SQLAlchemy 2.0.30 is incompatible with Python 3.12+ due to a `__firstlineno__` metaclass conflict. Use SQLAlchemy 2.0.50 or later.

**Note on pydantic-settings:** This is a separate package from `pydantic` since v2 and must be installed explicitly.

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/dishitaghuge01/railway-pq-auth-demo.git
cd railway-pq-auth-demo

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Verify liboqs and pylibdmtx are working
python -c "import oqs; print(oqs.get_enabled_sig_mechanisms()[:3])"
python -c "from pylibdmtx.pylibdmtx import encode; print('pylibdmtx ok')"

# 5. Generate keypair
python scripts/keygen.py

# 6. Start all four services
honcho start
```

After `honcho start` you should see all four services reach `Application startup complete`. The PRS service prints the network IP for phone access:

```
prs_booking.1  | Network: http://192.168.x.x:8000  ← use this on phone (same WiFi)
```

---

## Requirements

```
fastapi==0.111.0
uvicorn[standard]==0.29.0
liboqs-python==0.10.1
pylibdmtx==0.1.10
Pillow==10.3.0
SQLAlchemy==2.0.50
pydantic-settings==2.7.1
typer[all]==0.13.1
click==8.1.8
httpx==0.27.0
python-dotenv==1.0.1
honcho==1.1.0
jinja2==3.1.4
```

---

## Key Generation

```bash
# First-time setup
python scripts/keygen.py

# Force overwrite (invalidates all existing tickets)
python scripts/keygen.py --force

# Key rotation (moves current key to old_public_key.bin, generates new current key)
python scripts/keygen.py --rotate
```

Key files:

| File | Size | Description |
|---|---|---|
| `keys/private_key.bin` | 1281 bytes | **Gitignored.** Simulates HSM private key. Never committed. |
| `keys/public_key.bin` | 897 bytes | Committed. Embedded in HHT, IRCTC, RailOne apps at build time. |
| `keys/old_public_key.bin` | 897 bytes | Previous key, present only after a rotation. Grace period: 120 days. |

In production, the private key is generated inside the HSM and never exported. The `private_key.bin` file exists only to simulate that boundary in the demo.

---

## CLI Reference

All commands communicate with the services over HTTP. The services must be running before using any command other than `keygen`.

### Book a ticket

```bash
# Interactive mode
python -m cli book

# From a JSON file (useful for demos and scripting)
python -m cli book --json demo_booking.json
```

Example `demo_booking.json`:
```json
{
  "ticket_type": "R",
  "train": "12051",
  "from_stn": "CSMT",
  "to_stn": "NDLS",
  "ticket_class": "3A",
  "travel_date": "2026-06-15",
  "departure_time": "06:00",
  "arrival_time": "10:00",
  "passengers": [
    {
      "name": "Rajan Kumar",
      "berth": "B2/14",
      "aadhaar": "123456789012",
      "dob": "1990-05-10"
    }
  ]
}
```

### Verify a ticket

```bash
# By PNR (fetches barcode from PRS service)
python -m cli verify --pnr PNR8472910 --tte TTE-MUM-047 --train 12051

# From a DataMatrix PNG image (simulates TTE scanning a physical ticket)
python -m cli verify --image tickets/scan.png --tte TTE-MUM-047 --train 12051

# With identity check (prompts for Aadhaar + DOB)
python -m cli verify --pnr PNR8472910 --tte TTE-MUM-047 --train 12051 --aadhaar
```

### Audit commands

```bash
python -m cli audit stats                          # Aggregated counts
python -m cli audit duplicates                     # All flagged duplicate UUIDs
python -m cli audit log <uuid>                     # All events for one ticket
```

### Chart commands

```bash
python -m cli chart show --train 12051 --date 2026-06-15
python -m cli chart clear --train 12051 --date 2026-06-15
```

### Attack demo commands

```bash
# Clone: copy a legitimate barcode to a new DataMatrix image
python -m cli clone --pnr PNR8472910

# Forge: tamper with a payload field, repack without re-signing
python -m cli forge --pnr PNR8472910 --field class --value 1A
```

---

## Demo Walkthrough

This sequence demonstrates all security properties end-to-end.

### 1. Book a legitimate ticket

```bash
python -m cli book --json demo_booking.json
```

Open the printed Ticket URL on your phone browser. You will see the ticket details and a DataMatrix barcode. Scan it with any 2D barcode scanner app — you will see the JSON payload followed by binary signature bytes.

### 2. Verify the legitimate ticket

```bash
python -m cli verify --pnr <PNR> --tte TTE-MUM-047 --train 12051
```

Expected output:
```
RESULT                  VALID

Falcon Signature        ✓ VALID
Chart Match             ✓ MATCHED
Duplicate               ✓ NO
Key Used                current
```

### 3. Clone attack — same barcode, second paper

```bash
python -m cli clone --pnr <PNR>
```

The clone command fetches the real ticket's packed bytes and generates a new DataMatrix PNG with identical content — same UUID, same valid signature. This simulates an attacker photographing a legitimate barcode and reprinting it.

Verify the original, then verify the clone:

```bash
python -m cli verify --pnr <PNR> --tte TTE-001 --train 12051         # → VALID
python -m cli verify --image tickets/CLONED_<PNR>_dm.png --tte TTE-002 --train 12051  # → DUPLICATE
python -m cli audit duplicates
```

The second scan returns `DUPLICATE`. The audit server marks both events and flags the UUID. The Falcon signature on the clone is valid — this attack is caught by the UUID deduplication layer, not the signature check.

### 4. Forgery attack — tampered payload field

```bash
python -m cli forge --pnr <PNR> --field class --value 1A
python -m cli verify --image tickets/FORGED_<PNR>_class_dm.png --tte TTE-001 --train 12051
```

Expected output:
```
RESULT                  FORGED

Falcon Signature        ✗ INVALID
```

The forge command modifies the `class` field in the payload JSON and repacks the binary with the original signature still attached. The signature now covers different bytes than what was signed, so `verify_signature` returns `False` immediately. The TTE sees `FORGED` before any other check runs.

### 5. Identity check

```bash
python -m cli verify --pnr <PNR> --tte TTE-001 --train 12051 --aadhaar
# Enter correct Aadhaar and DOB → Identity: PASSED

python -m cli verify --pnr <PNR> --tte TTE-001 --train 12051 --aadhaar
# Enter wrong Aadhaar → Identity: FAILED
```

The `id` field in the payload is `SHA256(aadhaar + "|" + dob)`. The TTE app recomputes this hash on-device from the passenger's input and compares it to the stored hash. The raw Aadhaar number is discarded from memory immediately after hashing and is never transmitted anywhere.

### 6. Check audit stats

```bash
python -m cli audit stats
```

---

## Verification Result Codes

| Code | Meaning |
|---|---|
| `VALID` | Signature valid, all checks passed |
| `FORGED` | Signature failed against both current and previous key |
| `DUPLICATE` | UUID seen before — audit server flagged this as a second scan |
| `EXPIRED` | Current time is after `vu` |
| `NOT_YET_VALID` | Current time is before `vf` |
| `WRONG_TRAIN` | Payload train number does not match TTE's session train |
| `WRONG_DATE` | Payload date does not match today's date |
| `INVALID_PNR` | UUID/berths not found in locally cached passenger chart |

`FORGED` is always checked first. If the signature is invalid, no other checks run — there is no point inspecting fields of a payload whose integrity cannot be proven.

---

## Running Tests

```bash
python tests/test_shared.py
```

32 tests covering `shared/crypto_utils.py` and `shared/payload.py`. No services need to be running. Tests include:

- Keypair generation produces correct sizes (1281 / 897 bytes)
- Signing returns exactly 666 bytes
- Valid signature verifies True
- Tampered signature verifies False
- Tampered payload verifies False
- Wrong public key verifies False
- `verify_signature` never raises for any garbage input
- Identity hash pipe separator prevents collision
- `pack → unpack` roundtrip preserves payload dict exactly
- Packed size for 6-passenger ticket fits within DataMatrix capacity (< 1558 bytes)
- Wire format structure is correct
- `unpack_signed_payload` rejects truncated and empty input

Expected runtime: 30–60 seconds (Falcon key generation is the slow step, called 8 times across the suite).

---

## Service API Reference

Full OpenAPI docs are available at `http://localhost:<port>/docs` for each service while running.

### CRIS Signing Service `:8001`

| Endpoint | Method | Description |
|---|---|---|
| `/sign` | POST | Sign a ticket payload. Returns `barcode_b64`, `uuid`, `pnr`. |
| `/public-key` | GET | Current and previous public keys (base64) and fingerprint. |
| `/health` | GET | Liveness check. Confirms private key is loaded. |

### Audit Server `:8002`

| Endpoint | Method | Description |
|---|---|---|
| `/log` | POST | Record a verification event. Returns `is_duplicate` flag. |
| `/duplicates` | GET | All UUIDs flagged as duplicate with full event history. |
| `/log/{uuid}` | GET | All events for a specific UUID. |
| `/stats` | GET | Aggregated counts by result code. |
| `/health` | GET | Liveness check. |

### HHT Service `:8003`

| Endpoint | Method | Description |
|---|---|---|
| `/verify` | POST | Full verification pipeline. Returns structured result. |
| `/chart/add` | POST | Add passengers to the local chart. |
| `/chart/{train}/{date}` | GET | View chart grouped by coach. |
| `/chart/{train}/{date}` | DELETE | Clear chart (end-of-journey wipe). |
| `/health` | GET | Liveness check. Confirms public key is loaded. |

### PRS Booking Service `:8000`

| Endpoint | Method | Description |
|---|---|---|
| `/book` | POST | Issue a ticket. Calls CRIS signer, generates DataMatrix, populates chart. |
| `/ticket/{pnr}` | GET | Phone-viewable HTML ticket page with embedded barcode. |
| `/ticket/{pnr}/qr` | GET | DataMatrix barcode PNG. |
| `/ticket/{pnr}/raw` | GET | Full ticket data including `barcode_b64` (for CLI/debug). |
| `/tickets` | GET | List all issued tickets (no barcode data). |
| `/health` | GET | Liveness check. |

---

## Directory Structure

```
railway-pq-auth-demo/
├── .env                        # Ports, DB path, key paths
├── .gitignore                  # keys/*.bin, db/*.db, tickets/*
├── Procfile                    # honcho: starts all 4 services
├── requirements.txt
├── README.md
│
├── keys/
│   ├── private_key.bin         # GITIGNORED — 1281 bytes
│   ├── public_key.bin          # 897 bytes
│   └── old_public_key.bin      # Present only after key rotation
│
├── db/
│   └── railway.db              # GITIGNORED — SQLite, created at runtime
│
├── tickets/                    # GITIGNORED — generated DataMatrix PNGs
│
├── shared/
│   ├── config.py               # Pydantic settings, reads .env
│   ├── database.py             # SQLAlchemy engine, session factory
│   ├── models.py               # ORM models: IssuedTicket, PassengerChart, AuditLog
│   ├── crypto_utils.py         # Falcon-padded-512 sign/verify, identity hash
│   └── payload.py              # Payload builder, binary pack/unpack
│
├── services/
│   ├── cris_signer/main.py     # Port 8001
│   ├── audit_server/main.py    # Port 8002
│   ├── hht_service/main.py     # Port 8003
│   └── prs_booking/
│       ├── main.py             # Port 8000
│       └── templates/
│           └── ticket.html     # Phone-viewable ticket page
│
├── cli/
│   ├── main.py                 # All CLI commands
│   └── __main__.py             # Entry point for python -m cli
│
├── scripts/
│   └── keygen.py               # Standalone key generation
│
└── tests/
    └── test_shared.py          # 32 unit tests for shared layer
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'pydantic_settings'`**
```bash
pip install "pydantic-settings==2.7.1"
```

**`TypeError: Can't replace canonical symbol for '__firstlineno__'` (SQLAlchemy)**

SQLAlchemy 2.0.30 is incompatible with Python 3.12+.
```bash
pip install "sqlalchemy==2.0.50"
```

**`liboqs version (major, minor) X.Y differs from liboqs-python version`**

This warning is usually safe to ignore if Falcon-padded-512 is available. Verify:
```bash
python -c "import oqs, warnings; warnings.filterwarnings('ignore'); print('Falcon-padded-512' in oqs.get_enabled_sig_mechanisms())"
```
Should print `True`.

**`Key generation failed: Falcon-padded-512`**

Your liboqs C library uses a different algorithm name. Check what names are available:
```bash
python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
```
Look for `Falcon-padded-512` or `ML-DSA-44` in the output. If neither is present, rebuild liboqs from the latest source.

**`Barcode generation failed: Could not encode data`**

The packed bytes are too large for the 144×144 DataMatrix symbol. This should not happen with Falcon-padded-512 for tickets up to 6 passengers. If you see this error, check that `scheme="Base256"` is being passed to `dm_encode` — without it, pylibdmtx uses ASCII encoding which expands binary data and will fail.

**`TypeError: Parameter.make_metavar() missing 1 required positional argument: 'ctx'`**

Typer/Click version mismatch on Python 3.14.
```bash
pip install "typer==0.13.1" "click==8.1.8"
```

**`CRIS Signer service is not reachable`**

Ensure all services are running:
```bash
honcho start
```
Or start the signer individually:
```bash
uvicorn services.cris_signer.main:app --port 8001 --reload
```

---

## Relationship to v1

This repo is a direct successor to [railway-auth-demo](https://github.com/dishitaghuge01/railway-auth-demo) (ECDSA P-256, QR codes). The architecture, API contracts, database schema, and CLI command structure are identical. Changes from v1 to v2:

| Concern | v1 (ECDSA) | v2 (Falcon) |
|---|---|---|
| Signing algorithm | ECDSA P-256 | Falcon-padded-512 (FIPS 206) |
| Barcode format | QR Code ECC Level H | DataMatrix ECC200 144×144 |
| Wire format | base64url JWT (`payload.sig`) | Binary: `[2B len][JSON][666B sig]` |
| Key format | PEM files (`.pem`) | Raw bytes (`.bin`) |
| Signature size | 64–72 bytes | 666 bytes (fixed) |
| Public key size | 64 bytes | 897 bytes |
| Private key size | 32 bytes | 1281 bytes |
| Quantum resistance | No (Shor's algorithm breaks ECDSA) | Yes (lattice hardness) |
| Python crypto lib | `cryptography` | `liboqs-python` |
| Python barcode lib | `qrcode[pil]` + `pyzbar` | `pylibdmtx` |

---

## Related

- [railway-auth-demo](https://github.com/dishitaghuge01/railway-auth-demo) — v1, ECDSA P-256
- [NIST FIPS 206](https://csrc.nist.gov/pubs/fips/206/final) — FN-DSA (Falcon) standard
- [Open Quantum Safe / liboqs](https://github.com/open-quantum-safe/liboqs) — C library used for Falcon
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) — Python bindings
- IEEE TENCON 2026 paper: *ArchIntel: Graph-Based Architectural Floor Plan Quality Assessment Using Space Syntax and LLM Integration*