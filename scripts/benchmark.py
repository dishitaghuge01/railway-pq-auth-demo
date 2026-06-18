"""
scripts/benchmark.py

Performance benchmark suite for the Railway PQ Auth Demo.

This script produces the numbers cited in the paper's abstract/Results
section: Falcon-padded-512 sign/verify latency and DataMatrix ECC200
encode/decode latency. It exists so those numbers have a committed,
reproducible source instead of being hand-measured once and typed into
the abstract.

Usage
-----
    python scripts/benchmark.py                  # full run, 300 trials/op
    python scripts/benchmark.py --trials 1000     # more trials, tighter CIs
    python scripts/benchmark.py --quick           # fast smoke test (30 trials)

No services need to be running. This talks directly to shared/crypto_utils.py,
shared/payload.py, and pylibdmtx — the same library calls the real services
make — so the numbers reflect actual library call latency, not network or
FastAPI overhead.

What is measured
-----------------
For both a 1-passenger and a 6-passenger reserved ticket (the realistic
min/max range for a single PNR):

  1. falcon_sign          — shared.crypto_utils.sign_payload() on the raw
                             JSON payload bytes that pack_signed_payload()
                             would sign.
  2. falcon_verify        — shared.crypto_utils.verify_signature() against
                             a known-valid signature.
  3. pack_signed_payload  — full application-layer signing path: JSON
                             serialise + sign + struct pack. This is what
                             CRIS actually calls per ticket.
  4. unpack_and_verify    — full application-layer verify path: struct
                             unpack + JSON parse + verify. This is what the
                             HHT actually calls per scan.
  5. datamatrix_encode    — pylibdmtx.encode() on the packed bytes
                             (Base256 scheme, 144x144), the call PRS makes
                             when issuing a ticket.
  6. datamatrix_decode    — pylibdmtx.decode() on the resulting image, the
                             call the HHT makes when scanning a ticket.

generate_keypair() is also timed, separately, a handful of times. It is
a one-time HSM operation at key rotation (every 6 months in the proposed
model), not a per-ticket cost, so it is reported separately and is NOT
included in any "combined" crypto figure.

Known correctness issue this script guards against
----------------------------------------------------
pylibdmtx's decode() truncates at the first 0x00 byte in the decoded
buffer (ctypes.string_at() with no explicit length defaults to strlen()
semantics). Since a Falcon signature is ~666 bytes of uniform-random
data, P(>=1 zero byte) ~ 92.6%, so an unpatched decode() silently
returns truncated bytes most of the time. This script applies the same
monkeypatch already used in cli/main.py (_patch_pylibdmtx_nul_truncation_bug)
and asserts the decoded bytes match the encoded input before trusting any
decode timing. If that assertion fails, the patch is broken or missing
and the reported decode numbers would be meaningless — the script raises
instead of silently writing bad data into the paper trail.

Output
------
Writes two files to benchmarks/ at the repo root:

  benchmarks/results.json   Machine-readable: every raw sample, summary
                             stats (mean/median/stdev/min/max/p95), and
                             full environment metadata (CPU, OS, Python,
                             liboqs, liboqs-python, pylibdmtx, Pillow
                             versions, trial/warmup counts, UTC timestamp).

  benchmarks/RESULTS.md     Human-readable report in the same format as
                             this README, meant to be linked or excerpted
                             directly in the paper's Results section.

Re-run this on the machine you are actually citing numbers for. Hardware
varies; the committed RESULTS.md should reflect the machine named in the
paper, not whatever machine happened to run it first.
"""

import argparse
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _pkg_version

# ---------------------------------------------------------------------------
# Path resolution — run from repo root: python scripts/benchmark.py
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from shared.crypto_utils import generate_keypair, sign_payload, verify_signature
from shared.payload import build_payload, pack_signed_payload, unpack_signed_payload

# ---------------------------------------------------------------------------
# ANSI colour helpers — same convention as scripts/keygen.py
# ---------------------------------------------------------------------------
def _green(s):  return f"\033[32m{s}\033[0m"
def _yellow(s): return f"\033[33m{s}\033[0m"
def _red(s):    return f"\033[31m{s}\033[0m"
def _bold(s):   return f"\033[1m{s}\033[0m"
def _cyan(s):   return f"\033[36m{s}\033[0m"


def _print_separator():
    print("─" * 70)


# ---------------------------------------------------------------------------
# pylibdmtx NUL-truncation patch
#
# Kept in sync with cli/main.py's _patch_pylibdmtx_nul_truncation_bug().
# Duplicated here rather than imported from cli/main.py so this script has
# no dependency on the CLI module (and its typer/click imports) — this is
# meant to run standalone, including in CI, with the minimum import surface.
# ---------------------------------------------------------------------------
_PYLIBDMTX_PATCHED = False


def _patch_pylibdmtx_nul_truncation_bug() -> None:
    global _PYLIBDMTX_PATCHED
    if _PYLIBDMTX_PATCHED:
        return

    import pylibdmtx.pylibdmtx as _dmtx_module
    from ctypes import string_at
    from pylibdmtx.wrapper import DmtxVector2, dmtxMatrix3VMultiplyBy

    def _decode_region_fixed(decoder, region, corrections, shrink):
        with _dmtx_module._decoded_matrix_region(decoder, region, corrections) as msg:
            if not msg:
                return None
            p00 = DmtxVector2()
            p11 = DmtxVector2(1.0, 1.0)
            dmtxMatrix3VMultiplyBy(p00, region.contents.fit2raw)
            dmtxMatrix3VMultiplyBy(p11, region.contents.fit2raw)
            x0 = int((shrink * p00.X) + 0.5)
            y0 = int((shrink * p00.Y) + 0.5)
            x1 = int((shrink * p11.X) + 0.5)
            y1 = int((shrink * p11.Y) + 0.5)
            data = string_at(msg.contents.output, msg.contents.outputIdx)
            return _dmtx_module.Decoded(
                data, _dmtx_module.Rect(x0, y0, x1 - x0, y1 - y0)
            )

    _dmtx_module._decode_region = _decode_region_fixed
    _PYLIBDMTX_PATCHED = True


# ---------------------------------------------------------------------------
# Environment / hardware info
# ---------------------------------------------------------------------------
def _safe_pkg_version(name: str) -> str:
    try:
        return _pkg_version(name)
    except PackageNotFoundError:
        return "unknown"


def collect_environment_info() -> dict:
    """
    Collect hardware and software environment metadata so benchmark
    numbers can be attributed to a specific machine and library version
    set, per the reviewer question this script exists to answer:
    "how did you measure this, on what hardware, how many trials?"
    """
    cpu_model = None
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        cpu_model = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
    elif platform.system() == "Darwin":
        try:
            import subprocess
            cpu_model = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"]
            ).decode().strip()
        except Exception:
            pass

    if not cpu_model:
        cpu_model = platform.processor() or "unknown — fill in manually before citing in the paper"

    try:
        import oqs
        liboqs_version = oqs.oqs_version()
        liboqs_python_version = oqs.oqs_python_version()
    except Exception as exc:
        liboqs_version = f"unknown ({exc})"
        liboqs_python_version = "unknown"

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu_model": cpu_model,
        "cpu_count_logical": os.cpu_count(),
        "os": platform.platform(),
        "machine_arch": platform.machine(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "liboqs_version": liboqs_version,
        "liboqs_python_version": liboqs_python_version,
        "pylibdmtx_version": _safe_pkg_version("pylibdmtx"),
        "pillow_version": _safe_pkg_version("Pillow"),
    }


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------
def time_call(fn, trials: int, warmup: int) -> list[float]:
    """
    Run fn() warmup times (discarded), then trials times, returning the
    wall-clock duration of each timed call in seconds (time.perf_counter).
    """
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return samples


def compute_stats(samples_sec: list[float]) -> dict:
    """Summary statistics in milliseconds from a list of second-denominated samples."""
    ms = sorted(s * 1000.0 for s in samples_sec)
    n = len(ms)
    p95_index = min(n - 1, int(round(0.95 * (n - 1))))
    return {
        "trials": n,
        "mean_ms": statistics.mean(ms),
        "median_ms": statistics.median(ms),
        "stdev_ms": statistics.stdev(ms) if n > 1 else 0.0,
        "min_ms": ms[0],
        "max_ms": ms[-1],
        "p95_ms": ms[p95_index],
    }


# ---------------------------------------------------------------------------
# Test fixture: a realistic ticket payload at a given passenger count
# ---------------------------------------------------------------------------
def _build_test_ticket(num_passengers: int, private_key: bytes) -> tuple[dict, bytes]:
    """
    Build a realistic reserved-ticket payload dict and its packed+signed
    bytes for `num_passengers` passengers, all with identity hashes
    present (the heavier, more representative case — Tatkal/AC classes
    require Aadhaar, and this maximises payload size for the given
    passenger count, which is the relevant case for capacity and
    worst-case timing claims).
    """
    payload = build_payload(
        ticket_type="R",
        uuid="550e8400-e29b-41d4-a716-446655440000",
        train="12051",
        from_stn="CSMT",
        to_stn="NDLS",
        ticket_class="3A",
        travel_date="2026-06-15",
        departure_unix=1_750_000_000,
        arrival_unix=1_750_010_000,
        passengers=[
            {
                "berth": f"B2/{i + 1}",
                "aadhaar": "123456789012",
                "dob": "1990-05-10",
            }
            for i in range(num_passengers)
        ],
    )
    packed = pack_signed_payload(payload, private_key)
    return payload, packed


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------
def run_benchmarks(trials: int, warmup: int, keygen_trials: int, keygen_warmup: int) -> dict:
    from pylibdmtx.pylibdmtx import encode as dm_encode, decode as dm_decode
    from PIL import Image

    _patch_pylibdmtx_nul_truncation_bug()

    print(_cyan(f"Generating a fresh Falcon-padded-512 keypair for this benchmark run..."))
    private_key, public_key = generate_keypair()

    results: dict = {"scenarios": {}}

    for num_passengers in (1, 6):
        label = f"{num_passengers}_passenger"
        print(_bold(f"\nScenario: {num_passengers}-passenger reserved ticket"))
        _print_separator()

        payload, packed = _build_test_ticket(num_passengers, private_key)
        _, raw_payload_bytes, raw_sig_bytes = unpack_signed_payload(packed)

        scenario: dict = {"packed_bytes": len(packed)}

        # --- raw Falcon primitives ---
        print("  Timing falcon_sign ...")
        sign_samples = time_call(
            lambda: sign_payload(raw_payload_bytes, private_key),
            trials=trials, warmup=warmup,
        )
        scenario["falcon_sign"] = compute_stats(sign_samples)

        print("  Timing falcon_verify ...")
        verify_samples = time_call(
            lambda: verify_signature(raw_payload_bytes, raw_sig_bytes, public_key),
            trials=trials, warmup=warmup,
        )
        scenario["falcon_verify"] = compute_stats(verify_samples)

        # --- full application-layer pipeline ---
        print("  Timing pack_signed_payload (serialise + sign + pack) ...")
        pack_samples = time_call(
            lambda: pack_signed_payload(payload, private_key),
            trials=trials, warmup=warmup,
        )
        scenario["pack_signed_payload"] = compute_stats(pack_samples)

        def _unpack_and_verify():
            _, rp, rs = unpack_signed_payload(packed)
            if not verify_signature(rp, rs, public_key):
                raise RuntimeError("benchmark fixture signature failed to verify — fixture is broken")

        print("  Timing unpack_and_verify (parse + struct unpack + verify) ...")
        unpack_verify_samples = time_call(_unpack_and_verify, trials=trials, warmup=warmup)
        scenario["unpack_and_verify"] = compute_stats(unpack_verify_samples)

        # --- DataMatrix barcode ---
        print("  Timing datamatrix_encode (pylibdmtx, Base256, 144x144) ...")
        encode_samples = time_call(
            lambda: dm_encode(packed, size="144x144", scheme="Base256"),
            trials=trials, warmup=warmup,
        )
        scenario["datamatrix_encode"] = compute_stats(encode_samples)

        # Build one encoded image to decode repeatedly, and verify the
        # round trip is byte-exact before trusting decode timings.
        encoded = dm_encode(packed, size="144x144", scheme="Base256")
        img = Image.frombytes("RGB", (encoded.width, encoded.height), encoded.pixels)
        decoded_check = dm_decode(img)
        if not decoded_check or decoded_check[0].data != packed:
            raise RuntimeError(
                "DataMatrix encode/decode round trip did not return the original "
                "bytes. The pylibdmtx NUL-truncation patch is missing or broken — "
                "decode timings would not correspond to a correct decode. Aborting "
                "rather than writing bad numbers to the paper trail."
            )

        print("  Timing datamatrix_decode (pylibdmtx) ...")
        decode_samples = time_call(lambda: dm_decode(img), trials=trials, warmup=warmup)
        scenario["datamatrix_decode"] = compute_stats(decode_samples)

        results["scenarios"][label] = scenario

        sign_mean = scenario["falcon_sign"]["mean_ms"]
        verify_mean = scenario["falcon_verify"]["mean_ms"]
        print(_green(
            f"  done. falcon sign+verify combined (mean): {sign_mean + verify_mean:.4f} ms"
        ))

    # --- key generation (one-time HSM op, reported separately) ---
    print(_bold("\nKey generation (one-time HSM operation, NOT a per-ticket cost)"))
    _print_separator()
    print(f"  Timing generate_keypair x{keygen_trials} (this is the slow one)...")
    keygen_samples = time_call(generate_keypair, trials=keygen_trials, warmup=keygen_warmup)
    results["key_generation"] = compute_stats(keygen_samples)

    return results


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------
def write_json_report(path: str, env: dict, args: argparse.Namespace, results: dict) -> None:
    payload = {
        "environment": env,
        "trials": args.trials,
        "warmup": args.warmup,
        "keygen_trials": args.keygen_trials,
        "keygen_warmup": args.keygen_warmup,
        "results": results,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def _fmt_row(name: str, stats: dict) -> str:
    return (
        f"| {name} | {stats['trials']} | {stats['mean_ms']:.4f} | "
        f"{stats['median_ms']:.4f} | {stats['stdev_ms']:.4f} | "
        f"{stats['min_ms']:.4f} | {stats['max_ms']:.4f} | {stats['p95_ms']:.4f} |"
    )


def write_markdown_report(path: str, env: dict, args: argparse.Namespace, results: dict) -> None:
    lines = []
    lines.append("# Performance Benchmark Results")
    lines.append("")
    lines.append(
        "Generated by `scripts/benchmark.py`. Re-run this script and regenerate "
        "this file before citing numbers in the paper if the target hardware "
        "or library versions change."
    )
    lines.append("")
    lines.append("## Environment")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Timestamp (UTC) | {env['timestamp_utc']} |")
    lines.append(f"| CPU | {env['cpu_model']} |")
    lines.append(f"| Logical cores | {env['cpu_count_logical']} |")
    lines.append(f"| OS | {env['os']} |")
    lines.append(f"| Architecture | {env['machine_arch']} |")
    lines.append(f"| Python | {env['python_implementation']} {env['python_version']} |")
    lines.append(f"| liboqs | {env['liboqs_version']} |")
    lines.append(f"| liboqs-python | {env['liboqs_python_version']} |")
    lines.append(f"| pylibdmtx | {env['pylibdmtx_version']} |")
    lines.append(f"| Pillow | {env['pillow_version']} |")
    lines.append(f"| Trials per operation | {args.trials} (warmup {args.warmup}, discarded) |")
    lines.append(
        f"| Key generation trials | {args.keygen_trials} (warmup {args.keygen_warmup}, discarded) |"
    )
    lines.append("")
    lines.append(
        "All timings use `time.perf_counter()` around a single library call, "
        "single-threaded, with no other load on the machine. Each operation "
        "reuses one Falcon keypair generated fresh for this run; warmup calls "
        "are discarded before timed trials begin."
    )
    lines.append("")

    for label, scenario in results["scenarios"].items():
        n = label.replace("_passenger", "")
        lines.append(f"## {n}-passenger reserved ticket (packed size: {scenario['packed_bytes']} bytes)")
        lines.append("")
        lines.append("| Operation | Trials | Mean (ms) | Median (ms) | Stdev (ms) | Min (ms) | Max (ms) | p95 (ms) |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        lines.append(_fmt_row("Falcon sign", scenario["falcon_sign"]))
        lines.append(_fmt_row("Falcon verify", scenario["falcon_verify"]))
        lines.append(_fmt_row("pack_signed_payload (serialise+sign+pack)", scenario["pack_signed_payload"]))
        lines.append(_fmt_row("unpack_and_verify (parse+verify)", scenario["unpack_and_verify"]))
        lines.append(_fmt_row("DataMatrix encode (Base256, 144x144)", scenario["datamatrix_encode"]))
        lines.append(_fmt_row("DataMatrix decode", scenario["datamatrix_decode"]))
        lines.append("")
        sign_mean = scenario["falcon_sign"]["mean_ms"]
        verify_mean = scenario["falcon_verify"]["mean_ms"]
        lines.append(
            f"Falcon sign + verify combined (mean): **{sign_mean + verify_mean:.4f} ms**"
        )
        lines.append("")

    lines.append("## Key generation (one-time HSM operation)")
    lines.append("")
    lines.append("Not a per-ticket cost — happens once per key rotation (every 6 months in the proposed model).")
    lines.append("")
    lines.append("| Operation | Trials | Mean (ms) | Median (ms) | Stdev (ms) | Min (ms) | Max (ms) | p95 (ms) |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    lines.append(_fmt_row("generate_keypair", results["key_generation"]))
    lines.append("")

    # Overall min/max across both scenarios for encode and decode, to
    # support a single cited range (e.g. "16-41 ms") in the abstract.
    all_encode = [s["datamatrix_encode"] for s in results["scenarios"].values()]
    all_decode = [s["datamatrix_decode"] for s in results["scenarios"].values()]
    overall_min = min(min(s["min_ms"] for s in all_encode), min(s["min_ms"] for s in all_decode))
    overall_max = max(max(s["max_ms"] for s in all_encode), max(s["max_ms"] for s in all_decode))
    all_sign = [s["falcon_sign"] for s in results["scenarios"].values()]
    all_verify = [s["falcon_verify"] for s in results["scenarios"].values()]
    combined_means = [
        results["scenarios"][label]["falcon_sign"]["mean_ms"]
        + results["scenarios"][label]["falcon_verify"]["mean_ms"]
        for label in results["scenarios"]
    ]

    lines.append("## Summary for citation")
    lines.append("")
    lines.append(
        f"- Falcon sign+verify combined, across both ticket sizes: "
        f"**{min(combined_means):.4f}-{max(combined_means):.4f} ms** (mean per scenario)"
    )
    lines.append(
        f"- DataMatrix encode/decode, across both ticket sizes, min-to-max single-trial range: "
        f"**{overall_min:.1f}-{overall_max:.1f} ms**"
    )
    lines.append("")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark Falcon sign/verify and DataMatrix encode/decode latency."
    )
    parser.add_argument("--trials", type=int, default=300, help="Timed trials per operation (default: 300)")
    parser.add_argument("--warmup", type=int, default=20, help="Discarded warmup calls per operation (default: 20)")
    parser.add_argument("--keygen-trials", type=int, default=15, help="Timed trials for generate_keypair (default: 15)")
    parser.add_argument("--keygen-warmup", type=int, default=3, help="Discarded warmup calls for generate_keypair (default: 3)")
    parser.add_argument(
        "--quick", action="store_true",
        help="Fast smoke test: overrides trials=30, warmup=5, keygen-trials=3, keygen-warmup=1",
    )
    parser.add_argument(
        "--output-dir", type=str, default=os.path.join(_repo_root, "benchmarks"),
        help="Directory to write results.json and RESULTS.md into (default: benchmarks/)",
    )
    args = parser.parse_args()

    if args.quick:
        args.trials = 30
        args.warmup = 5
        args.keygen_trials = 3
        args.keygen_warmup = 1

    _print_separator()
    print(_bold("Railway PQ Auth Demo — Performance Benchmark"))
    print(_bold("Falcon-padded-512 sign/verify + DataMatrix ECC200 encode/decode"))
    _print_separator()

    env = collect_environment_info()
    print(_cyan(f"CPU:      {env['cpu_model']}"))
    print(_cyan(f"OS:       {env['os']}"))
    print(_cyan(f"Python:   {env['python_implementation']} {env['python_version']}"))
    print(_cyan(f"liboqs:   {env['liboqs_version']} (liboqs-python {env['liboqs_python_version']})"))
    print(_cyan(f"pylibdmtx: {env['pylibdmtx_version']}, Pillow: {env['pillow_version']}"))
    print(_cyan(f"Trials:   {args.trials} per op (warmup {args.warmup}), keygen {args.keygen_trials} (warmup {args.keygen_warmup})"))

    results = run_benchmarks(
        trials=args.trials,
        warmup=args.warmup,
        keygen_trials=args.keygen_trials,
        keygen_warmup=args.keygen_warmup,
    )

    json_path = os.path.join(args.output_dir, "results.json")
    md_path = os.path.join(args.output_dir, "RESULTS.md")
    write_json_report(json_path, env, args, results)
    write_markdown_report(md_path, env, args, results)

    _print_separator()
    print(_green(f"Wrote {json_path}"))
    print(_green(f"Wrote {md_path}"))
    _print_separator()
    print(_yellow(
        "Reminder: re-run this on the exact machine you cite in the paper, "
        "then commit benchmarks/results.json and benchmarks/RESULTS.md. "
        "Numbers vary across hardware."
    ))


if __name__ == "__main__":
    main()