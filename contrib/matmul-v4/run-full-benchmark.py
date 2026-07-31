#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
BTX MatMul v4.7 full-workload benchmark.

The default ``production`` shape is the Epoch-A Profile-1 ExactReplay workload.
Historical Profile-2 and coupled measurements require the explicit
``profile2-production`` or ``coupled-production`` shape. See
doc/btx-matmul-v4.7-transition-roadmap.md.

One command that (1) describes the full proof-of-work workload, (2) detects the
host hardware and states, per component, whether the OPTIMIZED path or a FALLBACK
will run, (3) decides resident-vs-streamed from actual VRAM and says WHY, and
(4) runs the real episode harness and reports every phase separately and combined.

This is an observation/measurement tool only. It never changes consensus, never flips
activation heights, and mines nothing. The numbers it prints come from the
`matmul-v4-rc-harness` binary (the same code path a miner runs); this script only
orchestrates, labels, and explains.

Usage:
    contrib/matmul-v4/run-full-benchmark.py [--harness PATH] [--shape SHAPE]
                                            [--episodes N] [--backend auto|cpu|DEVICE]
                                            [--json OUT.json] [--quick]

    --shape   toy | medium | production | profile1-production |
              profile2-production | coupled-production
              (``production`` aliases Profile 1; default: production)
    --quick   run only the toy shape as a fast sanity pass
    --harness path to matmul-v4-rc-harness (else auto-located under build*/)

Exit status is 0 only after a completed, schema-valid, passing run. Production
shapes require an explicit backend; ``--allow-production-cpu-auto`` is the
deliberate opt-in for an ``auto`` run that may resolve to CPU.
"""

import argparse
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------- #
# Small terminal helpers (no external deps; degrade to plain text when piped). #
# --------------------------------------------------------------------------- #
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def bold(s):   return _c("1", s)
def green(s):  return _c("32", s)
def yellow(s): return _c("33", s)
def red(s):    return _c("31", s)
def cyan(s):   return _c("36", s)
def dim(s):    return _c("2", s)


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def hr(title=""):
    width = 78
    if title:
        pad = width - len(title) - 4
        print(bold("== " + title + " " + "=" * max(0, pad)))
    else:
        print(bold("=" * width))


def gib(nbytes) -> str:
    return f"{nbytes / (1 << 30):.2f} GiB"


# --------------------------------------------------------------------------- #
# The workload description — printed verbatim so the report is self-contained. #
# --------------------------------------------------------------------------- #
WORKLOAD_DOC = """\
The ENC_RC episode is a chain-bound transformer forward pass evaluated as exact
integer (int8·int8 -> int64) arithmetic. One episode, in the order it executes:

  1. Operand generation (XOF)   PRF-derives the per-episode weights/activations
                                on-device via SHA-256. Hash-bound; scales with
                                the SHA lane (SHA-NI / SHA-ext / multibuffer).
  2. Attention  (QK^T, A·V)     Per layer. Deliberately kept SUB-dominant by the
                                n_ctx hash-bound guardrail (low arithmetic
                                intensity) so SHA-ASICs cannot win the episode.
  3. FFN up / down projections  Per layer. The DOMINANT arithmetic-intensity
                                work — this is what an AI accelerator's INT8/FP4
                                tensor cores accelerate. The economic core.
  4. Residual / curriculum      Chain-binds each layer's output into the next so
                                the episode cannot be precomputed or reordered.
  5. Merkle / transcript        Commits tiles for the succinct/relay proof path.

Profile-2/coupled research also has two execution regimes for its larger
working set (~48-51 GiB):
  * RESIDENT  — whole set held in VRAM (needs a >=64 GiB-class card, e.g. B200).
                The datacenter-advantage regime.
  * STREAMED  — set paged in chunks (bounded peak). What a 24/32 GB consumer
                card runs. Forced automatically when VRAM is insufficient.
"""


# --------------------------------------------------------------------------- #
# Hardware detection.                                                          #
# --------------------------------------------------------------------------- #
def detect_cpu():
    info = {"model": platform.processor() or "unknown", "arch": platform.machine(),
            "flags": set()}
    sysname = platform.system()
    if sysname == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                txt = f.read()
            m = re.search(r"model name\s*:\s*(.+)", txt)
            if m:
                info["model"] = m.group(1).strip()
            fm = re.search(r"^flags\s*:\s*(.+)$", txt, re.MULTILINE)
            if not fm:  # aarch64 uses "Features"
                fm = re.search(r"^Features\s*:\s*(.+)$", txt, re.MULTILINE)
            if fm:
                info["flags"] = set(fm.group(1).split())
        except OSError:
            pass
    elif sysname == "Darwin":
        def sysctl(key):
            try:
                return subprocess.check_output(["sysctl", "-n", key],
                                               text=True).strip()
            except (OSError, subprocess.CalledProcessError):
                return ""
        info["model"] = sysctl("machdep.cpu.brand_string") or info["model"]
        # Apple silicon exposes capability via hw.optional.*; SHA-2 + int8 matmul
        # (SMMLA) are present on M-series. x86 macs expose machdep.cpu.features.
        feats = (sysctl("machdep.cpu.features") + " " +
                 sysctl("machdep.cpu.leaf7_features")).lower().split()
        info["flags"] = set(feats)
        if info["arch"] in ("arm64", "aarch64"):
            info["flags"].add("_apple_silicon")
    return info


def cpu_feature(flags, arch, *names):
    return any(n in flags for n in names)


def detect_gpus():
    """Return a list of {vendor, name, vram_total, vram_free} in bytes."""
    gpus = []

    # NVIDIA
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.check_output(
                ["nvidia-smi",
                 "--query-gpu=name,memory.total,memory.free",
                 "--format=csv,noheader,nounits"], text=True)
            for line in out.strip().splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == 3:
                    gpus.append({"vendor": "nvidia", "name": parts[0],
                                 "vram_total": int(float(parts[1])) << 20,
                                 "vram_free": int(float(parts[2])) << 20})
        except (OSError, subprocess.CalledProcessError, ValueError):
            pass

    # AMD
    if shutil.which("rocm-smi"):
        try:
            out = subprocess.check_output(
                ["rocm-smi", "--showmeminfo", "vram", "--json"], text=True)
            data = json.loads(out)
            for card, fields in data.items():
                tot = fields.get("VRAM Total Memory (B)")
                used = fields.get("VRAM Total Used Memory (B)")
                if tot is not None:
                    tot = int(tot)
                    free = tot - int(used) if used is not None else None
                    gpus.append({"vendor": "amd", "name": card,
                                 "vram_total": tot,
                                 "vram_free": free if free is not None else tot})
        except (OSError, subprocess.CalledProcessError, ValueError, KeyError):
            pass

    # Apple
    if platform.system() == "Darwin" and platform.machine() in ("arm64", "aarch64"):
        # Unified memory: report system RAM as the VRAM budget.
        try:
            mem = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"],
                                              text=True).strip())
            gpus.append({"vendor": "apple", "name": "Apple GPU (unified memory)",
                         "vram_total": mem, "vram_free": mem})
        except (OSError, subprocess.CalledProcessError, ValueError):
            pass

    return gpus


# --------------------------------------------------------------------------- #
# Backend map: for each component, which path WILL run on this host.           #
# --------------------------------------------------------------------------- #
RESIDENT_VRAM_FLOOR = 64 << 30          # kRCResidentVramFloorBytes
PRODUCTION_WORKING_SET = 48 << 30       # ~48 GiB V2 expanded int8 resident set


def cpu_backend_map(cpu):
    flags, arch = cpu["flags"], cpu["arch"]
    is_arm = arch in ("arm64", "aarch64")
    rows = []

    if is_arm:
        sha = cpu_feature(flags, arch, "sha2", "sha256", "_apple_silicon")
        rows.append(("Operand XOF (SHA-256)",
                     "ARM SHA-2 (SHA-NI)" if sha else "scalar",
                     sha))
        i8mm = cpu_feature(flags, arch, "i8mm", "_apple_silicon")
        rows.append(("FFN int8 recompute",
                     "SMMLA / i8mm" if i8mm else "NEON/scalar", i8mm))
        rows.append(("SV attention recompute", "NEON/scalar", None))
    else:
        sha = cpu_feature(flags, arch, "sha_ni", "sha")
        rows.append(("Operand XOF (SHA-256)",
                     "x86 SHA-NI" if sha else "AVX2 multibuffer / scalar", sha))
        vnni = cpu_feature(flags, arch, "avx512_vnni", "avx512vnni")
        avx2 = cpu_feature(flags, arch, "avx2")
        if vnni:
            rows.append(("FFN int8 recompute", "AVX-512-VNNI", True))
        elif avx2:
            rows.append(("FFN int8 recompute", "AVX2 (VPMADDUBSW)", True))
        else:
            rows.append(("FFN int8 recompute", "scalar", False))
        rows.append(("SV attention recompute",
                     "AVX2 int64-chunked" if avx2 else "scalar", avx2))
    return rows


def gpu_backend_note(gpus, large_profile):
    if not gpus:
        return ("CPU only", "no GPU detected — mining/verify run on the CPU int64 path")
    g = max(gpus, key=lambda x: x["vram_total"])
    if large_profile:
        resident = g["vram_total"] >= RESIDENT_VRAM_FLOOR
        regime = (
            "Profile-2 RESIDENT-class (>=64 GiB)"
            if resident else "Profile-2 STREAMED-class (<64 GiB)"
        )
    else:
        regime = "Profile-1 ExactReplay accelerator"
    return (f"{g['name']} — {gib(g['vram_total'])} VRAM",
            f"{regime}; production defaults to exact-gated dense INT8. Native "
            f"FP4/Ozaki is correctness-qualified but remains an explicit "
            f"measurement mode until separately production-eligible.")


# --------------------------------------------------------------------------- #
# Harness location + run.                                                      #
# --------------------------------------------------------------------------- #
def locate_harness(explicit):
    if explicit:
        return explicit if os.path.exists(explicit) else None
    if shutil.which("matmul-v4-rc-harness"):
        return shutil.which("matmul-v4-rc-harness")
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for base in ("build", "build_l4", "build_release", "out"):
        for sub in ("src", "bin", os.path.join("src", "bin")):
            cand = os.path.join(root, base, sub, "matmul-v4-rc-harness")
            if os.path.exists(cand):
                return cand
    return None


SHAPE_FLAGS = {
    "toy": [],  # harness default
    "medium": ["--medium"],
    "production": ["--base-production"],
    "profile1-production": ["--base-production"],
    "profile2-production": ["--production"],
    "coupled-production": ["--coupled-production-v2"],
}

PRODUCTION_SHAPES = {
    "production",
    "profile1-production",
    "profile2-production",
    "coupled-production",
}

EXIT_HARNESS_NOT_FOUND = 2
EXIT_INVOCATION_FAILED = 3
EXIT_TIMEOUT = 4
EXIT_HARNESS_FAILED = 5
EXIT_INVALID_REPORT = 6
EXIT_BACKEND_POLICY = 7


def run_harness(harness, shape, episodes, backend, mem_cap, timeout_seconds=7200):
    # The harness writes its JSON report to the --out path (it treats "-" as a
    # literal filename, not stdout), so give it a real temp file and read it back.
    out_fd, out_path = tempfile.mkstemp(prefix="rc-bench-", suffix=".json")
    os.close(out_fd)
    argv = [harness] + SHAPE_FLAGS[shape] + \
        ["--episodes", str(episodes), "--backend", backend, "--out", out_path]
    if mem_cap:
        argv += ["--mem-cap", str(mem_cap)]
    print(dim("  $ " + " ".join(argv)), flush=True)
    print(cyan(f"  STARTED: backend={backend}; timeout={timeout_seconds:g}s; "
               "progress is reported every 30s."), flush=True)
    stdout_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    stderr_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    started = time.monotonic()
    try:
        proc = subprocess.Popen(argv, stdout=stdout_file, stderr=stderr_file, text=True)
    except OSError as e:
        print(red(f"  harness invocation failed: {e}"))
        _unlink_quiet(out_path)
        stdout_file.close()
        stderr_file.close()
        return None, "", EXIT_INVOCATION_FAILED

    timed_out = False
    while proc.poll() is None:
        elapsed = time.monotonic() - started
        remaining = timeout_seconds - elapsed
        if remaining <= 0:
            timed_out = True
            proc.kill()
            proc.wait()
            break
        try:
            proc.wait(timeout=min(30.0, remaining))
        except subprocess.TimeoutExpired:
            print(dim(f"  progress: harness still running "
                      f"({time.monotonic() - started:.0f}s)"), flush=True)

    stdout_file.seek(0)
    stderr_file.seek(0)
    stdout = stdout_file.read()
    stderr = stderr_file.read()
    stdout_file.close()
    stderr_file.close()

    # The loud native/streamed banners go to stderr — surface them.
    if stderr.strip():
        for ln in stderr.strip().splitlines():
            print(yellow("  " + ln))
    if timed_out:
        print(red(f"  harness timed out after {timeout_seconds:g}s"))
        _unlink_quiet(out_path)
        return None, stdout, EXIT_TIMEOUT
    if proc.returncode != 0:
        print(red(f"  harness exited with status {proc.returncode}"))
        if stdout.strip():
            print(dim("  harness stdout:\n" + stdout.rstrip()))
        _unlink_quiet(out_path)
        return None, stdout, EXIT_HARNESS_FAILED

    blob = None
    try:
        with open(out_path) as f:
            blob = json.load(f)
    except (OSError, json.JSONDecodeError):
        # Fallback: some builds may still emit the JSON as the last {...} on stdout.
        m = re.search(r"\{.*\}\s*$", stdout, re.DOTALL)
        if m:
            try:
                blob = json.loads(m.group(0))
            except json.JSONDecodeError:
                blob = None
    _unlink_quiet(out_path)
    return blob, stdout, 0


def validate_report(blob, shape, episodes, requested_backend):
    """Return schema/correctness failures for a purported completed run."""
    errors = []
    if not isinstance(blob, dict):
        return ["report root is not a JSON object"]
    if blob.get("tool") != "rc-episode-harness":
        errors.append("tool must be rc-episode-harness")
    version = blob.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 2:
        errors.append("schema_version must be an integer >= 2")
    if blob.get("stub") is not False:
        errors.append("stub must be false")
    provider = blob.get("backend")
    if not isinstance(provider, str) or not provider.strip():
        errors.append("backend provider is missing")

    qual = blob.get("extractmx_self_qual")
    if not isinstance(qual, dict):
        errors.append("extractmx_self_qual object is missing")
    else:
        if qual.get("status") != "pass":
            errors.append("extractmx_self_qual.status is not pass")
        measured_episodes = qual.get("episodes")
        if (not isinstance(measured_episodes, int) or
                isinstance(measured_episodes, bool) or
                measured_episodes < episodes):
            errors.append("extractmx_self_qual.episodes is incomplete")

    walls = blob.get("phase_wall_s")
    total = walls.get("total") if isinstance(walls, dict) else None
    if (not isinstance(total, (int, float)) or isinstance(total, bool) or
            total < 0 or total != total or
            total in (float("inf"), float("-inf"))):
        errors.append("phase_wall_s.total is missing or invalid")

    if shape in PRODUCTION_SHAPES and blob.get("production_dims") is not True:
        errors.append("production run did not report production_dims=true")

    cpu_provider = isinstance(provider, str) and provider.lower() in {
        "cpu", "cpu_reference", "serial_cpu", "reference",
    }
    if shape in PRODUCTION_SHAPES and requested_backend not in ("auto", "cpu"):
        if cpu_provider:
            errors.append(
                f"explicit accelerator {requested_backend!r} resolved to CPU")
    return errors


# --------------------------------------------------------------------------- #
# Report a single run's numbers, separate and combined.                       #
# --------------------------------------------------------------------------- #
def report_run(blob):
    if not blob:
        print(red("  no JSON parsed from harness output (see raw output above)"))
        return

    # Native FP4 / fallback status — the optimized-vs-fallback truth for the GPU.
    mx = blob.get("native_mxfp4")
    if mx is not None:
        if mx.get("qualified"):
            print("  " + green(f"native FP4 ACTIVE: {mx.get('selected_backend','?')} "
                               f"({mx.get('arch_key','?')})"))
        elif mx.get("native_declined"):
            print("  " + red("native FP4 DEACTIVATED -> INT8 fallback; reason: "
                             + (mx.get("deficit_reason") or "unspecified")))
        else:
            print("  " + yellow("native FP4 not built into this binary -> INT8/CPU path"))

    # Per-phase (separate) and combined.
    walls = blob.get("phase_wall_s") or {}
    if walls:
        bank = walls.get("bank"); barr = walls.get("barriers"); tot = walls.get("total")
        print("  phase walls (separate):")
        if bank is not None:  print(f"      operand/bank : {bank:.4f} s")
        if barr is not None:  print(f"      barriers/FFN : {barr:.4f} s")
        if tot is not None:   print("  " + bold(f"    COMBINED total: {tot:.4f} s"))

    # Resident vs streamed comparison, when both were measured.
    mode_walls = blob.get("mode_walls")
    if isinstance(mode_walls, list) and mode_walls:
        print("  execution regimes:")
        for mw in mode_walls:
            if isinstance(mw, dict) and "mode" in mw:
                print(f"      {mw['mode']:<16} {mw.get('wall_s', float('nan')):.4f} s")
    coup = blob.get("coupled") or {}
    if coup.get("auto_streamed"):
        print("  " + yellow("regime: STREAMED was forced (working set exceeded the "
                            "memory budget) — see VRAM analysis above."))
    ratio = coup.get("stream_vs_resident_wall_ratio")
    if ratio:
        print(f"      stream/resident wall ratio: {ratio:.3f}")

    if blob.get("digest"):
        print(dim(f"  digest: {blob['digest']}  modes_match="
                  f"{blob.get('modes_digest_match')}  mine_ok="
                  f"{blob.get('mine_matches_cpu')}"))


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="BTX ENC_RC turnkey full-workload benchmark")
    ap.add_argument("--harness")
    ap.add_argument("--shape", default="production", choices=list(SHAPE_FLAGS))
    ap.add_argument("--episodes", type=int, default=3)
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--json")
    ap.add_argument("--quick", action="store_true", help="toy shape, fast sanity pass")
    ap.add_argument(
        "--allow-production-cpu-auto",
        action="store_true",
        help="explicitly permit production --backend auto even if it resolves to CPU",
    )
    ap.add_argument(
        "--timeout-seconds",
        type=float,
        default=7200,
        help="harness timeout in seconds (default: 7200)",
    )
    args = ap.parse_args()
    if args.quick:
        args.shape = "toy"
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        ap.error("--timeout-seconds must be positive")
    if (args.shape in PRODUCTION_SHAPES and args.backend == "auto" and
            not args.allow_production_cpu_auto):
        print(red(
            "Refusing production --backend auto: select an explicit accelerated "
            "backend (for example cuda, hip, metal, or ascend), use --backend cpu "
            "for a deliberate reference run, or pass --allow-production-cpu-auto."
        ))
        return EXIT_BACKEND_POLICY

    hr("BTX MatMul v4.7 ENC_RC — full-workload benchmark")
    print(WORKLOAD_DOC)

    # ---- Hardware ---- #
    hr("Host hardware")
    cpu = detect_cpu()
    print(f"  OS/arch : {platform.system()} {platform.release()} / {cpu['arch']}")
    print(f"  CPU     : {cpu['model']}")
    gpus = detect_gpus()
    for g in gpus:
        print(f"  GPU     : {g['name']}  total={gib(g['vram_total'])} "
              f"free={gib(g['vram_free'])}")
    if not gpus:
        print("  GPU     : none detected")

    # ---- Backend map: optimized vs fallback, per component ---- #
    hr("Backend map — OPTIMIZED vs FALLBACK on THIS host")
    print(dim("  (which kernel each component will actually run — a FALLBACK here is\n"
              "   a performance gap to fix on this hardware, not a broken result.)"))
    for name, path, optimized in cpu_backend_map(cpu):
        if optimized is True:
            tag = green("[OPTIMIZED]")
        elif optimized is False:
            tag = red("[FALLBACK] ")
        else:
            tag = yellow("[baseline] ")
        print(f"  {tag} {name:<26} -> {path}")
    large_profile = args.shape in ("profile2-production", "coupled-production")
    gname, gnote = gpu_backend_note(gpus, large_profile)
    print(f"  {cyan('[GPU]')}       {gname}")
    print(dim(f"              {gnote}"))

    # ---- Resident vs streamed decision (verbose) ---- #
    hr("Memory regime decision")
    mem_cap = 0
    top = max(gpus, key=lambda x: x["vram_total"]) if gpus else None
    if large_profile and top:
        free = top["vram_free"]
        need = PRODUCTION_WORKING_SET
        print(f"  production resident working set ~= {gib(need)}")
        print(f"  {top['name']} free VRAM          ~= {gib(free)}")
        if free < need:
            mem_cap = free
            print("  " + yellow(
                f"DECISION: free VRAM ({gib(free)}) < working set ({gib(need)}) "
                f"-> FORCING STREAMED."))
            print(dim("  Streaming pages the set in bounded chunks; it is the correct,\n"
                      "  supported path for this card — not a failure. A >=64 GiB card\n"
                      "  (e.g. B200) would hold it RESIDENT and skip the paging."))
        else:
            print("  " + green(
                f"DECISION: free VRAM ({gib(free)}) >= working set ({gib(need)}) "
                f"-> RESIDENT eligible."))
    else:
        print(dim("  (Profile 1, small/toy shape, or no GPU — the Profile-2\n"
                  "   48 GiB resident/streamed decision does not apply.)"))

    # ---- Run ---- #
    hr(f"Running episode harness — shape={args.shape}, episodes={args.episodes}, "
       f"backend={args.backend}")
    harness = locate_harness(args.harness)
    if not harness:
        print(red("  matmul-v4-rc-harness not found."))
        print("  Build it, then re-run this script:")
        print(dim("      cmake --build build --target matmul-v4-rc-harness"))
        print("\n  The hardware analysis and backend map above are still valid and\n"
              "  tell you exactly which paths WILL run once the binary exists.")
        return EXIT_HARNESS_NOT_FOUND

    print(dim(f"  harness: {harness}"))
    blob, _, run_status = run_harness(
        harness,
        args.shape,
        args.episodes,
        args.backend,
        mem_cap,
        timeout_seconds=args.timeout_seconds,
    )
    if run_status != 0:
        return run_status

    errors = validate_report(blob, args.shape, args.episodes, args.backend)
    if errors:
        hr("Results")
        print(red("  invalid or failed harness report:"))
        for error in errors:
            print(red(f"    - {error}"))
        return EXIT_INVALID_REPORT

    hr("Results")
    report_run(blob)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(blob, f, indent=2)
        print(dim(f"\n  full JSON written to {args.json}"))

    hr("Summary")
    print("  This run measured the "
          + bold(args.shape)
          + " ENC_RC workload. Any [FALLBACK]/native_declined line above is a\n"
          "  concrete optimization gap for THIS hardware — the code ran, but not on\n"
          "  its fastest path. Fix those to close the gap; the numbers are honest\n"
          "  either way because every path is gated byte-exact to the int64 oracle.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
