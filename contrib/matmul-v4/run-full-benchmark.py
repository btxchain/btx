#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
BTX MatMul v4.6 ENC_RC — turnkey full-workload benchmark.

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
                                            [--episodes N] [--backend auto|cpu]
                                            [--json OUT.json] [--quick]

    --shape   toy | medium | production | coupled-production  (default: production)
    --quick   run only the toy shape as a fast sanity pass
    --harness path to matmul-v4-rc-harness (else auto-located under build*/)

Exit status is 0 on a completed run, 2 if the harness could not be found (the
hardware analysis and backend map are still printed so the report is useful even
before you have built the binary).
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

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

Two execution regimes for the working set (~48-51 GiB at production):
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


def gpu_backend_note(gpus):
    if not gpus:
        return ("CPU only", "no GPU detected — mining/verify run on the CPU int64 path")
    g = max(gpus, key=lambda x: x["vram_total"])
    resident = g["vram_total"] >= RESIDENT_VRAM_FLOOR
    regime = "RESIDENT-class (>=64 GiB)" if resident else "STREAMED-class (<64 GiB)"
    return (f"{g['name']} — {gib(g['vram_total'])} VRAM",
            f"{regime}; native FP4/INT8 tensor path is attempted by default and "
            f"self-qualifies byte-exact on real silicon (else falls back to INT8, "
            f"reported by the harness as native_declined).")


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
    "production": ["--production"],
    "coupled-production": ["--coupled-production-v2"],
}


def run_harness(harness, shape, episodes, backend, mem_cap):
    # The harness writes its JSON report to the --out path (it treats "-" as a
    # literal filename, not stdout), so give it a real temp file and read it back.
    out_fd, out_path = tempfile.mkstemp(prefix="rc-bench-", suffix=".json")
    os.close(out_fd)
    argv = [harness] + SHAPE_FLAGS[shape] + \
        ["--episodes", str(episodes), "--backend", backend, "--out", out_path]
    if mem_cap:
        argv += ["--mem-cap", str(mem_cap)]
    print(dim("  $ " + " ".join(argv)))
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=7200)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(red(f"  harness invocation failed: {e}"))
        _unlink_quiet(out_path)
        return None, ""
    # The loud native/streamed banners go to stderr — surface them.
    if proc.stderr.strip():
        for ln in proc.stderr.strip().splitlines():
            print(yellow("  " + ln))
    blob = None
    try:
        with open(out_path) as f:
            blob = json.load(f)
    except (OSError, json.JSONDecodeError):
        # Fallback: some builds may still emit the JSON as the last {...} on stdout.
        m = re.search(r"\{.*\}\s*$", proc.stdout, re.DOTALL)
        if m:
            try:
                blob = json.loads(m.group(0))
            except json.JSONDecodeError:
                blob = None
    _unlink_quiet(out_path)
    return blob, proc.stdout


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
    args = ap.parse_args()
    if args.quick:
        args.shape = "toy"

    hr("BTX MatMul v4.6 ENC_RC — full-workload benchmark")
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
    gname, gnote = gpu_backend_note(gpus)
    print(f"  {cyan('[GPU]')}       {gname}")
    print(dim(f"              {gnote}"))

    # ---- Resident vs streamed decision (verbose) ---- #
    hr("Memory regime decision")
    mem_cap = 0
    top = max(gpus, key=lambda x: x["vram_total"]) if gpus else None
    if args.shape in ("production", "coupled-production") and top:
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
        print(dim("  (small/toy shape or no GPU — the working set fits trivially; the\n"
                  "   harness runs its default regime sweep.)"))

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
        return 2

    print(dim(f"  harness: {harness}"))
    blob, _ = run_harness(harness, args.shape, args.episodes, args.backend, mem_cap)

    hr("Results")
    report_run(blob)

    if args.json and blob is not None:
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
