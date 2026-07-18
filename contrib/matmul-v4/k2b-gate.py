#!/usr/bin/env python3
# MatMul v4.2 / ENC-BMX4C — K.2b GO/NO-GO aggregator (decision-support tool).
#
# WHAT THIS IS. `measure-hardware.sh <backend> --profile bmx4c --mt24` produces
# ONE machine-readable `matmul-v4-report-*.json` PER box/backend (schema_version
# 2). Settling ENC-BMX4C's activation gate has always required a human to collect
# those JSONs across datacenter / consumer / Apple silicon and apply the spec's
# decision rule by hand (see doc/btx-matmul-v4.2-datacenter-measurement-runbook.md
# §2.3: "Aggregation is manual ... there is no automated aggregator in this repo").
# This script IS that aggregator: point it at the collected JSONs, label each with
# its {vendor, class}, and it prints a single GO / NO-GO verdict plus every
# blocking reason, and exits 0 (GO) / 1 (NO-GO) / 2 (usage/parse error).
#
# WHAT THIS IS NOT. This is a HUMAN decision-support tool run OFFLINE, before an
# activation episode — it does NOT wire measurements into consensus. Per the
# runbook §0.7-(4) the protocol reads none of this; only humans do, in the open.
# Automating the tally does not change that: `nMatMulBMX4CHeight` stays INT32_MAX
# until humans read this verdict and act. The script fabricates nothing — with
# today's inputs (no on-device BMX4-C kernel wired anywhere yet, so every non-CPU
# backend honestly reports native_path_eligible=false, and only CPU-reference
# runs exist) it prints NO-GO with the exact reason, which is the truthful state.
#
# THE DECISION RULE (faithful to doc/btx-matmul-v4.2-bmx4c-spec.md §5.3/§7.5/§9,
# the runbook §2.3, and ACTIVATION.md Gate C). GO requires ALL of:
#   G1  bit-exactness       every collected report bit_exact==true AND stage-
#                           bit-exact==true. A FAIL is a hard consensus-split
#                           signal (runbook §1.0/§2.2) -> immediate NO-GO.
#   G2  correct profile     every report is the ENC-BMX4C profile (schema_version
#                           2). v4.1/ENC-S8 reports carry no M-t24 verdict and are
#                           excluded from the gate with a note.
#   G3  M-t24 cross-vendor   native_path_eligible==true on frontier silicon from
#                           >= 2 INDEPENDENT vendors, AND at least one of them a
#                           datacenter-class part (spec §9 item 1; two parts from
#                           the same vendor do NOT satisfy the cross-vendor bar).
#                           CPU-reference runs never count as frontier silicon.
#   G4  tensor majority      tensor_share_pct > 50 on every measured frontier part
#                           (spec §9 item 4 / §K.2b; the report tool itself flips
#                           its own per-box verdict to NO-GO at <= 50%).
#   G5  no reward inversion   device-measured throughput is strictly ordered
#                           datacenter > consumer > apple (the WHOLE POINT: more
#                           powerful AI silicon must win). A run counts as
#                           device-measured ONLY when a native device kernel is
#                           wired (mt24.device_native_kernel_wired) AND the backend
#                           is not CPU; a CPU-reference nonce/s is NOT a device
#                           rate, so an all-CPU-reference set leaves G5 UNVERIFIED
#                           (which blocks GO) rather than inventing an ordering.
#
# LABELS. {vendor, class} are decision inputs the report JSON does not carry, so
# the operator supplies them, keyed by the report's own `host`/`backend`:
#   --manifest parts.tsv   TSV rows:  <host-or-file>\t<vendor>\t<class>[\t<part>]
#   --label   host=vendor:class[:part]   (repeatable; overrides the manifest)
# class in {datacenter, consumer, apple, other}. backend==cpu is auto-labeled
# vendor=reference class=cpu-ref no matter what (a CPU is the consensus reference,
# never a frontier data point — runbook §1.3). An unlabeled non-CPU report is
# included in G1/G2 but excluded from G3/G4/G5 with an explicit "needs label" note.
#
# Usage:
#   contrib/matmul-v4/k2b-gate.py results/                       # a dir of JSONs
#   contrib/matmul-v4/k2b-gate.py a.json b.json --manifest parts.tsv
#   contrib/matmul-v4/k2b-gate.py results/ --label b200=nvidia:datacenter:B200 \
#       --label mi355=amd:datacenter:MI355X --label 5090=nvidia:consumer:RTX5090
#   contrib/matmul-v4/k2b-gate.py results/ --json            # machine-readable out
#
# Stdlib only (json, argparse, glob, pathlib). No third-party deps, no network.

import argparse
import glob
import json
import os
import sys

VALID_CLASSES = {"datacenter", "consumer", "apple", "other", "cpu-ref"}
FRONTIER_CLASSES = {"datacenter", "consumer", "other"}  # silicon that can bear M-t24
# Strict no-inversion order (index = rank; higher rank must be strictly faster).
CLASS_ORDER = ["apple", "consumer", "datacenter"]


def die(msg, code=2):
    sys.stderr.write("k2b-gate: " + msg + "\n")
    sys.exit(code)


def load_reports(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.json"))))
        else:
            files.append(p)
    if not files:
        die("no JSON reports found in the given path(s)")
    reports = []
    for f in files:
        try:
            with open(f, "r") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            die("cannot parse %s: %s" % (f, e))
        if data.get("tool") != "matmul-v4-report":
            die("%s is not a matmul-v4-report JSON (tool=%r)" % (f, data.get("tool")))
        data["_file"] = os.path.basename(f)
        reports.append(data)
    return reports


def parse_labels(manifest_path, label_args):
    """Return {key: (vendor, class, part)} keyed by host-or-file token."""
    labels = {}
    if manifest_path:
        try:
            with open(manifest_path, "r") as fh:
                for lineno, raw in enumerate(fh, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    cols = line.split("\t")
                    if len(cols) < 3:
                        die("manifest %s line %d: need >=3 tab-separated columns "
                            "(host, vendor, class[, part])" % (manifest_path, lineno))
                    key, vendor, cls = cols[0].strip(), cols[1].strip(), cols[2].strip().lower()
                    part = cols[3].strip() if len(cols) > 3 else ""
                    labels[key] = (vendor, cls, part)
        except OSError as e:
            die("cannot read manifest %s: %s" % (manifest_path, e))
    for lab in label_args or []:
        if "=" not in lab:
            die("--label must be host=vendor:class[:part], got %r" % lab)
        key, spec = lab.split("=", 1)
        bits = spec.split(":")
        if len(bits) < 2:
            die("--label value must be vendor:class[:part], got %r" % spec)
        vendor, cls = bits[0].strip(), bits[1].strip().lower()
        part = bits[2].strip() if len(bits) > 2 else ""
        labels[key.strip()] = (vendor, cls, part)
    for _, (_, cls, _) in labels.items():
        if cls not in VALID_CLASSES:
            die("label class %r invalid; use one of %s"
                % (cls, ", ".join(sorted(VALID_CLASSES))))
    return labels


def label_for(rep, labels):
    """Resolve (vendor, class, part) for a report; CPU is always the reference."""
    backend = rep.get("backend", "")
    host = rep.get("host", "")
    if backend == "cpu":
        return ("reference", "cpu-ref", "CPU")
    # Match by filename, then host, then host/backend — first hit wins.
    for key in (rep["_file"], rep["_file"].replace(".json", ""), host,
                "%s/%s" % (host, backend), backend):
        if key in labels:
            return labels[key]
    # Loose contains-match on host so 'b200' labels a 'matmul-v4-report-b200-x.json'.
    for key, val in labels.items():
        if key and (key in rep["_file"] or key in host):
            return val
    return (None, None, None)  # unlabeled non-CPU


def stage_bit_exact(rep):
    st = rep.get("stages") or {}
    # schema 2 nests bit_exact inside stages; tolerate either spelling.
    return bool(st.get("bit_exact", rep.get("bit_exact", False)))


def device_measured(rep):
    """True only when this run's throughput reflects the DEVICE, not the host CPU."""
    if rep.get("backend") == "cpu":
        return False
    mt24 = rep.get("mt24") or {}
    return bool(mt24.get("device_native_kernel_wired", False))


def throughput_nps(rep):
    st = rep.get("stages") or {}
    # bmx4c reports emit the rate as cpu_reference_nonce_per_s (host CPU today);
    # a real device path, once wired, populates the same field with the device rate.
    v = st.get("cpu_reference_nonce_per_s")
    if v is None:
        v = rep.get("backend_nonce_per_s")
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def evaluate(reports, labels):
    rows, reasons, notes = [], [], []
    frontier = []  # labeled, non-CPU, bmx4c reports

    for rep in reports:
        vendor, cls, part = label_for(rep, labels)
        is_bmx4c = (rep.get("schema_version") == 2 and rep.get("profile") == "bmx4c")
        be = bool(rep.get("bit_exact", False)) and stage_bit_exact(rep)
        npe = bool(rep.get("native_path_eligible", False))
        tsp = rep.get("tensor_share_pct")
        try:
            tsp = float(tsp) if tsp is not None else None
        except (TypeError, ValueError):
            tsp = None
        row = {
            "file": rep["_file"], "host": rep.get("host", ""),
            "backend": rep.get("backend", ""), "vendor": vendor, "class": cls,
            "part": part or "", "bmx4c": is_bmx4c, "bit_exact": be,
            "native_path_eligible": npe, "tensor_share_pct": tsp,
            "device_measured": device_measured(rep), "nps": throughput_nps(rep),
        }
        rows.append(row)

        # G1 — a bit-exactness FAIL is a hard consensus-split signal.
        if not be:
            reasons.append("G1 bit-exactness FAIL on %s (%s/%s) — a consensus-split "
                           "signal; NO-GO regardless of any other gate."
                           % (rep["_file"], vendor or "?", rep.get("backend", "?")))
        # G2 — wrong profile carries no M-t24 verdict.
        if not is_bmx4c:
            notes.append("%s is not an ENC-BMX4C report (schema_version=%r "
                         "profile=%r) — excluded from the M-t24 gate."
                         % (rep["_file"], rep.get("schema_version"), rep.get("profile")))
            continue
        if rep.get("backend") == "cpu":
            notes.append("%s is a CPU-reference run — certifies the harness, never "
                         "counts as frontier silicon (runbook §1.3)." % rep["_file"])
            continue
        if cls is None:
            notes.append("%s (host=%s backend=%s) is UNLABELED — included in G1/G2 "
                         "but excluded from G3/G4/G5. Add --label %s=vendor:class."
                         % (rep["_file"], rep.get("host", "?"), rep.get("backend", "?"),
                            rep.get("host") or rep["_file"]))
            continue
        frontier.append(row)

    # G3 — M-t24 native-path eligibility on >= 2 independent vendors, >=1 datacenter.
    eligible = [r for r in frontier if r["native_path_eligible"]]
    eligible_vendors = sorted({r["vendor"] for r in eligible})
    has_dc = any(r["class"] == "datacenter" for r in eligible)
    g3 = len(eligible_vendors) >= 2 and has_dc
    if not g3:
        if not eligible:
            reasons.append("G3 M-t24: NO frontier part reports native_path_eligible="
                           "true. (Today no on-device BMX4-C kernel is wired for any "
                           "backend, so every non-CPU run honestly reports false — "
                           "spec §9 item 1 / ACTIVATION.md Gate C item C2.)")
        elif len(eligible_vendors) < 2:
            reasons.append("G3 M-t24: eligible on only %d vendor(s) {%s}; spec §9 item 1 "
                           "requires >= 2 INDEPENDENT vendors' frontier parts."
                           % (len(eligible_vendors), ", ".join(eligible_vendors)))
        elif not has_dc:
            reasons.append("G3 M-t24: eligible vendors {%s} but none datacenter-class; "
                           "need >= 1 datacenter frontier part."
                           % ", ".join(eligible_vendors))

    # G4 — tensor-stage majority on every measured frontier part.
    g4_fail = [r for r in frontier if r["tensor_share_pct"] is not None
               and r["tensor_share_pct"] <= 50.0]
    missing_tsp = [r for r in frontier if r["tensor_share_pct"] is None]
    g4 = (len(frontier) > 0 and not g4_fail and not missing_tsp)
    for r in g4_fail:
        reasons.append("G4 tensor-majority FAIL on %s: tensor_share_pct=%.1f%% <= 50%% "
                       "(§K.2b) — the combine is a MINORITY of wall time on this device."
                       % (r["file"], r["tensor_share_pct"]))
    for r in missing_tsp:
        reasons.append("G4 tensor-majority: %s carries no tensor_share_pct." % r["file"])

    # G5 — no reward inversion: device-measured throughput strictly DC > consumer > apple.
    measured = [r for r in frontier if r["device_measured"] and r["nps"] is not None]
    class_best = {}
    for r in measured:
        c = r["class"]
        if c not in CLASS_ORDER:
            continue
        if c not in class_best or r["nps"] > class_best[c]["nps"]:
            class_best[c] = r
    present = [c for c in CLASS_ORDER if c in class_best]
    if len(present) < 2:
        g5 = False
        if not measured:
            reasons.append("G5 no-inversion: UNVERIFIED — no DEVICE-measured throughput "
                           "in the set (a CPU-reference nonce/s is not a device rate). "
                           "Need real on-silicon rates once device kernels are wired.")
        else:
            reasons.append("G5 no-inversion: only class(es) {%s} have device-measured "
                           "throughput; need >= 2 of {datacenter, consumer, apple} to "
                           "check ordering." % ", ".join(present))
    else:
        g5 = True
        inversions = []
        for i in range(len(present) - 1):
            lo, hi = present[i], present[i + 1]  # hi must be strictly faster than lo
            if not (class_best[hi]["nps"] > class_best[lo]["nps"]):
                inversions.append(
                    "%s (%.3g nonce/s) !> %s (%.3g nonce/s)"
                    % (hi, class_best[hi]["nps"], lo, class_best[lo]["nps"]))
        if inversions:
            g5 = False
            reasons.append("G5 REWARD INVERSION detected — more powerful silicon does "
                           "NOT win: " + "; ".join(inversions) + ". This is the exact "
                           "failure the whole design exists to prevent.")

    gates = {"G1_bit_exact": all(r["bit_exact"] for r in rows),
             "G2_profile": all(r["bmx4c"] for r in rows if r["backend"] != "cpu"),
             "G3_mt24_cross_vendor": g3, "G4_tensor_majority": g4,
             "G5_no_inversion": g5}
    # G2 is a GO gate per §5.3/§7.5/§9 (see header): every device-measured report
    # MUST be the production ENC-BMX4C profile (schema_version 2, profile "bmx4c"),
    # or the measurement does not certify the profile that will actually ship. The
    # earlier `or True` (and G2's absence from `go`) silently neutralised it, so a
    # device report on the wrong profile would still read GO. Wire it in for real.
    go = gates["G1_bit_exact"] and gates["G2_profile"] and g3 and g4 and g5
    return go, gates, rows, reasons, notes, {
        "eligible_vendors": eligible_vendors, "frontier_count": len(frontier),
        "measured_classes": present}


def print_human(go, gates, rows, reasons, notes, extra):
    W = 92
    print("=" * W)
    print("MatMul ENC-BMX4C — K.2b GO/NO-GO aggregate verdict")
    print("=" * W)
    hdr = "%-26s %-8s %-9s %-11s %-6s %-7s %-9s %s" % (
        "file", "backend", "vendor", "class", "bitex", "mt24", "tensor%", "nonce/s")
    print(hdr)
    print("-" * W)
    for r in rows:
        tsp = "%.1f" % r["tensor_share_pct"] if r["tensor_share_pct"] is not None else "-"
        nps = ("%.3g%s" % (r["nps"], "" if r["device_measured"] else "*")) if r["nps"] is not None else "-"
        print("%-26s %-8s %-9s %-11s %-6s %-7s %-9s %s" % (
            r["file"][:26], r["backend"], (r["vendor"] or "UNLABELED")[:9],
            (r["class"] or "-")[:11], "YES" if r["bit_exact"] else "NO",
            "YES" if r["native_path_eligible"] else "no", tsp, nps))
    print("-" * W)
    print("  (* = host CPU-reference nonce/s, NOT a device rate — excluded from G5)")
    print()
    print("Gate results:")
    labels = {"G1_bit_exact": "G1 bit-exactness (no consensus split)",
              "G3_mt24_cross_vendor": "G3 M-t24 native-path on >=2 vendors (>=1 DC)",
              "G4_tensor_majority": "G4 tensor-stage majority (>50%)",
              "G5_no_inversion": "G5 no reward inversion (DC > consumer > apple)"}
    for k in ["G1_bit_exact", "G3_mt24_cross_vendor", "G4_tensor_majority", "G5_no_inversion"]:
        print("  [%s] %s" % ("PASS" if gates[k] else "FAIL", labels[k]))
    if notes:
        print("\nNotes:")
        for n in notes:
            print("  - " + n)
    if reasons:
        print("\nBlocking reasons:")
        for r in reasons:
            print("  - " + r)
    print()
    print("=" * W)
    if go:
        print("VERDICT: GO — all K.2b gates satisfied. Humans may now ratify activation")
        print("         (set nMatMulBMX4CHeight) per ACTIVATION.md Gate C. This tool does")
        print("         not and cannot flip consensus itself.")
    else:
        print("VERDICT: NO-GO — see blocking reasons above. nMatMulBMX4CHeight stays")
        print("         INT32_MAX. This is the correct, honest state until real on-silicon")
        print("         cross-vendor measurement clears every gate.")
    print("=" * W)


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate matmul-v4-report JSONs into one ENC-BMX4C K.2b GO/NO-GO verdict.")
    ap.add_argument("paths", nargs="+", help="JSON report files and/or directories of them")
    ap.add_argument("--manifest", help="TSV: <host-or-file>\\t<vendor>\\t<class>[\\t<part>]")
    ap.add_argument("--label", action="append", default=[],
                    help="host=vendor:class[:part] (repeatable; overrides manifest)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of a table")
    args = ap.parse_args()

    reports = load_reports(args.paths)
    labels = parse_labels(args.manifest, args.label)
    go, gates, rows, reasons, notes, extra = evaluate(reports, labels)

    if args.json:
        print(json.dumps({"verdict": "GO" if go else "NO-GO", "gates": gates,
                          "rows": rows, "blocking_reasons": reasons, "notes": notes,
                          "summary": extra}, indent=2))
    else:
        print_human(go, gates, rows, reasons, notes, extra)
    sys.exit(0 if go else 1)


if __name__ == "__main__":
    main()
