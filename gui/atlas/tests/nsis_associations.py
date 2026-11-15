#!/usr/bin/env python3
"""Windows-native component regression for Atlas's NSIS association hooks.

Requires Windows, Python 3, and an explicitly supplied installed NSIS 3 compiler:
  py tests/nsis_associations.py --makensis C:\\NSIS\\makensis.exe --out result.json
Use --baseline-macros C:\\path\\FileAssociation.nsh to run the same expectations
against the original vendor macros (regression failures still exit nonzero).
No downloads, administrator rights, real .btx/protocol keys, or shell launches.
This tests the actual macros in a minimal installer, not the full Tauri bundle.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


FIXTURE = r'''
Unicode true
RequestExecutionLevel user
SilentInstall silent
SilentUnInstall silent
Name "Disposable Atlas association regression"
OutFile "${OUTPUT}"
InstallDir "${DESTINATION}"
!include "${MACROS}"

Function .onInit
  SetShellVarContext current
  SetRegView 64
FunctionEnd
Function un.onInit
  SetShellVarContext current
  SetRegView 64
FunctionEnd

Section
  SetOutPath "$INSTDIR"
  !insertmacro APP_ASSOCIATE "${EXTENSION}" "${FILECLASS}" "Fixture handler" "$\"$INSTDIR\inert.exe$\",0" "Open fixture" "$\"$INSTDIR\inert.exe$\" $\"%1$\""
  ; A missing association/backup can leave NSIS's sticky error flag set.
  ClearErrors
  WriteUninstaller "$INSTDIR\uninstall.exe"
  IfErrors 0 +2
    Abort "Uninstaller creation failed"
SectionEnd

Section "Uninstall"
  !insertmacro APP_UNASSOCIATE "${EXTENSION}" "${FILECLASS}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  FileOpen $0 "${COMPLETION}" w
  FileWrite $0 "association-uninstall-finished"
  FileClose $0
SectionEnd
'''

MARKER = "association-uninstall-finished"
CASES = ("prior", "repeated", "later", "clean", "self-backup",
         "missing-backup", "later-self-backup", "later-reinstall")


def run(args, report):
    if sys.platform != "win32":
        raise RuntimeError("Requires native Windows; no emulated registry fallback")
    import winreg as reg

    compiler = Path(args.makensis).resolve(strict=True)
    macros = (Path(args.baseline_macros) if args.baseline_macros else
              Path(__file__).resolve().parents[1] / "src-tauri/windows/association-hooks.nsh")
    macros = macros.resolve(strict=True)
    if not compiler.is_file() or not macros.is_file():
        raise RuntimeError("Compiler and macro input must be files")
    report["inputs"] = {
        "makensis": str(compiler), "macros": str(macros),
        "macros_sha256": hashlib.sha256(macros.read_bytes()).hexdigest(),
        "baseline": bool(args.baseline_macros),
    }
    view = reg.KEY_WOW64_64KEY
    token = uuid.uuid4().hex
    scratch = Path(tempfile.mkdtemp(prefix="atlas-associations-" + token + "-"))
    owned_keys = []
    report.update(token=token, scratch=str(scratch))

    def command(argv, environment=None):
        result = subprocess.run(list(map(str, argv)), capture_output=True,
                                timeout=60, env=environment)
        report["commands"].append({"args": list(map(str, argv)),
                                   "exit": result.returncode,
                                   "stdout": result.stdout.decode("utf-8", "replace"),
                                   "stderr": result.stderr.decode("utf-8", "replace")})
        if result.returncode:
            raise RuntimeError("Native command failed: " + str(argv[0]))

    def tree(key):
        try:
            handle = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_READ | view)
        except FileNotFoundError:
            return None
        with handle:
            children, count, _ = reg.QueryInfoKey(handle)
            values = {}
            for index in range(count):
                name, value, kind = reg.EnumValue(handle, index)
                if isinstance(value, bytes):
                    value = {"hex": value.hex()}
                values[name] = {"type": kind, "value": value}
            return {"values": values, "children": {
                name: tree(key + "\\" + name)
                for name in (reg.EnumKey(handle, i) for i in range(children))}}

    def write(key, name, value, kind=reg.REG_SZ):
        with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_WRITE | view) as handle:
            reg.SetValueEx(handle, name, 0, kind, value)

    def remove(key):
        try:
            handle = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_READ | view)
        except FileNotFoundError:
            return
        with handle:
            children = [reg.EnumKey(handle, i) for i in range(reg.QueryInfoKey(handle)[0])]
        for child in children:
            remove(key + "\\" + child)
        reg.DeleteKeyEx(reg.HKEY_CURRENT_USER, key, view, 0)

    def check(case, label, actual, expected):
        report["checks"].append({"case": case, "check": label,
                                  "pass": actual == expected,
                                  "actual": actual, "expected": expected})

    def typed(value):
        return {"type": reg.REG_SZ, "value": value}

    def value(snapshot, key, name=""):
        return (snapshot[key] or {}).get("values", {}).get(name)

    def nsis(value):
        # /D definitions expand inside quoted NSIS strings, not shell commands.
        return str(value).replace("$", "$$").replace('"', '$\\"')

    try:
        command([compiler, "/VERSION"])
        for case in CASES:
            extension = "atlasprobe" + token + case.replace("-", "")
            progid = "AtlasProbe." + token + "." + case
            ext, own, prior, later = ["Software\\Classes\\" + name for name in
                                      ("." + extension, progid, progid + ".Prior", progid + ".Later")]
            keys = (ext, own, prior, later)
            # Claim only absent, UUID-namespaced keys; never remove a shared parent.
            if any(tree(key) is not None for key in keys):
                raise RuntimeError("Unexpected collision in disposable registry namespace")
            owned_keys.extend(keys)
            backup = progid + "_backup"
            prior_id, later_id = progid + ".Prior", progid + ".Later"
            for key, label in ((prior, "Prior"), (later, "Later")):
                write(key, "", label + " fixture handler")
                write(key + "\\shell\\open\\command", "", '"fixture-only.exe" "%1"')
                write(key, "typed-sentinel", 713, reg.REG_DWORD)
            write(ext, "unrelated", "keep-" + token)
            write(ext + "\\UnrelatedSubkey", "number", 991, reg.REG_DWORD)
            if case in ("self-backup", "missing-backup"):
                write(ext, "", progid)
                if case == "self-backup":
                    write(ext, backup, progid)
            elif case != "clean":
                write(ext, "", prior_id)

            case_dir = scratch / case
            case_dir.mkdir()
            destination = case_dir / "installed"
            completion = case_dir / "finished.txt"
            installer = case_dir / "install.exe"
            fixture = case_dir / "fixture.nsi"
            fixture.write_text(FIXTURE, encoding="utf-8")
            defines = {"OUTPUT": installer, "DESTINATION": destination,
                       "COMPLETION": completion, "MACROS": macros,
                       "EXTENSION": extension, "FILECLASS": progid}
            command([compiler, "/NOCD", "/V3", "/INPUTCHARSET", "UTF8",
                     *["/D" + key + "=" + nsis(val) for key, val in defines.items()], fixture])

            def snapshot(stage):
                observed = {key: tree(key) for key in keys}
                report["snapshots"].append({"case": case, "stage": stage,
                                             "keys": observed})
                return observed

            before = snapshot("before")

            def preserved(observed, stage):
                for key, label in ((prior, "prior definition"), (later, "later definition")):
                    check(case, stage + " preserves " + label, observed[key], before[key])
                check(case, stage + " preserves unrelated value",
                      value(observed, ext, "unrelated"), value(before, ext, "unrelated"))
                check(case, stage + " preserves unrelated subkey",
                      (observed[ext] or {}).get("children", {}).get("UnrelatedSubkey"),
                      before[ext]["children"]["UnrelatedSubkey"])

            def install(stage, expected_backup):
                command([installer, "/S"])
                observed = snapshot(stage)  # Always retain observations before assertions.
                check(case, stage + " sets default", value(observed, ext), typed(progid))
                check(case, stage + " retains backup", value(observed, ext, backup), expected_backup)
                check(case, stage + " creates command", (observed[own] or {}).get(
                    "children", {}).get("shell", {}).get("children", {}).get("open", {}).get(
                    "children", {}).get("command", {}).get("values", {}).get(""),
                    typed('"' + str(destination / "inert.exe") + '" "%1"'))
                preserved(observed, stage)
                if not (destination / "uninstall.exe").is_file():
                    raise RuntimeError(case + ": native uninstaller was not created")

            first_backup = (None if case == "missing-backup" else typed(
                progid if case == "self-backup" else "" if case == "clean" else prior_id))
            install("install", first_backup)
            if case == "repeated":
                install("reinstall", typed(prior_id))
            if case in ("later", "later-self-backup", "later-reinstall"):
                write(ext, "", later_id)
                if case == "later-self-backup":
                    write(ext, backup, progid)
                observed = snapshot("later-choice")
                preserved(observed, "later-choice")
                if case == "later-reinstall":
                    install("reinstall-after-later", typed(later_id))

            uninstall_temp = case_dir / "uninstall-temp"
            uninstall_temp.mkdir()
            environment = dict(os.environ, TEMP=str(uninstall_temp), TMP=str(uninstall_temp))
            command([destination / "uninstall.exe", "/S"], environment)
            # NSIS's default uninstaller self-copy outlives its launcher. Wait for
            # the final marker content, not launcher exit or mere file existence.
            deadline = time.monotonic() + 20
            while True:
                try:
                    finished = completion.read_text(encoding="ascii") == MARKER
                except OSError:
                    finished = False
                if finished or time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
            observed = snapshot("uninstall")
            if not finished:
                raise RuntimeError(case + ": native uninstaller completion marker timed out")
            expected = (later_id if case.startswith("later") else prior_id)
            actual = value(observed, ext)
            if case in ("clean", "self-backup", "missing-backup"):
                check(case, "leaves no prior handler", actual in (None, typed("")), True)
            else:
                check(case, "restores selected handler", actual, typed(expected))
            check(case, "removes owned class", observed[own], None)
            check(case, "does not leave dangling owned default", actual == typed(progid), False)
            check(case, "removes backup", value(observed, ext, backup), None)
            check(case, "removes install directory", destination.exists(), False)
            preserved(observed, "uninstall")
    finally:
        # Each cleanup failure is recorded independently so later keys still get
        # cleaned, and a primary runtime failure is not hidden by cleanup.
        for key in reversed(owned_keys):
            try:
                remove(key)
                if tree(key) is not None:
                    raise RuntimeError("Registry key remains: " + key)
            except (OSError, RuntimeError) as exc:
                report["errors"].append("Registry cleanup: " + repr(exc))
        deadline = time.monotonic() + 20
        while scratch.exists():
            try:
                shutil.rmtree(scratch)
            except OSError as exc:
                if time.monotonic() >= deadline:
                    report["errors"].append("Filesystem cleanup: " + repr(exc))
                    break
                time.sleep(0.1)
        report["cleanup"] = {"registry_keys": len(owned_keys),
                               "scratch_removed": not scratch.exists()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--makensis", required=True, help="Path to an existing native makensis.exe")
    parser.add_argument("--baseline-macros", help="Original vendor FileAssociation.nsh instead of Atlas's hook")
    parser.add_argument("--out", type=Path, help="Optional JSON observations, typed registry snapshots, and errors")
    args = parser.parse_args()
    report = {"schema": 1, "platform": platform.platform(), "python": sys.version,
              "scope": "Native NSIS macros; isolated HKCU 64-bit fixture keys; not full Tauri acceptance",
              "uninstaller_mode": "Default self-copy; final marker content with bounded wait",
              "commands": [], "snapshots": [], "checks": [], "errors": []}
    try:
        run(args, report)
    except Exception as exc:
        report["errors"].append(repr(exc))
    report["pass"] = (bool(report["checks"]) and not report["errors"] and
                       all(check["pass"] for check in report["checks"]))
    if args.out:
        try:
            args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            report["errors"].append("Cannot write JSON report: " + repr(exc))
            report["pass"] = False
    failures = [check for check in report["checks"] if not check["pass"]]
    print(json.dumps({"pass": report["pass"], "failures": failures, "errors": report["errors"]}, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
