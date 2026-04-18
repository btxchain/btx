#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Create consistent BTX wallet backups and optionally seal each wallet natively."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class BackupError(RuntimeError):
    """Raised when wallet backup export fails."""


@dataclass
class CLIContext:
    cli: str
    datadir: Path
    base_cli_args: list[str]

    def command(self, *args: str, wallet: str | None = None, extra_cli_args: list[str] | None = None) -> list[str]:
        cmd = [self.cli, f"-datadir={self.datadir}", *self.base_cli_args]
        if wallet:
            cmd.append(f"-rpcwallet={wallet}")
        if extra_cli_args:
            cmd.extend(extra_cli_args)
        cmd.extend(args)
        return cmd

    def run_text(
        self,
        *args: str,
        wallet: str | None = None,
        input_text: str | None = None,
        extra_cli_args: list[str] | None = None,
    ) -> str:
        cmd = self.command(*args, wallet=wallet, extra_cli_args=extra_cli_args)
        try:
            proc = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                input=input_text,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            stdout = (exc.stdout or "").strip()
            detail = stderr or stdout or f"command failed: {' '.join(cmd)}"
            raise BackupError(detail) from exc
        return proc.stdout.strip()

    def run_json(
        self,
        *args: str,
        wallet: str | None = None,
        input_text: str | None = None,
        extra_cli_args: list[str] | None = None,
    ) -> Any:
        output = self.run_text(*args, wallet=wallet, input_text=input_text, extra_cli_args=extra_cli_args)
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise BackupError(f"expected JSON from {' '.join(args)}, got: {output[:200]}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create BTX wallet backups plus descriptor/viewing-key exports, with optional native per-wallet archive sealing.",
    )
    parser.add_argument("--datadir", required=True, help="BTX datadir that contains the wallets and RPC cookie.")
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where the timestamped backup root will be created.",
    )
    parser.add_argument(
        "--cli",
        default="btx-cli",
        help="Path to the btx-cli binary (default: %(default)s).",
    )
    parser.add_argument(
        "--cli-arg",
        dest="cli_args",
        action="append",
        default=[],
        help="Extra argument to pass to every btx-cli invocation, for example --cli-arg=-regtest.",
    )
    parser.add_argument(
        "--wallet",
        dest="wallets",
        action="append",
        default=[],
        help="Wallet name to export. Repeat to limit the backup set; defaults to every wallet in listwalletdir.",
    )
    parser.add_argument(
        "--unlock-timeout",
        type=int,
        default=300,
        help="Seconds to keep an encrypted wallet unlocked while exporting private material (default: %(default)s).",
    )
    parser.add_argument(
        "--skip-viewing-keys",
        action="store_true",
        help="Skip z_exportviewingkey exports.",
    )
    parser.add_argument(
        "--encrypt-output",
        action="store_true",
        help="Export each wallet as a native encrypted bundle archive instead of a plaintext bundle directory.",
    )
    parser.add_argument(
        "--remove-plaintext",
        action="store_true",
        help="Accepted for compatibility; plaintext wallet bundle directories are not written when --encrypt-output is used.",
    )
    return parser.parse_args()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    path.chmod(0o700)


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as infile:
        for chunk in iter(lambda: infile.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record_wallet_warnings(warnings_handle, wallet: str, source: str, warnings: list[str]) -> None:
    for warning in warnings:
        warnings_handle.write(f"{wallet}\t{source}\t{warning}\n")


def record_integrity_result(warnings_handle, wallet: str, integrity: dict[str, Any]) -> None:
    warnings = list(integrity.get("warnings", []))
    if not integrity.get("integrity_ok", False) and not warnings:
        warnings = ["integrity verification failed without a detailed warning; inspect z_verifywalletintegrity.json"]
    record_wallet_warnings(warnings_handle, wallet, "integrity", warnings)


def select_wallets(ctx: CLIContext, requested: list[str]) -> list[str]:
    listed = ctx.run_json("listwalletdir")
    available = [entry["name"] for entry in listed["wallets"]]
    if not requested:
        return available

    missing = [wallet for wallet in requested if wallet not in available]
    if missing:
        raise BackupError(f"wallet(s) not present in listwalletdir: {', '.join(missing)}")
    return requested


def maybe_unlock_wallet(ctx: CLIContext, wallet: str, info: dict[str, Any], timeout: int) -> bool:
    if not info.get("private_keys_enabled", True):
        return False

    unlocked_until = info.get("unlocked_until")
    if unlocked_until is None or unlocked_until > 0:
        return False

    for attempt in range(3):
        passphrase = getpass.getpass(f"Wallet passphrase for '{wallet}': ")
        try:
            ctx.run_text("walletpassphrase", passphrase, str(timeout), wallet=wallet)
            return True
        except BackupError as exc:
            if attempt == 2:
                raise BackupError(f"failed to unlock wallet '{wallet}': {exc}") from exc
            print(f"Unlock failed for '{wallet}': {exc}", file=sys.stderr)
    return False


def export_wallet(
    ctx: CLIContext,
    wallet: str,
    wallet_dir: Path,
    unlock_timeout: int,
    skip_viewing_keys: bool,
    warnings_handle,
) -> dict[str, Any]:
    key_dir = wallet_dir / "shielded_viewing_keys"
    ensure_dir(wallet_dir)
    ensure_dir(key_dir)
    write_text(key_dir / "index.tsv", "")

    info = ctx.run_json("getwalletinfo", wallet=wallet)
    unlocked_by_script = maybe_unlock_wallet(ctx, wallet, info, unlock_timeout)
    try:
        if unlocked_by_script:
            info = ctx.run_json("getwalletinfo", wallet=wallet)

        integrity = ctx.run_json("z_verifywalletintegrity", wallet=wallet)
        record_integrity_result(warnings_handle, wallet, integrity)
        write_json(wallet_dir / "z_verifywalletintegrity.json", integrity)

        ctx.run_text("backupwallet", str(wallet_dir / f"{wallet}.backup.dat"), wallet=wallet)
        write_json(wallet_dir / "getwalletinfo.json", info)
        write_json(wallet_dir / "getbalances.json", ctx.run_json("getbalances", wallet=wallet))
        write_json(wallet_dir / "z_gettotalbalance.json", ctx.run_json("z_gettotalbalance", wallet=wallet))
        write_json(wallet_dir / "listdescriptors_public.json", ctx.run_json("listdescriptors", "false", wallet=wallet))

        if info.get("private_keys_enabled", True):
            write_json(wallet_dir / "listdescriptors_private.json", ctx.run_json("listdescriptors", "true", wallet=wallet))

        z_addrs = ctx.run_json("z_listaddresses", wallet=wallet)
        write_json(wallet_dir / "z_listaddresses.json", z_addrs)

        if not skip_viewing_keys:
            index_lines: list[str] = []
            for idx, entry in enumerate(z_addrs, start=1):
                address = entry if isinstance(entry, str) else entry["address"]
                address_hash = hashlib.sha256(address.encode("utf-8")).hexdigest()
                out_name = f"{idx}_{address_hash}.json"
                try:
                    viewing_key = ctx.run_json("z_exportviewingkey", address, wallet=wallet)
                except BackupError as exc:
                    warnings_handle.write(f"{wallet}\t{address}\tz_exportviewingkey failed: {exc}\n")
                    continue
                write_json(key_dir / out_name, viewing_key)
                index_lines.append(f"{out_name}\t{address}")
            write_text(key_dir / "index.tsv", "\n".join(index_lines) + ("\n" if index_lines else ""))
    finally:
        if unlocked_by_script:
            try:
                ctx.run_text("walletlock", wallet=wallet)
            except BackupError as exc:
                warnings_handle.write(f"{wallet}\twalletlock failed: {exc}\n")

    return {
        "wallet": wallet,
        "private_keys_enabled": info.get("private_keys_enabled", True),
        "encrypted": "unlocked_until" in info,
        "unlocked_by_script": unlocked_by_script,
        "backup_file": str(wallet_dir / f"{wallet}.backup.dat"),
        "export_dir": str(wallet_dir),
        "integrity_ok": bool(integrity.get("integrity_ok", False)),
        "integrity_warnings": integrity.get("warnings", []),
    }


def prompt_archive_passphrase() -> str:
    passphrase = getpass.getpass("Archive encryption passphrase: ")
    confirm = getpass.getpass("Confirm archive encryption passphrase: ")
    if passphrase != confirm:
        raise BackupError("archive passphrases did not match")
    if not passphrase:
        raise BackupError("archive passphrase cannot be empty")
    return passphrase


def export_wallet_archive(
    ctx: CLIContext,
    wallet: str,
    archive_path: Path,
    unlock_timeout: int,
    skip_viewing_keys: bool,
    archive_passphrase: str,
    warnings_handle,
) -> dict[str, Any]:
    info = ctx.run_json("getwalletinfo", wallet=wallet)
    unlocked_by_script = maybe_unlock_wallet(ctx, wallet, info, unlock_timeout)
    try:
        if unlocked_by_script:
            info = ctx.run_json("getwalletinfo", wallet=wallet)

        backup_args = [
            "backupwalletbundlearchive",
            str(archive_path),
            "",
        ]
        if skip_viewing_keys:
            backup_args.append("false")
        archive = ctx.run_json(
            *backup_args,
            wallet=wallet,
            input_text=archive_passphrase + "\n",
            extra_cli_args=["-stdinbundlepassphrase"],
        )
        record_wallet_warnings(warnings_handle, wallet, "archive", archive.get("warnings", []))
        record_integrity_result(warnings_handle, wallet, archive["integrity"])
    finally:
        if unlocked_by_script:
            try:
                ctx.run_text("walletlock", wallet=wallet)
            except BackupError as exc:
                warnings_handle.write(f"{wallet}\twalletlock failed: {exc}\n")

    return {
        "wallet": wallet,
        "private_keys_enabled": info.get("private_keys_enabled", True),
        "encrypted": "unlocked_until" in info,
        "unlocked_by_script": unlocked_by_script,
        "archive_file": archive["archive_file"],
        "archive_sha256": archive["archive_sha256"],
        "bundle_name": archive["bundle_name"],
        "bundle_files": archive["bundle_files"],
        "warnings": archive["warnings"],
        "integrity_ok": archive["integrity"]["integrity_ok"],
        "integrity_warnings": archive["integrity"].get("warnings", []),
    }


def main() -> int:
    args = parse_args()
    os.umask(0o077)
    if args.remove_plaintext and not args.encrypt_output:
        raise BackupError("--remove-plaintext requires --encrypt-output")

    datadir = Path(args.datadir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)

    ctx = CLIContext(cli=args.cli, datadir=datadir, base_cli_args=args.cli_args)

    walletdir_listing = ctx.run_json("listwalletdir")
    blockchain_info = ctx.run_json("getblockchaininfo")
    version_text = ctx.run_text("--version")
    initially_loaded = set(ctx.run_json("listwallets"))
    wallets = select_wallets(ctx, args.wallets)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = output_dir / f"{datadir.name}-{timestamp}"
    ensure_dir(backup_root)
    archive_passphrase = prompt_archive_passphrase() if args.encrypt_output else None

    manifest: dict[str, Any] = {
        "created_at_utc": timestamp,
        "datadir": str(datadir),
        "backup_root": str(backup_root),
        "chain": blockchain_info.get("chain"),
        "tip_height": blockchain_info.get("blocks"),
        "cli": args.cli,
        "cli_args": args.cli_args,
        "wallets": wallets,
        "initially_loaded_wallets": sorted(initially_loaded),
        "warnings_file": str(backup_root / "export_warnings.log"),
        "export_mode": "native-encrypted-archive" if args.encrypt_output else "directory",
    }

    write_json(backup_root / "blockchaininfo.json", blockchain_info)
    write_json(backup_root / "listwalletdir.json", walletdir_listing)
    write_text(backup_root / "blockcount.txt", str(blockchain_info.get("blocks", "")) + "\n")
    write_text(backup_root / "btx_cli_version.txt", version_text + "\n")
    write_text(backup_root / "wallets.txt", "\n".join(wallets) + ("\n" if wallets else ""))
    write_json(backup_root / "initial_loaded_wallets.json", sorted(initially_loaded))

    exported_wallets: list[dict[str, Any]] = []
    export_index_lines: list[str] = []
    loaded_by_script: list[str] = []

    warnings_path = backup_root / "export_warnings.log"
    warnings_path.touch(mode=0o600)
    warnings_path.chmod(0o600)

    try:
        with warnings_path.open("a", encoding="utf-8") as warnings_handle:
            for wallet in wallets:
                if wallet not in initially_loaded:
                    load_result = ctx.run_json("loadwallet", wallet)
                    record_wallet_warnings(warnings_handle, wallet, "loadwallet", load_result.get("warnings", []))
                    loaded_by_script.append(wallet)

                if args.encrypt_output:
                    archive_path = backup_root / f"{wallet}.bundle.btx"
                    exported = export_wallet_archive(
                        ctx=ctx,
                        wallet=wallet,
                        archive_path=archive_path,
                        unlock_timeout=args.unlock_timeout,
                        skip_viewing_keys=args.skip_viewing_keys,
                        archive_passphrase=archive_passphrase,
                        warnings_handle=warnings_handle,
                    )
                    export_index_lines.append(f"{wallet}\t{archive_path}")
                else:
                    wallet_dir = backup_root / wallet
                    exported = export_wallet(
                        ctx=ctx,
                        wallet=wallet,
                        wallet_dir=wallet_dir,
                        unlock_timeout=args.unlock_timeout,
                        skip_viewing_keys=args.skip_viewing_keys,
                        warnings_handle=warnings_handle,
                    )
                    export_index_lines.append(f"{wallet}\t{wallet_dir}")
                exported_wallets.append(exported)
                print(f"exported {wallet}")
    finally:
        for wallet in loaded_by_script:
            try:
                ctx.run_text("unloadwallet", wallet)
                print(f"unloaded {wallet}")
            except BackupError as exc:
                with warnings_path.open("a", encoding="utf-8") as warnings_handle:
                    warnings_handle.write(f"{wallet}\tunloadwallet failed: {exc}\n")

    final_loaded = ctx.run_json("listwallets")
    write_json(backup_root / "final_loaded_wallets.json", final_loaded)
    write_text(backup_root / "export_index.tsv", "\n".join(export_index_lines) + ("\n" if export_index_lines else ""))

    manifest["exported_wallets"] = exported_wallets
    manifest["loaded_by_script"] = loaded_by_script
    manifest["final_loaded_wallets"] = final_loaded
    manifest_path = backup_root / "manifest.json"
    write_json(manifest_path, manifest)

    print(f"backup_root={backup_root}")
    print(f"manifest={manifest_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BackupError as exc:
        print(f"wallet_secure_backup.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
