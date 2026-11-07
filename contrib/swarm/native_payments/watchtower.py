#!/usr/bin/env python3
"""Persistent, owner-presigned HTLC refund recovery for isolated BTX regtest.

No wallet signing RPC is called. Each registration is one bounded authorization:
exact funding outpoint, descriptor terms, owner destination, lock height, fee cap,
and already-signed refund transaction. This is an HTLC recovery watch, not a
revocable-channel punishment protocol or evidence of production L2 safety.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from decimal import Decimal
from typing import Any, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_MONEY = 21_000_000 * 100_000_000
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class PaymentError(RuntimeError):
    pass


class RPC(Protocol):
    def call(self, method: str, *params: Any) -> Any: ...


def atoms(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise PaymentError("atoms require a canonical decimal integer")
    text = str(value)
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        raise PaymentError("atoms require a canonical decimal integer")
    number = int(text)
    if number > MAX_MONEY:
        raise PaymentError("atoms exceed MoneyRange")
    return number


def coin_atoms(value: Any) -> int:
    value = Decimal(str(value)) * 100_000_000
    if value != value.to_integral_value():
        raise PaymentError("fractional atom in node response")
    return atoms(str(int(value)))


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class CookieRPC:
    """Loopback HTTP endpoint with a cookie read per request; no secret in argv."""
    def __init__(self, endpoint: str, cookie: Path, timeout: float = 15):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1", "localhost")
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise PaymentError("use a loopback HTTP RPC endpoint, optionally with a wallet path")
        self.endpoint, self.cookie, self.timeout = endpoint, cookie, timeout
        self.request_id = 0

    def call(self, method: str, *params: Any) -> Any:
        self.request_id += 1
        secret = self.cookie.read_text(encoding="utf-8").strip().encode()
        payload = canonical({"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}).encode()
        request = Request(self.endpoint, payload, {
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(secret).decode(),
        })
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
        except Exception as exc:
            # Network messages can contain authenticated URLs. Never echo them.
            raise PaymentError(f"RPC transport failed ({type(exc).__name__})") from None
        if len(raw) > 16 * 1024 * 1024:
            raise PaymentError("RPC response limit exceeded")
        result = json.loads(raw, parse_float=Decimal)
        if result.get("id") != self.request_id or result.get("error"):
            error = result.get("error") or {}
            raise PaymentError(f"RPC {method} failed ({error.get('code', 'response')})")
        return result["result"]


class RefundWatchtower:
    def __init__(self, database: Path, rpc: RPC):
        self.rpc = rpc
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.database.is_symlink():
            raise PaymentError("refuse a symlink database")
        # Exclusive create avoids making an existing database/world-readable
        # journal visible even briefly. SQLite journals inherit this mode.
        try:
            fd = os.open(self.database, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        except FileExistsError:
            if not self.database.is_file():
                raise PaymentError("database is not a regular file")
        os.chmod(self.database, 0o600)
        self.db = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("""CREATE TABLE IF NOT EXISTS refunds (
            outpoint TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
            authorization TEXT NOT NULL, authorization_hash TEXT NOT NULL,
            raw_hex TEXT NOT NULL, refund_txid TEXT NOT NULL,
            state TEXT NOT NULL, last_tip TEXT, last_error TEXT,
            submitted_at INTEGER, receipt TEXT)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, outpoint TEXT NOT NULL,
            kind TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL)""")

    def close(self) -> None:
        self.db.close()

    @contextlib.contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def network(self) -> dict[str, Any]:
        info = self.rpc.call("getblockchaininfo")
        if info.get("chain") != "regtest":
            raise PaymentError("this unqualified recovery profile is restricted to isolated regtest")
        if info.get("initialblockdownload") is True or info.get("headers", 0) > info.get("blocks", 0):
            raise PaymentError("chain view is not synchronized")
        if not HEX64.fullmatch(info.get("bestblockhash", "")):
            raise PaymentError("invalid chain tip")
        return info

    def _event(self, point: str, kind: str, payload: Any):
        self.db.execute("INSERT INTO events(outpoint,kind,payload,created_at) VALUES(?,?,?,?)",
                        (point, kind, canonical(payload), int(time.time())))

    def register(self, funding_txid: str, frozen: dict[str, Any], destination: str,
                 refund_hex: str, fee_cap_atoms: str, sequence: int = 1) -> dict[str, Any]:
        self.network()
        if not HEX64.fullmatch(funding_txid) or isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= 2**63 - 1:
            raise PaymentError("invalid funding id or authorization sequence")
        if not isinstance(refund_hex, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", refund_hex) or len(refund_hex) > 8_000_000:
            raise PaymentError("invalid bounded signed refund hex")
        principal, cap = atoms(frozen.get("amount_atoms")), atoms(fee_cap_atoms)
        if principal <= cap:
            raise PaymentError("refund fee cap must leave positive owner proceeds")
        height = frozen.get("refund_height")
        if isinstance(height, bool) or not isinstance(height, int) or not 0 < height < 500_000_000:
            raise PaymentError("refund height must be a CLTV block height")
        owner = self.rpc.call("getaddressinfo", destination)
        if owner.get("ismine") is not True or not isinstance(owner.get("scriptPubKey"), str):
            raise PaymentError("refund destination is not owned by the selected wallet")
        status = self.rpc.call("getmodelfundingsettlement", funding_txid, frozen)
        if status.get("funded") is not True or status.get("state") != "FUNDED":
            raise PaymentError("funding output is not confirmed and unspent")
        vout = status.get("funding_vout")
        if isinstance(vout, bool) or not isinstance(vout, int) or vout < 0:
            raise PaymentError("invalid funding outpoint")
        decoded = self.rpc.call("decoderawtransaction", refund_hex)
        inputs, outputs = decoded.get("vin", []), decoded.get("vout", [])
        if (len(inputs) != 1 or inputs[0].get("txid") != funding_txid or inputs[0].get("vout") != vout
                or inputs[0].get("sequence", 0xFFFFFFFF) == 0xFFFFFFFF
                or decoded.get("locktime") != height or not inputs[0].get("txinwitness")):
            raise PaymentError("refund does not bind the exact outpoint, CLTV, and witness")
        witness = inputs[0]["txinwitness"]
        refund_leaf = status.get("refund_leaf")
        if (not isinstance(witness, list) or len(witness) < 3 or not isinstance(refund_leaf, str)
                or not refund_leaf or witness[-2] != refund_leaf):
            raise PaymentError("refund witness does not use the native contract's refund leaf")
        if len(outputs) != 1 or outputs[0].get("scriptPubKey", {}).get("hex") != owner["scriptPubKey"]:
            raise PaymentError("refund must pay one owner-controlled destination")
        paid = coin_atoms(outputs[0].get("value"))
        if paid <= 0 or paid > principal or principal - paid > cap:
            raise PaymentError("refund exceeds the authorized fee cap")
        txid = decoded.get("txid")
        if not HEX64.fullmatch(txid or ""):
            raise PaymentError("invalid refund transaction id")
        # Include only immutable contract fields. Caller summaries such as
        # 'settled'/'complete' have no effect and are not durable authorities.
        terms = {key: frozen[key] for key in ("key_hash", "claimant", "refund_pubkey", "refund_height", "amount_atoms")}
        if "release_id" in frozen:
            terms["release_id"] = frozen["release_id"]
        if "funding_blockhash" in frozen:
            terms["funding_blockhash"] = frozen["funding_blockhash"]
        authorization = {
            "funding_txid": funding_txid, "funding_vout": vout,
            "terms": terms, "destination": destination, "destination_script": owner["scriptPubKey"],
            "fee_cap_atoms": str(cap), "principal_atoms": str(principal), "refund_height": height,
            "refund_txid": txid, "sequence": sequence,
        }
        point = f"{funding_txid}:{vout}"
        body = canonical(authorization)
        digest = hashlib.sha256(body.encode()).hexdigest()
        with self.transaction():
            old = self.db.execute("SELECT * FROM refunds WHERE outpoint=?", (point,)).fetchone()
            if old:
                if old["authorization_hash"] == digest and old["raw_hex"].lower() == refund_hex.lower():
                    return {"outpoint": point, "state": old["state"], "duplicate": True}
                previous = json.loads(old["authorization"])
                # A higher sequence can replace a signed fee variant, never
                # the owner, hashlock, principal, or CLTV protection.
                for key in ("funding_txid", "funding_vout", "terms", "destination", "destination_script", "principal_atoms", "refund_height"):
                    if previous[key] != authorization[key]:
                        raise PaymentError("immutable refund authorization changed")
                if sequence <= old["sequence"]:
                    raise PaymentError("stale refund authorization sequence")
                if old["state"] in ("SUBMITTED", "CONFIRMED"):
                    raise PaymentError("cannot replace an already submitted refund")
            self.db.execute("""INSERT INTO refunds(outpoint,sequence,authorization,authorization_hash,raw_hex,refund_txid,state)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(outpoint) DO UPDATE SET sequence=excluded.sequence,
                authorization=excluded.authorization,authorization_hash=excluded.authorization_hash,
                raw_hex=excluded.raw_hex,refund_txid=excluded.refund_txid,state=excluded.state,
                last_error=NULL,receipt=NULL,submitted_at=NULL""",
                (point, sequence, body, digest, refund_hex.lower(), txid, "WAITING"))
            self._event(point, "REGISTERED", {"authorization_hash": digest, "sequence": sequence, "refund_txid": txid})
        return {"outpoint": point, "state": "WAITING", "duplicate": False}

    def _observe_spend(self, row: sqlite3.Row, authorization: dict[str, Any]) -> dict[str, Any]:
        options = dict(authorization["terms"], destination=authorization["destination"],
                       max_settlement_fee_atoms=authorization["fee_cap_atoms"])
        return self.rpc.call("getmodelfundingsettlement", authorization["funding_txid"], options, row["refund_txid"])

    def poll(self) -> list[dict[str, Any]]:
        chain = self.network()
        outcomes = []
        # BEGIN IMMEDIATE fences registration/replacement against this pass.
        # The raw txid is stable, so a crash after broadcast but before commit
        # is reconciled through node observation on the next pass.
        with self.transaction():
            for row in self.db.execute("SELECT * FROM refunds ORDER BY outpoint").fetchall():
                auth = json.loads(row["authorization"])
                if hashlib.sha256(row["authorization"].encode()).hexdigest() != row["authorization_hash"]:
                    raise PaymentError("authorization journal integrity failure")
                state, receipt, message = "WAITING", None, None
                try:
                    receipt = self._observe_spend(row, auth)
                except Exception:
                    # Missing tx/index is not settlement. Check the UTXO before
                    # deciding whether any presigned recovery can be attempted.
                    receipt = None
                if receipt and receipt.get("settled") is True:
                    if receipt.get("branch") != "REFUND" or receipt.get("settlement_txid") != row["refund_txid"]:
                        raise PaymentError("unexpected settlement observation")
                    state = "CONFIRMED"
                else:
                    coin = self.rpc.call("gettxout", auth["funding_txid"], auth["funding_vout"], True)
                    mempool = self.rpc.call("getrawmempool")
                    if row["refund_txid"] in mempool:
                        state = "SUBMITTED"
                    elif coin is None:
                        state = "SPENT_UNKNOWN"
                    elif chain["blocks"] < auth["refund_height"]:
                        state = "WAITING"
                    else:
                        # Recheck current chain ownership/terms and consensus
                        # acceptance; no caller 'signed_ok' or clock timestamp
                        # is sufficient to reach sendrawtransaction.
                        status = self.rpc.call("getmodelfundingsettlement", auth["funding_txid"], auth["terms"])
                        if status.get("state") != "FUNDED" or status.get("funded") is not True:
                            state = "FUNDING_UNCONFIRMED"
                        elif status.get("chain_tip") != chain["bestblockhash"]:
                            state = "RETRY_CHAIN_CHANGED"
                        else:
                            accepted = self.rpc.call("testmempoolaccept", [row["raw_hex"]])
                            if len(accepted) != 1 or accepted[0].get("allowed") is not True:
                                state = "REJECTED"
                                message = accepted[0].get("reject-reason", "consensus validation failed") if accepted else "empty validation"
                            else:
                                txid = self.rpc.call("sendrawtransaction", row["raw_hex"])
                                if txid != row["refund_txid"]:
                                    raise PaymentError("broadcast returned a different transaction id")
                                state = "SUBMITTED"
                                self.db.execute("UPDATE refunds SET submitted_at=? WHERE outpoint=?", (int(time.time()), row["outpoint"]))
                if state != row["state"]:
                    self._event(row["outpoint"], state, {"tip": chain["bestblockhash"], "height": chain["blocks"]})
                self.db.execute("UPDATE refunds SET state=?,last_tip=?,last_error=?,receipt=? WHERE outpoint=?",
                                (state, chain["bestblockhash"], message, canonical(receipt) if receipt else None, row["outpoint"]))
                outcomes.append({"outpoint": row["outpoint"], "state": state, "refund_txid": row["refund_txid"],
                                 "automatic_spend_atoms": "0", "signatures_created": 0})
        return outcomes

    def status(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.db.execute(
            "SELECT outpoint,sequence,refund_txid,state,last_tip,last_error,submitted_at,receipt FROM refunds ORDER BY outpoint")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True, help="loopback URL, e.g. http://127.0.0.1:18443/wallet/funder")
    parser.add_argument("--cookie", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("register")
    add.add_argument("--funding-txid", required=True)
    add.add_argument("--frozen", required=True, type=Path)
    add.add_argument("--destination", required=True)
    add.add_argument("--signed-refund", required=True, type=Path)
    add.add_argument("--fee-cap-atoms", required=True)
    add.add_argument("--sequence", type=int, default=1)
    sub.add_parser("poll")
    sub.add_parser("status")
    args = parser.parse_args()
    tower = RefundWatchtower(args.database, CookieRPC(args.rpc, args.cookie))
    try:
        if args.command == "register":
            result = tower.register(args.funding_txid, json.loads(args.frozen.read_text()), args.destination,
                                    args.signed_refund.read_text().strip(), args.fee_cap_atoms, args.sequence)
        elif args.command == "poll":
            result = tower.poll()
        else:
            result = tower.status()
        print(json.dumps(result, indent=2))
        return 0
    finally:
        tower.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PaymentError, ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from None
