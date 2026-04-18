#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Deterministic multisig-to-shielded transfer bundle planner/simulator/executor.

This tool builds real unsigned PSBTs using the wallet RPCs already present in the
node, stores them as the canonical transfer plan, and then simulates or executes
that exact plan later.
"""

from __future__ import annotations

import argparse
import base64
import copy
import http.client
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from typing import Any
from urllib.parse import quote

EIGHT_PLACES = Decimal("0.00000001")
ZERO = Decimal("0")
DEFAULT_FEE = Decimal("0.00010000")
DEFAULT_BLOCK_MAX_WEIGHT = 4_000_000
DEFAULT_BLOCK_MAX_SIGOPS = 480_000
BUNDLE_FORMAT = "btx-shielded-transfer-bundle/1"
SIMULATION_FORMAT = "btx-shielded-transfer-simulation/1"
EXECUTION_FORMAT = "btx-shielded-transfer-execution/1"
JSON_ID = "shielded-transfer-builder"


class BuilderError(RuntimeError):
    pass


class RPCError(BuilderError):
    pass


class RPCClient:
    def __init__(self, host: str, port: int, auth_header: str, wallet: str | None = None):
        self.host = host
        self.port = port
        self.auth_header = auth_header
        self.wallet = wallet

    def with_wallet(self, wallet: str | None) -> "RPCClient":
        return RPCClient(self.host, self.port, self.auth_header, wallet)

    def _path(self) -> str:
        if self.wallet:
            return f"/wallet/{quote(self.wallet, safe='')}"
        return "/"

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        body = json.dumps({
            "jsonrpc": "1.0",
            "id": JSON_ID,
            "method": method,
            "params": params or [],
        })
        headers = {
            "Authorization": self.auth_header,
            "Content-Type": "application/json",
        }
        conn = http.client.HTTPConnection(self.host, self.port, timeout=300)
        try:
            conn.request("POST", self._path(), body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read().decode("utf-8")
        finally:
            conn.close()
        if response.status != 200:
            raise RPCError(f"RPC HTTP {response.status}: {payload}")
        data = json.loads(payload)
        if data.get("error"):
            err = data["error"]
            raise RPCError(f"RPC {method} failed ({err.get('code')}): {err.get('message')}")
        return data["result"]


def quantize_amount(value: Decimal) -> Decimal:
    return value.quantize(EIGHT_PLACES, rounding=ROUND_DOWN)


def decimal_from_value(value: Any) -> Decimal:
    return quantize_amount(Decimal(str(value)))



def amount_str(value: Decimal) -> str:
    return format(quantize_amount(value), ".8f")



def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")



def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)



def write_json(path: Path, payload: dict[str, Any], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise BuilderError(f"Refusing to overwrite existing file: {path}")
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp.replace(path)



def compute_digest(payload: dict[str, Any], digest_field: str) -> str:
    stripped = copy.deepcopy(payload)
    stripped.pop(digest_field, None)
    encoded = json.dumps(stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    import hashlib

    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()



def parse_destination(raw: str) -> dict[str, Any]:
    if "=" not in raw:
        raise BuilderError(f"Destination must use address=amount form: {raw}")
    address, amount = raw.split("=", 1)
    address = address.strip()
    if not address:
        raise BuilderError(f"Destination address is empty: {raw}")
    value = decimal_from_value(amount)
    if value <= ZERO:
        raise BuilderError(f"Destination amount must be positive: {raw}")
    return {"address": address, "amount": amount_str(value)}



def parse_bitcoin_conf(datadir: Path, chain: str) -> dict[str, str]:
    conf_path = None
    for candidate in (datadir / "bitcoin.conf", datadir / "btx.conf"):
        if candidate.exists():
            conf_path = candidate
            break
    if conf_path is None:
        return {}
    active_sections = {None, chain}
    current = None
    values: dict[str, str] = {}
    chain_values: dict[str, str] = {}
    with conf_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if current is None:
                values[key] = value
            elif current in active_sections:
                chain_values[key] = value
    values.update(chain_values)
    return values



def rpc_auth_header(args: argparse.Namespace) -> str:
    if args.rpcuser and args.rpcpassword:
        token = f"{args.rpcuser}:{args.rpcpassword}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")
    if not args.datadir:
        raise BuilderError("Either --rpcuser/--rpcpassword or --datadir must be provided")
    datadir = Path(args.datadir)
    conf = parse_bitcoin_conf(datadir, args.chain)
    conf_user = conf.get("rpcuser")
    conf_password = conf.get("rpcpassword")
    if conf_user and conf_password:
        token = f"{conf_user}:{conf_password}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")
    cookie_candidates = []
    if args.chain == "main":
        cookie_candidates.append(datadir / ".cookie")
    cookie_candidates.append(datadir / args.chain / ".cookie")
    cookie_candidates.append(datadir / ".cookie")
    for cookie_path in cookie_candidates:
        if cookie_path.exists():
            userpass = cookie_path.read_text(encoding="utf-8").strip()
            token = userpass.encode("utf-8")
            return "Basic " + base64.b64encode(token).decode("ascii")
    raise BuilderError(f"Unable to locate RPC auth material under {datadir} (checked config and cookie)")



def rpc_port(args: argparse.Namespace) -> int:
    if args.rpcport is not None:
        return args.rpcport
    if not args.datadir:
        raise BuilderError("--rpcport is required unless --datadir points to a readable bitcoin.conf")
    conf = parse_bitcoin_conf(Path(args.datadir), args.chain)
    if "rpcport" in conf:
        return int(conf["rpcport"])
    defaults = {"main": 8332, "test": 18332, "regtest": 18443, "signet": 38332}
    if args.chain in defaults:
        return defaults[args.chain]
    raise BuilderError("--rpcport is required for this chain")



def make_rpc(args: argparse.Namespace) -> RPCClient:
    auth = rpc_auth_header(args)
    return RPCClient(args.rpcconnect, rpc_port(args), auth)



def plan_options(args: argparse.Namespace) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if args.max_inputs_per_chunk is not None:
        options["max_inputs_per_chunk"] = args.max_inputs_per_chunk
    return options


def utxo_sort_key(utxo: dict[str, Any]) -> tuple[Decimal, str, int]:
    return (
        -decimal_from_value(utxo["amount"]),
        str(utxo["txid"]),
        int(utxo["vout"]),
    )


def utxo_key(utxo: dict[str, Any]) -> tuple[str, int]:
    return (str(utxo["txid"]), int(utxo["vout"]))


def load_fallback_candidates(wallet_rpc: RPCClient) -> list[dict[str, Any]]:
    utxos = wallet_rpc.call("listunspent", [1])
    candidates = [
        utxo for utxo in utxos
        if utxo.get("safe", True) and (utxo.get("spendable", False) or utxo.get("solvable", False))
    ]
    candidates.sort(key=utxo_sort_key)
    return candidates


def fallback_preview_state(wallet_rpc: RPCClient) -> dict[str, Any]:
    candidates = load_fallback_candidates(wallet_rpc)
    excluded = {
        (coin["txid"], int(coin["vout"]))
        for coin in currently_locked_inputs(wallet_rpc, candidates)
    }
    return {
        "candidates": candidates,
        "excluded": excluded,
        "skip_wallet_planner": False,
    }



def build_fallback_preview_chunk(wallet_rpc: RPCClient,
                                 remaining_amount: Decimal,
                                 options: dict[str, Any],
                                 preview_state: dict[str, Any]) -> dict[str, Any]:
    limit = int(options.get("max_inputs_per_chunk") or 64)
    candidates = preview_state["candidates"]
    excluded = preview_state["excluded"]
    if not candidates:
        raise BuilderError("No spendable transparent UTXOs available for planning")

    desired_total = quantize_amount(remaining_amount + DEFAULT_FEE)
    selected: list[dict[str, Any]] = []
    gross = ZERO
    for utxo in candidates:
        if utxo_key(utxo) in excluded:
            continue
        selected.append(utxo)
        gross = quantize_amount(gross + decimal_from_value(utxo["amount"]))
        if len(selected) >= limit or gross >= desired_total:
            break

    preview_amount = quantize_amount(min(remaining_amount, gross - DEFAULT_FEE))
    if preview_amount <= ZERO:
        raise BuilderError("Fallback chunk preview could not fund a positive shielded amount")

    return {
        "gross_amount": amount_str(gross),
        "amount": amount_str(preview_amount),
        "fee": amount_str(DEFAULT_FEE),
        "transparent_inputs": len(selected),
        "preview_source": "deterministic-listunspent",
    }



def build_preview_chunk(wallet_rpc: RPCClient,
                        destination: str,
                        remaining_amount: Decimal,
                        options: dict[str, Any],
                        preview_state: dict[str, Any]) -> dict[str, Any]:
    if not preview_state["skip_wallet_planner"]:
        try:
            preview = wallet_rpc.call(
                "z_planshieldfunds",
                [amount_str(remaining_amount), destination, amount_str(DEFAULT_FEE), options],
            )
            preview_chunk = copy.deepcopy(preview["chunks"][0])
            preview_chunk["preview_source"] = "wallet-planner"
            return preview_chunk
        except RPCError as exc:
            message = str(exc)
            if (
                "Shielded keys require an encrypted wallet" not in message
                and "SignTransaction returned false" not in message
                and "does not support shielded features" not in message
            ):
                raise
            preview_state["skip_wallet_planner"] = True
    return build_fallback_preview_chunk(wallet_rpc, remaining_amount, options, preview_state)





def extract_inputs(decoded_psbt: dict[str, Any]) -> list[dict[str, Any]]:
    vins = decoded_psbt.get("tx", {}).get("vin", [])
    return [{"txid": vin["txid"], "vout": vin["vout"]} for vin in vins]



def extract_outputs(decoded_psbt: dict[str, Any]) -> list[dict[str, Any]]:
    outputs = []
    for vout in decoded_psbt.get("tx", {}).get("vout", []):
        script = vout.get("scriptPubKey", {})
        outputs.append({
            "n": vout.get("n"),
            "value": amount_str(decimal_from_value(vout.get("value", "0"))),
            "type": script.get("type"),
            "address": script.get("address"),
            "addresses": script.get("addresses", []),
        })
    return outputs



def block_pack(transactions: list[dict[str, Any]], max_weight: int, max_sigops: int, weight_key: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packed_blocks: list[dict[str, Any]] = []
    txs: list[dict[str, Any]] = []
    current_weight = 0
    current_sigops = 0
    current_indexes: list[int] = []
    block_index = 0
    for tx in transactions:
        tx_weight = int(tx[weight_key])
        tx_sigops = int(tx["estimated_sigop_cost"])
        if tx_weight > max_weight:
            raise BuilderError(f"Transaction {tx['index']} exceeds block weight limit: {tx_weight} > {max_weight}")
        if tx_sigops > max_sigops:
            raise BuilderError(f"Transaction {tx['index']} exceeds block sigops limit: {tx_sigops} > {max_sigops}")
        if current_indexes and (current_weight + tx_weight > max_weight or current_sigops + tx_sigops > max_sigops):
            packed_blocks.append({
                "index": block_index,
                "transaction_indexes": current_indexes,
                "total_weight": current_weight,
                "total_sigops": current_sigops,
            })
            block_index += 1
            current_indexes = []
            current_weight = 0
            current_sigops = 0
        tx["block_index"] = block_index
        current_indexes.append(tx["index"])
        current_weight += tx_weight
        current_sigops += tx_sigops
        txs.append(tx)
    if current_indexes:
        packed_blocks.append({
            "index": block_index,
            "transaction_indexes": current_indexes,
            "total_weight": current_weight,
            "total_sigops": current_sigops,
        })
    return txs, packed_blocks



def ensure_bundle_chain(bundle: dict[str, Any], rpc: RPCClient) -> None:
    chain = rpc.call("getblockchaininfo")["chain"]
    if chain != bundle["chain"]:
        raise BuilderError(f"Bundle was created for chain {bundle['chain']}, current node is {chain}")



def fund_authoritative_chunk(wallet_rpc: RPCClient,
                             destination: str,
                             remaining_amount: Decimal,
                             preview_chunk: dict[str, Any],
                             options: dict[str, Any]) -> tuple[dict[str, Any], Decimal, Decimal]:
    preview_gross = decimal_from_value(preview_chunk["gross_amount"])
    requested_amount = min(remaining_amount, decimal_from_value(preview_chunk["amount"]))
    fee = decimal_from_value(preview_chunk["fee"])

    for _ in range(6):
        funded = wallet_rpc.call(
            "z_fundpsbt",
            [amount_str(requested_amount), destination, amount_str(fee), options],
        )
        if not funded.get("fee_authoritative", False):
            raise BuilderError(
                f"Non-authoritative fee quote for destination {destination}: "
                f"{funded.get('fee_authoritative_error', 'unknown error')}"
            )
        required_fee = decimal_from_value(funded["required_mempool_fee"])
        max_amount = quantize_amount(preview_gross - required_fee)
        if max_amount <= ZERO:
            raise BuilderError(
                f"Preview gross amount {amount_str(preview_gross)} cannot satisfy required fee {amount_str(required_fee)}"
            )
        adjusted_amount = min(remaining_amount, max_amount)
        applied_fee = decimal_from_value(funded["fee"])
        if adjusted_amount == requested_amount and required_fee == fee and applied_fee == fee:
            funded_amount = decimal_from_value(funded["shielded_amount"])
            if funded_amount != adjusted_amount:
                raise BuilderError(
                    f"Funded shielded amount {amount_str(funded_amount)} did not match requested amount {amount_str(adjusted_amount)}"
                )
            return funded, adjusted_amount, required_fee
        requested_amount = adjusted_amount
        fee = required_fee

    raise BuilderError(f"Failed to converge authoritative fee for destination {destination}")



def gather_locked_inputs(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    locked: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for tx in bundle["transactions"]:
        for coin in tx["selected_inputs"]:
            key = (coin["txid"], int(coin["vout"]))
            if key in seen:
                continue
            seen.add(key)
            locked.append({"txid": coin["txid"], "vout": int(coin["vout"])})
    return locked
def currently_locked_inputs(wallet_rpc: RPCClient, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    locked_now = {
        (entry["txid"], int(entry["vout"]))
        for entry in wallet_rpc.call("listlockunspent")
    }
    return [
        {"txid": coin["txid"], "vout": int(coin["vout"])}
        for coin in candidates
        if (coin["txid"], int(coin["vout"])) in locked_now
    ]





def sign_psbt(base_rpc: RPCClient, signer_wallets: list[str], psbt: str) -> str:
    current = psbt
    for signer in signer_wallets:
        res = base_rpc.with_wallet(signer).call("walletprocesspsbt", [current])
        current = res["psbt"]
    return current



def simulate_bundle(base_rpc: RPCClient, bundle: dict[str, Any]) -> dict[str, Any]:
    source_rpc = base_rpc.with_wallet(bundle["source_wallet"])
    ensure_bundle_chain(bundle, base_rpc)
    simulation: dict[str, Any] = {
        "format": SIMULATION_FORMAT,
        "bundle_digest": bundle["bundle_digest"],
        "chain": bundle["chain"],
        "source_wallet": bundle["source_wallet"],
        "signer_wallets": bundle["signer_wallets"],
        "created_at": utc_now(),
        "transactions": [],
        "totals": {
            "planned_shielded_amount": bundle["totals"]["planned_shielded_amount"],
            "planned_fee": bundle["totals"]["planned_fee"],
            "tx_count": bundle["totals"]["tx_count"],
        },
    }
    simulated_txs: list[dict[str, Any]] = []
    for tx in bundle["transactions"]:
        signed = sign_psbt(base_rpc, bundle["signer_wallets"], tx["psbt"])
        preview = source_rpc.call("z_finalizepsbt", [signed, False])
        if not preview.get("complete", False):
            raise BuilderError(f"Simulation did not fully finalize transaction {tx['index']}")
        accept = base_rpc.call("testmempoolaccept", [[preview["hex"]]])[0]
        if not accept.get("allowed", False):
            reason = accept.get("reject-reason", "rejected")
            raise BuilderError(f"Simulation mempool rejection for transaction {tx['index']}: {reason}")
        decoded = base_rpc.call("decoderawtransaction", [preview["hex"]])
        simulation["transactions"].append({
            "index": tx["index"],
            "destination_index": tx["destination_index"],
            "destination": tx["destination"],
            "txid": decoded["txid"],
            "hex": preview["hex"],
            "weight": decoded["weight"],
            "vsize": decoded["vsize"],
            "estimated_sigop_cost": tx["estimated_sigop_cost"],
            "block_index": tx.get("block_index"),
            "allowed": True,
        })
        simulated_txs.append({
            "index": tx["index"],
            "estimated_sigop_cost": tx["estimated_sigop_cost"],
            "actual_weight": decoded["weight"],
        })

    _, blocks = block_pack(simulated_txs, bundle["block_limits"]["max_weight"], bundle["block_limits"]["max_sigops"], "actual_weight")
    simulation["blocks"] = blocks
    simulation["totals"]["block_count"] = len(blocks)
    simulation["simulation_digest"] = compute_digest(simulation, "simulation_digest")
    return simulation



def execute_bundle(base_rpc: RPCClient, bundle: dict[str, Any], simulation: dict[str, Any]) -> dict[str, Any]:
    ensure_bundle_chain(bundle, base_rpc)
    if simulation.get("bundle_digest") != bundle.get("bundle_digest"):
        raise BuilderError("Simulation does not match bundle digest")
    expected = {tx["index"]: tx for tx in simulation["transactions"]}
    source_rpc = base_rpc.with_wallet(bundle["source_wallet"])
    result: dict[str, Any] = {
        "format": EXECUTION_FORMAT,
        "bundle_digest": bundle["bundle_digest"],
        "simulation_digest": simulation["simulation_digest"],
        "chain": bundle["chain"],
        "created_at": utc_now(),
        "transactions": [],
    }
    for tx in bundle["transactions"]:
        signed = sign_psbt(base_rpc, bundle["signer_wallets"], tx["psbt"])
        preview = source_rpc.call("z_finalizepsbt", [signed, False])
        if not preview.get("complete", False):
            raise BuilderError(f"Execution dry-run did not finalize transaction {tx['index']}")
        accept = base_rpc.call("testmempoolaccept", [[preview["hex"]]])[0]
        if not accept.get("allowed", False):
            reason = accept.get("reject-reason", "rejected")
            raise BuilderError(f"Execution preflight rejection for transaction {tx['index']}: {reason}")
        decoded = base_rpc.call("decoderawtransaction", [preview["hex"]])
        expected_tx = expected.get(tx["index"])
        if expected_tx is None:
            raise BuilderError(f"Simulation missing transaction index {tx['index']}")
        if decoded["txid"] != expected_tx["txid"]:
            raise BuilderError(
                f"Transaction {tx['index']} txid changed between simulation and execution: "
                f"{expected_tx['txid']} != {decoded['txid']}"
            )
        finalized = source_rpc.call("z_finalizepsbt", [signed, True])
        if finalized.get("txid") != expected_tx["txid"]:
            raise BuilderError(
                f"Broadcast txid mismatch for transaction {tx['index']}: "
                f"{finalized.get('txid')} != {expected_tx['txid']}"
            )
        result["transactions"].append({
            "index": tx["index"],
            "txid": finalized["txid"],
            "destination": tx["destination"],
            "block_index": tx.get("block_index"),
        })
    result["txids"] = [tx["txid"] for tx in result["transactions"]]
    result["totals"] = {
        "tx_count": len(result["transactions"]),
        "planned_shielded_amount": bundle["totals"]["planned_shielded_amount"],
        "planned_fee": bundle["totals"]["planned_fee"],
    }
    result["execution_digest"] = compute_digest(result, "execution_digest")
    return result



def cmd_plan(args: argparse.Namespace) -> int:
    base_rpc = make_rpc(args)
    source_rpc = base_rpc.with_wallet(args.rpcwallet)
    chaininfo = base_rpc.call("getblockchaininfo")
    destinations = [parse_destination(raw) for raw in args.destination]
    if not destinations:
        raise BuilderError("At least one --destination is required")
    if len(destinations) > 10:
        raise BuilderError("At most 10 destinations are supported")
    options = plan_options(args)
    preview_state = fallback_preview_state(source_rpc)
    block_limits = {
        "max_weight": args.block_max_weight,
        "max_sigops": args.block_max_sigops,
    }
    bundle: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "created_at": utc_now(),
        "chain": chaininfo["chain"],
        "best_block_hash": chaininfo["bestblockhash"],
        "source_wallet": args.rpcwallet,
        "signer_wallets": args.signer_wallet,
        "destinations": destinations,
        "block_limits": block_limits,
        "options": {
            "max_inputs_per_chunk": args.max_inputs_per_chunk,
            "lock_inputs": not args.no_lock_inputs,
        },
        "transactions": [],
        "totals": {
            "requested_amount": amount_str(sum(decimal_from_value(d["amount"]) for d in destinations)),
            "planned_shielded_amount": "0.00000000",
            "planned_fee": "0.00000000",
            "tx_count": 0,
            "block_count": 0,
        },
    }
    locked_inputs: list[dict[str, Any]] = []
    tx_index = 0
    try:
        for destination_index, destination in enumerate(destinations):
            remaining = decimal_from_value(destination["amount"])
            while remaining > ZERO:
                preview_chunk = build_preview_chunk(source_rpc, destination["address"], remaining, options, preview_state)
                funded, funded_amount, funded_fee = fund_authoritative_chunk(
                    source_rpc,
                    destination["address"],
                    remaining,
                    preview_chunk,
                    options,
                )
                decoded_psbt = base_rpc.call("decodepsbt", [funded["psbt"]])
                selected_inputs = extract_inputs(decoded_psbt)
                if not selected_inputs:
                    raise BuilderError(f"Planned transaction {tx_index} selected no inputs")
                preview_state["excluded"].update((coin["txid"], int(coin["vout"])) for coin in selected_inputs)
                source_rpc.call("lockunspent", [False, selected_inputs])
                locked_inputs.extend(selected_inputs)
                tx_entry = {
                    "index": tx_index,
                    "destination_index": destination_index,
                    "destination": destination["address"],
                    "requested_amount": amount_str(funded_amount),
                    "shielded_amount": amount_str(decimal_from_value(funded["shielded_amount"])),
                    "fee": amount_str(funded_fee),
                    "required_mempool_fee": amount_str(decimal_from_value(funded["required_mempool_fee"])),
                    "fee_authoritative": funded["fee_authoritative"],
                    "estimated_vsize": int(funded["estimated_vsize"]),
                    "estimated_sigop_cost": int(funded["estimated_sigop_cost"]),
                    "transparent_inputs": int(funded["transparent_inputs"]),
                    "preview": {
                        "gross_amount": amount_str(decimal_from_value(preview_chunk["gross_amount"])),
                        "amount": amount_str(decimal_from_value(preview_chunk["amount"])),
                        "fee": amount_str(decimal_from_value(preview_chunk["fee"])),
                        "transparent_inputs": int(preview_chunk["transparent_inputs"]),
                        "tx_weight": int(preview_chunk["tx_weight"]) if "tx_weight" in preview_chunk else None,
                        "txid": preview_chunk.get("txid"),
                        "preview_source": preview_chunk.get("preview_source"),
                    },
                    "selected_inputs": selected_inputs,
                    "transparent_outputs": extract_outputs(decoded_psbt),
                    "psbt": funded["psbt"],
                }
                bundle["transactions"].append(tx_entry)
                remaining = quantize_amount(remaining - funded_amount)
                tx_index += 1

        seen_inputs: set[tuple[str, int]] = set()
        for tx in bundle["transactions"]:
            for coin in tx["selected_inputs"]:
                key = (coin["txid"], int(coin["vout"]))
                if key in seen_inputs:
                    raise BuilderError(f"Input reused across planned transactions: {coin['txid']}:{coin['vout']}")
                seen_inputs.add(key)

        planned_txs, blocks = block_pack(bundle["transactions"], args.block_max_weight, args.block_max_sigops, "estimated_vsize")
        bundle["transactions"] = planned_txs
        bundle["blocks"] = blocks
        bundle["totals"]["planned_shielded_amount"] = amount_str(sum(decimal_from_value(tx["shielded_amount"]) for tx in planned_txs))
        bundle["totals"]["planned_fee"] = amount_str(sum(decimal_from_value(tx["fee"]) for tx in planned_txs))
        bundle["totals"]["tx_count"] = len(planned_txs)
        bundle["totals"]["block_count"] = len(blocks)
        bundle["bundle_digest"] = compute_digest(bundle, "bundle_digest")
        write_json(Path(args.bundle), bundle, args.overwrite)
        if locked_inputs and args.no_lock_inputs:
            source_rpc.call("lockunspent", [True, locked_inputs])
            locked_inputs.clear()
        print(json.dumps({
            "bundle": args.bundle,
            "bundle_digest": bundle["bundle_digest"],
            "tx_count": bundle["totals"]["tx_count"],
            "block_count": bundle["totals"]["block_count"],
            "planned_shielded_amount": bundle["totals"]["planned_shielded_amount"],
            "planned_fee": bundle["totals"]["planned_fee"],
            "locked_inputs": len(locked_inputs),
        }, indent=2, sort_keys=True))
        return 0
    except Exception:
        if locked_inputs and (args.no_lock_inputs or args.unlock_on_failure):
            try:
                source_rpc.call("lockunspent", [True, locked_inputs])
            except Exception:
                pass
        raise



def cmd_simulate(args: argparse.Namespace) -> int:
    base_rpc = make_rpc(args)
    bundle = load_json(Path(args.bundle))
    if bundle.get("format") != BUNDLE_FORMAT:
        raise BuilderError(f"Unsupported bundle format: {bundle.get('format')}")
    if bundle.get("bundle_digest") != compute_digest(bundle, "bundle_digest"):
        raise BuilderError("Bundle digest mismatch; refusing to simulate a modified plan")
    simulation = simulate_bundle(base_rpc, bundle)
    write_json(Path(args.simulation), simulation, args.overwrite)
    print(json.dumps({
        "simulation": args.simulation,
        "simulation_digest": simulation["simulation_digest"],
        "tx_count": simulation["totals"]["tx_count"],
        "block_count": simulation["totals"]["block_count"],
    }, indent=2, sort_keys=True))
    return 0



def cmd_execute(args: argparse.Namespace) -> int:
    base_rpc = make_rpc(args)
    bundle = load_json(Path(args.bundle))
    simulation = load_json(Path(args.simulation))
    if bundle.get("format") != BUNDLE_FORMAT:
        raise BuilderError(f"Unsupported bundle format: {bundle.get('format')}")
    if simulation.get("format") != SIMULATION_FORMAT:
        raise BuilderError(f"Unsupported simulation format: {simulation.get('format')}")
    if bundle.get("bundle_digest") != compute_digest(bundle, "bundle_digest"):
        raise BuilderError("Bundle digest mismatch; refusing to execute a modified plan")
    if simulation.get("simulation_digest") != compute_digest(simulation, "simulation_digest"):
        raise BuilderError("Simulation digest mismatch; refusing to execute a modified simulation")
    result = execute_bundle(base_rpc, bundle, simulation)
    if bundle.get("options", {}).get("lock_inputs", False):
        locked_inputs = gather_locked_inputs(bundle)
        if locked_inputs:
            source_rpc = base_rpc.with_wallet(bundle["source_wallet"])
            unlockable = currently_locked_inputs(source_rpc, locked_inputs)
            if unlockable:
                source_rpc.call("lockunspent", [True, unlockable])
    write_json(Path(args.result), result, args.overwrite)
    print(json.dumps({
        "result": args.result,
        "execution_digest": result["execution_digest"],
        "txids": result["txids"],
    }, indent=2, sort_keys=True))
    return 0



def cmd_release(args: argparse.Namespace) -> int:
    base_rpc = make_rpc(args)
    bundle = load_json(Path(args.bundle))
    if bundle.get("format") != BUNDLE_FORMAT:
        raise BuilderError(f"Unsupported bundle format: {bundle.get('format')}")
    locked_inputs = gather_locked_inputs(bundle)
    if locked_inputs:
        source_rpc = base_rpc.with_wallet(bundle["source_wallet"])
        unlockable = currently_locked_inputs(source_rpc, locked_inputs)
        if unlockable:
            source_rpc.call("lockunspent", [True, unlockable])
    print(json.dumps({
        "released_inputs": len(locked_inputs),
        "bundle": args.bundle,
    }, indent=2, sort_keys=True))
    return 0



def add_common_rpc_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rpcconnect", default="127.0.0.1", help="RPC host (default: 127.0.0.1)")
    parser.add_argument("--rpcport", type=int, help="RPC port; if omitted, read from bitcoin.conf/btx.conf or chain default")
    parser.add_argument("--rpcuser", help="RPC user; if omitted, use auth from btx.conf/bitcoin.conf or the cookie from --datadir")
    parser.add_argument("--rpcpassword", help="RPC password; if omitted, use auth from btx.conf/bitcoin.conf or the cookie from --datadir")
    parser.add_argument("--datadir", help="BTX datadir used to locate RPC config and cookie auth")
    parser.add_argument("--chain", default="main", help="Chain name for config/cookie lookup (default: main)")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="Build a deterministic transfer bundle and store it to disk")
    add_common_rpc_args(plan)
    plan.add_argument("--rpcwallet", required=True, help="Source watch-only multisig wallet used for z_fundpsbt and z_finalizepsbt")
    plan.add_argument("--signer-wallet", action="append", required=True, help="Signer wallet name; repeat for every required signer in signing order")
    plan.add_argument("--destination", action="append", required=True, help="Destination in address=amount form; repeat up to 10 times")
    plan.add_argument("--bundle", required=True, help="Output path for the JSON bundle file")
    plan.add_argument("--max-inputs-per-chunk", type=int, help="Override max_inputs_per_chunk for wallet planning/funding")
    plan.add_argument("--block-max-weight", type=int, default=DEFAULT_BLOCK_MAX_WEIGHT, help=f"Block packing weight limit (default: {DEFAULT_BLOCK_MAX_WEIGHT})")
    plan.add_argument("--block-max-sigops", type=int, default=DEFAULT_BLOCK_MAX_SIGOPS, help=f"Block packing sigops limit (default: {DEFAULT_BLOCK_MAX_SIGOPS})")
    plan.add_argument("--no-lock-inputs", action="store_true", help="Do not lock selected inputs after planning")
    plan.add_argument("--unlock-on-failure", action="store_true", help="Best-effort unlock any inputs already locked if planning fails")
    plan.add_argument("--overwrite", action="store_true", help="Overwrite the bundle output file if it already exists")
    plan.set_defaults(func=cmd_plan)

    simulate = subparsers.add_parser("simulate", help="Sign/finalize the exact plan without broadcasting and confirm mempool acceptance")
    add_common_rpc_args(simulate)
    simulate.add_argument("--bundle", required=True, help="Input bundle JSON file")
    simulate.add_argument("--simulation", required=True, help="Output path for the simulation JSON file")
    simulate.add_argument("--overwrite", action="store_true", help="Overwrite the simulation output file if it already exists")
    simulate.set_defaults(func=cmd_simulate)

    execute = subparsers.add_parser("execute", help="Execute a previously simulated bundle and broadcast it deterministically")
    add_common_rpc_args(execute)
    execute.add_argument("--bundle", required=True, help="Input bundle JSON file")
    execute.add_argument("--simulation", required=True, help="Simulation JSON file produced by the simulate subcommand")
    execute.add_argument("--result", required=True, help="Output path for the execution JSON file")
    execute.add_argument("--overwrite", action="store_true", help="Overwrite the result output file if it already exists")
    execute.set_defaults(func=cmd_execute)

    release = subparsers.add_parser("release", help="Unlock all inputs referenced by a bundle without executing it")
    add_common_rpc_args(release)
    release.add_argument("--bundle", required=True, help="Input bundle JSON file")
    release.set_defaults(func=cmd_release)

    return parser



def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (BuilderError, RPCError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
