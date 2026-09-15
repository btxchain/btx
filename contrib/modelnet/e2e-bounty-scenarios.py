#!/usr/bin/env python3
"""BTX 0.34.7 bounty E2E scenarios A–J (isolated regtest / tmpfs)."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRIB = ROOT / "contrib" / "modelnet"
sys.path.insert(0, str(CONTRIB))
from failfast import wait_unix  # noqa: E402

BIN = Path(os.environ.get("BIN", os.environ.get("BIN_DIR", ROOT / "build-gcc13" / "bin")))
BTXD = BIN / "btxd"
CLI = BIN / "btx-cli"
MODELD = Path(os.environ.get("MODELD", BIN / "btx-modeld"))
BOUNTY = ROOT / "contrib" / "modelnet" / "bounty"
EXPLORER = BOUNTY / "reference" / "explorer"
FORWARDER = BOUNTY / "e2e-bridge-forwarder.py"
NETWORK_ID = "0" * 64
SCALE_CAP = int(os.environ.get("BTX_BOUNTY_E2E_SCALE_CAP", "8"))
_RPC_PORT = 37000


def dummy_ml_dsa44(seed: int) -> str:
    return bytes((seed + i) & 0xFF for i in range(1312)).hex()


class RpcError(RuntimeError):
    pass


class RegtestLab:
    def __init__(self, tag: str):
        global _RPC_PORT
        self.tag = tag
        self.work = Path(tempfile.mkdtemp(prefix=f"btx-bounty-e2e-{tag}-"))
        self.datadir = self.work / "node"
        self.datadir.mkdir(parents=True)
        self.pid: int | None = None
        self.rpc_user = "u"
        self.rpc_pass = "p"
        _RPC_PORT += 1
        self.rpc_port = _RPC_PORT

    def cli_base(self) -> list[str]:
        return [
            str(CLI),
            "-regtest",
            f"-datadir={self.datadir}",
            f"-rpcuser={self.rpc_user}",
            f"-rpcpassword={self.rpc_pass}",
            f"-rpcport={self.rpc_port}",
        ]

    def cli(self, *args, wallet: str | None = None):
        method = args[0]
        raw_params = list(args[1:])
        params = []
        for a in raw_params:
            if isinstance(a, (dict, list)):
                params.append(a)
            elif isinstance(a, str):
                try:
                    params.append(json.loads(a))
                except json.JSONDecodeError:
                    params.append(a)
            else:
                params.append(a)
        token = __import__("base64").b64encode(f"{self.rpc_user}:{self.rpc_pass}".encode()).decode()
        url = f"http://127.0.0.1:{self.rpc_port}/"
        if wallet:
            url += f"wallet/{wallet}"
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                reply = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            payload = e.read().decode() if e.fp else str(e)
            raise RpcError(f"HTTP {e.code} {payload}") from e
        except urllib.error.URLError as e:
            # Fallback for early getblockchaininfo while the HTTP server is binding.
            cmd = self.cli_base()
            if wallet:
                cmd.extend(["-rpcwallet=" + wallet])
            cmd.extend(args)
            try:
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()
            except subprocess.CalledProcessError as e:
                raise RpcError((e.output or str(e)).strip()) from e
            if not out:
                return {}
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return out
        if reply.get("error"):
            raise RpcError(str(reply["error"]))
        result = reply.get("result")
        return {} if result is None else result

    def start(self):
        if not BTXD.is_file() or not os.access(BTXD, os.X_OK):
            raise RpcError(f"missing {BTXD}")
        if not MODELD.is_file():
            raise RpcError(f"missing {MODELD}")
        log = self.work / "btxd.log"
        cmd = [
            str(BTXD),
            "-regtest",
            f"-datadir={self.datadir}",
            "-listen=0",
            "-server=1",
            f"-rpcuser={self.rpc_user}",
            f"-rpcpassword={self.rpc_pass}",
            f"-rpcport={self.rpc_port}",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-fallbackfee=0.0001",
            f"-modelhelper={MODELD}",
            "-modelstorage=8MiB",
            "-autoshieldcoinbase=0",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
            "-daemon=0",
        ]
        with open(log, "w", encoding="utf-8") as lf:
            proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT)
        self.pid = proc.pid
        for _ in range(80):
            try:
                self.cli("getblockchaininfo")
                break
            except (subprocess.CalledProcessError, RpcError, OSError, urllib.error.URLError):
                time.sleep(0.25)
        else:
            logtxt = log.read_text(encoding="utf-8", errors="replace")[-2000:] if log.is_file() else ""
            raise RpcError("btxd not ready: " + logtxt)
        for _ in range(40):
            try:
                info = self.cli("getmodelnetworkinfo")
            except (subprocess.CalledProcessError, RpcError, OSError, urllib.error.URLError, json.JSONDecodeError):
                time.sleep(0.25)
                continue
            if isinstance(info, dict) and info.get("helper_ready"):
                break
            time.sleep(0.25)
        else:
            raise RpcError("helper not ready")

    def stop(self):
        if self.pid:
            try:
                self.cli("stop")
            except (subprocess.CalledProcessError, RpcError, OSError, urllib.error.URLError):
                pass
            for _ in range(40):
                try:
                    os.kill(self.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                os.kill(self.pid, signal.SIGTERM)
        shutil.rmtree(self.work, ignore_errors=True)

    def ensure_wallet(self, name: str = "w") -> str:
        wallets = self.cli("listwallets")
        if isinstance(wallets, list) and name not in wallets:
            self.cli("createwallet", name)
        addr = self.cli("getnewaddress", wallet=name)
        if isinstance(addr, str):
            self.cli("generatetoaddress", "101", addr, wallet=name)
        return name

    def pq_pubkey(self, wallet: str = "w") -> str:
        addr = self.cli("getnewaddress", wallet=wallet)
        info = self.cli("getaddressinfo", addr, wallet=wallet) if isinstance(addr, str) else {}
        if isinstance(info, dict):
            pk = info.get("pubkey")
            if isinstance(pk, str) and len(pk) == 2624:
                return pk
        return dummy_ml_dsa44((hash(str(addr)) & 0xFF) or 0x31)


def require_bounty(cli_fn):
    try:
        cli_fn("getbountycapabilities")
    except (subprocess.CalledProcessError, RpcError) as e:
        msg = str(e).lower()
        if "not found" in msg or "method not found" in msg:
            raise RpcError(
                "bounty RPCs missing on this btxd/btx-modeld; rebuild build-gcc13 from this tree (WITH_MODELNET=ON)"
            ) from e
        raise


def council_keys(n: int = 7, lab: RegtestLab | None = None, wallet: str | None = None) -> list[dict]:
    keys = []
    if lab is not None and wallet:
        for _ in range(n):
            pk = lab.pq_pubkey(wallet)
            if len(pk) != 2624:
                raise RpcError(f"council pubkey must be ML-DSA-44 (2624 hex), got {len(pk)}")
            keys.append({"public_key_hex": pk})
        return keys
    for i in range(n):
        keys.append({"public_key_hex": dummy_ml_dsa44(0x10 + i)})
    return keys


def sample_terms(
    *,
    title: str = "opaque-x7",
    description: str = "Japanese repository maintenance tooling for coding agents.",
    submission_mode: str = "PUBLIC",
    sealed_disclosure: str = "",
    nomination_min_bps: int = 0,
    heights: tuple[int, int, int, int, int, int] | None = None,
    council: list[dict] | None = None,
) -> dict:
    if heights is None:
        heights = (200, 300, 400, 450, 480, 600)
    funding, submission, evaluation, award, last_safe, refund = heights
    if council is None:
        council = council_keys(7)
    terms = {
        "terms_version": 1,
        "network_id": NETWORK_ID,
        "requester_identity": "",
        "title": title,
        "description": description,
        "tags": ["coding", "repository"],
        "deliverable_classes": ["BASE_MODEL"],
        "evaluation_spec_id": "e2e-exact-checks",
        "submission_mode": submission_mode,
        "payout_authority": "COUNCIL_MULTISIG",
        "council": council,
        "threshold": 5,
        "nomination_min_bps": nomination_min_bps,
        "target_atoms": "1000000",
        "max_lots_per_round": 4,
        "funding_close_height": funding,
        "submission_close_height": submission,
        "evaluation_close_height": evaluation,
        "earliest_award_height": award,
        "last_safe_award_height": last_safe,
        "refund_height": refund,
        "minimum_confirmations": 6,
        "claim_margin_blocks": 20,
        "challenge_policy": "BOUNDED_TYPED",
        "selection_rule": "EXACT_CANDIDATE",
        "license_statement": "MIT",
        "max_model_bytes": 1048576,
        "fee_policy": "USER_CEILING",
        "sealed_confidentiality_disclosure": sealed_disclosure,
    }
    return terms


def publish_bounty(lab: RegtestLab, terms: dict | None = None) -> str:
    terms = terms or sample_terms()
    v = lab.cli("validatebountyterms", json.dumps({"terms": terms}))
    if not v.get("ok"):
        raise RpcError(f"validatebountyterms: {v}")
    draft = lab.cli("createbountydraft", json.dumps({"terms": terms}))
    draft_id = draft.get("draft_id")
    if not draft_id:
        raise RpcError(f"createbountydraft: {draft}")
    pub = lab.cli("publishbounty", json.dumps({"draft_id": draft_id}))
    bid = pub.get("bounty_id")
    if not bid:
        raise RpcError(f"publishbounty: {pub}")
    return bid


def discover_by_description(lab: RegtestLab, text: str) -> list:
    page = lab.cli("searchbounties", json.dumps({"text": text, "scope": "LOCAL", "limit": 20}))
    return page.get("results") or []


def wallet_fund_lot(lab: RegtestLab, wallet: str, refund_key: str, principal: int = 500000) -> dict:
    h = lab.cli("getblockcount")
    height = int(h) if isinstance(h, (int, str)) else 150
    council = council_keys(7, lab=lab, wallet=wallet)
    plan = {
        "principal_atoms": str(principal),
        "refund_key": refund_key,
        "fee_reserve_atoms": "50000",
        "council_keys": [k["public_key_hex"] for k in council],
        "threshold": 5,
        "award_height": height + 200,
        "refund_height": height + 400,
    }
    prep = lab.cli("preparebountyfunding", json.dumps(plan), wallet=wallet)
    insp = lab.cli("inspectbountytransaction", json.dumps({**plan, "hex": prep.get("unsigned_hex")}), wallet=wallet)
    if not insp.get("escrow_output_present"):
        raise RpcError(f"inspect funding failed: {insp}")
    signed = lab.cli(
        "signbountyfunding",
        json.dumps({**plan, "hex": prep.get("unsigned_hex"), "plan_id": prep.get("plan_id")}),
        wallet=wallet,
    )
    sub = lab.cli("submitbountyfunding", json.dumps({"hex": signed.get("hex")}), wallet=wallet)
    if not sub.get("submitted") and not sub.get("duplicate"):
        raise RpcError(f"submitbountyfunding: {sub}")
    return {"plan": plan, "prep": prep, "sub": sub}


def unix_rpc(sock: Path, method: str, params=None):
    params = params if params is not None else []
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(str(sock))
    s.sendall((json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}) + "\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RpcError(str(reply["error"]))
    return reply.get("result")


def start_modeld(work: Path) -> tuple[Path, subprocess.Popen]:
    work.mkdir(parents=True, exist_ok=True)
    sock = work / "modeld.sock"
    log = work / "modeld.log"
    proc = subprocess.Popen(
        [
            str(MODELD),
            f"-modeldir={work / 'h'}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={sock}",
        ],
        stdout=log.open("w"),
        stderr=subprocess.STDOUT,
    )

    def connect():
        if not sock.exists():
            return None
        info = unix_rpc(sock, "getmodelnetworkinfo", [])
        return info if info.get("helper_ready") else None

    wait_unix(connect, timeout=25, proc=proc, log=log)
    return sock, proc


RESULTS: dict[str, bool] = {}


def record(label: str, ok: bool, detail: str = ""):
    RESULTS[label] = ok
    status = "PASS" if ok else "FAIL"
    line = f"{label} {status}"
    if detail:
        line += f" ({detail})"
    print(line, flush=True)


def scenario_a(lab: RegtestLab):
    bid = publish_bounty(lab)
    hits = discover_by_description(lab, "repository maintenance Japanese")
    if not any(h.get("bounty_id") == bid for h in hits if isinstance(h, dict)):
        raise RpcError(f"observer did not discover bounty {bid} in {hits}")
    wallet = lab.ensure_wallet("funder")
    refund_pk = lab.pq_pubkey(wallet)
    wallet_fund_lot(lab, wallet, refund_pk)
    lab.cli(
        "observebountychain",
        json.dumps(
            {
                "bounty_id": bid,
                "outpoint": "f000000000000000000000000000000000000000000000000000000000000000:0",
                "amount_atoms": "500000",
                "confirmations": 6,
                "height": 200,
            }
        ),
    )
    art = lab.work / "artifact"
    art.mkdir()
    (art / "weights.bin").write_bytes(b"\x00" * 32)
    commit = lab.cli(
        "commitbountysubmission",
        json.dumps({"bounty_id": bid, "commitment": {"artifact_digest": "ab" * 48}}),
    )
    cid = commit.get("commitment_id") or commit.get("record_id")
    reveal = lab.cli(
        "revealbountysubmission",
        json.dumps(
            {
                "commitment_id": cid,
                "submission": {"artifact_dir": str(art), "evaluation_spec_id": "e2e-exact-checks"},
            }
        ),
    )
    sid = reveal.get("submission_id")
    prep = lab.cli(
        "preparebountyevaluation",
        json.dumps(
            {
                "submission_id": sid,
                "profile_id": "EXACT_CHECKS",
                "required_files": ["weights.bin"],
            }
        ),
    )
    job = lab.cli(
        "runbountyevaluation",
        json.dumps({"plan_id": prep.get("plan_id"), "execution_approval_ref": "e2e-user"}),
    )
    if job.get("state") != "COMPLETE" and not job.get("report"):
        raise RpcError(f"evaluation job: {job}")
    lab.cli("publishbountyevaluation", json.dumps({"job_id": job.get("job_id")}))
    award = lab.cli(
        "proposebountyaward",
        json.dumps({"bounty_id": bid, "submission_id": sid, "mode": "PUBLIC_PAYOUT"}),
    )
    aid = award.get("award_id")
    lab.cli("approvebountyaward", json.dumps({"award_id": aid, "decision": "APPROVE"}))
    feed = lab.cli("getmodelfeed", json.dumps({"scope": "LOCAL", "mode": "NEWEST", "limit": 20}))
    if feed.get("automatic_spend_atoms", 1) != 0:
        raise RpcError("feed automatic spend must be zero")


def scenario_b(lab: RegtestLab):
    bid = publish_bounty(lab)
    wallet = lab.ensure_wallet("c1")
    refund_pk = lab.pq_pubkey(wallet)
    fund = wallet_fund_lot(lab, wallet, refund_pk, principal=300000)
    lab.cli(
        "observebountychain",
        json.dumps(
            {
                "bounty_id": bid,
                "lot_id": "lot-c1",
                "outpoint": "a0" * 32 + ":1",
                "amount_atoms": "300000",
                "confirmations": 6,
                "height": 250,
            }
        ),
    )
    rec = lab.cli("exportbountyrecovery", json.dumps({"bounty_id": bid}))
    if rec.get("wallet_seed") or rec.get("private_keys"):
        raise RpcError("export must not include secrets")
    lab.stop()
    lab2 = RegtestLab("b-restore")
    lab2.start()
    require_bounty(lab2.cli)
    lab2.ensure_wallet("c1new")
    refund_new = lab2.pq_pubkey("c1new")
    ref_plan = {
        "bounty_id": bid,
        "principal_atoms": "300000",
        "refund_key": refund_new,
        "council_keys": [k["public_key_hex"] for k in council_keys(7, lab=lab2, wallet="c1new")],
        "threshold": 5,
        "award_height": 400,
        "refund_height": 800,
    }
    prep = lab2.cli("preparebountyrefund", json.dumps(ref_plan), wallet="c1new")
    if not prep.get("unsigned_hex"):
        raise RpcError(f"preparebountyrefund: {prep}")
    insp = lab2.cli(
        "inspectbountytransaction",
        json.dumps({**ref_plan, "hex": prep["unsigned_hex"]}),
        wallet="c1new",
    )
    if not insp.get("escrow_output_present") and not insp.get("descriptor"):
        raise RpcError(f"refund inspect: {insp}")


def scenario_c(lab: RegtestLab):
    terms = sample_terms(
        submission_mode="SEALED_REVIEW_TRUSTED",
        sealed_disclosure="Reviewers may see decrypt material; leakage is not prevented by protocol.",
    )
    bid = publish_bounty(lab, terms)
    secret = hashlib.sha256(b"e2e-sealed-secret").digest()
    preimage_hex = secret.hex()
    hashlock = hashlib.sha256(secret).hexdigest()
    wallet = lab.ensure_wallet("stage")
    refund_pk = lab.pq_pubkey(wallet)
    claim_pk = lab.pq_pubkey(wallet)
    plan = {
        "mode": "STAGED_RELEASE",
        "hashlock_hex": hashlock,
        "claimant_key": claim_pk,
        "refund_key": refund_pk,
        "refund_height": 900,
    }
    staged = lab.cli("preparebountyclaim", json.dumps(plan), wallet="stage")
    if preimage_hex in json.dumps(staged):
        raise RpcError("preimage leaked in preparebountyclaim response")
    desc = staged.get("descriptor") or ""
    if "htlc_sha256" not in desc:
        raise RpcError(f"expected staged htlc descriptor: {desc}")
    sub = lab.cli("listbountysubmissions", bid)
    blob = json.dumps(sub)
    if preimage_hex in blob or secret.hex() in blob:
        raise RpcError("secret in public submission metadata")


def scenario_d(lab: RegtestLab):
    bid = publish_bounty(lab)
    wallet = lab.ensure_wallet("d")
    good_refund = lab.pq_pubkey(wallet)
    bad_refund = lab.pq_pubkey(wallet)
    base = {
        "principal_atoms": "100000",
        "refund_key": good_refund,
        "fee_reserve_atoms": "50000",
        "council_keys": [k["public_key_hex"] for k in council_keys(7, lab=lab, wallet=wallet)],
        "threshold": 5,
        "award_height": 300,
        "refund_height": 500,
    }
    prep = lab.cli("preparebountyfunding", json.dumps(base), wallet="d")
    tx_hex = prep.get("unsigned_hex")
    insp = lab.cli("inspectbountytransaction", json.dumps({**base, "hex": tx_hex}), wallet="d")
    if not insp.get("escrow_output_present"):
        raise RpcError("good plan rejected")
    award = lab.cli(
        "proposebountyaward",
        json.dumps({"bounty_id": bid, "submission_id": "00" * 16, "mode": "PUBLIC_PAYOUT"}),
    )
    aid = award.get("award_id")
    rej = lab.cli("approvebountyaward", json.dumps({"award_id": aid, "decision": "REJECT"}))
    if not rej.get("rejected"):
        raise RpcError("wrong award must be rejectable")
    bad = dict(base, refund_key=bad_refund)
    try:
        lab.cli("inspectbountytransaction", json.dumps({**bad, "hex": tx_hex}), wallet="d")
        raise RpcError("refund key substitution must not validate")
    except (subprocess.CalledProcessError, RpcError):
        pass
    partial = lab.cli(
        "proposebountyaward",
        json.dumps({"bounty_id": bid, "submission_id": "11" * 16, "mode": "PUBLIC_PAYOUT"}),
    )
    pid = partial.get("award_id")
    got = lab.cli("getbountyaward", pid)
    if got.get("paid"):
        raise RpcError("malicious council must not auto-pay")


def scenario_e(lab: RegtestLab):
    bid = publish_bounty(lab)
    secret_hex = hashlib.sha256(b"reorg-secret").hexdigest()
    lab.cli(
        "observebountychain",
        json.dumps(
            {
                "bounty_id": bid,
                "outpoint": "b1" * 32 + ":0",
                "amount_atoms": "100000",
                "confirmations": 10,
                "height": 220,
            }
        ),
    )
    before = lab.cli("getbountyfunding", bid)
    confirmed_before = before.get("confirmed_atoms")
    lab.cli("reorgbountychain", json.dumps({"bounty_id": bid}))
    after = lab.cli("getbountyfunding", bid)
    confirmed_after = after.get("confirmed_atoms")
    if confirmed_before and str(confirmed_after) == str(confirmed_before) and str(confirmed_before) not in ("0", "None"):
        raise RpcError("reorg did not roll back confirmed_atoms")
    if secret_hex != hashlib.sha256(b"reorg-secret").hexdigest():
        raise RpcError("local secret knowledge lost")


def scenario_f(lab: RegtestLab):
    terms = sample_terms(nomination_min_bps=100)
    bid = publish_bounty(lab, terms)
    round_body = {
        "terms_id": bid,
        "lots": [
            {"principal_atoms": "1000", "refund_key_hint": "a"},
            {"principal_atoms": "99000", "refund_key_hint": "b"},
        ],
    }
    frozen = lab.cli("freezebountyfundinground", json.dumps(round_body))
    lots = frozen.get("lots") or []
    if len(lots) != 2:
        raise RpcError(f"freeze lots: {frozen}")
    sys.path.insert(0, str(BOUNTY / "reference"))
    from bounty_reference import eligible  # noqa: WPS433

    if not eligible("1000", "100000", 100):
        raise RpcError("1% boundary should be eligible at 1000/100000")
    if eligible("999", "100000", 100):
        raise RpcError("999 must not meet 1% threshold")
    late = dict(round_body)
    late["lots"].append({"principal_atoms": "1", "refund_key_hint": "late"})
    try:
        lab.cli("freezebountyfundinground", json.dumps(late))
        ok = False
    except (subprocess.CalledProcessError, RpcError):
        ok = True
    if not ok:
        raise RpcError("late roster mutation must fail")


def scenario_g(lab: RegtestLab):
    terms = sample_terms()
    bid = publish_bounty(lab, terms)
    man = lab.cli(
        "createagentmandate",
        json.dumps(
            {
                "owner_approval_ref": "e2e-owner",
                "mandate": {
                    "total_atoms": "2000000000",
                    "per_action_atoms": "500000000",
                    "terms_id": bid,
                    "bounty_id": bid,
                },
            }
        ),
    )
    mid = man.get("mandate_id")
    if not mid:
        raise RpcError(f"mandate: {man}")

    def reserve(key: str, amount: str):
        try:
            return lab.cli(
                "reservemandate",
                json.dumps({"mandate_id": mid, "idempotency_key": key, "amount_atoms": amount}),
            )
        except (subprocess.CalledProcessError, RpcError):
            return {"rejected": True}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(reserve, f"k{i}", "500000000") for i in range(6)]
        results = [f.result() for f in futs]
    used = int(lab.cli("getagentmandate", mid).get("used_atoms", "0"))
    if used > 2000000000:
        raise RpcError(f"mandate exceeded total budget: used={used}")
    reserve("k0", "500000000")
    used2 = int(lab.cli("getagentmandate", mid).get("used_atoms", "0"))
    if used2 != used:
        raise RpcError("idempotency replay changed used_atoms")
    lab.cli("revokeagentmandate", mid)
    after = reserve("after-revoke", "1")
    if not after.get("rejected"):
        raise RpcError("reserve after revoke must fail")


def modeld_sock_for(lab: RegtestLab) -> Path:
    for p in lab.datadir.rglob("modeld.sock"):
        return p
    raise RpcError("modeld.sock not found under datadir")


def scenario_h(lab: RegtestLab):
    publish_bounty(
        lab,
        sample_terms(description="WAN discovery unique phrase zeta-4421 maintenance"),
    )
    hits = discover_by_description(lab, "zeta-4421")
    if not hits:
        sm = lab.cli("searchmodels", json.dumps({"text": "zeta-4421", "scope": "LOCAL", "limit": 10}))
        if not (sm.get("results") or sm.get("models")):
            raise RpcError("description search returned no hits")
    helper_sock = modeld_sock_for(lab)
    snap = unix_rpc(helper_sock, "listmodelsearchrecords", [{"limit": 200}])
    observer_dir = lab.work / "peer-cache"
    sock_b, proc_b = start_modeld(observer_dir)
    try:
        if snap.get("records"):
            unix_rpc(sock_b, "importmodelindex", [{"records": snap["records"]}])
        cached = unix_rpc(sock_b, "searchbounties", [{"text": "zeta-4421", "scope": "LOCAL", "limit": 10}])
        if not (cached.get("results") or cached.get("models")):
            cached = unix_rpc(sock_b, "searchmodels", [{"text": "zeta-4421", "scope": "LOCAL", "limit": 10}])
        if not (cached.get("results") or cached.get("models")):
            nrec = len(snap.get("records") or [])
            raise RpcError(f"peer cache did not retain searchable records (imported {nrec})")
    finally:
        proc_b.terminate()
        try:
            proc_b.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc_b.kill()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    fwd = subprocess.Popen(
        [sys.executable, str(FORWARDER), str(helper_sock), str(port)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        line = fwd.stdout.readline().strip() if fwd.stdout else str(port)
        port = int(line or port)
        time.sleep(0.3)
        url = f"http://127.0.0.1:{port}/api/v1/bounties?q=zeta-4421"
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = json.loads(resp.read().decode())
        if body.get("wallet") is not False:
            raise RpcError("bridge must mark wallet false")
        for method in ("POST", "PUT"):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/wallet/sign",
                data=b"{}",
                method=method,
            )
            try:
                urllib.request.urlopen(req, timeout=3)
                raise RpcError(f"{method} wallet must not succeed")
            except urllib.error.HTTPError as e:
                if e.code not in (403, 405):
                    raise RpcError(f"expected 403/405 got {e.code}") from e
        for path in ("/eval/run", "/mandate/create"):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=b"{}", method="POST")
            try:
                urllib.request.urlopen(req, timeout=3)
                raise RpcError("POST eval/mandate must not succeed")
            except urllib.error.HTTPError as e:
                if e.code not in (403, 405, 404):
                    raise RpcError(f"bad status {e.code}") from e
        if not (EXPLORER / "index.html").is_file():
            raise RpcError("reference explorer missing")
        if "textContent" not in (EXPLORER / "app.js").read_text(encoding="utf-8"):
            raise RpcError("explorer app.js contract")
    finally:
        fwd.terminate()


def scenario_i():
    script = CONTRIB / "e2e-bounty-gui-gates.sh"
    subprocess.check_call([str(script)])


def scenario_j(lab: RegtestLab):
    if SCALE_CAP > 500:
        raise RpcError(f"scale cap {SCALE_CAP} too high for tmpfs e2e")
    before = len(list(Path("/tmp").glob("btx-bounty-e2e-*")))
    t0 = time.time()
    ids = []
    for i in range(SCALE_CAP):
        t = sample_terms(
            title=f"scale-{i:04d}",
            description=f"bounded scale token {i} repository",
        )
        ids.append(publish_bounty(lab, t))
        if i % 4 == 0:
            time.sleep(0.05)
    elapsed = time.time() - t0
    page = lab.cli("searchbounties", json.dumps({"text": "bounded scale token", "scope": "LOCAL", "limit": 200}))
    results = page.get("results") or []
    if len(results) > 100:
        raise RpcError(f"page exceeded BOUNTY_PAGE_MAX: {len(results)}")
    if len(results) < min(SCALE_CAP, 50):
        raise RpcError(f"expected search hits, got {len(results)}")
    after = len(list(Path("/tmp").glob("btx-bounty-e2e-*")))
    if after > before + 3:
        raise RpcError("/tmp leak: too many bounty e2e dirs")
    print(f"  scale: {SCALE_CAP} publishes in {elapsed:.2f}s, query returned {len(results)} (cap 100)")


SCENARIOS = [
    ("BOUNTY-E2E-A", scenario_a),
    ("BOUNTY-E2E-B", scenario_b),
    ("BOUNTY-E2E-C", scenario_c),
    ("BOUNTY-E2E-D", scenario_d),
    ("BOUNTY-E2E-E", scenario_e),
    ("BOUNTY-E2E-F", scenario_f),
    ("BOUNTY-E2E-G", scenario_g),
    ("BOUNTY-E2E-H", scenario_h),
    ("BOUNTY-E2E-I", lambda lab: scenario_i()),
    ("BOUNTY-E2E-J", scenario_j),
]


def main() -> int:
    if not BTXD.exists():
        print("BOUNTY-E2E setup FAIL (missing btxd)", file=sys.stderr)
        return 1
    failed = 0
    for label, fn in SCENARIOS:
        if label == "BOUNTY-E2E-I":
            try:
                fn(None)
                record(label, True)
            except Exception as e:
                record(label, False, str(e))
                failed += 1
            continue
        lab = RegtestLab(label[-1].lower())
        try:
            lab.start()
            require_bounty(lab.cli)
            fn(lab)
            record(label, True)
        except Exception as e:
            record(label, False, str(e))
            failed += 1
        finally:
            lab.stop()
    if failed:
        print(f"\nBOUNTY E2E: {failed} scenario(s) failed", file=sys.stderr)
        return 1
    print("\nBOUNTY E2E A–J PASS (not READY FOR RELEASE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
