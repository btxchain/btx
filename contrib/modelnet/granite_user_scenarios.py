#!/usr/bin/env python3
"""User scenarios for granite-4.0-h-tiny: .btx link, FREE_ONLY retrieve, checkout, CUDA hold+smoke.

Not a claim of usefulness, safety, or alignment. execution_profile stays 0
(unqualified hybrid; not dense-decoder-v1). automatic_spend_atoms stays 0.
Does not touch production btxd or ~/.btx. Does not disturb a helper on 29447.
loadmodel with BTX_MODEL_CUDA_LOADER keeps tensors resident until unloadmodel.
inference/remote_inference stay false (no network server).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failfast import poll_job, wait_unix

WANT_PIECES = 3322
WANT_BYTES = 13888336427


def rpc(sock: Path, method: str, params, timeout: float):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def wait_sock(path: Path, proc=None, timeout=20):
    wait_unix(
        lambda: rpc(path, "getmodelnetworkinfo", [], timeout=5) or True,
        timeout=timeout,
        proc=proc,
        log=path.parent / "modeld.log",
    )


def fail(msg):
    raise SystemExit(msg)


def spend0(obj, where: str):
    if not isinstance(obj, dict) or "automatic_spend_atoms" not in obj:
        fail(f"{where}: automatic_spend_atoms missing")
    if int(obj["automatic_spend_atoms"]) != 0:
        fail(f"{where}: automatic_spend_atoms={obj['automatic_spend_atoms']}")


def under_home_btx(path: Path) -> bool:
    home = (Path.home() / ".btx").resolve()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path.absolute()
    return resolved == home or home in resolved.parents


def sha384_file(path: Path) -> str:
    digest = hashlib.sha384()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_pieces(peer_dir: Path):
    root = peer_dir / "store" / "artifacts"
    pieces = []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            kept = []
            for d in dirnames:
                if not (Path(dirpath) / d).is_symlink():
                    kept.append(d)
            dirnames[:] = kept
            for name in filenames:
                fp = Path(dirpath) / name
                if name.endswith(".piece") and fp.is_file() and not fp.is_symlink():
                    pieces.append(fp)
    nbytes = sum(p.stat().st_size for p in pieces)
    return len(pieces), nbytes


def require_pieces(peer_dir: Path, where: str):
    n, nbytes = count_pieces(peer_dir)
    if n != WANT_PIECES or nbytes != WANT_BYTES:
        fail(f"{where}: peer store {n} pieces / {nbytes} bytes; want {WANT_PIECES} / {WANT_BYTES}")


def pick_model(listed, uri=None):
    models = listed.get("models") or []
    if uri:
        for m in models:
            if m.get("uri") == uri or m.get("model_id") == uri:
                return m
    complete = [m for m in models if m.get("complete") is True and m.get("incomplete") is not True]
    if len(complete) == 1:
        return complete[0]
    if len(models) == 1:
        return models[0]
    return None


def finish_getmodel(sock: Path, got: dict, timeout: float, label: str):
    spend0(got, label)
    status = got.get("status")
    job_id = got.get("job_id")
    if status in ("retrieved", "local"):
        return got
    if status == "running" or got.get("async"):
        if not job_id:
            fail(f"{label}: async getmodel missing job_id: {got}")
        t0 = time.time()

        def progress(job):
            print(
                label,
                job.get("job_id") or job_id,
                job.get("status"),
                "elapsed",
                int(time.time() - t0),
                "bytes_committed",
                job.get("bytes_committed"),
                "pieces",
                job.get("pieces_committed"),
                "file",
                job.get("file_index"),
                "piece",
                job.get("piece_index"),
                "inflight",
                job.get("inflight"),
                "last_err",
                job.get("last_err") or job.get("error"),
                flush=True,
            )

        job = poll_job(
            lambda: rpc(sock, "getmodeljob", [job_id], timeout=120),
            timeout=timeout,
            interval=2.0,
            progress=progress,
            stall_s=300.0,
            job_id=job_id,
        )
        print(label, "job_done", job.get("status"), "elapsed_s", int(time.time() - t0), flush=True)
        result = job.get("result") or {}
        if isinstance(result, dict) and "automatic_spend_atoms" in result:
            spend0(result, label + " result")
        if not isinstance(result, dict) or result.get("status") not in ("retrieved", "local"):
            fail(f"{label}: retrieve did not complete: {job}")
        return job
    fail(f"{label}: retrieve did not complete: {got}")


def checkout_file(root: Path, rel: str) -> Path:
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        fail(f"catalog path escapes checkout: {rel}")
    dest = root.joinpath(*rel_path.parts)
    if ".." in dest.parts:
        fail(f"catalog path escapes checkout: {rel}")
    return dest


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bin", required=True, help="directory containing btx-modeld")
    p.add_argument("--fixture", required=True, help="granite-4.0-h-tiny directory")
    p.add_argument("--host-dir", required=True)
    p.add_argument("--peer-dir", required=True)
    p.add_argument("--bind", default="127.0.0.1:29449")
    p.add_argument("--btx-out", default="granite.btx")
    p.add_argument("--cuda-loader", default="", help="path to cuda_safetensors_load; sets BTX_MODEL_CUDA_LOADER on the peer")
    p.add_argument("--generate-adapter", default="", help="path to BTX_MODEL_GENERATE adapter on the peer (optional local generate after unload)")
    p.add_argument("--skip-import", action="store_true")
    p.add_argument("--retrieve-timeout", type=float, default=14400)
    p.add_argument("--import-timeout", type=float, default=7200)
    p.add_argument("--cache", type=int, default=85899345920)
    args = p.parse_args()

    if str(args.bind).endswith(":29447"):
        fail("refusing bind port 29447; leftover helpers stay up")

    host_dir = Path(args.host_dir)
    peer_dir = Path(args.peer_dir)
    if under_home_btx(host_dir) or under_home_btx(peer_dir):
        fail("refusing datadir under ~/.btx")
    if host_dir.resolve() == peer_dir.resolve():
        fail("host-dir and peer-dir must differ")

    btx_out = Path(args.btx_out)
    if not btx_out.is_absolute():
        btx_out = Path.cwd() / btx_out
    btx_out = btx_out.absolute()
    if under_home_btx(btx_out):
        fail("refusing --btx-out under ~/.btx")
    btx_out.parent.mkdir(parents=True, exist_ok=True)

    cuda_loader = Path(args.cuda_loader).absolute() if args.cuda_loader else None
    if cuda_loader is not None and not cuda_loader.is_file():
        fail(f"cuda loader is not a file: {cuda_loader}")
    generate_adapter = Path(args.generate_adapter).absolute() if args.generate_adapter else None
    if generate_adapter is not None and not generate_adapter.is_file():
        fail(f"generate adapter is not a file: {generate_adapter}")

    bindir = Path(args.bin)
    modeld = bindir / "run-modeld.sh"
    if not modeld.exists():
        modeld = bindir / "btx-modeld"
    env = os.environ.copy()
    lib = bindir.parent / "lib"
    if (lib / "libssl.so.3").exists():
        env["LD_LIBRARY_PATH"] = str(lib) + ((":" + env["LD_LIBRARY_PATH"]) if env.get("LD_LIBRARY_PATH") else "")
        env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
        if (bindir / "openssl35").exists():
            env["BTX_OPENSSL"] = str(bindir / "openssl35")
    peer_env = env.copy()
    if cuda_loader is not None:
        peer_env["BTX_MODEL_CUDA_LOADER"] = str(cuda_loader)
    if generate_adapter is not None:
        peer_env["BTX_MODEL_GENERATE"] = str(generate_adapter)

    host_dir.mkdir(parents=True, exist_ok=True)
    peer_dir.mkdir(parents=True, exist_ok=True)
    hs = host_dir / "modeld.sock"
    ps = peer_dir / "modeld.sock"

    logh = open(host_dir / "modeld.log", "ab")
    logp = open(peer_dir / "modeld.log", "ab")
    ph = subprocess.Popen(
        [
            str(modeld),
            f"-modeldir={host_dir}",
            f"-modelcache={args.cache}",
            f"-modelbind={args.bind}",
            "-modelhost",
            f"-modelrpcsocket={hs}",
        ],
        stdout=logh,
        stderr=subprocess.STDOUT,
        env=env,
    )
    pp = subprocess.Popen(
        [
            str(modeld),
            f"-modeldir={peer_dir}",
            f"-modelcache={args.cache}",
            f"-modelrpcsocket={ps}",
        ],
        stdout=logp,
        stderr=subprocess.STDOUT,
        env=peer_env,
    )
    try:
        wait_sock(hs, proc=ph)
        wait_sock(ps, proc=pp)

        # A. Host import (or skip), complete list, .btx link with uri + copy_text.
        listed = rpc(hs, "listmodels", [], timeout=30)
        spend0(listed, "listmodels")
        row = pick_model(listed)
        uri = None
        if row and row.get("complete") is True and not args.skip_import and listed.get("local_count"):
            uri = row.get("uri")
            print("already_imported", uri, flush=True)
        if args.skip_import:
            if not row or row.get("complete") is not True:
                fail(f"skip-import requires a complete listmodels row: {listed}")
            uri = row.get("uri")
        elif not uri:
            print("importing", args.fixture, flush=True)
            t0 = time.time()
            imported = rpc(hs, "importmodel", [args.fixture, {"pin": True}], timeout=args.import_timeout)
            spend0(imported, "importmodel")
            if imported.get("pinned") is not True:
                fail(f"importmodel pin=true did not pin: {imported}")
            uri = imported.get("uri")
            print("imported", uri, "elapsed_s", int(time.time() - t0), flush=True)
        if not uri or not str(uri).startswith("btx://"):
            fail(f"no btx uri: {uri}")
        listed_h = rpc(hs, "listmodels", [], timeout=30)
        spend0(listed_h, "listmodels")
        host_row = pick_model(listed_h, uri)
        if not host_row or host_row.get("complete") is not True or host_row.get("incomplete") is True:
            fail(f"listmodels is not complete: {host_row}")
        link = rpc(hs, "exportmodellink", [uri, str(btx_out)], timeout=60)
        spend0(link, "exportmodellink")
        if link.get("written") is not True:
            fail(f"exportmodellink did not write: {link}")
        if not btx_out.is_file():
            fail(f"missing link file {btx_out}")
        doc = json.loads(btx_out.read_text(encoding="utf-8"))
        link_uri = str(doc.get("uri") or "")
        copy_text = str(doc.get("copy_text") or "")
        if not link_uri.startswith("btx://") or "btx://" not in copy_text:
            fail(f".btx missing uri+copy_text: {doc}")
        if link_uri != uri or uri not in copy_text:
            fail(f"link uri/copy_text does not match imported {uri}: {doc}")
        canon = link_uri
        print("scenario A ok", canon, flush=True)

        # B. Opening the .btx is a preview: no network, no inference, FREE_ONLY is proposed.
        opened = rpc(hs, "openmodelshare", [str(btx_out)], timeout=30)
        spend0(opened, "openmodelshare")
        if opened.get("network") is not False or opened.get("inference") is not False:
            fail(f"openmodelshare network/inference: {opened}")
        actions = opened.get("proposed_actions") or []
        if "getmodel FREE_ONLY" not in actions:
            fail(f"openmodelshare proposed_actions missing getmodel FREE_ONLY: {actions}")
        print("scenario B ok", flush=True)

        # C. Cold peer. hostmodel of the .btx is a share card; getmodel retrieves the uri.
        rpc(ps, "addmodelnode", [args.bind], timeout=10)
        card = rpc(ps, "hostmodel", [str(btx_out)], timeout=60)
        spend0(card, "hostmodel")
        if card.get("reason") != "share_card":
            fail(f"hostmodel of .btx must be share_card: {card}")
        card_uri = str(card.get("uri") or "")
        if not card_uri.startswith("btx://"):
            fail(f"share_card missing uri: {card}")
        if card_uri != canon:
            fail(f"share_card uri {card_uri} != link uri {canon}")
        print("retrieve FREE_ONLY", card_uri, flush=True)
        got = rpc(ps, "getmodel", [card_uri, "FREE_ONLY"], timeout=60)
        finish_getmodel(ps, got, args.retrieve_timeout, "scenario C")
        listed_b = rpc(ps, "listmodels", [], timeout=30)
        spend0(listed_b, "peer listmodels")
        peer_row = pick_model(listed_b, canon)
        if not peer_row or peer_row.get("complete") is not True or peer_row.get("incomplete") is True:
            fail(f"peer listmodels is not complete: {peer_row}")
        info_b = rpc(ps, "getmodelnetworkinfo", [], timeout=10)
        used = int(info_b.get("used_bytes") or 0)
        if used < WANT_BYTES:
            fail(f"peer used_bytes {used} < {WANT_BYTES}")
        require_pieces(peer_dir, "scenario C")
        print("scenario C ok", WANT_PIECES, WANT_BYTES, flush=True)

        # D. Canonical btx:// from the link file. Already-local is success.
        got_d = rpc(ps, "getmodel", [canon, "FREE_ONLY"], timeout=60)
        if got_d.get("status") == "local":
            spend0(got_d, "scenario D")
        else:
            finish_getmodel(ps, got_d, args.retrieve_timeout, "scenario D")
        require_pieces(peer_dir, "scenario D")
        print("scenario D ok", canon, got_d.get("status"), flush=True)

        # E. Checkout is real files, not only .piece objects. sha384 matches the catalog.
        exported = rpc(ps, "exportmodelpath", [canon], timeout=args.retrieve_timeout)
        spend0(exported, "exportmodelpath")
        if exported.get("inference") is not False or exported.get("runtime_started") is not False:
            fail(f"exportmodelpath started a runtime: {exported}")
        root = Path(str(exported.get("path") or ""))
        if not root.is_dir():
            fail(f"exportmodelpath path is not a directory: {exported.get('path')}")
        files = exported.get("files") or []
        if not files:
            fail("exportmodelpath has no catalog files")
        saw_cfg = False
        saw_st = False
        saw_piece_name = False
        for f in files:
            rel = str(f.get("path") or "")
            if not rel or rel.endswith(".piece") or Path(rel).name.endswith(".piece"):
                saw_piece_name = True
            fp = checkout_file(root, rel)
            if fp.is_symlink():
                fail(f"checkout symlink: {rel}")
            try:
                st = fp.lstat()
            except OSError:
                fail(f"checkout missing regular file: {rel}")
            if not stat.S_ISREG(st.st_mode):
                fail(f"checkout missing regular file: {rel}")
            size = int(f["size"])
            if st.st_size != size:
                fail(f"size mismatch {rel}: disk={st.st_size} catalog={size}")
            digest = sha384_file(fp)
            want = str(f.get("sha384") or "").lower()
            if not want or digest != want:
                fail(f"sha384 mismatch {rel}: disk={digest} catalog={want}")
            name = Path(rel).name
            if name == "config.json":
                saw_cfg = True
            if name.endswith(".safetensors"):
                saw_st = True
        if saw_piece_name and not saw_st:
            fail("exportmodelpath catalog is only .piece files")
        disk_st = []
        disk_pieces = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
            for name in filenames:
                fp = Path(dirpath) / name
                if fp.is_symlink():
                    continue
                if name.endswith(".piece"):
                    disk_pieces.append(fp)
                if name.endswith(".safetensors") and stat.S_ISREG(fp.lstat().st_mode):
                    disk_st.append(fp)
        if not (root / "config.json").is_file() and not saw_cfg:
            fail(f"checkout missing config.json: {root}")
        if not saw_cfg:
            cfg = root / "config.json"
            if not cfg.is_file() or cfg.is_symlink():
                fail(f"checkout missing config.json: {root}")
        if not saw_st or not disk_st:
            fail(f"checkout has no real .safetensors (piece files={len(disk_pieces)})")
        print("scenario E ok", root, "files", len(files), "safetensors", len(disk_st), flush=True)

        # F. loadmodel keeps CUDA tensors resident and smokes a kernel. No network server.
        loaded = rpc(ps, "loadmodel", [canon], timeout=args.retrieve_timeout)
        spend0(loaded, "loadmodel")
        if loaded.get("inference") is not False or loaded.get("remote_inference") is not False:
            fail(f"loadmodel started a network inference server: {loaded}")
        if int(loaded.get("execution_profile") or 0) != 0:
            fail(f"granite execution_profile must stay 0: {loaded}")
        if cuda_loader is not None:
            if peer_env.get("BTX_MODEL_CUDA_LOADER") != str(cuda_loader):
                fail("BTX_MODEL_CUDA_LOADER was not set on the peer")
            if loaded.get("device_loaded") is not True:
                fail(f"device_loaded is not true: {loaded}")
            if loaded.get("weights_resident") is not True:
                fail(f"weights_resident is not true: {loaded}")
            if loaded.get("runtime_started") is not True:
                fail(f"runtime_started is not true: {loaded}")
            if loaded.get("smoke_passed") is not True:
                fail(f"smoke_passed is not true: {loaded}")
            if int(loaded.get("bytes_on_device") or 0) <= 0:
                fail(f"bytes_on_device not > 0: {loaded}")
            unloaded = rpc(ps, "unloadmodel", [canon], timeout=60)
            spend0(unloaded, "unloadmodel")
            if unloaded.get("unloaded") is not True:
                fail(f"unloadmodel failed: {unloaded}")
        elif loaded.get("device_loaded") is True:
            fail(f"device_loaded without cuda loader: {loaded}")
        print("scenario F ok", "device_loaded", loaded.get("device_loaded"), "bytes_on_device", loaded.get("bytes_on_device"), "smoke", loaded.get("smoke_passed"), flush=True)

        # G. Optional local generate after CUDA unload (host-profile match; not a network server).
        if generate_adapter is not None:
            gen = rpc(ps, "generatemodel", [canon, {"prompt": "Hello", "max_new_tokens": 8}], timeout=args.retrieve_timeout)
            spend0(gen, "generatemodel")
            if gen.get("generated") is not True or gen.get("local_generate") is not True:
                fail(f"generatemodel did not generate: {gen}")
            if gen.get("inference") is not False or gen.get("remote_inference") is not False:
                fail(f"generatemodel claimed a network server: {gen}")
            if not str(gen.get("text") or "").strip():
                fail(f"generatemodel empty text: {gen}")
            print("scenario G ok", "backend", gen.get("backend"), "arch", gen.get("architecture"), flush=True)
        print("GRANITE_USER_SCENARIOS PASS")
    finally:
        for proc in (ph, pp):
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        logh.close()
        logp.close()


if __name__ == "__main__":
    main()
