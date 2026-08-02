#!/usr/bin/env python3
"""Two-node trusted-mirror rehearsal: GPU archive + CPU mirror.

Archive runs matmulvalidation=consensus with attestation signing/serving.
Mirror runs matmulvalidation=trusted and accepts Profile-1 ExactReplay via
signed quorum from the archive — no local GPU required.

Usage (run on the non-GPU host):

  ARCHIVE_HOST=gpu-archive.example.invalid \\
  ARCHIVE_USER=operator \\
  ARCHIVE_BTXD=/path/to/gpu-build/bin/btxd \\
  ARCHIVE_CLI=/path/to/gpu-build/bin//path/to/btx-cli \\
  MIRROR_BTXD=/path/to/cpu-build/bin/btxd \\
  MIRROR_CLI=/path/to/cpu-build/bin//path/to/btx-cli \\
  SIGNER_WIF_FILE=/secure/path/to/signer.wif \\
  SIGNER_PUB_FILE=/secure/path/to/signer.pub \\
  python3 -u contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py
"""
from __future__ import annotations

import atexit
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ACTIVATION = 6
DISABLED = 2_147_483_647

ARCHIVE_HOST = os.environ["ARCHIVE_HOST"]
ARCHIVE_USER = os.environ["ARCHIVE_USER"]
ARCHIVE_BTXD = os.environ["ARCHIVE_BTXD"]
ARCHIVE_CLI = os.environ["ARCHIVE_CLI"]
MIRROR_BTXD = Path(os.environ["MIRROR_BTXD"])
MIRROR_CLI = Path(os.environ["MIRROR_CLI"])
SIGNER_WIF_FILE = Path(os.environ["SIGNER_WIF_FILE"])
SIGNER_PUB = Path(os.environ["SIGNER_PUB_FILE"]).read_text().strip()

RUNTIME_ROOT = Path(os.environ.get("BTX_TRUSTED_MIRROR_TMPDIR", tempfile.gettempdir()))
ARCHIVE_DD = ""
MIRROR_DD = Path(tempfile.mkdtemp(prefix="btx-trusted-mirror-", dir=RUNTIME_ROOT))
ARCHIVE_RPC = 19821
ARCHIVE_P2P = 19822
MIRROR_RPC = 19831
MIRROR_P2P = 19832
OUT = Path(os.environ.get("BTX_TRUSTED_MIRROR_OUT", "trusted-mirror-result.json"))
KEEP_ARTIFACTS = os.environ.get("BTX_TRUSTED_MIRROR_KEEP_ARTIFACTS") == "1"


def cleanup_local_artifacts() -> None:
    if not KEEP_ARTIFACTS:
        shutil.rmtree(MIRROR_DD, ignore_errors=True)


atexit.register(cleanup_local_artifacts)


def sh_local(cmd: list[str], timeout: int = 120) -> str:
    r = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def sh_remote(remote_cmd: str, timeout: int = 120, input_text: str | None = None) -> str:
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", f"{ARCHIVE_USER}@{ARCHIVE_HOST}", remote_cmd],
        check=True,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
    )
    return r.stdout.strip()


def mirror_rpc(*args: str, timeout: int = 120):
    out = sh_local(
        [
            str(MIRROR_CLI),
            f"-datadir={MIRROR_DD}",
            f"-rpcport={MIRROR_RPC}",
            "-rpcuser=u",
            "-rpcpassword=p",
            "-rpcclienttimeout=0",
            *args,
        ],
        timeout=timeout,
    )
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def archive_rpc(*args: str, timeout: int = 120):
    # Escape for remote shell
    joined = " ".join(json.dumps(a) for a in args)
    cmd = (
        f"{shlex.quote(ARCHIVE_CLI)} -datadir={shlex.quote(ARCHIVE_DD)} "
        f"-rpcport={ARCHIVE_RPC} "
        f"-rpcuser=u -rpcpassword=p -rpcclienttimeout=0 {joined}"
    )
    out = sh_remote(cmd, timeout=timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def wait_rpc(fn, label: str, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            fn("getblockchaininfo")
            return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            time.sleep(0.5)
    raise RuntimeError(f"{label} RPC not ready: {last}")


def cleanup_remote_archive() -> None:
    if not ARCHIVE_DD:
        return
    try:
        sh_remote(
            f"kill $(cat {shlex.quote(ARCHIVE_DD + '/regtest/btxd.pid')} "
            "2>/dev/null) 2>/dev/null || true"
        )
    except Exception:
        pass
    try:
        sh_remote(f"rm -f -- {shlex.quote(ARCHIVE_DD + '/regtest/signer.wif')}")
    except Exception:
        pass
    if not KEEP_ARTIFACTS:
        try:
            sh_remote(f"rm -rf -- {shlex.quote(ARCHIVE_DD)}")
        except Exception:
            pass


def main() -> None:
    global ARCHIVE_DD
    ARCHIVE_DD = sh_remote("mktemp -d \"${TMPDIR:-/tmp}/btx-trusted-archive.XXXXXX\"")
    if not ARCHIVE_DD.startswith("/") or ARCHIVE_DD in {"/", "/tmp"}:
        raise RuntimeError("remote mktemp returned an unsafe archive datadir")
    atexit.register(cleanup_remote_archive)
    archive_regtest = f"{ARCHIVE_DD}/regtest"
    sh_remote(f"umask 077; mkdir -p {shlex.quote(archive_regtest)}")
    signer_wif = SIGNER_WIF_FILE.read_text().strip() + "\n"
    sh_remote(
        f"umask 077; cat > {shlex.quote(archive_regtest + '/signer.wif')}",
        input_text=signer_wif,
    )
    del signer_wif

    common_regtest = f"""
regtest=1
server=1
dnsseed=0
fixedseeds=0
listen=1
discover=0
rpcuser=u
rpcpassword=p
fallbackfee=0.0002
debug=net
printtoconsole=0
matmulasyncverify=1
regtestmatmulbindingheight=2
regtestmatmulproductdigestheight=2
regtestmatmulrequireproductpayload=0
regtestmatmulv4height={ACTIVATION}
regtestbmx4cheight={ACTIVATION}
regtestdrltheight={DISABLED}
regtestrcheight={ACTIVATION}
regtestrccoupledheight={DISABLED}
regtestrcprofile=1
regtestrctoydims=0
regtestrccoupledtoydims=0
regtestmatmulltsealaspow=0
regtestmatmulv4dimension=4096
regtestmatmulv4maxdimension=4096
matmultrustedpubkey={SIGNER_PUB}
matmultrustedthreshold=1
matmultrustedwaitms=60000
"""

    archive_conf = common_regtest + f"""
matmulvalidation=consensus
matmulrcexecution=strict-device
matmulattestationsignerkeyfile=signer.wif
matmulattestationserve=1
listenonion=0
allowdangerousnoban=1
whitelist=noban,in,out@127.0.0.1
[regtest]
port={ARCHIVE_P2P}
rpcport={ARCHIVE_RPC}
bind=127.0.0.1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
"""
    # Write archive conf remotely
    sh_remote(
        f"umask 077; cat > {shlex.quote(ARCHIVE_DD + '/btx.conf')}",
        input_text=archive_conf,
    )

    # SSH local forward so this host reaches archive P2P on loopback
    # (LAN P2P may be firewalled; RPC stays via ssh command).
    tunnel = subprocess.Popen(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-N",
            "-L",
            f"127.0.0.1:{ARCHIVE_P2P}:127.0.0.1:{ARCHIVE_P2P}",
            f"{ARCHIVE_USER}@{ARCHIVE_HOST}",
        ]
    )
    atexit.register(tunnel.terminate)
    time.sleep(1)

    mirror_conf = common_regtest + f"""
matmulvalidation=trusted
matmulrcexecution=strict-device
matmulattestationserve=0
listenonion=0
[regtest]
port={MIRROR_P2P}
rpcport={MIRROR_RPC}
connect=127.0.0.1:{ARCHIVE_P2P}
"""
    (MIRROR_DD / "btx.conf").write_text(mirror_conf)

    # Start archive on GPU host
    sh_remote(
        f"CUDA_VISIBLE_DEVICES=0 nohup {shlex.quote(ARCHIVE_BTXD)} "
        f"-datadir={shlex.quote(ARCHIVE_DD)} "
        f"-conf={shlex.quote(ARCHIVE_DD + '/btx.conf')} "
        f">{shlex.quote(ARCHIVE_DD + '/stdout.log')} 2>&1 & echo $!"
    )
    wait_rpc(archive_rpc, "archive")
    archive_rpc("createwallet", "miner")

    # Start local mirror
    mirror_log = (MIRROR_DD / "stdout.log").open("w")
    mirror_proc = subprocess.Popen(
        [str(MIRROR_BTXD), f"-datadir={MIRROR_DD}", f"-conf={MIRROR_DD / 'btx.conf'}"],
        stdout=mirror_log,
        stderr=subprocess.STDOUT,
    )
    atexit.register(mirror_proc.terminate)
    try:
        wait_rpc(mirror_rpc, "mirror")
        # Wait until P2P link is up through the tunnel
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            peers = mirror_rpc("getpeerinfo") or []
            if peers:
                print(f"mirror peers={[p.get('addr') for p in peers]}", flush=True)
                break
            time.sleep(1)
        else:
            raise RuntimeError("mirror never connected to archive P2P via tunnel")

        a_net = archive_rpc("getnetworkinfo")
        m_net = mirror_rpc("getnetworkinfo")
        a_services = a_net.get("localservicesnames", [])
        m_services = m_net.get("localservicesnames", [])
        print("archive_services", a_services, flush=True)
        print("mirror_services", m_services, flush=True)

        # Mine through activation+2 on archive; mirror should follow via attestations
        timings = []
        for _ in range(ACTIVATION + 2):
            t0 = time.perf_counter()
            archive_rpc("generatetoaddress", "1", archive_rpc("getnewaddress"))
            dt = time.perf_counter() - t0
            ah = archive_rpc("getblockcount")
            timings.append({"mined_height": ah, "archive_generate_s": round(dt, 3)})
            print(f"archive mined h={ah} in {dt:.3f}s", flush=True)

        tip = archive_rpc("getbestblockhash")
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if mirror_rpc("getbestblockhash") == tip:
                break
            time.sleep(1)
        else:
            raise RuntimeError(
                "mirror did not catch tip; trusted="
                + json.dumps(mirror_rpc("getmatmultrustedstatus"))
            )

        trusted = mirror_rpc("getmatmultrustedstatus")
        archive_rc = archive_rpc("getmininginfo").get("rc_exact_replay", {})
        canary = archive_rc.get("production_canary", {})
        validation = archive_rc.get("last_validation", {})
        if not (
            canary.get("passed")
            and validation.get("fully_accelerated")
            and validation.get("cpu_gemm_calls") == 0
            and validation.get("cpu_gemm_fallbacks") == 0
        ):
            raise RuntimeError("archive did not prove strict zero-fallback ExactReplay")
        result = {
            "ok": True,
            "archive_host_class": "cuda_gpu_exactreplay_archive",
            "mirror_host_class": "cpu_trusted_mirror",
            "p2p_path": "ssh_local_forward",
            "activation_height": ACTIVATION,
            "archive_tip": tip,
            "mirror_tip": mirror_rpc("getbestblockhash"),
            "mirror_height": mirror_rpc("getblockcount"),
            "archive_services": a_services,
            "mirror_services": m_services,
            "mirror_mode": mirror_rpc("getblockchaininfo").get("matmulvalidationmode"),
            "trusted_status": trusted,
            "archive_production_canary": canary,
            "archive_last_validation": validation,
            "timings": timings,
            "activation_block_s": next(
                (t["archive_generate_s"] for t in timings if t["mined_height"] == ACTIVATION),
                None,
            ),
        }
        OUT.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        print(f"WROTE {OUT}")
    finally:
        mirror_proc.terminate()
        try:
            mirror_proc.wait(timeout=30)
        except Exception:
            mirror_proc.kill()
        atexit.unregister(mirror_proc.terminate)
        tunnel.terminate()
        try:
            tunnel.wait(timeout=10)
        except Exception:
            tunnel.kill()
        atexit.unregister(tunnel.terminate)
        cleanup_remote_archive()
        atexit.unregister(cleanup_remote_archive)
        cleanup_local_artifacts()
        atexit.unregister(cleanup_local_artifacts)


if __name__ == "__main__":
    main()
