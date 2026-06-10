#!/usr/bin/env python3
"""
contrib/mining/live-mining-loop.py — RPC-keepalive variant of the live mining loop.

WHY THIS FILE EXISTS
====================
The shell-based ``live-mining-loop.sh`` in this same directory drives mining by
forking ``btx-cli`` once per loop iteration. On a 1-second cadence that is
~86,400 process spawns per day, plus another spawn every iteration for
``getmininginfo`` and assorted health probes, so a host running a single solo
miner can easily fork ``btx-cli`` 150,000+ times per day.

On macOS in particular, every fresh process triggers ``syspolicyd`` and
``XprotectService`` malware-scan checks. At one-second cadence that workload
keeps those system services warm continuously, which on portable hardware
manifests as sustained moderate CPU use, audible fans, and (eventually)
``kernel_task`` thermal throttling — even when the underlying mining work is
trivial. The shell loop is functionally correct; the cost is purely in the
per-spawn overhead.

This Python loop replaces the per-iteration fork with a single long-running
process that holds an HTTP keepalive connection to the same JSON-RPC endpoint
``btx-cli`` would have talked to internally. Functionally identical to the
shell loop's inner ``generatetoaddress`` call; one process spawn at startup
instead of one per iteration.

DESIGN POSITIONING vs ``live-mining-loop.sh``
=============================================
- The shell loop is the supervisor: it watches ``getmininginfo.chain_guard``,
  manages peer remediation, restarts ``btxd`` when the node stalls, gates on
  an optional ``--should-mine-command`` idleness probe, and so on.
- This Python loop is the leaner alternative: it assumes the daemon is already
  running and healthy and does *only* the mining-call cadence. It is suited to
  setups where you have separate health/peer monitoring, or where the
  per-spawn cost of the shell loop is the dominant operational concern (e.g.,
  laptops, low-thermal-headroom Apple Silicon hosts, dev workstations).
- Both files share the same flag interface for the options that apply to both,
  so an operator can swap one for the other by changing only the script path.

The ``contrib/mining/README.md`` discusses when each is appropriate.

AUTH MODEL
==========
``btxd`` accepts JSON-RPC auth via either:
  1. ``rpcuser`` / ``rpcpassword`` set in ``btx.conf`` (or passed via flags), or
  2. an auto-generated ``.cookie`` file inside ``-datadir`` (when no rpcuser
     is configured).

This loop supports both. Resolution order at startup:
  - explicit ``--rpcuser`` / ``--rpcpassword`` flags
  - explicit ``--rpccookiefile`` flag
  - ``rpcuser`` / ``rpcpassword`` parsed from ``--conf`` (or ``$DATADIR/btx.conf``)
  - ``.cookie`` file inside ``--datadir``

If the daemon restarts and rotates its cookie or its config is edited live,
the loop re-reads credentials on the next 401 / connection error so it
recovers without operator intervention.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import pathlib
import platform
import sys
import time
from typing import Optional


# Match the existing live-mining-loop.sh defaults so the two scripts feel
# interchangeable from the operator's point of view.
DEFAULT_SLEEP_SECS = 1.0
DEFAULT_RPC_HOST = "127.0.0.1"
DEFAULT_RPC_PORT = 19334
DEFAULT_WALLET = "miner"


class RpcAuthError(RuntimeError):
    """Raised when no usable RPC credential can be resolved."""


class RpcConfig:
    """
    Bundles the resolved JSON-RPC connection parameters.

    Mutable so the loop can refresh credentials in-place after a 401 or a
    daemon restart that rotated the cookie.
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: Optional[str],
        password: Optional[str],
        cookie_path: Optional[pathlib.Path],
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.cookie_path = cookie_path

    def auth_header(self) -> str:
        # Bitcoin/btxd JSON-RPC uses HTTP Basic auth. Cookie-mode credentials
        # are formatted as "__cookie__:<random_hex>" inside the .cookie file —
        # already a valid Basic credential, no special handling required.
        if self.user is not None and self.password is not None:
            token = f"{self.user}:{self.password}"
        elif self.cookie_path is not None:
            token = self.cookie_path.read_text().strip()
        else:
            raise RpcAuthError(
                "no rpcuser/rpcpassword and no cookie file available"
            )
        return "Basic " + base64.b64encode(token.encode()).decode()


def parse_btx_conf(conf_path: pathlib.Path) -> dict[str, str]:
    """
    Parse the subset of btx.conf keys we care about.

    btxd's config format is one ``key=value`` per line, with ``#`` comments
    and optional ``[section]`` headers. We do not need section-awareness for
    rpcuser / rpcpassword / rpcport on a single-chain node.
    """
    out: dict[str, str] = {}
    if not conf_path.is_file():
        return out
    for raw in conf_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("[") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def resolve_rpc_config(args: argparse.Namespace) -> RpcConfig:
    """
    Build an RpcConfig from CLI flags, falling back to btx.conf and then to
    the cookie file inside datadir. Flags always win; this matches the
    precedence ``btx-cli`` itself uses.
    """
    conf_path = (
        pathlib.Path(args.conf)
        if args.conf
        else (pathlib.Path(args.datadir) / "btx.conf" if args.datadir else None)
    )
    conf = parse_btx_conf(conf_path) if conf_path else {}

    host = args.rpcconnect or conf.get("rpcconnect") or DEFAULT_RPC_HOST
    port_str = args.rpcport or conf.get("rpcport")
    port = int(port_str) if port_str else DEFAULT_RPC_PORT

    user = args.rpcuser or conf.get("rpcuser")
    password = args.rpcpassword or conf.get("rpcpassword")

    cookie_path: Optional[pathlib.Path] = None
    if args.rpccookiefile:
        cookie_path = pathlib.Path(args.rpccookiefile)
    elif (user is None or password is None) and args.datadir:
        candidate = pathlib.Path(args.datadir) / ".cookie"
        if candidate.is_file():
            cookie_path = candidate

    if (user is None or password is None) and cookie_path is None:
        raise RpcAuthError(
            "no rpcuser/rpcpassword in flags or btx.conf, and no .cookie "
            "file in datadir; cannot authenticate to JSON-RPC"
        )

    return RpcConfig(
        host=host, port=port, user=user, password=password, cookie_path=cookie_path
    )


def is_apple_silicon_host() -> bool:
    host_os = os.environ.get("BTX_MINING_HOST_OS_FOR_TEST") or platform.system()
    host_arch = os.environ.get("BTX_MINING_HOST_ARCH_FOR_TEST") or platform.machine()
    return host_os == "Darwin" and host_arch == "arm64"


def default_required_backend() -> str:
    configured = os.environ.get(
        "BTX_MINING_REQUIRE_BACKEND",
        os.environ.get("BTX_MATMUL_REQUIRE_BACKEND", ""),
    )
    if configured:
        return configured
    return "metal" if is_apple_silicon_host() else ""


def resolve_address(args: argparse.Namespace) -> str:
    if args.address:
        return args.address.strip()
    if args.address_file:
        return pathlib.Path(args.address_file).read_text().strip()
    raise RuntimeError("either --address or --address-file must be provided")


def log(stream, msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S%z')}] {msg}", file=stream, flush=True)


def normalize_backend(value: str) -> str:
    return value.strip().lower()


def resolved_required_backend(args: argparse.Namespace) -> str:
    required = normalize_backend(args.require_backend or "")
    if required in {"", "0", "false", "no", "off", "none", "disabled"}:
        return ""
    if required in {"1", "true", "yes", "on"}:
        env_backend = os.environ.get("BTX_MATMUL_BACKEND", "").strip()
        if env_backend:
            return normalize_backend(env_backend)
        return "metal" if platform.system() == "Darwin" else "cpu"
    return required


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="live-mining-loop.py",
        description=(
            "RPC-keepalive variant of live-mining-loop.sh. Mines via a single "
            "long-running process that reuses one HTTP connection to the "
            "JSON-RPC endpoint, instead of forking btx-cli per iteration."
        ),
    )
    p.add_argument("--datadir", help="BTX datadir (used to find btx.conf and .cookie)")
    p.add_argument("--conf", help="Path to btx.conf (default: $DATADIR/btx.conf)")
    p.add_argument("--rpcconnect", help="JSON-RPC host (default: 127.0.0.1)")
    p.add_argument("--rpcport", help="JSON-RPC port (default: 19334 or btx.conf)")
    p.add_argument("--rpcuser", help="JSON-RPC username")
    p.add_argument("--rpcpassword", help="JSON-RPC password")
    p.add_argument("--rpccookiefile", help="Explicit cookie file path for cookie auth")
    p.add_argument(
        "--wallet",
        default=DEFAULT_WALLET,
        help="Wallet name. Currently unused by generatetoaddress but accepted "
        "for flag compatibility with live-mining-loop.sh.",
    )
    p.add_argument("--address", help="Mining payout address")
    p.add_argument("--address-file", help="File containing a mining payout address")
    p.add_argument(
        "--sleep",
        type=float,
        default=DEFAULT_SLEEP_SECS,
        help=f"Seconds between RPC calls (default: {DEFAULT_SLEEP_SECS})",
    )
    p.add_argument(
        "--results-dir",
        help="Directory for log files. If unset, logs go to stdout/stderr only.",
    )
    p.add_argument(
        "--max-loops",
        type=int,
        default=0,
        help="Stop after this many iterations (0 = unlimited). Used by tests.",
    )
    p.add_argument(
        "--require-backend",
        default=default_required_backend(),
        help="Fail closed unless getmininginfo.backend_runtime reports this backend active.",
    )
    p.add_argument(
        "--max-backend-fallbacks",
        type=int,
        default=int(os.environ.get("BTX_MINING_MAX_BACKEND_FALLBACKS", "0")),
        help="Maximum GPU-to-CPU fallbacks allowed when --require-backend is set (default: 0).",
    )
    return p.parse_args(argv)


def open_log_streams(results_dir: Optional[str]):
    """
    Returns (out_stream, err_stream). When ``results_dir`` is provided, append
    to ``live-mining-loop.out`` / ``live-mining-loop.err`` so this loop's
    output dovetails with the existing supervisor's conventions.
    """
    if not results_dir:
        return sys.stdout, sys.stderr
    base = pathlib.Path(results_dir)
    base.mkdir(parents=True, exist_ok=True)
    out = open(base / "live-mining-loop.out", "a", buffering=1)
    err = open(base / "live-mining-loop.err", "a", buffering=1)
    return out, err


def rpc_post(conn: http.client.HTTPConnection, auth: str, req_id: int, method: str, params: list):
    body = json.dumps({
        "jsonrpc": "1.0",
        "id": str(req_id),
        "method": method,
        "params": params,
    })
    headers = {"Content-Type": "application/json", "Authorization": auth}
    conn.request("POST", "/", body, headers)
    resp = conn.getresponse()
    data = resp.read()
    if resp.status != 200:
        return resp.status, data, None
    return resp.status, data, json.loads(data)


def backend_fallback_count(info: dict, backend: str) -> int:
    runtime = info.get("backend_runtime") or {}
    if backend == "metal":
        return int(runtime.get("metal_fallbacks_to_cpu") or 0) + int(
            runtime.get("metal_nonce_seed_scan_fallbacks_to_cpu") or 0
        )
    if backend == "cuda":
        return int(runtime.get("cuda_fallbacks_to_cpu") or 0) + int(
            runtime.get("cuda_nonce_seed_scan_fallbacks_to_cpu") or 0
        )
    return 0


def check_backend_requirement(
    conn: http.client.HTTPConnection,
    auth: str,
    req_id: int,
    args: argparse.Namespace,
    err_stream,
) -> Optional[bool]:
    required = resolved_required_backend(args)
    if not required:
        return True

    status, data, payload = rpc_post(conn, auth, req_id, "getmininginfo", [])
    if status != 200:
        if status == 401:
            log(err_stream, "backend check auth failed (401), reloading rpc credentials")
            return None
        log(err_stream, f"backend check HTTP {status}: {data[:200]!r}")
        return False
    err_obj = payload.get("error")
    if err_obj:
        log(err_stream, f"backend check rpc error: {err_obj}")
        return False

    info = payload.get("result") or {}
    runtime = info.get("backend_runtime") or {}
    active = normalize_backend(str(runtime.get("active_backend") or ""))
    requested = runtime.get("requested_backend") or "missing"
    reason = runtime.get("backend_selection_reason") or "missing"
    requirement_satisfied = bool(runtime.get("required_backend_satisfied", True))
    if active != required or not requirement_satisfied:
        log(
            err_stream,
            "backend requirement failed: "
            f"required={required} active={active or 'missing'} "
            f"requested={requested} reason={reason}",
        )
        return False

    fallback_count = backend_fallback_count(info, required)
    if fallback_count > args.max_backend_fallbacks:
        log(
            err_stream,
            "backend requirement failed: "
            f"required={required} fallbacks={fallback_count} "
            f"max={args.max_backend_fallbacks}",
        )
        return False
    return True


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    rpc = resolve_rpc_config(args)
    address = resolve_address(args)
    out_stream, err_stream = open_log_streams(args.results_dir)

    log(
        err_stream,
        f"started pid={os.getpid()} addr={address} "
        f"rpc={rpc.host}:{rpc.port} interval={args.sleep}s "
        f"auth={'user' if rpc.user else 'cookie'} "
        f"require_backend={resolved_required_backend(args) or 'none'}",
    )

    auth = rpc.auth_header()
    # ``generatetoaddress`` blocks server-side until a block is found, which can
    # take many minutes at higher difficulty. Use no socket timeout so the call
    # mirrors what ``btx-cli`` does: block as long as needed, fail only on real
    # connection loss. (The shell loop has no timeout either.)
    conn = http.client.HTTPConnection(rpc.host, rpc.port, timeout=None)
    req_id = 0
    consecutive_errors = 0
    iterations = 0

    while True:
        if args.max_loops and iterations >= args.max_loops:
            log(err_stream, f"max-loops reached ({args.max_loops}), exiting")
            return 0
        iterations += 1
        req_id += 1

        try:
            if args.require_backend:
                backend_ok = check_backend_requirement(conn, auth, req_id, args, err_stream)
                if backend_ok is None:
                    rpc = resolve_rpc_config(args)
                    auth = rpc.auth_header()
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = http.client.HTTPConnection(rpc.host, rpc.port, timeout=None)
                    time.sleep(args.sleep)
                    continue
                if not backend_ok:
                    return 1
                req_id += 1

            resp_status, data, payload = rpc_post(
                conn,
                auth,
                req_id,
                "generatetoaddress",
                [1, address],
            )

            if resp_status == 401:
                # Either rpcuser/rpcpassword changed in btx.conf, or btxd
                # restarted and rotated its .cookie. Re-resolve from disk.
                log(err_stream, "auth failed (401), reloading rpc credentials")
                rpc = resolve_rpc_config(args)
                auth = rpc.auth_header()
            elif resp_status != 200:
                log(err_stream, f"HTTP {resp_status}: {data[:200]!r}")
            else:
                err_obj = payload.get("error")
                if err_obj:
                    # Match the .sh's behavior: log RPC-level errors but keep
                    # looping. ``mining paused by chain guard`` is a normal
                    # transient — the supervisor would react; we just retry.
                    log(err_stream, f"rpc error: {err_obj}")
                else:
                    # Successful generation. Result is a list of block hashes.
                    # Print to stdout, one per line, mirroring btx-cli output.
                    for h in payload.get("result") or []:
                        print(h, file=out_stream, flush=True)
                consecutive_errors = 0

        except (http.client.HTTPException, OSError, json.JSONDecodeError) as e:
            consecutive_errors += 1
            log(
                err_stream,
                f"rpc transport error ({consecutive_errors}): {e}, reconnecting",
            )
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(rpc.host, rpc.port, timeout=None)
            # Daemon may have restarted and rotated cookie / changed config.
            try:
                rpc = resolve_rpc_config(args)
                auth = rpc.auth_header()
            except RpcAuthError as ce:
                log(err_stream, f"rpc auth reload failed: {ce}")

        time.sleep(args.sleep)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
