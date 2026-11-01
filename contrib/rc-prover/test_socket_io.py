#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise the real C++ WinSock/POSIX framing code; no node, wallet or GPU."""
import argparse
import json
import socket
import subprocess
import threading
import time


def run_case(exe, mode):
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(3)
                    if mode == "write_timeout":
                        time.sleep(0.6)
                        return
                    request = peer.makefile("rb").readline(1024)
                    if request != b'{"nonce64":18446744073709551615}\n':
                        errors.append("request bytes changed")
                    if mode == "echo":
                        peer.sendall(request[:7]); peer.sendall(request[7:])
                    elif mode == "crlf": peer.sendall(b"ok\r\n")
                    elif mode == "oversize": peer.sendall(b"x" * 129 + b"\n")
                    elif mode == "timeout": time.sleep(0.4)
                    elif mode == "slow":
                        for _ in range(20):
                            peer.sendall(b"x"); time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # The deadline/size checks deliberately close the client.
            except Exception as exc:
                errors.append(str(exc))
        thread = threading.Thread(target=serve)
        thread.start()
        result = subprocess.run([exe, str(port), mode], capture_output=True, text=True, timeout=6)
        thread.join(timeout=4)
        if thread.is_alive(): errors.append("test server did not finish")
        if result.returncode: errors.append("C++ exit=" + str(result.returncode))
        return {"case": mode, "passed": not errors, "errors": errors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("exe")
    args = parser.parse_args()
    rows = [run_case(args.exe, mode) for mode in ["echo", "crlf", "timeout", "slow", "eof", "oversize", "write_timeout"]]
    print(json.dumps(rows, indent=2))
    return int(not all(row["passed"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
