"""SwapNet startup must not log SQLite misuse or a schema change.

The node installs one process-wide SQLite log. executescript() steps a null
trailing statement, and a repeated user_version write invalidates a prepared
SELECT. Both showed up on every start, including a fresh datadir.
"""
import ctypes
import importlib.util
import os
import subprocess
import sys
import textwrap

import pytest


def _sqlite_library(extension_origin):
    """Return a file whose exports include SQLite's log API, or None.

    On Linux and macOS a symbol lookup in the _sqlite3 extension also finds
    the SQLite library it links. On Windows GetProcAddress only sees the
    module's own exports, which for _sqlite3.pyd do not include SQLite; the
    python.org build keeps sqlite3.dll next to it.
    """
    candidates = [extension_origin]
    if os.name == "nt":
        candidates.append(os.path.join(os.path.dirname(extension_origin), "sqlite3.dll"))
    for path in candidates:
        try:
            lib = ctypes.CDLL(path)
        except OSError:
            continue
        if hasattr(lib, "sqlite3_config") and hasattr(lib, "sqlite3_log"):
            return path
    return None


def test_schema_setup_does_not_log_sqlite_misuse_or_schema_change():
    extension = importlib.util.find_spec("_sqlite3")
    if extension is None or not extension.has_location:
        pytest.skip("SQLite log hook requires a loadable _sqlite3 extension")
    library = _sqlite_library(extension.origin)
    if library is None:
        pytest.skip("no loadable library next to _sqlite3 exports sqlite3_config")

    script = textwrap.dedent(
        r"""
        import ctypes, os, tempfile
        from pathlib import Path
        # Resolve the library Python actually uses, without importing sqlite3
        # before configuring SQLite's process-wide hook.
        lib = ctypes.CDLL(os.environ["SWAPNET_SQLITE_LIBRARY"])
        msgs = []
        LOG = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p)
        def cb(arg, code, msg):
            msgs.append((code, msg.decode() if msg else ""))
        hook = LOG(cb)
        # ctypes needs the fixed arguments of variadic functions on Apple ARM64.
        lib.sqlite3_config.argtypes = [ctypes.c_int]
        lib.sqlite3_log.argtypes = [ctypes.c_int, ctypes.c_char_p]
        lib.sqlite3_log.restype = None
        if lib.sqlite3_config(16, hook, ctypes.c_void_p()) != 0:
            raise SystemExit("sqlite log hook")
        lib.sqlite3_log(1, b"SwapNet test hook control")
        if msgs != [(1, "SwapNet test hook control")]:
            raise SystemExit("sqlite log hook did not receive control message")
        msgs.clear()
        import sqlite3, sys
        lib.sqlite3_libversion.restype = ctypes.c_char_p
        if lib.sqlite3_libversion().decode() != sqlite3.sqlite_version:
            raise SystemExit("SQLite hook resolved a different library")
        sys.path.insert(0, os.environ["SWAPNET_ROOT"])
        from swapnet.store import Store
        from swapnet.journal import Journal
        from swapnet.public_market import PublicMarket
        from swapnet.market_lifecycle import Participation
        td = tempfile.mkdtemp()
        os.chmod(td, 0o700)
        store = Store(Path(td) / "state.sqlite")
        journal = Journal(store)
        journal.setting("native_wallet", "")
        journal.setting("asset_policies", {})
        journal.setting("identity")
        again = Journal(store)
        Participation(again, None)
        class Identity:
            def verify(self, *args):
                return True
        PublicMarket(store, again, "11" * 32, Identity())
        again.setting("market.participation", "taker")
        Journal(store)
        again.setting("markets", [])
        if msgs:
            raise SystemExit(repr(msgs))
        """
    )
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    env = os.environ.copy()
    env["SWAPNET_ROOT"] = root
    env["SWAPNET_SQLITE_LIBRARY"] = library
    proc = subprocess.run([sys.executable, "-c", script], env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
