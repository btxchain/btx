"""SwapNet startup must not log SQLite misuse or a schema change.

The node installs one process-wide SQLite log. executescript() steps a null
trailing statement, and a repeated user_version write invalidates a prepared
SELECT. Both showed up on every start, including a fresh datadir.
"""
import os
import subprocess
import sys
import textwrap


def test_schema_setup_does_not_log_sqlite_misuse_or_schema_change():
    script = textwrap.dedent(
        r"""
        import ctypes, os, tempfile
        from pathlib import Path
        lib = ctypes.CDLL("libsqlite3.so.0")
        msgs = []
        LOG = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p)
        def cb(arg, code, msg):
            msgs.append((code, msg.decode() if msg else ""))
        hook = LOG(cb)
        if lib.sqlite3_config(16, hook, None) != 0:
            raise SystemExit("sqlite log hook")
        import sys
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
    proc = subprocess.run([sys.executable, "-c", script], env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
