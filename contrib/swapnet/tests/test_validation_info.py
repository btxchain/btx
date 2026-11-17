"""getswapvalidationinfo names the host build, not only the SwapNet source version."""
import os

import pytest

from swapnet.application import VERSION, Application
from swapnet.authorization import Principal
from swapnet.store import Store
from swapnet.vault import ForeignKeyVault
from test_execution_v2 import NETWORK, Identity


def _app(tmp_path, **kwargs):
    os.chmod(tmp_path, 0o700)
    store = Store(tmp_path / "state.sqlite")
    vault = ForeignKeyVault(tmp_path / "foreign-vault.json", b"1" * 32)
    return Application(store, NETWORK, Identity("alice"), vault, {}, lambda *args: True, **kwargs)


def test_reports_the_client_version_it_is_given(tmp_path):
    app = _app(tmp_path, client_version="v0.34.17")
    info = app.rpc(Principal("reader"), "getswapvalidationinfo", {})
    assert info["client_version"] == "v0.34.17"
    assert info["source_version"] == VERSION
    app.close()


def test_client_version_is_null_without_a_host(tmp_path):
    app = _app(tmp_path)
    assert app.rpc(Principal("reader"), "getswapvalidationinfo", {})["client_version"] is None
    app.close()


@pytest.mark.parametrize("bad", ["", "v" * 129, 34017, b"v0.34.17"])
def test_an_unusable_client_version_is_reported_as_null(tmp_path, bad):
    app = _app(tmp_path, client_version=bad)
    assert app.rpc(Principal("reader"), "getswapvalidationinfo", {})["client_version"] is None
    app.close()
