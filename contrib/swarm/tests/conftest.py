"""Isolated state-machine fixture backed by the real database and signing key."""

import time

import pytest

from btxmesh.identity import Identity
from btxmesh.state import State, default_policy
from btxmesh.storage import Database
from support import H


class StateMachine:
    def __init__(self, directory):
        self.owner = Identity(directory / "owner")
        self.db = Database(directory / "control.sqlite")
        self.state = State(self.db, [self.owner.id])
        self.index = 0

    def realm(self):
        self.index += 1
        payload = {
            "kind": "realm.create",
            "id": str(self.index),
            "body": {
                "name": "test realm",
                "nonce": str(self.index),
                "owner_domain": "test-owner",
                "policy": default_policy(H("suite"), H("holdout")),
            },
        }
        command = {
            **payload,
            "actor": self.owner.id,
            "time_ms": int(time.time() * 1000),
            "authorization": self.owner.envelope(payload),
        }
        with self.db.tx() as connection:
            result = self.state.apply(connection, command, self.index, 1)
        assert "error" not in result, result
        return result["id"]


@pytest.fixture
def machine(tmp_path):
    machine = StateMachine(tmp_path)
    try:
        yield machine
    finally:
        machine.db.close()
