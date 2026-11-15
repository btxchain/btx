#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check the in-process observer and contribution views on an isolated node.

Catalog entries are synthetic metadata fixtures, not evidence of acquired model
bytes. No helper, inference, wallet, or external model peer is used.
"""

import hashlib
import json
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SwarmCatalogTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_nodes(self):
        self.modeldir = Path(self.options.tmpdir) / "catalog-models"
        (self.modeldir / "swarm").mkdir(parents=True)
        self.extra_args = [[
            "-disablewallet", "-modelnet=1", "-modelnetrequired=0", "-modelbind=off",
            "-modelstorage=0", f"-modeldir={self.modeldir}",
            f"-modelhelper={self.modeldir / 'absent-helper'}",
        ]]
        super().setup_nodes()

    def run_test(self):
        model, artifact, family = "a" * 96, "b" * 96, "c" * 96
        provisional = hashlib.sha384(b'BTX/ProvisionalModelTopic/1\0' +
                                     ('{"model_id":"' + model + '"}').encode()).hexdigest()
        catalog = self.modeldir / "catalog.json"
        mappings = self.modeldir / "swarm/lineage-mappings.json"
        observers = self.modeldir / "swarm/observers.json"
        contribution = self.modeldir / "swarm/contribution.json"
        entry = dict(model_id=model, artifact_id=artifact, bytes_verified=True,
                     incomplete=False, visibility="public")

        def write(path, value):
            tmp = path.with_suffix(".test-tmp")
            tmp.write_text(json.dumps(value), encoding="utf8")
            tmp.replace(path)

        def views():
            if not observers.exists() or not contribution.exists():
                return None
            return json.loads(observers.read_text()), json.loads(contribution.read_text())

        def expect_identity(lineage, public):
            def matches():
                pair = views()
                if pair is None:
                    return False
                observed, joined = pair[0]["subscriptions"], pair[1]["models"]
                return (len(observed) == len(joined) == 1 and
                        observed[0]["lineage_id"] == joined[0]["lineage_id"] == lineage and
                        (observed[0]["visibility"] == "public") == joined[0]["seed"] == public)
            self.wait_until(matches, timeout=15)
            observed, joined = views()
            assert_equal(observed["automatic_spend_atoms"], "0")
            assert_equal(joined["automatic_spend_atoms"], "0")
            assert not observed["payment_authority"]
            assert_equal(joined["models"][0]["private_acquire"], not public)
            assert_equal(observed["subscriptions"][0]["lineage_assurance"],
                         joined["models"][0]["lineage_assurance"])

        def expect_empty():
            self.wait_until(lambda: views() is not None and
                            not views()[0]["subscriptions"] and not views()[1]["models"], timeout=15)

        write(catalog, {"models": [entry]})
        expect_identity(provisional, False)
        write(mappings, {artifact: dict(lineage_id=family, visibility="public")})
        expect_identity(family, True)
        mappings.unlink()
        expect_identity(provisional, False)
        entry["bytes_verified"] = False
        write(catalog, {"models": [entry]})
        expect_empty()
        entry["bytes_verified"] = True
        write(catalog, {"models": [entry]})
        expect_identity(provisional, False)
        write(catalog, {"models": []})
        expect_empty()
        write(catalog, {"models": [entry]})
        expect_identity(provisional, False)
        catalog.unlink()
        expect_empty()
        self.restart_node(0)
        expect_empty()


if __name__ == "__main__":
    SwarmCatalogTest(__file__).main()
