#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest E2E for decentralized model search (doc/modelnet/search.md).

Exclusive to searchmodels: response contract, query routing (scope, filters,
sort, paging, rejects, job lifecycle, local hide/mute) and the all-ones peer
fanout bound. Complements feature_modelnet_0348_ops.py, which only smoke-tests
one LOCAL searchmodels call, and feature_modelnet_unique_todos.py, which only
smoke-tests one addmodelindex call.

Search is model-plane only: no monetary consensus, no addrman, no wallet, and
coverage is never complete. Never production btxd. Never SIGKILL the live GPU
attestor. --timeout-factor=1.

  python3 test/functional/feature_modelnet_search.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import os
import re
import struct
import subprocess
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

# Mirrors src/modelnet/search.h. These are protocol bounds, not tunables.
SEARCH_FANOUT_MAX = 8
SEARCH_PAGE_MAX = 100
SEARCH_QUERY_BYTES_MAX = 4096
SEARCH_TERMS_MAX = 16

# Distinctive loopback ports so the fanout set can never collide with the
# helper's own swarm bind endpoint. Nothing listens on them.
INDEX_PEERS = [f"127.0.0.1:{39301 + i}" for i in range(SEARCH_FANOUT_MAX + 4)]

MINI_ID = "a1" * 48
BASE_ID = "b2" * 48
LARGE_ID = "c3" * 48
LARGE_PUBLISHER = "d4" * 48

QUERY_ID_RE = re.compile(r"\A[0-9a-f]{16}\Z")


def write_minimal_safetensors(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", 2) + b"{}")


class ModelNetSearchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        candidates = []
        for env_name in ("BTXMODELD", "BTX_MODELD"):
            env_val = os.environ.get(env_name)
            if env_val:
                candidates.append(Path(env_val))
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / name)
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        if self.modeld_socket.exists():
            self.modeld_socket.unlink()
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        log_path = self.modeldir / "modeld.log"
        self.modeld_log = open(log_path, "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir)
        )

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test helper SIGTERM timeout; SIGKILL test child only")
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def _zero_spend(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not an object: {obj}")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _rpc_name(self, fn):
        inner = getattr(fn, "auth_service_proxy_instance", fn)
        name = getattr(inner, "_service_name", None)
        if isinstance(name, str) and name:
            return name.split(".")[-1]
        got = getattr(fn, "__name__", None)
        if isinstance(got, str) and got:
            return got
        return "unknown_rpc"

    def _skip_method_name(self, entry):
        text = str(entry).strip()
        head = text.split(":", 1)[0].strip().split()[0] if text else ""
        if head and head.replace("_", "").isalnum() and head[0].isalpha():
            return head
        return text or "unknown_rpc"

    def _rpc_or_skip(self, fn, *args, **kwargs):
        """Absent helper verb (-32601 / method not found) is an honest skip."""
        name = self._rpc_name(fn)
        try:
            return fn(*args, **kwargs)
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc)
            code = exc.error.get("code") if isinstance(exc.error, dict) else None
            if code == -32601 or "METHOD_NOT_FOUND" in blob:
                self.skipped.append(f"{name}: {exc.error}")
                return None
            raise

    def _reject(self, node, query, *needles):
        """searchmodels must fail closed; helper error text reaches the operator."""
        try:
            got = node.searchmodels(query)
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc)
            if "INVALID_PARAMETER" not in blob:
                raise AssertionError(f"{needles} reject must be INVALID_PARAMETER: {blob}") from exc
            for needle in needles:
                if needle not in blob:
                    raise AssertionError(f"reject text missing {needle!r}: {blob}") from exc
            return
        raise AssertionError(f"searchmodels({str(query)[:80]}) must be rejected, got {got}")

    def _search(self, node, *params):
        """Call searchmodels and assert the invariants that hold for every query."""
        resp = node.searchmodels(*params)
        where = f"searchmodels({str(params)[:120]})"
        if not isinstance(resp, dict):
            raise AssertionError(f"{where} not an object: {resp}")
        self._zero_spend(resp, where)
        if not isinstance(resp.get("schema_version"), int) or resp["schema_version"] < 2:
            raise AssertionError(f"{where} schema_version: {resp.get('schema_version')}")
        if not QUERY_ID_RE.match(str(resp.get("query_id", ""))):
            raise AssertionError(f"{where} query_id not 16 lowercase hex: {resp.get('query_id')}")
        cov = resp.get("coverage")
        if not isinstance(cov, dict):
            raise AssertionError(f"{where} coverage missing: {resp}")
        if cov.get("local") is not True:
            raise AssertionError(f"{where} coverage.local: {cov}")
        # The whole point of the search plane: no response may claim a global
        # directory, on any scope, with any peer set.
        if cov.get("complete") is not False or cov.get("global_complete") is not False:
            raise AssertionError(f"{where} claimed complete coverage: {cov}")
        if resp.get("coverage_complete") is True or resp.get("global_complete") is True:
            raise AssertionError(f"{where} claimed complete coverage: {resp}")
        if "not a complete global directory" not in str(resp.get("note", "")):
            raise AssertionError(f"{where} note: {resp.get('note')}")
        for key in ("results", "applied_filters", "unsupported_filters"):
            if not isinstance(resp.get(key), list):
                raise AssertionError(f"{where} {key} not an array: {resp.get(key)}")
        if resp.get("results_returned") != len(resp["results"]):
            raise AssertionError(f"{where} results_returned vs results: {resp}")
        if len(resp["results"]) > SEARCH_PAGE_MAX:
            raise AssertionError(f"{where} page over {SEARCH_PAGE_MAX}: {resp['results_returned']}")
        if resp.get("total_candidates_seen", 0) < resp["results_returned"]:
            raise AssertionError(f"{where} total_candidates_seen < returned: {resp}")
        if resp.get("remote_count") != cov.get("responses_received"):
            raise AssertionError(f"{where} remote_count vs responses_received: {resp}")
        for card in resp["results"]:
            if not isinstance(card, dict):
                raise AssertionError(f"{where} card not an object: {card}")
            self._zero_spend(card, f"{where} card")
            avail = card.get("availability")
            if isinstance(avail, dict) and avail.get("global_complete") is not False:
                raise AssertionError(f"{where} card availability global_complete: {avail}")
        return resp

    def _names(self, resp):
        return sorted(card.get("name", "") for card in resp["results"])

    def _ids(self, resp):
        return sorted(card.get("model_id", "") for card in resp["results"])

    def _attempted(self, resp):
        """Peers this node actually reached out to for one query."""
        cov = resp["coverage"]
        return int(cov.get("responses_received", 0)) + int(cov.get("timed_out", 0))

    def _publish(self, node, model_id, metadata):
        published = node.publishmodelsearchrecord(model_id, metadata)
        self._zero_spend(published, f"publishmodelsearchrecord {metadata['canonical_name']}")
        if published.get("signed_metadata") is not True:
            raise AssertionError(f"published record must be ML-DSA signed: {published}")
        if published.get("wallet_key") is not False:
            raise AssertionError(f"search publish must not use a wallet key: {published}")
        if published.get("model_id") != model_id:
            raise AssertionError(f"publish model_id: {published}")
        return published

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"btx-modeld died {self.modeld_proc.returncode}")
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.wait_until(helper_ready, timeout=30)

        self.log.info("SEARCH-00: catalog ingest gives one unsigned record")
        host_src = Path(self.options.tmpdir) / "host-src" / "zephyr-host-fixture.safetensors"
        write_minimal_safetensors(host_src)
        hosted = node.hostmodel(str(host_src), {"publish": False})
        self._zero_spend(hosted, "hostmodel")
        hosted_id = hosted.get("model_id")
        if not isinstance(hosted_id, str) or len(hosted_id) != 96:
            raise AssertionError(f"hostmodel model_id: {hosted}")
        if hosted.get("search_published") is not False or hosted.get("signed_metadata") is not False:
            raise AssertionError(f"publish=false must not sign a search card: {hosted}")

        self.log.info("SEARCH-01: publish three signed records")
        self._publish(node, MINI_ID, {
            "canonical_name": "zephyrquartz-mini",
            "display_name": "zephyrquartz-mini",
            "aliases": ["zq-mini"],
            "family": "llama",
            "architecture": "decoder",
            "format": "safetensors",
            "quantization": "Q4_K_M",
            "languages": ["en"],
            "modalities": ["text"],
            "tags": ["research", "license:mit"],
            "short_description": "zephyrquartz routing fixture, smallest",
            "size_bytes": 1024,
            "file_count": 1,
            "parameter_count": 1000000,
        })
        self._publish(node, BASE_ID, {
            "canonical_name": "zephyrquartz-base",
            "display_name": "zephyrquartz-base",
            "family": "mistral",
            "architecture": "decoder",
            "format": "gguf",
            "quantization": "Q8_0",
            "languages": ["en", "de"],
            "tags": ["research"],
            "short_description": "zephyrquartz routing fixture, middle",
            "size_bytes": 4096,
            "file_count": 2,
            "parameter_count": 7000000,
        })
        self._publish(node, LARGE_ID, {
            "canonical_name": "zephyrquartz-large",
            "display_name": "zephyrquartz-large",
            "family": "llama",
            "architecture": "decoder",
            "format": "safetensors",
            "publisher_identity": LARGE_PUBLISHER,
            "publisher_display_name": "quartzlab",
            "tags": ["research"],
            "short_description": "zephyrquartz routing fixture, largest",
            "size_bytes": 8192,
            "file_count": 3,
            "parameter_count": 70000000,
        })

        self.log.info("SEARCH-02: default scope is LOCAL for bare and untargeted queries")
        bare = self._search(node)
        if bare.get("scope") != "LOCAL":
            raise AssertionError(f"bare searchmodels must stay LOCAL: {bare.get('scope')}")
        untargeted = self._search(node, {"limit": SEARCH_PAGE_MAX})
        if untargeted.get("scope") != "LOCAL":
            raise AssertionError(f"query without text/scope must stay LOCAL: {untargeted}")
        if untargeted["results_returned"] < 4:
            raise AssertionError(f"empty text must match every record: {untargeted}")

        alias_scope = self._search(node, {"text": "zephyrquartz", "scope": "local"})
        if alias_scope.get("scope") != "LOCAL":
            raise AssertionError(f"operator alias 'local' must resolve to LOCAL: {alias_scope}")

        self.log.info("SEARCH-03: result card shape and signed vs catalog provenance")
        both = self._search(node, {"text": "zephyr", "scope": "LOCAL"})
        if both["results_returned"] != 4:
            raise AssertionError(f"'zephyr' must match 3 published + 1 hosted: {self._names(both)}")
        verified = {}
        for card in both["results"]:
            for key in ("model_id", "uri", "name", "publisher", "family", "tags",
                        "description", "size_bytes", "availability", "local", "release", "search"):
                if key not in card:
                    raise AssertionError(f"result card missing {key}: {sorted(card)}")
            search_meta = card["search"]
            if not isinstance(search_meta, dict) or "score" not in search_meta:
                raise AssertionError(f"card search block: {card.get('search')}")
            if "local_index" not in search_meta.get("provenance", []):
                raise AssertionError(f"local hit provenance: {search_meta}")
            verified[card["model_id"]] = search_meta.get("metadata_verified")
        if verified.get(MINI_ID) is not True:
            raise AssertionError(f"published record must be metadata_verified: {verified}")
        if verified.get(hosted_id) is not False:
            raise AssertionError(f"catalog-ingested record must not claim verified metadata: {verified}")
        hosted_card = next(c for c in both["results"] if c["model_id"] == hosted_id)
        if hosted_card["local"].get("known") is not True:
            raise AssertionError(f"hosted model must be locally known: {hosted_card['local']}")

        record = node.getmodelsearchrecord(MINI_ID)
        if record.get("type") != "btx-model-search-v1":
            raise AssertionError(f"record type: {record}")
        if record.get("canonical_name") != "zephyrquartz-mini":
            raise AssertionError(f"record canonical_name: {record}")
        if record.get("signing_domain") != "BTX/ModelSearchRecord/v2":
            raise AssertionError(f"new records sign under the v2 domain: {record}")
        try:
            node.getmodelsearchrecord("ee" * 48)
            raise AssertionError("getmodelsearchrecord miss must be NOT_FOUND")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc)
            if "NOT_FOUND" not in blob:
                raise AssertionError(f"record miss error: {blob}") from exc

        self.log.info("SEARCH-04: filters route the query inside the local index")
        quartz = {"text": "zephyrquartz", "scope": "LOCAL"}
        all_three = self._search(node, quartz)
        if self._ids(all_three) != sorted([MINI_ID, BASE_ID, LARGE_ID]):
            raise AssertionError(f"'zephyrquartz' must match exactly the published three: {self._ids(all_three)}")

        family = self._search(node, {**quartz, "filters": {"family": "llama"}})
        if self._ids(family) != sorted([MINI_ID, LARGE_ID]):
            raise AssertionError(f"family=llama: {self._ids(family)}")
        if "family" not in family["applied_filters"]:
            raise AssertionError(f"applied_filters must report family: {family['applied_filters']}")

        fmt = self._search(node, {**quartz, "filters": {"format": "gguf"}})
        if self._ids(fmt) != [BASE_ID]:
            raise AssertionError(f"format=gguf: {self._ids(fmt)}")

        sized = self._search(node, {**quartz, "filters": {"min_size_bytes": 4096}})
        if self._ids(sized) != sorted([BASE_ID, LARGE_ID]):
            raise AssertionError(f"min_size_bytes=4096: {self._ids(sized)}")
        if "min_size_bytes" not in sized["applied_filters"]:
            raise AssertionError(f"applied_filters must report min_size_bytes: {sized['applied_filters']}")

        tagged = self._search(node, {**quartz, "filters": {"tags": ["license:mit"]}})
        if self._ids(tagged) != [MINI_ID]:
            raise AssertionError(f"tags=[license:mit]: {self._ids(tagged)}")

        pub_name = self._search(node, {**quartz, "filters": {"publisher_name": "quartzlab"}})
        if self._ids(pub_name) != [LARGE_ID]:
            raise AssertionError(f"publisher_name=quartzlab: {self._ids(pub_name)}")

        empty = self._search(node, {**quartz, "filters": {"family": "nosuchfamily"}})
        if empty["results_returned"] != 0:
            raise AssertionError(f"unmatched filter must return nothing: {empty}")

        self.log.info("SEARCH-05: paging and sort are bounded and deterministic")
        page = self._search(node, {**quartz, "limit": 2})
        if page["results_returned"] != 2:
            raise AssertionError(f"limit=2: {page['results_returned']}")
        tail = self._search(node, {**quartz, "limit": 2, "offset": 2})
        if tail["results_returned"] != 1:
            raise AssertionError(f"offset=2 tail: {tail['results_returned']}")
        over = self._search(node, {**quartz, "limit": 10 * SEARCH_PAGE_MAX})
        if over["results_returned"] != 3:
            raise AssertionError(f"oversized limit must clamp, not error: {over['results_returned']}")

        by_size = self._search(node, {**quartz, "sort": "size_asc"})
        sizes = [card["size_bytes"] for card in by_size["results"]]
        if sizes != sorted(sizes):
            raise AssertionError(f"sort=size_asc: {sizes}")
        by_name = self._search(node, {**quartz, "sort": "name"})
        names = [card["name"] for card in by_name["results"]]
        if names != sorted(names):
            raise AssertionError(f"sort=name: {names}")
        for alias in ("available", "popular", "rare", "RELEVANCE", "newest"):
            self._search(node, {**quartz, "sort": alias})

        long_text = " ".join(["zephyrquartz"] + [f"tok{i:02d}" for i in range(40)])
        many_terms = self._search(node, {"text": long_text, "scope": "LOCAL"})
        if many_terms["results_returned"] != 3:
            raise AssertionError(f"over-{SEARCH_TERMS_MAX}-term query must clamp terms, not drop hits: {many_terms}")
        if many_terms.get("text") != long_text:
            raise AssertionError(f"query text must be echoed verbatim: {many_terms.get('text')}")

        self.log.info("SEARCH-06: malformed queries fail closed")
        self._reject(node, {"text": "zephyrquartz", "scope": "GLOBAL"}, "bad scope")
        self._reject(node, {"text": "zephyrquartz", "sort": "MOST_DOWNLOADED"}, "bad sort")
        self._reject(node, {"text": "z" * (SEARCH_QUERY_BYTES_MAX + 64)}, "query too large")

        self.log.info("SEARCH-07: scope LOCAL keeps the query on this node")
        added = self._rpc_or_skip(node.addmodelindex, INDEX_PEERS[0])
        index_peers_usable = isinstance(added, dict)
        if index_peers_usable:
            self._zero_spend(added, "addmodelindex")
            if added.get("addrman") is not False:
                raise AssertionError(f"index peers must not be monetary addrman: {added}")
            for endpoint in INDEX_PEERS[1:]:
                self._zero_spend(node.addmodelindex(endpoint), "addmodelindex")
            listed_peers = self._rpc_or_skip(node.getsearchpeers)
            if isinstance(listed_peers, dict):
                peers = listed_peers.get("peers", [])
                if len(peers) != len(INDEX_PEERS):
                    raise AssertionError(f"getsearchpeers count: {peers}")
                for peer in peers:
                    if peer.get("capability") != "NODE_MODEL_INDEX":
                        raise AssertionError(f"index peer capability: {peer}")
                    if peer.get("monetary_service_bit") is not False:
                        raise AssertionError(f"index peer must not carry a monetary service bit: {peer}")

            local = self._search(node, quartz)
            cov = local["coverage"]
            if cov.get("index_peers_configured") != len(INDEX_PEERS):
                raise AssertionError(f"LOCAL must still report configured peers: {cov}")
            for counter in ("connected_peers_queried", "index_peers_queried",
                            "routing_peers_queried", "responses_received", "timed_out"):
                if cov.get(counter) != 0:
                    raise AssertionError(f"LOCAL scope leaked the query via {counter}: {cov}")
            if local["results_returned"] != 3:
                raise AssertionError(f"LOCAL results with peers configured: {local}")

            self.log.info("SEARCH-08: all-ones fanout stays capped at %d", SEARCH_FANOUT_MAX)
            for scope in ("NETWORK", "PEERS", "ALL"):
                netq = self._search(node, {"text": "zephyrquartz", "scope": scope})
                cov = netq["coverage"]
                if self._attempted(netq) != SEARCH_FANOUT_MAX:
                    raise AssertionError(
                        f"scope={scope} must fill and cap the fanout at {SEARCH_FANOUT_MAX} "
                        f"with {len(INDEX_PEERS)} configured: {cov}"
                    )
                if cov.get("responses_received") != 0 or cov.get("index_peers_queried") != 0:
                    raise AssertionError(f"dead peers must not count as replies: {cov}")
                if cov.get("routing_peers_queried", 0) > SEARCH_FANOUT_MAX:
                    raise AssertionError(f"routing peers over fanout cap: {cov}")
                if netq["results_returned"] != 3:
                    raise AssertionError(f"local hits must survive dead peers: {netq}")

            bare_text = self._search(node, "zephyrquartz")
            if bare_text.get("scope") != "NETWORK":
                raise AssertionError(f"a bare text query defaults to NETWORK: {bare_text}")
            if self._attempted(bare_text) != SEARCH_FANOUT_MAX:
                raise AssertionError(f"bare text fanout: {bare_text['coverage']}")

            for endpoint in INDEX_PEERS:
                self._zero_spend(node.removemodelindex(endpoint), "removemodelindex")
            drained = self._search(node, {"text": "zephyrquartz", "scope": "NETWORK"})
            if drained["coverage"].get("index_peers_configured") != 0:
                raise AssertionError(f"removemodelindex must drop preferences: {drained['coverage']}")
            if self._attempted(drained) > SEARCH_FANOUT_MAX:
                raise AssertionError(f"fanout after drain: {drained['coverage']}")
        else:
            self.log.info("HONEST_NOT_RUN fanout: addmodelindex unavailable")

        self.log.info("SEARCH-09: job status and cancel are local job state")
        job = self._search(node, quartz)
        query_id = job["query_id"]
        status = self._rpc_or_skip(node.getsearchstatus, query_id)
        if isinstance(status, dict):
            if status.get("state") != "COMPLETE":
                raise AssertionError(f"finished query state: {status}")
            if status.get("complete") is not False or status.get("global_complete") is not False:
                raise AssertionError(f"getsearchstatus must not claim completeness: {status}")
            if status.get("results_returned") != 3:
                raise AssertionError(f"getsearchstatus results: {status}")
        cancelled = self._rpc_or_skip(node.cancelmodelsearch, query_id)
        if isinstance(cancelled, dict):
            if cancelled.get("ok") is not True:
                raise AssertionError(f"cancel of a known query: {cancelled}")
            unknown = node.cancelmodelsearch("00" * 8)
            if unknown.get("ok") is not False:
                raise AssertionError(f"cancel of an unknown query must be false: {unknown}")
            after = self._rpc_or_skip(node.getsearchstatus, query_id)
            if isinstance(after, dict) and after.get("state") != "CANCELLED":
                raise AssertionError(f"state after cancel: {after}")

        self.log.info("SEARCH-10: hide and mute are local policy, not moderation")
        hidden = node.hidesearchmodel(MINI_ID)
        if hidden.get("hidden") is not True:
            raise AssertionError(f"hidesearchmodel: {hidden}")
        after_hide = self._search(node, quartz)
        if self._ids(after_hide) != sorted([BASE_ID, LARGE_ID]):
            raise AssertionError(f"hidden model must leave search: {self._ids(after_hide)}")
        still_there = node.getmodelsearchrecord(MINI_ID)
        if still_there.get("canonical_name") != "zephyrquartz-mini":
            raise AssertionError(f"hide must not affect retrieve-by-id: {still_there}")
        node.unhidesearchmodel(MINI_ID)

        muted = node.mutesearchpublisher(LARGE_PUBLISHER)
        if muted.get("muted") is not True:
            raise AssertionError(f"mutesearchpublisher: {muted}")
        after_mute = self._search(node, quartz)
        if self._ids(after_mute) != sorted([MINI_ID, BASE_ID]):
            raise AssertionError(f"muted publisher must leave search: {self._ids(after_mute)}")
        node.unmutesearchpublisher(LARGE_PUBLISHER)
        restored = self._search(node, quartz)
        if self._ids(restored) != sorted([MINI_ID, BASE_ID, LARGE_ID]):
            raise AssertionError(f"unhide/unmute must restore the view: {self._ids(restored)}")

        self.log.info("SEARCH-11: search never touched money")
        if node.getblockcount() != 0:
            raise AssertionError("search must not advance the chain")
        if node.getblockchaininfo().get("chain") != "regtest":
            raise AssertionError("chain after search")

        # Search verbs skipped on this build are HONEST_NOT_RUN. A NEW skip fails.
        honest_rpc = frozenset({
            "addmodelindex",
            "getsearchpeers",
            "getsearchstatus",
            "cancelmodelsearch",
        })
        unexpected = []
        for entry in self.skipped:
            name = self._skip_method_name(entry)
            self.log.info("HONEST_NOT_RUN %s: %s", name, entry)
            if name not in honest_rpc:
                unexpected.append(name)
        if unexpected:
            raise AssertionError(
                f"NEW skip not in HONEST_NOT_RUN catalog allowlist: {unexpected}; skipped={self.skipped}"
            )
        self.log.info("modelnet search e2e passed skipped=%s", self.skipped)


if __name__ == "__main__":
    ModelNetSearchTest(__file__).main()
