#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Local subscription filters, feed/event journal paging, and gossip reconcile.

One regtest node + one test-spawned btx-modeld over a unix socket. No
-modelhost, no public bind, no WAN fanout. Never touches production btxd.

Exclusive subjects of this file (no other functional test calls them):

  watch teardown
    unwatchbounty          bounty watch removal, idempotent

  event journal
    getmodelfeedsequence   feed cursor, never a global chronology
    getmodelfeed           LOCAL scope page that must not fan out
    getreleasefeed         release-campaign mode of the same journal
    getbountyevents        bounty journal cursor / epoch / gap / page cap

  gossip reconcile
    exportmodelindex       search records out
    importmodelindex       re-verified import, malformed records rejected
    exportmodelpeers       public endpoints out, no secret material
    importmodelpeers       deduplicating contact import
    importmodelcontacts    canonical name shares one contact set
    importmodeltrust       operator-authorized import, same dedupe
    getmodelproviders      observed providers, never a census
    getmodelpeercount      observed provider counts

The remaining watch/subscribe RPCs and the search mute/hide filters belong
to sibling tests, so this file only owns the bounty watch teardown.
watchbounty, importmodel and getmodelnetworkinfo are setup only and are
asserted elsewhere. A subject RPC that is not registered is reported
NOT_RUN and skipped, never silently passed.

Run (do not cmake/ninja):

  python3 test/functional/feature_modelnet_events.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import json
import os
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

# src/modelnet/bounty.h: constexpr int BOUNTY_PAGE_MAX = 100.
BOUNTY_PAGE_MAX = 100

# RFC 5737 documentation addresses. Never dialed: every feed query below is
# LOCAL scope, so an imported contact is not a fanout target.
DOC_PEERS = ["203.0.113.7:8433", "198.51.100.19:8433"]

# Substrings that must never appear in a gossip export payload.
SECRET_MARKERS = ("privkey", "private_key", "secret", "xprv", "seedphrase", "mnemonic")

SUBJECTS = (
    "unwatchbounty",
    "getmodelfeedsequence",
    "getmodelfeed",
    "getreleasefeed",
    "getbountyevents",
    "exportmodelindex",
    "importmodelindex",
    "exportmodelpeers",
    "importmodelpeers",
    "importmodelcontacts",
    "importmodeltrust",
    "getmodelproviders",
    "getmodelpeercount",
)


def write_minimal_safetensors(path: Path) -> None:
    """10-byte SafeTensors: LE64(2) + '{}' (same fixture as modelnet_tests)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", 2) + b"{}")


class ModelNetEventsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.not_run = []
        self.exercised = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld binary not found (BUILDDIR/bin or next to btxd)")

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

    # ---- RPC plumbing -----------------------------------------------------

    @staticmethod
    def _is_method_missing(exc):
        err = exc.error if isinstance(exc.error, dict) else {}
        if err.get("code") not in (-32601, -1):
            return False
        blob = f"{exc} {err.get('message', '')}".lower()
        return (
            "not found" in blob
            or "method_not_found" in blob
            or "unknown model rpc" in blob
            or "unknown method" in blob
        )

    def _call(self, node, method, *args):
        """Return (ok, value). ok is False only when the RPC is not registered."""
        try:
            value = getattr(node, method)(*args)
        except AttributeError:
            self._mark_not_run(method, "not registered on node")
            return False, None
        except JSONRPCException as exc:
            if self._is_method_missing(exc):
                self._mark_not_run(method, str(exc))
                return False, None
            raise
        if method in SUBJECTS and method not in self.exercised:
            self.exercised.append(method)
        return True, value

    def _mark_not_run(self, method, why):
        if method not in self.not_run:
            self.not_run.append(method)
            self.log.warning("NOT_RUN %s: %s", method, why)

    def _obj(self, method, value):
        if not isinstance(value, dict):
            raise AssertionError(f"{method} must return an object: {value!r}")
        return value

    def _arr(self, method, obj, key):
        value = obj.get(key)
        if not isinstance(value, list):
            raise AssertionError(f"{method} {key} must be an array: {obj!r}")
        return value

    def _int(self, method, obj, key):
        value = obj.get(key)
        if isinstance(value, str):
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool):
            raise AssertionError(f"{method} {key} must be an integer: {obj!r}")
        return value

    def _zero_spend(self, method, obj):
        """automatic_spend_atoms, when reported, must be 0. Nothing here pays."""
        if not isinstance(obj, dict):
            return
        for key in ("automatic_spend_atoms", "automatic_spend"):
            if key not in obj:
                continue
            raw = obj[key]
            if raw in (None, False):
                continue
            if int(raw) != 0:
                raise AssertionError(f"{method} must not auto-spend: {obj!r}")

    def _expect_invalid(self, node, method, *args):
        """The RPC must reject these arguments rather than accept them."""
        try:
            value = getattr(node, method)(*args)
        except JSONRPCException as exc:
            if self._is_method_missing(exc):
                self._mark_not_run(method, str(exc))
                return
            self.log.info("%s rejected %r: %s", method, args, exc)
            return
        raise AssertionError(f"{method} accepted invalid arguments {args!r}: {value!r}")

    # ---- helper process ---------------------------------------------------

    def _start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        self.modeld_log = open(self.modeldir / "modeld.log", "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir)
        )

    def _helper_log_tail(self):
        if self.modeldir is None:
            return ""
        log_path = self.modeldir / "modeld.log"
        if not log_path.exists():
            return ""
        return log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    def _stop_helper(self):
        proc, self.modeld_proc = self.modeld_proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                # Test-spawned btx-modeld only. Never production btxd.
                self.log.warning("test helper ignored SIGTERM; killing test child")
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(
                f"btx-modeld exited immediately with {self.modeld_proc.returncode}\n"
                f"{self._helper_log_tail()}"
            )
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

    def _wait_helper_ready(self, node):
        def ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(
                    f"btx-modeld exited with {self.modeld_proc.returncode}\n"
                    f"{self._helper_log_tail()}"
                )
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.log.info("waiting for getmodelnetworkinfo helper_ready")
        self.wait_until(ready, timeout=30)

    # ---- watch teardown ---------------------------------------------------

    def _test_unwatchbounty(self, node):
        try:
            created = node.watchbounty({"bounty_id": "bty-events-" + "9" * 8})
        except (AttributeError, JSONRPCException) as exc:
            self._mark_not_run("unwatchbounty", f"watchbounty setup unavailable: {exc}")
            return
        created = self._obj("watchbounty", created)
        watch_id = created.get("watch_id")
        if not watch_id:
            self._mark_not_run("unwatchbounty", f"watchbounty returned no watch_id: {created!r}")
            return
        for key in ("downloads", "evaluates", "spends"):
            if created.get(key) is not False:
                raise AssertionError(f"a bounty watch must not {key}: {created!r}")

        ok, removed = self._call(node, "unwatchbounty", {"watch_id": watch_id})
        if not ok:
            return
        removed = self._obj("unwatchbounty", removed)
        self._zero_spend("unwatchbounty", removed)
        if removed.get("watch_id") != watch_id:
            raise AssertionError(f"unwatchbounty must echo the watch_id: {removed!r}")
        if not isinstance(removed.get("removed"), bool):
            raise AssertionError(f"unwatchbounty removed must be boolean: {removed!r}")

        # Removing an unknown watch is a no-op, not an error.
        _, unknown = self._call(node, "unwatchbounty", {"watch_id": "00" * 8})
        self._obj("unwatchbounty", unknown)
        self.log.info("unwatchbounty: removed=%s", removed.get("removed"))

    # ---- event journal ----------------------------------------------------

    def _test_feed_sequence(self, node):
        ok, status = self._call(node, "getmodelfeedsequence")
        if not ok:
            return None
        status = self._obj("getmodelfeedsequence", status)
        self._zero_spend("getmodelfeedsequence", status)
        sequence = self._int("getmodelfeedsequence", status, "feed_sequence")
        if sequence < 0:
            raise AssertionError(f"feed_sequence must not be negative: {status!r}")
        for key in ("coverage_complete", "global_complete"):
            if status.get(key) is not False:
                raise AssertionError(f"getmodelfeedsequence {key} must be false: {status!r}")
        if "chronology" not in str(status.get("coverage_disclaimer", "")).lower():
            raise AssertionError(
                f"getmodelfeedsequence must disclaim a global chronology: {status!r}"
            )
        if self._int("getmodelfeedsequence", status, "cap") <= 0:
            raise AssertionError(f"the feed must be capped: {status!r}")

        _, second = self._call(node, "getmodelfeedsequence")
        later = self._int("getmodelfeedsequence", self._obj("getmodelfeedsequence", second),
                          "feed_sequence")
        if later < sequence:
            raise AssertionError(f"feed_sequence went backwards: {sequence} then {later}")
        self.log.info("getmodelfeedsequence: %d", later)
        return later

    def _check_feed_page(self, node, method, sequence, limit=5):
        """LOCAL scope must serve from the local journal without any fanout."""
        ok, page = self._call(node, method, {"scope": "LOCAL", "limit": limit})
        if not ok:
            return None
        page = self._obj(method, page)
        self._zero_spend(method, page)
        items = self._arr(method, page, "items")
        if page.get("scope") != "LOCAL":
            raise AssertionError(f"{method} must echo the requested scope: {page!r}")
        if len(items) > limit:
            raise AssertionError(f"{method} ignored limit={limit}: {len(items)} items")
        if page.get("partial") is not True:
            raise AssertionError(f"a feed page is always partial: {page!r}")
        if not page.get("mode"):
            raise AssertionError(f"{method} must name the feed mode it served: {page!r}")

        coverage = self._obj(f"{method} coverage", page.get("coverage"))
        for key in ("complete", "global_complete"):
            if coverage.get(key) is not False:
                raise AssertionError(f"{method} coverage {key} must be false: {coverage!r}")
        for key in ("responses_received", "peers_contributing", "timed_out"):
            if self._int(f"{method} coverage", coverage, key) != 0:
                raise AssertionError(f"LOCAL scope must not query peers: {coverage!r}")

        if sequence is not None:
            page_sequence = self._int(method, page, "feed_sequence")
            if page_sequence < sequence:
                raise AssertionError(
                    f"{method} sequence {page_sequence} is behind {sequence}: {page!r}"
                )
        for item in items:
            item = self._obj(f"{method} item", item)
            if not item.get("event_type"):
                raise AssertionError(f"feed item without an event_type: {item!r}")

        self._expect_invalid(node, method, {"scope": "galaxy"})
        self._expect_invalid(node, method, {"scope": "LOCAL", "mode": "not-a-mode"})
        self.log.info("%s LOCAL: %d item(s), mode=%s, no fanout",
                      method, len(items), page.get("mode"))
        return page

    def _test_feed_pages(self, node, sequence):
        model_feed = self._check_feed_page(node, "getmodelfeed", sequence)
        release_feed = self._check_feed_page(node, "getreleasefeed", sequence)
        if model_feed is None or release_feed is None:
            return
        # Same journal, different default mode: the release feed must not
        # silently serve the general feed.
        if release_feed.get("mode") == model_feed.get("mode"):
            raise AssertionError(
                f"getreleasefeed reused the getmodelfeed mode {model_feed.get('mode')!r}"
            )

    def _test_bounty_journal(self, node):
        """The bounty journal is a node-local cursor: no gap, no page blowout."""
        ok, first = self._call(node, "getbountyevents", {"cursor": "0"})
        if not ok:
            return
        first = self._obj("getbountyevents", first)
        self._zero_spend("getbountyevents", first)
        events = self._arr("getbountyevents", first, "events")
        if not isinstance(first.get("cursor"), str):
            raise AssertionError(f"getbountyevents cursor must be a string: {first!r}")
        if first.get("gap") is not False:
            raise AssertionError(f"a fresh journal must not report a gap: {first!r}")
        cursor = self._int("getbountyevents", first, "cursor")
        epoch = self._int("getbountyevents", first, "epoch")
        if cursor < len(events):
            raise AssertionError(f"cursor is behind the page it returned: {first!r}")

        # Replaying from the returned cursor must not repeat what we just read.
        _, tail = self._call(node, "getbountyevents", {"cursor": first["cursor"]})
        tail = self._obj("getbountyevents", tail)
        if self._int("getbountyevents", tail, "cursor") < cursor:
            raise AssertionError(f"journal cursor went backwards: {first!r} then {tail!r}")
        if self._int("getbountyevents", tail, "epoch") != epoch:
            raise AssertionError(f"epoch changed without a restart: {first!r} then {tail!r}")
        seen = {e.get("seq") for e in events if isinstance(e, dict)}
        for event in self._arr("getbountyevents", tail, "events"):
            if isinstance(event, dict) and event.get("seq") in seen:
                raise AssertionError(f"cursor replay duplicated seq {event.get('seq')}")

        # An oversized limit must be clamped, not honoured.
        _, capped = self._call(node, "getbountyevents", {"cursor": "0", "limit": 10 ** 6})
        capped_events = self._arr("getbountyevents", self._obj("getbountyevents", capped),
                                  "events")
        if len(capped_events) > BOUNTY_PAGE_MAX:
            raise AssertionError(
                f"getbountyevents ignored the page cap: {len(capped_events)} > {BOUNTY_PAGE_MAX}"
            )

        # A bounty_id filter must never widen the result set.
        _, filtered = self._call(node, "getbountyevents",
                                 {"bounty_id": "bty-no-such-" + "0" * 8})
        for event in self._arr("getbountyevents", self._obj("getbountyevents", filtered),
                               "events"):
            raise AssertionError(f"filter matched an unrelated bounty: {event!r}")
        self.log.info("getbountyevents: cursor=%d epoch=%d events=%d", cursor, epoch, len(events))

    # ---- gossip reconcile -------------------------------------------------

    def _test_index_reconcile(self, node):
        """A node must accept its own export back, and re-verify what it imports."""
        ok, exported = self._call(node, "exportmodelindex", {"limit": 10})
        if not ok:
            return
        exported = self._obj("exportmodelindex", exported)
        self._zero_spend("exportmodelindex", exported)
        records = self._arr("exportmodelindex", exported, "records")
        sequence = self._int("exportmodelindex", exported, "sequence")
        if len(records) > 10:
            raise AssertionError(f"exportmodelindex ignored limit=10: {len(records)} records")
        blob = json.dumps(records).lower()
        for marker in SECRET_MARKERS:
            if marker in blob:
                raise AssertionError(f"exportmodelindex leaked {marker!r}")

        ok, imported = self._call(node, "importmodelindex", {"records": records})
        if not ok:
            return
        imported = self._obj("importmodelindex", imported)
        self._zero_spend("importmodelindex", imported)
        accepted = self._int("importmodelindex", imported, "imported")
        rejected = self._int("importmodelindex", imported, "rejected")
        if accepted + rejected != len(records):
            raise AssertionError(
                f"importmodelindex lost records: {accepted}+{rejected} != {len(records)}"
            )
        if imported.get("reverified") is not True:
            raise AssertionError(f"importmodelindex must re-verify, not trust: {imported!r}")
        if rejected:
            self.log.warning("importmodelindex rejected %d of its own records", rejected)

        # A malformed record must be rejected, never counted as imported.
        _, junk = self._call(node, "importmodelindex",
                             {"records": [{"model_id": "not-a-digest"}]})
        junk = self._obj("importmodelindex", junk)
        if self._int("importmodelindex", junk, "imported") != 0:
            raise AssertionError(f"importmodelindex accepted a malformed record: {junk!r}")
        if self._int("importmodelindex", junk, "rejected") < 1:
            raise AssertionError(f"importmodelindex must count the rejection: {junk!r}")
        self._expect_invalid(node, "importmodelindex", {"limit": 1})

        _, after = self._call(node, "exportmodelindex", {"limit": 10})
        if self._int("exportmodelindex", self._obj("exportmodelindex", after),
                     "sequence") < sequence:
            raise AssertionError(f"index sequence went backwards from {sequence}: {after!r}")
        self.log.info("index reconcile: %d record(s), %d imported, %d rejected",
                      len(records), accepted, rejected)

    def _test_peer_reconcile(self, node):
        """export -> import must converge and must not duplicate or leak keys."""
        ok, exported = self._call(node, "exportmodelpeers")
        if not ok:
            return
        exported = self._obj("exportmodelpeers", exported)
        self._zero_spend("exportmodelpeers", exported)
        before = self._arr("exportmodelpeers", exported, "peers")
        # Scan the payload, not the "no secret keys" disclaimer in note.
        blob = json.dumps({k: v for k, v in exported.items() if k != "note"}).lower()
        for marker in SECRET_MARKERS:
            if marker in blob:
                raise AssertionError(f"exportmodelpeers leaked {marker!r}: {exported!r}")
        for peer in before:
            if not isinstance(peer, str):
                raise AssertionError(f"exported contact must be an endpoint string: {peer!r}")

        ok, imported = self._call(node, "importmodelpeers", DOC_PEERS)
        if not ok:
            for method in ("importmodelcontacts", "importmodeltrust"):
                self._mark_not_run(method, "importmodelpeers is missing; nothing to reconcile")
            return
        imported = self._obj("importmodelpeers", imported)
        self._zero_spend("importmodelpeers", imported)
        count = self._int("importmodelpeers", imported, "peers")
        expected = len(set(before) | set(DOC_PEERS))
        if count != expected:
            raise AssertionError(
                f"importmodelpeers count {count} != reconciled {expected}: {imported!r}"
            )

        # Re-importing the same endpoints is a no-op, not growth.
        _, repeat = self._call(node, "importmodelpeers", DOC_PEERS)
        if self._int("importmodelpeers", self._obj("importmodelpeers", repeat), "peers") != count:
            raise AssertionError(f"reconcile duplicated a known peer: {repeat!r}")

        # importmodelpeers is an alias of importmodelcontacts. Both names must
        # reconcile into one contact set, not two.
        ok, canonical = self._call(node, "importmodelcontacts", DOC_PEERS)
        if ok:
            if self._int("importmodelcontacts", self._obj("importmodelcontacts", canonical),
                         "peers") != count:
                raise AssertionError(
                    f"importmodelcontacts kept a separate contact set: {canonical!r}"
                )
            self._expect_invalid(node, "importmodelcontacts", 7)

        # An operator-authorized import shares the same dedupe. Whether it may
        # widen trusted identities is asserted by the trust-owning test.
        ok, trusted = self._call(node, "importmodeltrust", DOC_PEERS)
        if ok:
            trusted = self._obj("importmodeltrust", trusted)
            self._zero_spend("importmodeltrust", trusted)
            if self._int("importmodeltrust", trusted, "peers") != count:
                raise AssertionError(f"importmodeltrust duplicated a known peer: {trusted!r}")
            self._expect_invalid(node, "importmodeltrust", 7)

        _, after = self._call(node, "exportmodelpeers")
        after_peers = self._arr("exportmodelpeers", self._obj("exportmodelpeers", after), "peers")
        for peer in DOC_PEERS:
            if peer not in after_peers:
                raise AssertionError(f"imported peer {peer} did not survive export: {after!r}")
        if len(after_peers) != count:
            raise AssertionError(
                f"export disagrees with the reconciled count {count}: {after!r}"
            )

        self._expect_invalid(node, "importmodelpeers", 7)
        self.log.info("peer reconcile: %d -> %d contact(s)", len(before), count)

    def _test_provider_view(self, node, model_uri):
        if model_uri is None:
            for method in ("getmodelproviders", "getmodelpeercount"):
                self._mark_not_run(method, "importmodel setup produced no model id")
            return

        ok, providers = self._call(node, "getmodelproviders", model_uri)
        if ok:
            providers = self._obj("getmodelproviders", providers)
            self._zero_spend("getmodelproviders", providers)
            for provider in self._arr("getmodelproviders", providers, "providers"):
                provider = self._obj("getmodelproviders entry", provider)
                if not provider.get("provider_id"):
                    raise AssertionError(f"provider without an id: {provider!r}")
                if provider.get("reachability") not in ("direct", "relay"):
                    raise AssertionError(f"provider reachability: {provider!r}")
                if not isinstance(provider.get("complete"), bool):
                    raise AssertionError(f"provider complete must be boolean: {provider!r}")
            if providers.get("global_complete") is True:
                raise AssertionError(f"observed providers are not a census: {providers!r}")
            self.log.info("getmodelproviders: %d observation(s)", len(providers["providers"]))

        ok, counts = self._call(node, "getmodelpeercount", model_uri)
        if not ok:
            return
        counts = self._obj("getmodelpeercount", counts)
        self._zero_spend("getmodelpeercount", counts)
        totals = {}
        for key in ("total", "complete", "partial", "reachable_direct", "reachable_relay"):
            totals[key] = self._int("getmodelpeercount", counts, key)
            if totals[key] < 0:
                raise AssertionError(f"getmodelpeercount {key} must not be negative: {counts!r}")
        if totals["complete"] + totals["partial"] > totals["total"]:
            raise AssertionError(f"complete+partial exceeds total: {counts!r}")
        if "census" not in str(counts.get("note", "")).lower():
            raise AssertionError(f"getmodelpeercount must disclaim a global census: {counts!r}")
        self.log.info("getmodelpeercount: total=%d", totals["total"])

    # ---- driver -----------------------------------------------------------

    def _import_fixture(self, node):
        path = Path(self.options.tmpdir) / "events-import" / "model.safetensors"
        write_minimal_safetensors(path)
        try:
            imported = node.importmodel(str(path))
        except (AttributeError, JSONRPCException) as exc:
            self.log.warning("importmodel setup unavailable: %s", exc)
            return None
        if not isinstance(imported, dict):
            return None
        return imported.get("uri") or imported.get("model_id")

    def run_test(self):
        node = self.nodes[0]
        self._wait_helper_ready(node)

        model_uri = self._import_fixture(node)
        self.log.info("setup model: %s", model_uri)

        self._test_unwatchbounty(node)
        # Feed and index reads run before any contact import so that a
        # documentation endpoint is never a fanout candidate.
        sequence = self._test_feed_sequence(node)
        self._test_feed_pages(node, sequence)
        self._test_bounty_journal(node)
        self._test_index_reconcile(node)
        self._test_provider_view(node, model_uri)
        self._test_peer_reconcile(node)

        if not self.exercised:
            raise SkipTest(
                "none of the subscribe/journal/gossip subject RPCs are registered: "
                + ", ".join(SUBJECTS)
            )
        self.log.info("exercised: %s", ", ".join(sorted(self.exercised)))
        if self.not_run:
            self.log.warning("NOT_RUN (RPC missing): %s", ", ".join(sorted(self.not_run)))


if __name__ == "__main__":
    ModelNetEventsTest(__file__).main()
