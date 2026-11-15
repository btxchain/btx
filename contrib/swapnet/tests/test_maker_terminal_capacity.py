"""Probe real coordinator admission with simulated chains and SQLite only."""
from dataclasses import asdict, replace

import pytest

from swapnet.authorization import Principal
from swapnet.canonical import digest
from swapnet.errors import SwapError
from swapnet.quote import Quote
from test_execution_v2 import A, B, NETWORK, pair


def maker_state(pair):
    store, journal, _, _ = pair.nodes["bob"]
    _, state = journal.load(pair.sid)
    status, cost = store.db.execute(
        "SELECT state,cost FROM reservations WHERE id=?", (state["reservation_id"],)
    ).fetchone()
    count = store.db.execute(
        "SELECT count(*) FROM sn_negotiations WHERE stage NOT IN ('complete','refunded','cancelled','rejected')"
    ).fetchone()[0]
    return {
        "stage": state["stage"],
        "active": count,
        "reservation": status,
        "reserved_atoms": int(cost),
        "maker_funding_prepared": state["funding_prepared"],
        "maker_funding_broadcast": state["funding_broadcast"],
        "operations": [op["kind"] for op in journal.operations(pair.sid)],
        "action": state.get("last_action"),
        "long_leg": state.get("observations", {}).get("a"),
    }


def fresh_proposal(pair):
    _, _, _, initiator = pair.nodes["alice"]
    mandate = pair.mandate("alice", A)
    now = pair.time()
    nonce = "66" * 32
    requester = digest("BTX/SWAPNET/REQUESTER/2", {"identity": "alice", "nonce": nonce})
    rfq = dict(network=NETWORK, requester=requester, sell_asset=A, buy_asset=B,
               sell_atoms="10000", nonce=nonce, issued_at=now, expires_at=now + 120)
    quote = Quote(NETWORK, "bob", requester, "77" * 32, 2, A, B,
                  "10000", "20000", "10", "100", now, now + 120)
    envelope = {"quote": asdict(quote), "signature": pair.identities["bob"].sign(quote.signing_message)}
    initiator.start(Principal("alice"), envelope, rfq, mandate, "500", "100")
    sender, recipient, kind, sid, proposal = pair.queue.pop(0)
    assert (sender, recipient, kind) == ("alice", "bob", "proposal")
    assert sid != pair.sid
    return sid, proposal


def funded_long_leg(pair):
    pair.start()
    pair.deliver()
    initiator = pair.nodes["alice"][3]
    maker = pair.nodes["bob"][3]
    # Advance only the initiator until maturity. Maker is present for its
    # funding reference and observes in the maturity window, with no local fund.
    initiator.tick_one(pair.sid)
    initiator.tick_one(pair.sid)
    pair.deliver()
    return initiator, maker, pair.state("alice")["agreement"]


def mature_long_refund(pair, initiator, agreement):
    pair.a.height = agreement["long_leg"]["lock_value"]
    pair.b.height = agreement["short_leg"]["lock_value"]
    initiator.request_refund(Principal("alice"), pair.sid)


def test_maker_slot_after_confirmed_refund_and_restart(pair):
    initiator, maker, agreement = funded_long_leg(pair)
    mature_long_refund(pair, initiator, agreement)
    maker.tick_one(pair.sid)
    before = maker_state(pair)
    assert before["stage"] == "committed"
    assert before["long_leg"]["refunded"] and before["long_leg"]["confirmations"] == 0
    assert not before["maker_funding_prepared"] and not before["maker_funding_broadcast"]
    assert not before["operations"] and not pair.b.records
    print("REFUND_UNCONFIRMED", before)

    pair.a.mine(2)
    initiator.tick_one(pair.sid)
    assert pair.state("alice")["stage"] == "refunded"
    maker.tick_one(pair.sid)
    confirmed = maker_state(pair)
    assert confirmed["long_leg"]["confirmations"] == 2
    assert confirmed["long_leg"]["refunded"] and confirmed["long_leg"]["canonical"]
    assert confirmed["long_leg"]["exact_terms"] and not confirmed["long_leg"]["conflicting"]
    print("REFUND_CONFIRMED", confirmed)
    pair.restart("bob")
    store, journal, _, maker = pair.nodes["bob"]
    maker.tick_one(pair.sid)
    restarted = maker_state(pair)
    assert restarted == confirmed
    print("REFUND_AFTER_RESTART", restarted)

    assert restarted["stage"] == "cancelled"
    assert restarted["reservation"] == "closed" and restarted["active"] == 0
    for n in range(1, 128):
        journal.save(f"{n:064x}", {"stage":"committed","principal":"fixture","peer":"fixture"})
    assert maker_state(pair)["active"] == 127
    sid, proposal = fresh_proposal(pair)
    maker.receive_proposal("alice", sid, proposal, pair.market)
    assert journal.load(sid)[1]["stage"] == "offered"
    assert maker_state(pair)["active"] == 128
    # A reorg after unfunded closure cannot restart the old agreement.
    pair.a.rollback_spend()
    maker.tick_one(pair.sid)
    assert maker_state(pair)["stage"] == "cancelled"
    assert not pair.b.records
    assert store.verify_audit()


def test_noncanonical_remote_refund_retains_reservation(pair, monkeypatch):
    initiator, maker, agreement = funded_long_leg(pair)
    mature_long_refund(pair, initiator, agreement)
    pair.a.mine(2)
    remote = maker._driver(A)
    observe = remote.observe

    def noncanonical(terms, reference):
        report = observe(terms, reference)
        assert report.observation.refunded and report.observation.confirmations == 2
        return replace(report, observation=replace(report.observation, canonical=False))

    monkeypatch.setattr(remote, "observe", noncanonical)
    maker.tick_one(pair.sid)
    state = maker_state(pair)
    assert state["stage"] == "committed"
    assert not state["long_leg"]["canonical"]
    assert state["reservation"] == "held" and state["active"] == 1
    assert not state["operations"]
    print("NONCANONICAL_REFUND", state)


def test_funded_maker_recovers_its_own_leg(pair):
    initiator, maker, agreement = funded_long_leg(pair)
    pair.a.mine(2)
    pair.b.mine(2)
    maker.tick_one(pair.sid)
    maker.tick_one(pair.sid)
    pair.deliver()
    funded = maker_state(pair)
    assert funded["maker_funding_broadcast"] and funded["reservation"] == "funded"
    assert set(funded["operations"]) == {"fund", "refund"}
    mature_long_refund(pair, initiator, agreement)
    pair.a.mine(2)
    pair.restart("bob")
    maker = pair.nodes["bob"][3]
    maker.tick_one(pair.sid)
    pending = maker_state(pair)
    assert pending["stage"] == "refund_broadcast"
    assert pending["reservation"] == "funded" and pending["active"] == 1
    print("MAKER_REFUND_PENDING", pending)
    pair.b.mine(2)
    maker.tick_one(pair.sid)
    recovered = maker_state(pair)
    assert recovered["stage"] == "refunded"
    assert recovered["reservation"] == "closed" and recovered["active"] == 0
    print("MAKER_OWN_REFUND_CONFIRMED", recovered)

def test_durable_fund_record_prevents_release_even_with_old_flags(pair):
    initiator, maker, agreement = funded_long_leg(pair)
    journal = pair.nodes["bob"][1]
    journal.prepare(pair.sid, B, "fund", "88"*32, "00")
    mature_long_refund(pair, initiator, agreement)
    pair.a.mine(2)
    pair.restart("bob")
    pair.nodes["bob"][3].tick_one(pair.sid)
    state = maker_state(pair)
    assert not state["maker_funding_prepared"] and not state["maker_funding_broadcast"]
    assert state["operations"] == ["fund"]
    assert state["stage"] == "committed" and state["reservation"] == "held"


def test_slot_and_reservation_roll_back_together(pair, monkeypatch):
    initiator, maker, agreement = funded_long_leg(pair)
    mature_long_refund(pair, initiator, agreement)
    pair.a.mine(2)
    store = pair.nodes["bob"][0]
    audit = store._audit

    def interrupted(db, event):
        if event.get("stage") == "cancelled":
            raise RuntimeError("fixture stops after reservation update")
        return audit(db, event)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_audit", interrupted)
        with pytest.raises(RuntimeError, match="fixture stops"):
            maker.tick_one(pair.sid)
    pair.restart("bob")
    before = maker_state(pair)
    assert before["stage"] == "committed" and before["reservation"] == "held"
    pair.nodes["bob"][3].tick_one(pair.sid)
    after = maker_state(pair)
    assert after["stage"] == "cancelled" and after["reservation"] == "closed"
    assert pair.nodes["bob"][0].verify_audit()
