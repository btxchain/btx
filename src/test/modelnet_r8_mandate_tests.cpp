// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit/.

// R8 (wallet/mandates) review lane. Companion to audit/r8-wallet.md.
//
// Registered in src/test/CMakeLists.txt. F-R8-01..09 cases assert the fixed
// behaviour. The remaining *_documents_gap cases pin production wiring that
// still lives outside the mandate module.

#include <modelnet/subscription_mandate.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r8_mandate_tests, BasicTestingSetup)

namespace {

using namespace modelnet;

const int64_t kNow = 1'000'000;
const int64_t kExp = 2'000'000;

std::string HexN(size_t n, char c)
{
    return std::string(n, c);
}

const std::string kOwner = HexN(96, 'a');
const std::string kPublisher = HexN(96, 'b');
const std::string kStranger = HexN(96, 'c');
const std::string kNetwork = HexN(64, '0');
const std::string kOtherNetwork = HexN(64, '1');

UniValue MandateJson(const std::string& mandate_id = "r8-mid")
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_version", 1);
    if (!mandate_id.empty()) o.pushKV("mandate_id", mandate_id);
    o.pushKV("owner_identity", kOwner);
    o.pushKV("network_id", kNetwork);
    o.pushKV("publisher_id", kPublisher);
    UniValue kinds(UniValue::VARR);
    kinds.push_back("RELEASE");
    kinds.push_back("MODEL");
    o.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_WITH_MANDATE");
    acts.push_back("NOTIFY");
    o.pushKV("allowed_actions", acts);
    o.pushKV("per_action_principal_limit_atoms", "50");
    o.pushKV("total_principal_limit_atoms", "100");
    o.pushKV("total_fee_limit_atoms", "20");
    o.pushKV("outstanding_exposure_limit_atoms", "200");
    o.pushKV("max_actions", 16);
    o.pushKV("max_concurrent_reservations", 8);
    o.pushKV("expires_at_ms", std::to_string(kExp));
    o.pushKV("refund_key_policy", "OWNER_CONTROLLED_ONLY");
    o.pushKV("minimum_confirmations", 1);
    o.pushKV("assurance_mode_restrictions", UniValue(UniValue::VARR));
    o.pushKV("revocation_counter", "0");
    return o;
}

SubscriptionMandate MustParse(const UniValue& o)
{
    SubscriptionMandate m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(MandateFromJson(o, m, err), err);
    return m;
}

void MustBind(SubscriptionBudget& b, const UniValue& o)
{
    const SubscriptionMandate m = MustParse(o);
    std::string err;
    BOOST_REQUIRE_MESSAGE(b.Bind(m, err), err);
}

SubscriptionEvent FundEvent(const std::string& event_id, const std::string& mandate_id = "r8-mid")
{
    SubscriptionEvent ev;
    ev.event_id = event_id;
    ev.publisher_id = kPublisher;
    ev.object_kind = "RELEASE";
    ev.object_id = "obj-" + event_id;
    ev.action = "FUND_WITH_MANDATE";
    ev.mandate_id = mandate_id;
    ev.observed_at_ms = kNow;
    return ev;
}

SignedTerms Terms(int64_t principal, int64_t fee)
{
    SignedTerms t;
    t.known = true;
    t.terms_id = HexN(96, 'd');
    t.publisher_id = kPublisher;
    t.network_id_hex = kNetwork;
    t.principal_atoms = principal;
    t.fee_atoms = fee;
    t.object_kind = "RELEASE";
    t.confirmations = 1;
    return t;
}

UniValue Arr(const UniValue& o)
{
    UniValue a(UniValue::VARR);
    a.push_back(o);
    return a;
}

UniValue StoreTermsJson(int64_t principal, int64_t fee)
{
    UniValue t(UniValue::VOBJ);
    t.pushKV("terms_id", HexN(96, 'd'));
    t.pushKV("publisher_id", kPublisher);
    t.pushKV("network_id", kNetwork);
    t.pushKV("principal_atoms", std::to_string(principal));
    t.pushKV("fee_atoms", std::to_string(fee));
    t.pushKV("object_kind", "RELEASE");
    t.pushKV("confirmations", 1);
    return t;
}

UniValue StoreReserveJson(const std::string& mandate_id, const std::string& event_id, int64_t principal, int64_t fee)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_id", mandate_id);
    o.pushKV("event_id", event_id);
    o.pushKV("publisher_id", kPublisher);
    o.pushKV("object_kind", "RELEASE");
    o.pushKV("action", "FUND_WITH_MANDATE");
    o.pushKV("signed_terms", StoreTermsJson(principal, fee));
    return o;
}

UniValue MandateIdJson(const std::string& mandate_id)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_id", mandate_id);
    return o;
}

} // namespace

// F-R8-01, fixed. allowed_kinds is mandatory and wildcard-rejected, so an absent
// kind is not a wildcard: the event or the terms must name one, and the two must
// agree.
BOOST_AUTO_TEST_CASE(r8_01_absent_object_kind_is_refused)
{
    const SubscriptionMandate m = MustParse(MandateJson());
    std::string err;

    SubscriptionEvent wrong = FundEvent("e-kind-wrong");
    wrong.object_kind = "BOUNTY";
    SignedTerms t_wrong = Terms(10, 1);
    t_wrong.object_kind = "BOUNTY";
    BOOST_CHECK(!Evaluate(wrong, t_wrong, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "object_kind");

    SubscriptionEvent blank = FundEvent("e-kind-blank");
    blank.object_kind.clear();
    SignedTerms t_blank = Terms(10, 1);
    t_blank.object_kind.clear();
    err.clear();
    BOOST_CHECK(!Evaluate(blank, t_blank, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "object_kind");

    // Terms may supply the kind the event omitted: that is the helper's reserve shape.
    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(blank, Terms(10, 1), m, kNow, err), err);

    // Two allowed kinds that disagree is still a refusal, not a free choice.
    SignedTerms t_other = Terms(10, 1);
    t_other.object_kind = "MODEL";
    err.clear();
    BOOST_CHECK(!Evaluate(FundEvent("e-kind-split"), t_other, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "object_kind");
}

// F-R8-02, fixed. owner_identity is now read: a refund destination that names an
// identity must name the owner, and a payout destination must name the bound
// publisher or the owner.
BOOST_AUTO_TEST_CASE(r8_02_refund_and_recipient_bound_to_owner)
{
    const SubscriptionMandate m = MustParse(MandateJson());
    BOOST_CHECK_EQUAL(m.owner_identity, kOwner);
    BOOST_CHECK_EQUAL(m.refund_key_policy, std::string(SUBSCRIPTION_REFUND_POLICY));

    const SubscriptionEvent ev = FundEvent("e-refund");
    std::string err;

    SignedTerms stranger_refund = Terms(10, 1);
    stranger_refund.refund_key = kStranger;
    BOOST_CHECK(!Evaluate(ev, stranger_refund, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "refund_key");

    SignedTerms owner_refund = Terms(10, 1);
    owner_refund.refund_key = kOwner;
    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(ev, owner_refund, m, kNow, err), err);

    SignedTerms stranger_recipient = Terms(10, 1);
    stranger_recipient.recipient_id = kStranger;
    err.clear();
    BOOST_CHECK(!Evaluate(ev, stranger_recipient, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "recipient binding");

    SignedTerms publisher_recipient = Terms(10, 1);
    publisher_recipient.recipient_id = kPublisher;
    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(ev, publisher_recipient, m, kNow, err), err);

    SignedTerms owner_recipient = Terms(10, 1);
    owner_recipient.recipient_id = kOwner;
    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(ev, owner_recipient, m, kNow, err), err);

    // A lone recipient is bound too, not only a second one.
    SignedTerms one = Terms(10, 1);
    one.recipients = {kStranger};
    err.clear();
    BOOST_CHECK(!Evaluate(ev, one, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "recipient binding");

    SignedTerms two = Terms(10, 1);
    two.recipients = {kPublisher, kStranger};
    err.clear();
    BOOST_CHECK(!Evaluate(ev, two, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "nested recipient");
}

// F-R8-02 residue. A refund destination that is not an identity (a wallet label,
// descriptor alias, or script name) cannot be resolved against owner_identity in
// this module: nothing here maps a label to a key. It is accepted and left to the
// signer, so an owner who writes a label instead of an identity gets no binding.
// Closing this needs the wallet plane, not subscription_mandate.cpp.
BOOST_AUTO_TEST_CASE(r8_02b_opaque_refund_label_unbound_documents_gap)
{
    const SubscriptionMandate m = MustParse(MandateJson());
    SignedTerms label = Terms(10, 1);
    label.refund_key = "attacker-controlled-label";
    std::string err;
    BOOST_CHECK_MESSAGE(Evaluate(FundEvent("e-label"), label, m, kNow, err),
                        "expected the documented gap, got: " + err);
    BOOST_CHECK_NE(label.refund_key, m.owner_identity);
}

// F-R8-03, fixed. Known terms must state their network; silence is not a match.
BOOST_AUTO_TEST_CASE(r8_03_network_is_required_and_bound)
{
    const SubscriptionMandate m = MustParse(MandateJson());
    const SubscriptionEvent ev = FundEvent("e-net");
    std::string err;

    SignedTerms wrong = Terms(10, 1);
    wrong.network_id_hex = kOtherNetwork;
    BOOST_CHECK(!Evaluate(ev, wrong, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "network_id");

    SignedTerms absent = Terms(10, 1);
    absent.network_id_hex.clear();
    err.clear();
    BOOST_CHECK(!Evaluate(ev, absent, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "network_id");

    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(ev, Terms(10, 1), m, kNow, err), err);
}

// F-R8-03 residue. SubscriptionStore can be bound to the network the node is on,
// and then refuses a mandate for any other chain. No production caller binds it:
// the node's network id reaches the helper plane, not this module, so the global
// store runs unbound and a mandate for another chain is still accepted there.
BOOST_AUTO_TEST_CASE(r8_03b_node_network_unbound_in_production_documents_gap)
{
    SubscriptionStore store;
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(store.SetNodeNetwork(kNetwork, err));
    BOOST_CHECK_EQUAL(store.NodeNetwork(), kNetwork);

    UniValue foreign = MandateJson("r8-foreign");
    foreign.pushKV("network_id", kOtherNetwork);
    BOOST_CHECK(!store.Dispatch("createsubscriptionmandate", Arr(foreign), result, code, err, kNow));
    BOOST_CHECK_EQUAL(err, "network_id");
    BOOST_REQUIRE_MESSAGE(store.Dispatch("createsubscriptionmandate", Arr(MandateJson()), result, code, err, kNow), err);

    // The store the node actually dispatches through is never told which chain it is on.
    BOOST_CHECK(GlobalSubscriptionStore().NodeNetwork().empty());
}

// F-R8-04, fixed. A mandate with no id would accept an event carrying any id, so
// a spend against an unnamed mandate is refused outright.
BOOST_AUTO_TEST_CASE(r8_04_empty_mandate_id_is_refused)
{
    const SubscriptionMandate m = MustParse(MandateJson(/*mandate_id=*/""));
    BOOST_REQUIRE(m.mandate_id.empty());

    const SubscriptionEvent ev = FundEvent("e-anyid", "someone-elses-mandate");
    std::string err;
    BOOST_CHECK(!Evaluate(ev, Terms(10, 1), m, kNow, err));
    BOOST_CHECK_EQUAL(err, "mandate_id");

    SubscriptionMandate named = m;
    named.mandate_id = "r8-mid";
    err.clear();
    BOOST_CHECK(!Evaluate(ev, Terms(10, 1), named, kNow, err));
    BOOST_CHECK_EQUAL(err, "mandate_id");

    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(FundEvent("e-rightid"), Terms(10, 1), named, kNow, err), err);

    // The RPC surface still works: the store names an unnamed mandate on creation.
    SubscriptionStore store;
    UniValue result;
    std::string code;
    BOOST_REQUIRE_MESSAGE(
        store.Dispatch("createsubscriptionmandate", Arr(MandateJson(/*mandate_id=*/"")), result, code, err, kNow), err);
    BOOST_CHECK(!result["mandate_id"].get_str().empty());
}

// F-R8-04 residue. The other half of the finding is that nothing checks a
// signature over SignedTerms: `known` is set by the mere presence of a terms id
// and a publisher id, and there is no signature field to check even in principle.
// A verifier lives in the record/crypto plane, not here, so terms fabricated by
// whoever fed the helper the event are still evaluated as signed terms.
BOOST_AUTO_TEST_CASE(r8_04b_terms_signature_unverified_documents_gap)
{
    UniValue forged(UniValue::VOBJ);
    forged.pushKV("terms_id", HexN(96, 'f'));
    forged.pushKV("publisher_id", kPublisher);
    forged.pushKV("network_id", kNetwork);
    forged.pushKV("principal_atoms", "10");
    forged.pushKV("fee_atoms", "1");
    forged.pushKV("object_kind", "RELEASE");
    forged.pushKV("confirmations", 1);

    SignedTerms t;
    std::string err;
    BOOST_REQUIRE_MESSAGE(TermsFromJson(forged, t, err), err);
    BOOST_CHECK_MESSAGE(t.known, "expected the documented gap: presence of an id is taken for a signature");
    BOOST_CHECK(!forged.exists("signature"));

    const SubscriptionMandate m = MustParse(MandateJson());
    err.clear();
    BOOST_CHECK_MESSAGE(Evaluate(FundEvent("e-forged"), t, m, kNow, err),
                        "expected the documented gap, got: " + err);
}

// F-R8-06, fixed. A file-backed store reloads spent budget, revocation, and open
// reservations, so a restart no longer hands back a budget that was already spent.
BOOST_AUTO_TEST_CASE(r8_05_budget_and_revocation_survive_restart)
{
    const fs::path state = m_path_root / "r8-mandates" / "subscriptions.json";
    UniValue result;
    std::string code, err;

    {
        SubscriptionStore store;
        BOOST_REQUIRE_MESSAGE(store.SetPersistPath(state, err), err);
        BOOST_CHECK(store.Persisted());
        BOOST_REQUIRE_MESSAGE(store.Dispatch("createsubscriptionmandate", Arr(MandateJson()), result, code, err, kNow), err);
        BOOST_CHECK_EQUAL(result["mandate_id"].get_str(), "r8-mid");
        BOOST_REQUIRE_MESSAGE(
            store.Dispatch("reservesubscriptionmandate", Arr(StoreReserveJson("r8-mid", "e-restart", 50, 5)), result, code, err, kNow),
            err);
        BOOST_CHECK_EQUAL(result["used_principal_atoms"].get_str(), "50");
        BOOST_REQUIRE_MESSAGE(store.Dispatch("revokesubscriptionmandate", Arr(MandateJson()), result, code, err, kNow), err);
        BOOST_CHECK(result["revoked"].get_bool());
    }

    // Restart: a fresh store over the same file.
    SubscriptionStore restarted;
    BOOST_REQUIRE_MESSAGE(restarted.SetPersistPath(state, err), err);
    BOOST_REQUIRE_MESSAGE(restarted.Dispatch("getsubscriptionmandate", Arr(MandateIdJson("r8-mid")), result, code, err, kNow), err);
    BOOST_CHECK_MESSAGE(result["revoked"].get_bool(), "revocation must be durable");
    BOOST_CHECK_EQUAL(result["used_principal_atoms"].get_str(), "50");
    BOOST_CHECK_EQUAL(result["used_fee_atoms"].get_str(), "5");
    BOOST_CHECK_EQUAL(result["action_count"].getInt<int64_t>(), 1);

    // The id is taken, and the revoked mandate still refuses new reservations.
    BOOST_CHECK(!restarted.Dispatch("createsubscriptionmandate", Arr(MandateJson()), result, code, err, kNow));
    BOOST_CHECK_EQUAL(err, "mandate_id");
    BOOST_CHECK(!restarted.Dispatch("reservesubscriptionmandate", Arr(StoreReserveJson("r8-mid", "e-after-restart", 10, 1)),
                                    result, code, err, kNow));
    BOOST_CHECK_EQUAL(err, "revoked");

    // A replayed event id does not spend twice across the restart either.
    SubscriptionStore fresh;
    const fs::path second = m_path_root / "r8-mandates" / "second.json";
    BOOST_REQUIRE_MESSAGE(fresh.SetPersistPath(second, err), err);
    BOOST_REQUIRE_MESSAGE(fresh.Dispatch("createsubscriptionmandate", Arr(MandateJson("r8-mid-2")), result, code, err, kNow), err);
    BOOST_REQUIRE_MESSAGE(
        fresh.Dispatch("reservesubscriptionmandate", Arr(StoreReserveJson("r8-mid-2", "e-once", 40, 2)), result, code, err, kNow),
        err);
    SubscriptionStore fresh_restarted;
    BOOST_REQUIRE_MESSAGE(fresh_restarted.SetPersistPath(second, err), err);
    BOOST_REQUIRE_MESSAGE(
        fresh_restarted.Dispatch("reservesubscriptionmandate", Arr(StoreReserveJson("r8-mid-2", "e-once", 40, 2)), result, code, err, kNow),
        err);
    BOOST_CHECK_EQUAL(result["used_principal_atoms"].get_str(), "40");
    BOOST_CHECK_EQUAL(result["used_fee_atoms"].get_str(), "2");
}

// F-R8-06 residue. Persistence is opt-in and nothing switches it on: the store the
// node dispatches through is constructed by GlobalSubscriptionStore() and no caller
// gives it a path, so the shipped helper still forgets every mandate on restart.
// The wiring belongs to modelnet/helper.cpp (or init), not to this module.
BOOST_AUTO_TEST_CASE(r8_05b_global_store_not_file_backed_documents_gap)
{
    BOOST_CHECK_MESSAGE(!GlobalSubscriptionStore().Persisted(),
                        "expected the documented gap: no caller gives the global store a state file");
}

// F-R8-07, fixed. Exposure is what is reserved and not yet settled: broadcasting
// releases the exposure slot, while the lifetime totals keep their own caps.
BOOST_AUTO_TEST_CASE(r8_06_exposure_settles_on_broadcast)
{
    UniValue j = MandateJson();
    j.pushKV("total_principal_limit_atoms", "1000");
    j.pushKV("total_fee_limit_atoms", "1000");
    j.pushKV("outstanding_exposure_limit_atoms", "60");

    SubscriptionBudget budget;
    MustBind(budget, j);

    Reservation r;
    std::string err;
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-exp-1"), Terms(40, 5), r, kNow, err), err);
    BOOST_CHECK_EQUAL(budget.ConcurrentReservations(), 1);
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 45);

    BOOST_REQUIRE(budget.MarkBroadcast("e-exp-1", err));
    BOOST_CHECK_EQUAL(budget.ConcurrentReservations(), 0);
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 0); // exposure settles with the slot
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);      // spent stays spent

    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-exp-2"), Terms(40, 5), r, kNow, err), err);
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 45);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 80);

    // The ceiling still binds what is genuinely outstanding.
    BOOST_CHECK(!EvaluateAndReserve(budget, FundEvent("e-exp-3"), Terms(40, 5), r, kNow, err));
    BOOST_CHECK_EQUAL(err, "exposure cap");
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 45);

    // Settling the second one frees the ceiling again.
    BOOST_REQUIRE(budget.MarkBroadcast("e-exp-2", err));
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 0);
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-exp-3"), Terms(40, 5), r, kNow, err), err);
}

// F-R8-08, fixed. A reorg orphans the transaction a broadcast reservation paid for,
// so the replayed event is authorized afresh instead of being handed the settled
// reservation. Budget is not refunded: the re-authorization costs budget again.
BOOST_AUTO_TEST_CASE(r8_07_reorg_forces_reauthorization)
{
    SubscriptionBudget budget;
    MustBind(budget, MandateJson());

    Reservation first;
    std::string err;
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-reorg"), Terms(40, 3), first, kNow, err), err);
    BOOST_REQUIRE(budget.MarkBroadcast("e-reorg", err));

    // MarkBroadcast is idempotent: a duplicate submit must not free a slot twice.
    BOOST_REQUIRE(budget.MarkBroadcast("e-reorg", err));
    BOOST_CHECK_EQUAL(budget.ConcurrentReservations(), 0);
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 0);

    budget.NoteChainReorg();
    BOOST_CHECK_EQUAL(budget.ReorgCount(), 1);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40); // spent stays spent
    BOOST_CHECK_EQUAL(budget.UsedFees(), 3);

    Reservation replay;
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-reorg"), Terms(40, 3), replay, kNow, err), err);
    BOOST_CHECK_NE(replay.reservation_id, first.reservation_id);
    BOOST_CHECK_MESSAGE(!replay.broadcast, "a re-authorization must not start out broadcast");
    BOOST_CHECK_EQUAL(budget.ActionCount(), 2);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 80);
    BOOST_CHECK_EQUAL(budget.ConcurrentReservations(), 1);
    BOOST_CHECK_EQUAL(budget.OutstandingExposure(), 43);

    // An unbroadcast reservation is untouched by a reorg: it is still the same one.
    Reservation same;
    budget.NoteChainReorg();
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-reorg"), Terms(40, 3), same, kNow, err), err);
    BOOST_CHECK_EQUAL(same.reservation_id, replay.reservation_id);
    BOOST_CHECK_EQUAL(budget.ActionCount(), 2);
}

// F-R8-08 residue. Re-authorization now works, but nothing tells the store that a
// reorg happened: NoteChainReorg is a SubscriptionBudget method with no RPC and no
// validation-side caller, so a node that reorgs leaves its budgets believing the
// orphaned transactions are still on chain. The hook belongs to the helper plane.
BOOST_AUTO_TEST_CASE(r8_07b_reorg_hook_unreachable_from_rpc_documents_gap)
{
    for (const char* method : {"notesubscriptionreorg", "subscriptionmandatereorg", "reorgsubscriptionmandate"}) {
        BOOST_CHECK_MESSAGE(!IsSubscriptionHelperMethod(method),
                            std::string("unexpectedly routable: ") + method);
    }

    SubscriptionStore store;
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(store.Dispatch("createsubscriptionmandate", Arr(MandateJson()), result, code, err, kNow), err);
    BOOST_CHECK(!store.Dispatch("notesubscriptionreorg", Arr(MandateIdJson("r8-mid")), result, code, err, kNow));
    BOOST_CHECK_EQUAL(code, "NOT_FOUND");
    BOOST_CHECK_EQUAL(err, "method");
}

// F-R8-09, fixed. The reservation records the object and terms it authorized, so a
// reused event id that names a different object is a conflict, not a replay.
BOOST_AUTO_TEST_CASE(r8_08_event_id_collision_across_objects_is_refused)
{
    SubscriptionBudget budget;
    MustBind(budget, MandateJson());
    std::string err;

    SubscriptionEvent a = FundEvent("e-collide");
    a.object_id = "obj-A";
    SignedTerms ta = Terms(40, 2);
    ta.terms_id = HexN(96, 'd');

    SubscriptionEvent b = FundEvent("e-collide");
    b.object_id = "obj-B";
    SignedTerms tb = Terms(40, 2);
    tb.terms_id = HexN(96, 'e');

    Reservation ra, rb;
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, a, ta, ra, kNow, err), err);
    BOOST_CHECK(!EvaluateAndReserve(budget, b, tb, rb, kNow, err));
    BOOST_CHECK_EQUAL(err, "idempotency conflict");
    BOOST_CHECK_EQUAL(budget.ActionCount(), 1);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);

    // Same object, same terms, same amounts is still the idempotent replay.
    Reservation again;
    err.clear();
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, a, ta, again, kNow, err), err);
    BOOST_CHECK_EQUAL(again.reservation_id, ra.reservation_id);
    BOOST_CHECK_EQUAL(budget.ActionCount(), 1);

    // Mismatched amounts are refused as before.
    Reservation rc;
    BOOST_CHECK(!EvaluateAndReserve(budget, a, Terms(41, 2), rc, kNow, err));
    BOOST_CHECK_EQUAL(err, "idempotency conflict");
}

// Atomicity case the existing suite lacks: N threads racing on the SAME event id
// must charge the budget exactly once.
BOOST_AUTO_TEST_CASE(r8_09_same_event_concurrent_charges_budget_once)
{
    UniValue j = MandateJson();
    j.pushKV("total_principal_limit_atoms", "1000");
    j.pushKV("total_fee_limit_atoms", "1000");
    j.pushKV("outstanding_exposure_limit_atoms", "2000");
    j.pushKV("max_concurrent_reservations", 8);

    SubscriptionBudget budget;
    MustBind(budget, j);

    std::mutex mu;
    std::set<std::string> ids;
    int failures = 0;

    std::vector<std::thread> th;
    th.reserve(16);
    for (int i = 0; i < 16; ++i) {
        th.emplace_back([&] {
            Reservation r;
            std::string e;
            const bool ok = EvaluateAndReserve(budget, FundEvent("e-same"), Terms(40, 2), r, kNow, e);
            std::lock_guard<std::mutex> lock(mu);
            if (ok) ids.insert(r.reservation_id);
            else ++failures;
        });
    }
    for (auto& t : th) t.join();

    BOOST_CHECK_EQUAL(failures, 0);
    BOOST_CHECK_EQUAL(ids.size(), 1u);
    BOOST_CHECK_EQUAL(budget.ActionCount(), 1);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 2);
}

// The reservation handed to the wallet plane still carries no key material and no
// script: the object and terms binding added for F-R8-09 stays inside the budget.
BOOST_AUTO_TEST_CASE(r8_10_reservation_carries_no_wallet_or_object_binding)
{
    SubscriptionBudget budget;
    MustBind(budget, MandateJson());

    Reservation r;
    std::string err;
    BOOST_REQUIRE_MESSAGE(EvaluateAndReserve(budget, FundEvent("e-bind"), Terms(40, 2), r, kNow, err), err);
    BOOST_CHECK_EQUAL(r.object_id, "obj-e-bind");
    BOOST_CHECK_EQUAL(r.terms_id, HexN(96, 'd'));

    const UniValue o = ReservationToJson(r);
    for (const char* absent : {"terms_id", "object_id", "recipient_id", "publisher_id", "refund_key",
                               "descriptor", "output_script", "unsigned_hex", "private_key", "wallet_seed"}) {
        BOOST_CHECK_MESSAGE(!o.exists(absent), std::string("reservation unexpectedly exposes ") + absent);
    }
    BOOST_CHECK(!o["wallet_signed"].get_bool());
    BOOST_CHECK(!o["private_keys"].get_bool());
    BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int64_t>(), SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS);
    BOOST_CHECK_EQUAL(SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS, 0);
}

BOOST_AUTO_TEST_SUITE_END()
