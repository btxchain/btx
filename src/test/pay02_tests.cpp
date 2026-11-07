// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/pay02/pay02.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <map>
#include <vector>
#include <string>

BOOST_FIXTURE_TEST_SUITE(pay02_tests, BasicTestingSetup)

static void ExpectClosed(const modelnet::Pay02& eng)
{
    BOOST_CHECK(!eng.settled());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(record_funding_stores_paths_without_settlement)
{
    modelnet::Pay02 eng;
    std::string err = "stale";

    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.opened());
    BOOST_CHECK(!eng.claim_kept("case-1"));
    ExpectClosed(eng);

    BOOST_CHECK(!eng.RecordFunding("", true, true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.opened());
    BOOST_CHECK(!eng.claim_kept(""));

    err = "stale";
    BOOST_CHECK(!eng.RecordFunding("", false, false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.objective().empty());

    err = "stale";
    BOOST_CHECK(!eng.RecordFunding("case-1", false, true, err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.opened());
    BOOST_CHECK(!eng.claim_kept("case-1"));

    err = "stale";
    BOOST_CHECK(!eng.RecordFunding("case-1", true, false, err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.claim_kept("case-1"));

    err = "stale";
    BOOST_CHECK(!eng.RecordFunding("case-1", false, false, err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.opened());

    err = "stale";
    BOOST_CHECK(eng.RecordFunding("case-1", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.objective(), "case-1");
    BOOST_CHECK(eng.opened());
    BOOST_CHECK(eng.claim_kept("case-1"));
    BOOST_CHECK(!eng.claim_kept("case-2"));
    ExpectClosed(eng);

    err = "stale";
    BOOST_CHECK(!eng.RecordFunding("case-2", false, true, err));
    BOOST_CHECK_EQUAL(err, "PATH");
    BOOST_CHECK_EQUAL(eng.objective(), "case-1");
    BOOST_CHECK(eng.claim_kept("case-1"));
    BOOST_CHECK(!eng.claim_kept("case-2"));

    err = "stale";
    BOOST_CHECK(!eng.RecordFunding("", true, true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.objective(), "case-1");

    err = "stale";
    BOOST_CHECK(eng.RecordFunding("case-2", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.objective(), "case-2");
    BOOST_CHECK(eng.opened());
    BOOST_CHECK(eng.claim_kept("case-1"));
    BOOST_CHECK(eng.claim_kept("case-2"));
    ExpectClosed(eng);
}

BOOST_AUTO_TEST_CASE(prove_exit_stays_unqualified)
{
    modelnet::Pay02 eng;
    std::string err = "stale";

    BOOST_CHECK(eng.RecordFunding("case-1", true, true, err));
    BOOST_CHECK_EQUAL(eng.objective(), "case-1");

    const bool flags[][5] = {
        {false, false, false, false, false},
        {false, true, true, true, true},
        {true, false, true, true, true},
        {true, true, false, true, true},
        {true, true, true, false, true},
        {true, true, true, true, false},
        {true, true, true, true, true},
    };
    for (const auto& row : flags) {
        err = "stale";
        BOOST_CHECK(!eng.ProveExit(row[0], row[1], row[2], row[3], row[4], err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    }
    BOOST_CHECK_EQUAL(eng.objective(), "case-1");
    BOOST_CHECK(eng.claim_kept("case-1"));
    ExpectClosed(eng);
}

BOOST_AUTO_TEST_CASE(federate_refuses_a_second_organization)
{
    modelnet::Pay02 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Federate(0, true, err));
    BOOST_CHECK_EQUAL(err, "ORG");
    BOOST_CHECK(!eng.Federate(1, true, err));
    BOOST_CHECK_EQUAL(err, "ORG");
    BOOST_CHECK(!eng.Federate(-1, true, err));
    BOOST_CHECK_EQUAL(err, "ORG");
    BOOST_CHECK(!eng.Federate(2, false, err));
    BOOST_CHECK_EQUAL(err, "ORG");
    BOOST_CHECK(!eng.Federate(4, false, err));
    BOOST_CHECK_EQUAL(err, "ORG");
    BOOST_CHECK(!eng.Federate(1, false, err));
    BOOST_CHECK_EQUAL(err, "ORG");

    err = "stale";
    BOOST_CHECK(!eng.Federate(2, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Federate(3, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.opened());
    ExpectClosed(eng);
}

BOOST_AUTO_TEST_CASE(cross_host_faults_stay_unqualified)
{
    modelnet::Pay02 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.ExerciseFaults(true, true, true, true, 0, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(!eng.ExerciseFaults(true, true, true, true, 1, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(!eng.ExerciseFaults(false, true, true, true, 1, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");

    err = "stale";
    BOOST_CHECK(!eng.ExerciseFaults(false, true, true, true, 2, err));
    BOOST_CHECK_EQUAL(err, "FAULT");
    BOOST_CHECK(!eng.ExerciseFaults(true, false, true, true, 2, err));
    BOOST_CHECK_EQUAL(err, "FAULT");
    BOOST_CHECK(!eng.ExerciseFaults(true, true, false, true, 2, err));
    BOOST_CHECK_EQUAL(err, "FAULT");
    BOOST_CHECK(!eng.ExerciseFaults(true, true, true, false, 3, err));
    BOOST_CHECK_EQUAL(err, "FAULT");
    BOOST_CHECK(!eng.ExerciseFaults(false, false, false, false, 2, err));
    BOOST_CHECK_EQUAL(err, "FAULT");

    err = "stale";
    BOOST_CHECK(!eng.ExerciseFaults(true, true, true, true, 2, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.ExerciseFaults(true, true, true, true, 4, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(eng.objective().empty());
    BOOST_CHECK(!eng.opened());
    ExpectClosed(eng);
}

namespace {
class PaymentChainFixture : public modelnet::NativePaymentChainView {
public:
    std::map<Txid, modelnet::NativePaymentTransaction> transactions;
    uint256 tip{uint256::ONE};
    int height{200};
    bool unspent{true};
    bool mutate_tip{false};
    mutable int tip_reads{0};
    CTxOut coin;
    uint256 Tip() const override { return mutate_tip && ++tip_reads > 1 ? uint256{} : tip; }
    int Height() const override { return height; }
    bool Lookup(const Txid& id, modelnet::NativePaymentTransaction& out, std::string& err) const override
    {
        const auto found = transactions.find(id);
        if (found == transactions.end()) { err = "UNKNOWN_TX"; return false; }
        out = found->second;
        return true;
    }
    bool Unspent(const COutPoint&, CTxOut& out) const override { if (unspent) out = coin; return unspent; }
};

struct NativeLotFixture {
    PaymentChainFixture chain;
    modelnet::NativePaymentTerms terms;
    CMutableTransaction spend;
    NativeLotFixture()
    {
        terms.objective = "native-fixture-not-deployment";
        terms.funding_script = CScript() << OP_2 << std::vector<unsigned char>(32, 42);
        terms.claim_leaf = CScript() << OP_SHA256 << std::vector<unsigned char>(32, 1) << OP_EQUALVERIFY << OP_TRUE;
        terms.refund_leaf = CScript() << 190 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE;
        terms.destination = CScript() << OP_2 << std::vector<unsigned char>(32, 43);
        terms.principal_atoms = 100000;
        terms.max_settlement_fee_atoms = 1000;
        terms.refund_height = 190;
        CMutableTransaction funding;
        funding.vout.emplace_back(terms.principal_atoms, terms.funding_script);
        auto tx = MakeTransactionRef(funding);
        terms.funding = COutPoint(tx->GetHash(), 0);
        chain.transactions.emplace(tx->GetHash(), modelnet::NativePaymentTransaction{tx, 5, uint256::ONE});
        chain.coin = funding.vout[0];
        spend.vin.emplace_back(terms.funding);
        spend.vout.emplace_back(99000, terms.destination);
        spend.vin[0].scriptWitness.stack = {{1}, std::vector<unsigned char>(terms.claim_leaf.begin(), terms.claim_leaf.end()), {1}};
    }
    Txid AddSpend(int confirmations)
    {
        auto tx = MakeTransactionRef(spend);
        chain.transactions.insert_or_assign(tx->GetHash(), modelnet::NativePaymentTransaction{tx, confirmations,
            confirmations > 0 ? uint256::ONE : uint256{}});
        chain.unspent = false;
        return tx->GetHash();
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(native_observer_requires_confirmed_bytes_and_resets_on_reorg)
{
    NativeLotFixture lot;
    modelnet::Pay02 observer;
    std::string err;
    BOOST_REQUIRE(observer.ObserveNative(lot.chain, lot.terms, std::nullopt, err));
    BOOST_CHECK(observer.opened());
    BOOST_CHECK(!observer.settled());
    auto id = lot.AddSpend(0);
    BOOST_REQUIRE(observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK(!observer.settled());
    BOOST_CHECK_EQUAL(observer.native_receipt().state, "SETTLEMENT_UNCONFIRMED");
    id = lot.AddSpend(1);
    BOOST_REQUIRE(observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK(observer.settled());
    BOOST_CHECK_EQUAL(observer.atoms_moved(), 99000);
    BOOST_CHECK_EQUAL(observer.native_receipt().fee_atoms, 1000);
    BOOST_CHECK_EQUAL(observer.native_receipt().branch, "CLAIM");
    BOOST_CHECK(!observer.release_qualified());
    BOOST_CHECK_EQUAL(observer.automatic_spend(), "0");
    lot.chain.transactions[id].confirmations = -1;
    lot.chain.transactions[id].block_hash.SetNull();
    BOOST_REQUIRE(observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK(!observer.settled());
    BOOST_CHECK_EQUAL(observer.atoms_moved(), 0);
    lot.chain.transactions.erase(id);
    BOOST_CHECK(!observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK(!observer.settled());
}

BOOST_AUTO_TEST_CASE(native_observer_rejects_wrong_destination_fees_and_extra_inputs)
{
    NativeLotFixture lot;
    modelnet::Pay02 observer;
    std::string err;
    lot.spend.vout[0].scriptPubKey = CScript() << OP_TRUE;
    auto id = lot.AddSpend(1);
    BOOST_CHECK(!observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK_EQUAL(err, "NATIVE_PAYMENT_SETTLEMENT_MISMATCH");
    lot.spend.vout[0].scriptPubKey = lot.terms.destination;
    lot.spend.vout[0].nValue = 98000;
    id = lot.AddSpend(1);
    BOOST_CHECK(!observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK_EQUAL(err, "NATIVE_PAYMENT_FEE_CAP");
    lot.spend.vout[0].nValue = 99000;
    lot.spend.vin.push_back(lot.spend.vin[0]);
    id = lot.AddSpend(1);
    BOOST_CHECK(!observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK_EQUAL(err, "NATIVE_PAYMENT_SETTLEMENT_MISMATCH");
}

BOOST_AUTO_TEST_CASE(native_observer_refund_requires_cltv_and_stable_chain_view)
{
    NativeLotFixture lot;
    modelnet::Pay02 observer;
    std::string err;
    lot.spend.vin[0].scriptWitness.stack[1] = std::vector<unsigned char>(lot.terms.refund_leaf.begin(), lot.terms.refund_leaf.end());
    auto id = lot.AddSpend(1);
    BOOST_CHECK(!observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK_EQUAL(err, "NATIVE_PAYMENT_REFUND_LOCK");
    lot.spend.nLockTime = lot.terms.refund_height;
    lot.spend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    id = lot.AddSpend(1);
    BOOST_REQUIRE(observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK_EQUAL(observer.native_receipt().state, "REFUNDED");
    lot.chain.mutate_tip = true;
    lot.chain.tip_reads = 0;
    BOOST_CHECK(!observer.ObserveNative(lot.chain, lot.terms, id, err));
    BOOST_CHECK_EQUAL(err, "NATIVE_PAYMENT_CHAIN_CHANGED");
    BOOST_CHECK(!observer.settled());
    BOOST_CHECK_EQUAL(observer.atoms_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
