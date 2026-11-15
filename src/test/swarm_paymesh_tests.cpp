// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paymesh.h>
#include <crypto/sha256.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_paymesh_tests, BasicTestingSetup)

namespace {

std::string FixedId(char c)
{
    return std::string(96, c);
}

modelnet::SwarmSepManifest Manifest(int epoch)
{
    modelnet::SwarmSepManifest manifest;
    manifest.protocol = "BTX-SEP/1";
    manifest.network = "regtest";
    manifest.lineage_id = FixedId('a');
    manifest.checkpoint_id = FixedId('b');
    manifest.objective_type = "evaluation";
    manifest.recipe_id = FixedId('c');
    manifest.policy_id = FixedId('d');
    manifest.nonce = "n1";
    manifest.policy_epoch = epoch;
    manifest.parent_pool.clear();
    manifest.gross_budget_atoms = "1000";
    manifest.conditional_release = true;
    manifest.wallet_key_custody = "external";
    manifest.automatic_spend_atoms = "0";
    return manifest;
}

std::vector<unsigned char> Pubkey(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

std::string Sha256Hex(const std::vector<unsigned char>& bytes)
{
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(hash);
    return HexStr(Span<const unsigned char>(hash, CSHA256::OUTPUT_SIZE));
}

} // namespace

BOOST_AUTO_TEST_CASE(epoch_change_keeps_the_old_obligation)
{
    BOOST_CHECK(!modelnet::SwarmSchedulerHasSpendKey());
    BOOST_CHECK_EQUAL(std::string(modelnet::SWARM_AUTOMATIC_SPEND_ATOMS), "0");

    const modelnet::SwarmSepManifest first = Manifest(1);
    std::string err;
    const std::string old_id = modelnet::SwarmManifestPoolId(first, err);
    BOOST_REQUIRE(!old_id.empty());
    BOOST_CHECK(modelnet::SwarmNextEpoch(first, first, err) == old_id);

    modelnet::SwarmObligationBook book;
    BOOST_CHECK(book.Add(old_id, "work-1", 7, err));
    BOOST_CHECK(!book.Add(old_id, "work-1", 7, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE_WORK");
    BOOST_CHECK_EQUAL(book.Atoms(old_id, "work-1"), 7);

    modelnet::SwarmSepManifest next = first;
    next.policy_epoch = 2;
    const std::string new_id = modelnet::SwarmNextEpoch(first, next, err);
    BOOST_REQUIRE(!new_id.empty());
    BOOST_CHECK(new_id != old_id);
    BOOST_CHECK_EQUAL(book.Atoms(old_id, "work-1"), 7);
    BOOST_CHECK_EQUAL(book.Atoms(new_id, "work-1"), 0);

    modelnet::SwarmSepManifest spend = first;
    spend.automatic_spend_atoms = "1";
    BOOST_CHECK(!modelnet::SwarmValidateManifest(spend, err));
    BOOST_CHECK_EQUAL(err, "AUTOMATIC_SPEND");
}

BOOST_AUTO_TEST_CASE(reward_ppm_must_sum_to_one_million)
{
    modelnet::SwarmRewardSplit split;
    split.rollout_ppm = 200000;
    split.negative_ppm = 100000;
    split.reproduction_ppm = 100000;
    split.evaluation_ppm = 200000;
    split.challenger_ppm = 100000;
    split.milestone_ppm = 300000;
    std::string err;
    BOOST_CHECK(modelnet::SwarmValidateSplit(split, err));
    BOOST_CHECK(!modelnet::SwarmWinnerTakeAll(split));
    BOOST_CHECK_EQUAL(modelnet::SwarmPayShare(1000000, 200000), 200000);

    split.milestone_ppm = 299999;
    BOOST_CHECK(!modelnet::SwarmValidateSplit(split, err));
    BOOST_CHECK_EQUAL(err, "PPM");

    modelnet::SwarmRewardSplit winner;
    winner.milestone_ppm = 1000000;
    BOOST_CHECK(modelnet::SwarmValidateSplit(winner, err));
    BOOST_CHECK(modelnet::SwarmWinnerTakeAll(winner));

    BOOST_CHECK(!modelnet::SwarmWorkCycle(true, false, true, true, true, true, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(modelnet::SwarmWorkCycle(true, true, true, true, true, true, err));
}

BOOST_AUTO_TEST_CASE(refund_is_signed_before_funding_and_payout_is_monotonic)
{
    modelnet::SwarmChannelTx tx;
    tx.capacity = 1000;
    tx.fee_reserve = 10;
    tx.refund_height = 1000;
    tx.sponsor_pubkey = Pubkey(0x21);
    tx.worker_pubkey = Pubkey(0x22);
    std::string err;
    BOOST_CHECK(!modelnet::SwarmNoteChannelFunding(tx, err));
    BOOST_CHECK_EQUAL(err, "REFUND_NOT_SIGNED");
    BOOST_CHECK(!tx.funded);

    BOOST_CHECK(modelnet::SwarmBuildRefund(tx, err));
    BOOST_CHECK(tx.refund_signed);
    BOOST_CHECK(!tx.funded);
    BOOST_REQUIRE_EQUAL(tx.refund.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(tx.refund.vout.size(), 1U);
    BOOST_CHECK_EQUAL(tx.refund.vin[0].prevout.n, 0U);
    const uint256& prev = tx.refund.vin[0].prevout.hash.ToUint256();
    BOOST_CHECK(std::all_of(prev.begin(), prev.end(), [](unsigned char b) { return b == 0x11; }));
    BOOST_CHECK_EQUAL(tx.refund.vout[0].nValue, static_cast<CAmount>(1000));
    int64_t locktime = 0;
    PQAlgorithm algo = PQAlgorithm::ML_DSA_44;
    std::vector<unsigned char> parsed;
    const std::vector<unsigned char> script(tx.refund.vout[0].scriptPubKey.begin(), tx.refund.vout[0].scriptPubKey.end());
    BOOST_CHECK(ParseP2MRRefundLeaf(script, locktime, algo, parsed));
    BOOST_CHECK_EQUAL(locktime, 1000);

    BOOST_CHECK(modelnet::SwarmNoteChannelFunding(tx, err));
    BOOST_CHECK(tx.funded);
    BOOST_CHECK(modelnet::SwarmBuildPayout(tx, 40, 100, tx.refund_height, err));
    BOOST_REQUIRE_EQUAL(tx.payout.vout.size(), 2U);
    BOOST_CHECK_EQUAL(tx.payout.vout[0].nValue, static_cast<CAmount>(40));
    BOOST_CHECK_EQUAL(tx.payout.vout[1].nValue, static_cast<CAmount>(950));
    BOOST_CHECK_EQUAL(tx.cumulative, 40);
    BOOST_CHECK(modelnet::SwarmClaimBeforeRefund(100, tx.refund_height));

    BOOST_CHECK(!modelnet::SwarmBuildPayout(tx, 39, 100, tx.refund_height, err));
    BOOST_CHECK_EQUAL(err, "DECREASING_PAYMENT");
    BOOST_CHECK_EQUAL(tx.cumulative, 40);

    BOOST_CHECK(!modelnet::SwarmBuildPayout(tx, 40, 100, tx.refund_height + 1, err));
    BOOST_CHECK_EQUAL(err, "EXPIRY_CHANGE");
    BOOST_CHECK_EQUAL(tx.refund_height, 1000);
}

BOOST_AUTO_TEST_CASE(remedy_script_is_a_hashlock_without_secp_penalty)
{
    const modelnet::SwarmRevocation prior = modelnet::SwarmNewRevocation(1, 0x44);
    modelnet::SwarmRevocation next = modelnet::SwarmNewRevocation(2, 0x45);
    modelnet::SwarmRevocation stale = prior;
    std::string err;
    BOOST_CHECK(modelnet::SwarmSupersede(stale, next, err));
    BOOST_CHECK(stale.released);

    const std::vector<unsigned char> secret_hash(32, 0x46);
    const std::vector<unsigned char> script = modelnet::SwarmRemedyScript(secret_hash, Pubkey(0x47));
    BOOST_CHECK(!script.empty());
    std::vector<unsigned char> parsed_hash;
    PQAlgorithm algo = PQAlgorithm::ML_DSA_44;
    std::vector<unsigned char> parsed_key;
    BOOST_CHECK(ParseP2MRHTLCSha256Leaf(script, parsed_hash, algo, parsed_key));

    const modelnet::SwarmRemedyReport report = modelnet::SwarmWatchState(1, 2, 100, 1000, 160, stale);
    BOOST_CHECK_EQUAL(report.action, "HASHLOCK_REMEDY");
    BOOST_CHECK(report.hashlock_remedy);
    BOOST_CHECK(!report.secp_penalty);

    const modelnet::SwarmRemedyReport quiet = modelnet::SwarmWatchState(1, 2, 100, 1000, 160, prior);
    BOOST_CHECK_EQUAL(quiet.action, "STALE_STATE_ALERT");
    BOOST_CHECK(!quiet.secp_penalty);
}

BOOST_AUTO_TEST_CASE(preimage_reuse_and_unliquid_forward_are_rejected)
{
    const std::vector<unsigned char> preimage(32, 0x61);
    modelnet::SwarmInvoice invoice;
    invoice.id = "inv-1";
    invoice.amount = 25;
    invoice.beneficiary = "worker";
    invoice.objective = "evaluation";
    invoice.route_id = "route-1";
    invoice.preimage_hash = Sha256Hex(preimage);
    std::string err;
    BOOST_CHECK(modelnet::SwarmBindPreimage(invoice, preimage, err));

    std::set<std::string> seen;
    BOOST_CHECK(modelnet::SwarmReusePreimage(seen, invoice.preimage_hash, err));
    BOOST_CHECK(!modelnet::SwarmReusePreimage(seen, invoice.preimage_hash, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!modelnet::SwarmForwardAllowed(true, 5, 10, 500, 100, 160, err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK(modelnet::SwarmRouteMargin(400, 200, 160, err));
    BOOST_CHECK(modelnet::SwarmStopNewWork(900, 1000, 160));
}

BOOST_AUTO_TEST_CASE(economy_boundaries_refuse_reuse_profit_share_and_open_inference)
{
    modelnet::SwarmCollateralBook book;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmSameCollateral(book, "pool-a", "pool-b", "txid:0", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(book.FirstPool("txid:0"), "pool-a");
    BOOST_CHECK(modelnet::SwarmSameCollateral(book, "pool-a", "pool-a", "txid:0", err));

    BOOST_CHECK(!modelnet::SwarmAcceptInstrument("profit-share", err));
    BOOST_CHECK_EQUAL(err, "PASSIVE_INSTRUMENT");
    BOOST_CHECK(modelnet::SwarmAcceptInstrument("work-payment", err));

    BOOST_CHECK(!modelnet::SwarmTaxOpenInference(true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_TAXABLE");

    BOOST_CHECK_EQUAL(modelnet::SwarmMassExit(100000, 8000, 24000000), 34);

    modelnet::SwarmFiatRecord fiat;
    fiat.usd = "10";
    fiat.converted = false;
    fiat.btx_atoms.clear();
    BOOST_CHECK(!modelnet::SwarmRecordFiat(fiat, err));
    BOOST_CHECK_EQUAL(err, "FIAT_NOT_FUNDED");
    BOOST_CHECK(!fiat.usd_is_balance);
    fiat.converted = true;
    fiat.btx_atoms = "500";
    BOOST_CHECK(modelnet::SwarmRecordFiat(fiat, err));
    BOOST_CHECK(!fiat.usd_is_balance);
    BOOST_CHECK_EQUAL(fiat.btx_atoms, "500");

    modelnet::SwarmMiningNote note;
    note.swarm_atoms_per_hour = 80;
    note.mining_atoms_per_hour = 30;
    note.hash_left_mining = true;
    const modelnet::SwarmMiningDisplacementResult mined = modelnet::SwarmMiningDisplacement(note);
    BOOST_CHECK_EQUAL(mined.advantage, 50);
    BOOST_CHECK(!mined.security_increased);
}

BOOST_AUTO_TEST_CASE(recovery_keeps_earned_atoms_and_does_not_pick_a_validator)
{
    modelnet::SwarmRecoverySnapshot snapshot;
    snapshot.pending_jobs = 2;
    snapshot.earned_atoms = 77;
    snapshot.channel_sequence = 4;
    snapshot.checkpoint_present = true;
    snapshot.payment_plane_present = true;
    snapshot.execution_plane_present = false;
    modelnet::SwarmRecoverySnapshot kept;
    std::string err;
    BOOST_CHECK(modelnet::SwarmCoordinatorLost(snapshot, kept, err));
    BOOST_CHECK_EQUAL(kept.earned_atoms, 77);
    BOOST_CHECK_EQUAL(kept.channel_sequence, 4);

    snapshot.checkpoint_present = false;
    BOOST_CHECK(!modelnet::SwarmCoordinatorLost(snapshot, kept, err));
    BOOST_CHECK_EQUAL(err, "RETAIN_CHECKPOINT");
    BOOST_CHECK_EQUAL(kept.earned_atoms, 77);

    BOOST_CHECK(!modelnet::SwarmObsoleteSettlement(3, 4, err));
    BOOST_CHECK_EQUAL(err, "STALE_SETTLEMENT");
    BOOST_CHECK_EQUAL(modelnet::SwarmWorkerDisconnected(77), 77);

    bool accepted = true;
    BOOST_CHECK(!modelnet::SwarmConflictingValidators(accepted, err));
    BOOST_CHECK(!accepted);
    BOOST_CHECK_EQUAL(err, "CONFLICT");

    BOOST_CHECK(modelnet::SwarmExpiryPressure(900, 1000, 160));
    const modelnet::SwarmRecoverySnapshot frozen = modelnet::SwarmReorgExit(snapshot);
    BOOST_CHECK(frozen.frozen);
    BOOST_CHECK_EQUAL(frozen.earned_atoms, 77);
}

BOOST_AUTO_TEST_SUITE_END()
