// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_close.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_close_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(economy_identity_sponsor_lots_and_the_remaining_refusals)
{
    const modelnet::SwarmL1Limits limits = modelnet::SwarmMainnetLimits();
    BOOST_CHECK_EQUAL(limits.target_spacing_seconds, 90);
    BOOST_CHECK_EQUAL(limits.max_block_serialized, 24000000u);
    BOOST_CHECK_EQUAL(limits.max_block_weight, 24000000u);
    BOOST_CHECK_EQUAL(limits.witness_scale, 1);
    BOOST_CHECK_EQUAL(limits.blocks_per_day, 960);
    BOOST_CHECK(!limits.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(modelnet::SwarmTargetElapsedSeconds(160), 14400);
    BOOST_CHECK_EQUAL(modelnet::SwarmTargetElapsedSeconds(6720), 604800);

    const std::string economy = modelnet::SwarmEconomyIdentity(std::string(96, 'a'));
    BOOST_CHECK_EQUAL(economy, modelnet::SwarmEconomyIdentity(std::string(96, 'a')));
    BOOST_CHECK(economy != modelnet::SwarmEconomyIdentity(std::string(96, 'b')));

    modelnet::SwarmSponsorPool pool;
    std::string err;
    const std::vector<unsigned char> sponsor_a(MLDSA44_PUBKEY_SIZE, 0x11);
    const std::vector<unsigned char> sponsor_b(MLDSA44_PUBKEY_SIZE, 0x12);
    const std::vector<unsigned char> claimant(MLDSA44_PUBKEY_SIZE, 0x22);
    const std::vector<unsigned char> hash(32, 0xab);
    modelnet::SwarmSponsorLot lot_a{"a", sponsor_a, claimant, hash, 500, 600, {}, {}};
    modelnet::SwarmSponsorLot lot_b{"b", sponsor_b, claimant, hash, 700, 250, {}, {}};
    BOOST_REQUIRE(modelnet::SwarmAddSponsorLot(pool, lot_a, err));
    BOOST_REQUIRE(modelnet::SwarmAddSponsorLot(pool, lot_b, err));
    BOOST_CHECK_EQUAL(pool.gross_atoms, 850);
    BOOST_CHECK(pool.lots[0].refund_script != pool.lots[1].refund_script);
    BOOST_CHECK(!modelnet::SwarmAmendSponsorRefund(pool, "a", 900, err));
    BOOST_CHECK_EQUAL(pool.lots[0].refund_height, 500);

    BOOST_CHECK(modelnet::SwarmAcceptWorkEvidence("SIGNED_WORK_RESULT", err));
    BOOST_CHECK(!modelnet::SwarmAcceptWorkEvidence("hour-claim", err));
    BOOST_CHECK_EQUAL(err, "NOT_CONTRIBUTION");
    BOOST_CHECK(!modelnet::SwarmAcceptWorkEvidence("gradient-claim", err));
    BOOST_CHECK(!modelnet::SwarmCertificateIsPayment());
    BOOST_CHECK(!modelnet::SwarmPreimageProvesWork());
    BOOST_CHECK_EQUAL(modelnet::SwarmChannelAssurance(), "CUMULATIVE_NOT_WORK_PROOF");

    const modelnet::SwarmOriginRecord imported = modelnet::SwarmImportOrigin("https://huggingface.co/org/model");
    const modelnet::SwarmOriginRecord published = modelnet::SwarmPublishBack("https://huggingface.co/org/model");
    BOOST_CHECK(!imported.is_lineage);
    BOOST_CHECK(!imported.exclusive);
    BOOST_CHECK(!published.is_lineage);

    const modelnet::SwarmSpecialistSignal signal = modelnet::SwarmOfferSpecialistSignal("distillation", err);
    BOOST_CHECK(signal.ok);
    BOOST_CHECK(!signal.replaces_general);

    const std::vector<unsigned char> script = modelnet::SwarmEvaluatorThreshold({sponsor_a, sponsor_b, claimant}, 2);
    BOOST_CHECK(!script.empty());
    BOOST_CHECK(modelnet::SwarmEvaluatorThreshold({sponsor_a}, 2).empty());

    modelnet::SwarmChannelMesh mesh;
    BOOST_REQUIRE(mesh.Open("ch", "tx:0", "pool-a", err));
    BOOST_REQUIRE(mesh.Reference("ch", "pool-b", err));
    BOOST_CHECK(!mesh.Open("ch2", "tx:0", "pool-c", err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    const modelnet::SwarmChannelUse* use = mesh.Find("ch");
    BOOST_REQUIRE(use != nullptr);
    BOOST_CHECK_EQUAL(use->owner_pool, "pool-a");
    BOOST_CHECK_EQUAL(use->referencing_pools.size(), 2U);

    modelnet::SwarmRevenueSplit revenue;
    BOOST_REQUIRE(modelnet::SwarmSplitRevenue(10000, 700000, 200000, 100000, revenue, err));
    BOOST_CHECK_EQUAL(revenue.compute_atoms, 7000);
    BOOST_CHECK_EQUAL(revenue.improvement_atoms, 2000);
    BOOST_CHECK_EQUAL(revenue.evaluation_atoms, 1000);
    BOOST_CHECK(!modelnet::SwarmSplitRevenue(10000, 1, 1, 1, revenue, err));
    BOOST_CHECK(modelnet::SwarmCommunityContinues(1));
    BOOST_CHECK(!modelnet::SwarmCommunityContinues(0));
}

BOOST_AUTO_TEST_SUITE_END()
