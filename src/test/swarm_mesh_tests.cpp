// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/sha256.h>
#include <modelnet/swarm_channel.h>
#include <modelnet/swarm_frontier.h>
#include <modelnet/swarm_paymesh.h>
#include <modelnet/swarm_records.h>
#include <modelnet/swarm_economy.h>
#include <modelnet/swarm_evolution.h>
#include <modelnet/swarm_execution.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_membership.h>
#include <modelnet/training_integer.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <set>

BOOST_FIXTURE_TEST_SUITE(swarm_mesh_tests, BasicTestingSetup)

namespace {

std::string Id(char c)
{
    return std::string(96, c);
}

modelnet::SwarmPeer Peer(const char* id, const char* domain, bool authorized, bool available, int64_t rtt)
{
    modelnet::SwarmPeer peer;
    peer.id = id;
    peer.domain = domain;
    peer.authorized = authorized;
    peer.available = available;
    peer.rtt_us = rtt;
    peer.bandwidth_bps = 1000;
    return peer;
}

void WriteFile(const fs::path& path, const std::string& body)
{
    std::ofstream out(path, std::ios::trunc | std::ios::binary);
    out << body;
}

} // namespace

BOOST_AUTO_TEST_CASE(neighborhood_roles_and_governor_follow_the_device)
{
    const std::vector<modelnet::SwarmPeer> peers = {
        Peer("a", "d1", true, true, 10), Peer("b", "d1", true, true, 20), Peer("c", "d2", true, true, 30),
        Peer("d", "d1", false, true, 1), Peer("e", "d1", true, true, 5), Peer("f", "d3", true, true, 100),
        Peer("g", "d4", true, true, 110),
    };
    const auto chosen = modelnet::SwarmNeighbors(peers);
    BOOST_REQUIRE_EQUAL(chosen.size(), 6U);
    BOOST_CHECK_EQUAL(chosen[0].id, "e");
    BOOST_CHECK_EQUAL(chosen[1].id, "a");
    BOOST_CHECK_EQUAL(chosen[2].id, "b");
    BOOST_CHECK_EQUAL(chosen[3].id, "c");
    BOOST_CHECK_EQUAL(chosen[4].id, "f");
    BOOST_CHECK_EQUAL(chosen[5].id, "g");

    modelnet::SwarmDevice device;
    const modelnet::SwarmRoles idle = modelnet::SwarmEligibleRoles(device);
    BOOST_CHECK(idle.observer);
    BOOST_CHECK(!idle.seeder);
    BOOST_CHECK(!idle.trainer);
    BOOST_CHECK(!idle.private_prompts);
    BOOST_CHECK_EQUAL(idle.automatic_spend_atoms, "0");
    const modelnet::SwarmBudget drained = modelnet::SwarmGovern(device, 4);
    BOOST_CHECK(drained.drained);
    BOOST_CHECK_EQUAL(drained.active_workers, 0);

    device.idle_contribution = true;
    device.slots = 2;
    device.cpu_threads = 4;
    device.vram_bytes = 1024;
    device.max_steps = 8;
    device.license_allows_training = true;
    const modelnet::SwarmRoles ready = modelnet::SwarmEligibleRoles(device);
    BOOST_CHECK(ready.seeder);
    BOOST_CHECK(ready.evaluator);
    BOOST_CHECK(ready.trainer);
    BOOST_CHECK_EQUAL(modelnet::SwarmGovern(device, 9).active_workers, 2);
    device.thermal_hot = true;
    BOOST_CHECK(!modelnet::SwarmEligibleRoles(device).trainer);
    BOOST_CHECK(modelnet::SwarmGovern(device, 2).drained);

    const std::string artifact = Id('b');
    const std::string model = Id('a');
    const std::string checkpoint = Id('d');
    const modelnet::SwarmJoin provisional = modelnet::SwarmJoinLineage(artifact, model, checkpoint, "", "");
    BOOST_CHECK(provisional.ok);
    BOOST_CHECK_EQUAL(provisional.visibility, "private");
    BOOST_CHECK(provisional.lineage_id != checkpoint);
    BOOST_CHECK(!modelnet::SwarmOriginIsLineage("https://huggingface.co/org/model"));
    BOOST_CHECK(modelnet::SwarmClassifyTimescale("kv") == modelnet::SwarmTimescale::Immediate);
    BOOST_CHECK(modelnet::SwarmClassifyTimescale("generation") == modelnet::SwarmTimescale::Long);
}

BOOST_AUTO_TEST_CASE(kv_pages_cohorts_and_the_reference_trainer)
{
    modelnet::SwarmKvConfig config;
    config.checkpoint = Id('a');
    config.architecture = Id('b');
    config.tokenizer = Id('c');
    config.runtime_build = Id('d');
    config.dtype = "F16";
    config.layout = "BHTD";
    config.attention_mask = "causal";
    config.position_encoding = "rope";
    config.quantization = "none";
    config.layers = 1;
    config.kv_heads = 1;
    config.head_dim = 1;
    std::string err;
    const std::string fp = modelnet::SwarmKvFingerprint(config, err);
    BOOST_REQUIRE(!fp.empty());
    modelnet::SwarmKvPage page;
    page.start = 0;
    page.end = 4;
    page.fingerprint = fp;
    page.expires_ms = 100;
    BOOST_CHECK_EQUAL(modelnet::SwarmAcceptKv(fp, {page}, 4, 50), "OK");
    page.fingerprint = "other";
    BOOST_CHECK_EQUAL(modelnet::SwarmAcceptKv(fp, {page}, 4, 50), "KV_MISMATCH");
    page.fingerprint = fp;
    page.finite = false;
    BOOST_CHECK_EQUAL(modelnet::SwarmAcceptKv(fp, {page}, 4, 50), "KV_NONFINITE");
    page.finite = true;
    BOOST_CHECK_EQUAL(modelnet::SwarmAcceptKv(fp, {page}, 4, 100), "CACHE_EXPIRED");
    page.end = 3;
    BOOST_CHECK_EQUAL(modelnet::SwarmAcceptKv(fp, {page}, 4, 50), "KV_INCOMPLETE");

    const modelnet::SwarmPlacement place = modelnet::SwarmChooseExecution(100, 10, 0, 1000, 1000, 5, 0, 0);
    BOOST_CHECK(place.ok);
    BOOST_CHECK(!place.measured_benchmark);
    BOOST_CHECK_EQUAL(place.choice, "ROUTE_TO_OWNER");
    BOOST_CHECK_EQUAL(place.recompute_ms, 100);
    BOOST_CHECK_EQUAL(place.route_ms, 15);
    modelnet::SwarmPlacement transfer = place;
    transfer.choice = "TRANSFER_KV";
    const modelnet::SwarmPlacement missing = modelnet::SwarmExecutePlacement(transfer, false);
    BOOST_CHECK(!missing.ok);
    BOOST_CHECK_EQUAL(missing.code, "ENGINE_ABSENT");
    BOOST_CHECK(!missing.bytes_moved);
    const modelnet::SwarmPlacement present = modelnet::SwarmExecutePlacement(transfer, true);
    BOOST_CHECK(present.ok);
    BOOST_CHECK_EQUAL(present.code, "LOCAL");
    BOOST_CHECK(!present.bytes_moved);

    modelnet::SwarmCohort left{"ckpt", "recipe", true};
    modelnet::SwarmCohort right{"ckpt", "other", true};
    BOOST_CHECK(!modelnet::SwarmMayAverage(left, right));
    right.recipe = "recipe";
    BOOST_CHECK(modelnet::SwarmMayAverage(left, right));
    right.compatible = false;
    BOOST_CHECK(!modelnet::SwarmMayAverage(left, right));

    modelnet::IntegerTrainer trainer;
    BOOST_REQUIRE(trainer.Step(err));
    modelnet::IntegerState resumed;
    BOOST_CHECK(modelnet::SwarmResumeReference(trainer.State(), resumed, err));
    modelnet::IntegerState broken = trainer.State();
    broken.weight += 1;
    BOOST_CHECK(!modelnet::SwarmResumeReference(broken, resumed, err));
    BOOST_CHECK(!modelnet::SwarmCandidateId(Id('a'), Id('b'), Id('c'), "n1").empty());
    std::set<std::string> quarantine;
    modelnet::SwarmQuarantine(quarantine, "deadbeef");
    BOOST_CHECK(modelnet::SwarmIsQuarantined(quarantine, "deadbeef"));
}

BOOST_AUTO_TEST_CASE(evolution_matches_the_reference_vectors)
{
    const modelnet::SwarmBound bound = modelnet::SwarmPairedBound({10, 30, 5, 5}, 50000, 20);
    BOOST_REQUIRE(bound.ok);
    BOOST_CHECK_EQUAL(bound.n, 50);
    BOOST_CHECK_EQUAL(bound.delta_ppm, 500000);
    BOOST_CHECK_EQUAL(bound.lower_ppm, 10450);
    BOOST_CHECK_EQUAL(bound.upper_ppm, 989550);
    BOOST_CHECK_EQUAL(bound.method, "PAIRED_HOEFFDING_BONFERRONI_V1");

    modelnet::SwarmPolicy policy;
    policy.suite_id = "suite";
    policy.holdout_commitment = "hold";
    policy.alpha_ppm = 50000;
    policy.max_trials = 20;
    policy.min_examples = 50;
    policy.min_gain_ppm = 1;
    policy.max_regression_ppm["safety"] = 0;
    modelnet::SwarmReport report;
    report.suite_id = "suite";
    report.holdout_commitment = "hold";
    report.counts = {10, 30, 5, 5};
    report.regressions_ppm["safety"] = 0;
    report.reproducible = true;
    modelnet::SwarmBound qualified;
    std::string err;
    BOOST_CHECK(modelnet::SwarmQualify(report, policy, qualified, err));
    report.safety_regression = true;
    BOOST_CHECK(!modelnet::SwarmQualify(report, policy, qualified, err));
    BOOST_CHECK_EQUAL(err, "SAFETY_REGRESSION");

    const std::vector<modelnet::SwarmCandidate> candidates = {
        {"a", "science", 3, 2, 1},
        {"b", "math", 5, 9, 1},
        {"c", "code", 4, 1, 1},
    };
    const auto slots = modelnet::SwarmAllocate(candidates, 5, 20);
    BOOST_CHECK_EQUAL(slots.at("a"), 1);
    BOOST_CHECK_EQUAL(slots.at("b"), 2);
    BOOST_CHECK_EQUAL(slots.at("c"), 2);

    std::vector<modelnet::SwarmEvaluator> panel;
    for (int i = 0; i < 5; ++i) {
        modelnet::SwarmEvaluator row;
        row.evaluator = "e" + std::to_string(i);
        row.domain = i < 2 ? "d0" : (i < 4 ? "d1" : "d2");
        row.author = "author";
        panel.push_back(row);
    }
    BOOST_CHECK(modelnet::SwarmQuorum(panel, 5, 3, "author", err));
    panel[0].evaluator = "author";
    BOOST_CHECK(!modelnet::SwarmQuorum(panel, 5, 3, "author", err));
    panel[0].evaluator = "e0";
    BOOST_CHECK(!modelnet::SwarmQuorum(panel, 5, 4, "author", err));
    BOOST_CHECK(!modelnet::SwarmChallengerAffectsFitness(false));
    BOOST_CHECK(modelnet::SwarmChallengerAffectsFitness(true));

    modelnet::SwarmChannel general{"general/stable", "parent", "", "", "IDLE", 1};
    modelnet::SwarmChannel code{"code/stable", "code-parent", "", "", "IDLE", 1};
    BOOST_REQUIRE(modelnet::SwarmStage(code, "code-child", 2, true, err));
    BOOST_REQUIRE(modelnet::SwarmCanary(code, 3, err));
    BOOST_REQUIRE(modelnet::SwarmActivate(code, 4, err));
    BOOST_CHECK_EQUAL(code.active, "code-child");
    BOOST_CHECK_EQUAL(code.previous, "code-parent");
    BOOST_CHECK_EQUAL(general.active, "parent");
    BOOST_REQUIRE(modelnet::SwarmRollback(code, 5, err));
    BOOST_CHECK_EQUAL(code.active, "code-parent");
    BOOST_CHECK_EQUAL(general.active, "parent");
}

BOOST_AUTO_TEST_CASE(pools_channels_and_membership_do_not_spend)
{
    modelnet::SwarmPoolCommit commit;
    commit.chain = std::string(64, '1');
    commit.lineage = std::string(96, 'a');
    for (int i = 0; i < 48; ++i) commit.lineage.replace(static_cast<size_t>(i * 2), 2, "ab");
    commit.nonce = "n1";
    commit.objective = std::string(96, 'c');
    for (int i = 0; i < 48; ++i) commit.objective.replace(static_cast<size_t>(i * 2), 2, "cd");
    commit.policy = std::string(96, 'e');
    for (int i = 0; i < 48; ++i) commit.policy.replace(static_cast<size_t>(i * 2), 2, "ef");
    BOOST_CHECK_EQUAL(modelnet::SwarmPoolId(commit),
                      "f9186c44a155500542055e7aaf61d0ce6478e82e195704a19fd46549d7f09e8e03a920b712d26b18e6dad96ab4a0a6f7");

    modelnet::SwarmLedger ledger;
    std::string err;
    const std::string pool = ledger.CreatePool(commit, err);
    BOOST_REQUIRE(!pool.empty());
    const modelnet::SwarmBalances unfunded = ledger.Balances(pool);
    BOOST_CHECK(!unfunded.holds_money);
    BOOST_CHECK_EQUAL(unfunded.status, "UNFUNDED");
    BOOST_CHECK_EQUAL(unfunded.confirmed_backing_atoms, "0");
    BOOST_REQUIRE(ledger.ObserveBacking(pool, "tx:0", 1000, 10, "script", 1, err));
    BOOST_CHECK(ledger.Balances(pool).holds_money);
    BOOST_CHECK_EQUAL(ledger.Balances(pool).confirmed_backing_atoms, "1000");
    BOOST_REQUIRE(ledger.PledgeChannel(pool, "tx:0", err));
    BOOST_CHECK_EQUAL(ledger.Balances(pool).confirmed_backing_atoms, "0");
    BOOST_CHECK_EQUAL(ledger.Balances(pool).immediately_payable_l2_atoms, "0");
    BOOST_CHECK(!ledger.FundChannel(pool, "tx:0", false, err));
    BOOST_REQUIRE(ledger.FundChannel(pool, "tx:0", true, err));
    BOOST_CHECK_EQUAL(ledger.Balances(pool).immediately_payable_l2_atoms, "990");
    BOOST_CHECK_EQUAL(ledger.Balances(pool).confirmed_backing_atoms, "0");
    BOOST_CHECK(ledger.Conserved(pool));

    BOOST_REQUIRE(ledger.ObserveBacking(pool, "tx:1", 500, 0, "escrow", 1, err));
    const std::string actor = Id('a');
    const std::string worker = Id('b');
    const std::string mandate = ledger.GrantMandate(pool, actor, 400, 100, {worker}, "once", err);
    BOOST_REQUIRE(!mandate.empty());
    std::string reservation;
    BOOST_REQUIRE(ledger.Reserve(mandate, actor, "work-1", worker, 100, "terms", false, reservation, err));
    BOOST_CHECK(ledger.Reserve(mandate, actor, "work-1", worker, 100, "terms", false, reservation, err));
    BOOST_REQUIRE(ledger.AcceptWork(reservation, Id('c'), err));
    BOOST_CHECK(!ledger.Cancel(reservation, err));
    BOOST_REQUIRE(ledger.Invalidate("tx:1", "REORG", err));
    BOOST_CHECK(ledger.EarnedSurvives(pool, reservation));
    BOOST_CHECK_EQUAL(ledger.Balances(pool).status, "FROZEN");

    modelnet::SwarmFiatQuote quote;
    quote.usd = "10";
    std::string atoms;
    BOOST_CHECK(!modelnet::SwarmAcceptFiat(quote, atoms, err));
    quote.converted = true;
    quote.btx_atoms = "100";
    BOOST_CHECK(modelnet::SwarmAcceptFiat(quote, atoms, err));
    modelnet::SwarmOpportunity offer;
    BOOST_CHECK(!modelnet::SwarmRankOpportunity(offer).ok);
    offer.verified_backing = true;
    offer.demonstrated_payment = true;
    offer.signed_terms = true;
    offer.reward_per_hour = 80;
    offer.accept_ppm = 800000;
    offer.expense_per_hour = 10;
    offer.mining_alternative = 25;
    BOOST_CHECK_EQUAL(modelnet::SwarmRankOpportunity(offer).advantage, 29);

    const std::vector<unsigned char> sponsor(MLDSA44_PUBKEY_SIZE, 0x11);
    const std::vector<unsigned char> claimant(MLDSA44_PUBKEY_SIZE, 0x22);
    const std::vector<unsigned char> hash(32, 0xab);
    modelnet::SwarmHtlcLot lot = modelnet::SwarmBuildHtlcLot(sponsor, claimant, hash, 500);
    BOOST_REQUIRE(lot.ok);
    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm algo = PQAlgorithm::ML_DSA_44;
    int64_t locktime = 0;
    BOOST_CHECK(ParseP2MRHTLCSha256Leaf(lot.claim_script, parsed_hash, algo, parsed_key));
    BOOST_CHECK(parsed_hash == hash);
    BOOST_CHECK(ParseP2MRRefundLeaf(lot.refund_script, locktime, algo, parsed_key));
    BOOST_CHECK_EQUAL(locktime, 500);
    BOOST_CHECK(parsed_key == sponsor);
    BOOST_CHECK(!modelnet::SwarmAmendHtlcRefund(lot, 900, claimant));
    BOOST_CHECK_EQUAL(lot.refund_height, 500);

    modelnet::SwarmMonotonic channel;
    channel.id = "ch";
    channel.payer = "sponsor";
    channel.recipient = "worker";
    channel.capacity = 100;
    channel.fee_reserve = 5;
    channel.refund_height = 1000;
    channel.spend_key_present = true;
    BOOST_CHECK(!modelnet::SwarmSignRefund(channel, err));
    channel.spend_key_present = false;
    BOOST_CHECK(!modelnet::SwarmNoteFunding(channel, 1, err));
    BOOST_REQUIRE(modelnet::SwarmSignRefund(channel, err));
    BOOST_REQUIRE(modelnet::SwarmNoteFunding(channel, 1, err));
    BOOST_CHECK(!modelnet::SwarmAcceptOffer(channel, 1, 10, 900, err));
    BOOST_CHECK_EQUAL(err, "CHANNEL_DRAINING");
    BOOST_REQUIRE(modelnet::SwarmAcceptOffer(channel, 1, 40, 100, err));
    BOOST_CHECK(!modelnet::SwarmAcceptOffer(channel, 2, 30, 100, err));
    BOOST_CHECK_EQUAL(err, "DECREASING_PAYMENT");
    BOOST_CHECK_EQUAL(channel.cumulative, 40);

    modelnet::SwarmRouteEdge first{"ab", "alice", "router", 1000, 0, 0, 160, true};
    modelnet::SwarmRouteEdge second{"rb", "router", "worker", 1000, 5, 0, 160, true};
    const modelnet::SwarmRoute routed = modelnet::SwarmRoutePayment({first, second}, "alice", "worker", 100, 500, 10, 1000000, 5, 6720);
    BOOST_REQUIRE(routed.ok);
    BOOST_CHECK_EQUAL(routed.send_atoms, 105);
    BOOST_CHECK_EQUAL(routed.fee_atoms, 5);
    BOOST_CHECK_EQUAL(routed.hops.size(), 2U);

    modelnet::SwarmConditional box;
    box.capacity = 100;
    const std::vector<unsigned char> preimage(32, 0x07);
    unsigned char preimage_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(preimage_hash);
    const std::string payment_hash = HexStr(Span<const unsigned char>(preimage_hash, CSHA256::OUTPUT_SIZE));
    BOOST_REQUIRE(modelnet::SwarmLockPayment(box, "p1", 40, payment_hash, 50, 10, err));
    BOOST_CHECK(!modelnet::SwarmLockPayment(box, "p1", 40, payment_hash, 50, 10, err));
    BOOST_REQUIRE(modelnet::SwarmResolvePayment(box, "p1", preimage, 20, err));
    BOOST_CHECK(modelnet::SwarmPaymentsConserved(box));

    const modelnet::SwarmWatch stale = modelnet::SwarmWatchtower(1, 2, 10, 1000, 160, false);
    BOOST_CHECK_EQUAL(stale.action, "STALE_STATE_ALERT");
    BOOST_CHECK(!stale.secp_penalty);
    const modelnet::SwarmWatch remedy = modelnet::SwarmWatchtower(1, 2, 10, 1000, 160, true);
    BOOST_CHECK_EQUAL(remedy.action, "HASHLOCK_REMEDY");
    BOOST_CHECK(remedy.hashlock_remedy);
    BOOST_CHECK(!remedy.secp_penalty);

    modelnet::SwarmBinding binding{"principal", "realm", "observer", 100, false, true};
    BOOST_CHECK(!modelnet::SwarmAuthorize(binding, 10, "observer", err));
    binding.spend_key_present = false;
    BOOST_CHECK(modelnet::SwarmAuthorize(binding, 10, "observer", err));
    std::set<std::string> nonces;
    BOOST_CHECK(modelnet::SwarmAcceptInvitation(nonces, "bob", "n1", true, false, err));
    BOOST_CHECK(!modelnet::SwarmAcceptInvitation(nonces, "bob", "n1", true, false, err));
    BOOST_CHECK(!modelnet::SwarmAcceptInvitation(nonces, "bob", "n2", true, true, err));
    BOOST_CHECK(modelnet::SwarmCommitteeUnchanged({"a", "b"}, {"b", "a"}));
    BOOST_CHECK(!modelnet::SwarmCommitteeUnchanged({"a"}, {"a", "b"}));
    const modelnet::SwarmPublication published = modelnet::SwarmPublishGraduation(true);
    BOOST_CHECK(published.quality_graduated);
    BOOST_CHECK(!published.realm_promoted);
    BOOST_CHECK(!published.exact_replay_admitted);
}

BOOST_AUTO_TEST_CASE(coordinator_exit_keeps_the_checkpoint_and_the_mesh_state)
{
    const fs::path src = m_args.GetDataDirBase() / "swarm_journey_src";
    const fs::path dst = m_args.GetDataDirBase() / "swarm_journey_dst";
    std::error_code ec;
    fs::remove_all(src, ec);
    fs::remove_all(dst, ec);
    fs::create_directories(src / "swarm");
    WriteFile(src / "checkpoint.bin", "checkpoint-bytes");
    WriteFile(src / "observers.json", "{\"subscriptions\":[]}\n");
    WriteFile(src / "channel-state.json", "{\"sequence\":4,\"cumulative\":\"40\"}\n");
    WriteFile(src / "obligations.json", "{\"earned\":\"100\"}\n");
    WriteFile(src / "swarm" / "peers.json",
              "{\"peers\":[{\"id\":\"e\",\"domain\":\"d1\",\"authorized\":true,\"available\":true,\"rtt_us\":5},"
              "{\"id\":\"a\",\"domain\":\"d1\",\"authorized\":true,\"available\":true,\"rtt_us\":10}]}");
    WriteFile(src / "swarm" / "device.json", "{\"idle_contribution\":false,\"slots\":1,\"cpu_threads\":1,\"vram_bytes\":0,\"max_steps\":1}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(src, err));
    std::ifstream mesh_in(src / "swarm" / "mesh-state.json");
    std::string mesh((std::istreambuf_iterator<char>(mesh_in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(mesh));
    BOOST_CHECK_EQUAL(root["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(root["drained"].get_bool());
    BOOST_REQUIRE(modelnet::SwarmRetain(src, dst, err));
    std::ifstream kept(dst / "checkpoint.bin");
    std::string body((std::istreambuf_iterator<char>(kept)), std::istreambuf_iterator<char>());
    BOOST_CHECK_EQUAL(body, "checkpoint-bytes");
    BOOST_CHECK(fs::exists(dst / "channel-state.json"));
    BOOST_CHECK(fs::exists(dst / "obligations.json"));
    fs::remove_all(src, ec);
    fs::remove_all(dst, ec);
}

BOOST_AUTO_TEST_CASE(mesh_state_compare_keeps_its_meaning)
{
    const fs::path dir = m_args.GetDataDirBase() / "swarm_key_order";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir / "swarm");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    const fs::path mesh = dir / "swarm" / "mesh-state.json";
    std::ifstream in(mesh);
    const std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    UniValue root;
    BOOST_REQUIRE(root.read(body));
    // The same document with its keys reversed and the first key repeated at the
    // end: still the same document (the first value wins), so it is not rewritten.
    const std::vector<std::string>& keys = root.getKeys();
    std::string reordered = "{";
    for (size_t i = keys.size(); i-- > 0;) reordered += "\"" + keys[i] + "\":" + root.getValues()[i].write() + ",";
    reordered += "\"" + keys[0] + "\":\"later\"}";
    WriteFile(mesh, reordered);
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    std::ifstream again(mesh);
    BOOST_CHECK_EQUAL(std::string((std::istreambuf_iterator<char>(again)), std::istreambuf_iterator<char>()), reordered);
    // A different value is a different document.
    WriteFile(mesh, "{\"automatic_spend_atoms\":\"1\"}");
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    std::ifstream fresh(mesh);
    BOOST_CHECK_EQUAL(std::string((std::istreambuf_iterator<char>(fresh)), std::istreambuf_iterator<char>()), body);
    fs::remove_all(dir, ec);
}

BOOST_AUTO_TEST_CASE(coding_lineage_survives_the_coordinator)
{
    const std::string lineage = Id('a');
    const std::string parent = Id('b');
    const std::string recipe = Id('c');
    const std::string weights = Id('d');
    std::string err;
    modelnet::ModelLineage family;
    BOOST_REQUIRE(modelnet::SwarmMakeLineage("", {}, "decoder", "apache-2.0", true, family, err));
    BOOST_CHECK(!modelnet::SwarmLineageAllowsTraining(family, false));
    BOOST_CHECK(modelnet::SwarmLineageAllowsTraining(family, true));

    modelnet::SwarmAcquireState state;
    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Verify, state, true, true, false, false, false, err);
    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Join, state, true, true, false, false, false, err);
    BOOST_CHECK(state.joined);
    BOOST_CHECK(!state.private_prompts);
    BOOST_CHECK(modelnet::SwarmContributionKind("synthetic_trajectory", err));
    BOOST_CHECK(!modelnet::SwarmContributionKind("prompt", err));

    modelnet::SwarmCandidateRecord first = modelnet::SwarmMakeCandidateRecord(parent, recipe, weights, "n1", "prov", err);
    modelnet::SwarmCandidateRecord second = modelnet::SwarmMakeCandidateRecord(parent, recipe, Id('e'), "n2", "prov", err);
    BOOST_REQUIRE(!first.id.empty());
    BOOST_REQUIRE(first.id != second.id);
    modelnet::SwarmHeadLog heads;
    modelnet::SwarmPublishHead(heads, {"general/stable", parent, 1});
    modelnet::SwarmPublishHead(heads, {"code/stable", first.id, 2});
    BOOST_CHECK_EQUAL(modelnet::SwarmVisibleHeads(heads).size(), 2U);
    const modelnet::SwarmGradEffect graduated = modelnet::SwarmGraduate(true);
    BOOST_CHECK(graduated.quality_graduated);
    BOOST_CHECK(!graduated.realm_promoted);
    BOOST_CHECK(!graduated.exact_replay_admitted);

    modelnet::SwarmRecoverySnapshot snap;
    snap.pending_jobs = 1;
    snap.earned_atoms = 40;
    snap.channel_sequence = 4;
    snap.checkpoint_present = true;
    snap.payment_plane_present = true;
    snap.execution_plane_present = false;
    modelnet::SwarmRecoverySnapshot kept;
    BOOST_REQUIRE(modelnet::SwarmCoordinatorLost(snap, kept, err));
    BOOST_CHECK_EQUAL(kept.earned_atoms, 40);
    BOOST_CHECK_EQUAL(kept.channel_sequence, 4);
    (void)lineage;
}

BOOST_AUTO_TEST_CASE(oversized_swarm_inputs_are_not_read)
{
    const fs::path dir = m_args.GetDataDirBase() / "swarm_oversized";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir / "swarm");
    const std::string pad(1024 * 1024, ' ');
    std::string err;
    WriteFile(dir / "swarm" / "device.json", "{\"idle_contribution\":false}" + pad);
    BOOST_CHECK(!modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_CHECK_EQUAL(err, "DEVICE_READ");
    WriteFile(dir / "swarm" / "device.json", "{\"idle_contribution\":false}");
    WriteFile(dir / "swarm" / "peers.json", "{\"peers\":[]}" + pad);
    BOOST_CHECK(!modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_CHECK_EQUAL(err, "PEERS_READ");
    WriteFile(dir / "swarm" / "peers.json", "{\"peers\":[]}");
    WriteFile(dir / "swarm" / "mesh-state.json", "{\"drained\":true}" + pad);
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    BOOST_CHECK_LT(fs::file_size(dir / "swarm" / "mesh-state.json"), 4096U);
    fs::remove_all(dir, ec);
}

BOOST_AUTO_TEST_SUITE_END()
