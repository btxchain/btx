// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_close.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_live.h>
#include <modelnet/swarm_node.h>
#include <modelnet/swarm_paymesh.h>
#include <pqkey.h>
#include <psbt.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_node_tests, BasicTestingSetup)

namespace {

std::string Id(char c)
{
    return std::string(96, c);
}

fs::path Scratch()
{
    const fs::path path = fs::temp_directory_path() / ("btx-swarm-node-" + std::to_string(::getpid()));
    fs::remove_all(path);
    fs::create_directories(path);
    return path;
}

void Write(const fs::path& path, const std::string& body)
{
    std::ofstream file(path, std::ios::trunc);
    file << body;
}

std::vector<unsigned char> Key(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

} // namespace

BOOST_AUTO_TEST_CASE(default_offer_needs_no_flag_and_no_gpu)
{
    const modelnet::SwarmBuiltinOffer offer = modelnet::SwarmDefaultOffer();
    BOOST_CHECK(offer.seed_public);
    BOOST_CHECK(!offer.cpu_evaluate);
    BOOST_CHECK(!offer.gpu_train);
    BOOST_CHECK(!offer.private_prompts);
    BOOST_CHECK(!offer.startup_flag);
    BOOST_CHECK_EQUAL(offer.cpu_threads, 0);
    BOOST_CHECK(offer.hardware_threads >= 1);
    BOOST_CHECK_EQUAL(offer.vram_bytes, 0);
    BOOST_CHECK_EQUAL(offer.automatic_spend_atoms, "0");

    const fs::path dir = Scratch();
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(dir, err));
    std::ifstream in(dir / "swarm" / "mesh-state.json");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK(root["observer"].get_bool());
    BOOST_CHECK(root["seeder"].get_bool());
    BOOST_CHECK(!root["evaluator"].get_bool());
    BOOST_CHECK(!root["trainer"].get_bool());
    BOOST_CHECK(!root["drained"].get_bool());
    BOOST_CHECK(root["hardware_threads"].getInt<int>() >= 1);
    BOOST_CHECK_EQUAL(root["automatic_spend_atoms"].get_str(), "0");
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(catalog_join_splits_full_precision_from_four_bit)
{
    const fs::path dir = Scratch();
    Write(dir / "catalog.json",
          std::string("{\"models\":[") +
              "{\"model_id\":\"" + Id('1') + "\",\"artifact_id\":\"" + Id('a') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"visibility\":\"public\","
              "\"quantization\":\"full\",\"checkpoint_id\":\"ckpt\",\"recipe\":\"recipe\"}," +
              "{\"model_id\":\"" + Id('2') + "\",\"artifact_id\":\"" + Id('b') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"visibility\":\"public\","
              "\"quantization\":\"4bit\",\"checkpoint_id\":\"ckpt\",\"recipe\":\"recipe\"}" +
              "]}");
    fs::create_directories(dir / "swarm");
    Write(dir / "swarm" / "lineage-mappings.json",
          "{\"" + Id('a') + "\":{\"lineage_id\":\"" + Id('c') + "\",\"visibility\":\"public\"}," +
          "\"" + Id('b') + "\":{\"lineage_id\":\"" + Id('c') + "\",\"visibility\":\"public\"}}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    std::ifstream in(dir / "swarm" / "contribution.json");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK(!root["startup_flag"].get_bool());
    BOOST_CHECK(root["seed_public"].get_bool());
    BOOST_CHECK(!root["gpu_train"].get_bool());
    BOOST_CHECK_EQUAL(root["automatic_spend_atoms"].get_str(), "0");
    const UniValue& models = root["models"];
    BOOST_REQUIRE_EQUAL(models.size(), 2U);
    BOOST_CHECK_EQUAL(models[0]["acquire"].get_str(), "joined");
    BOOST_CHECK(models[0]["family"].get_bool());
    BOOST_CHECK(models[0]["cohort"].get_bool());
    BOOST_CHECK(!models[0]["kv_share"].get_bool());
    BOOST_CHECK_EQUAL(models[0]["checkpoint_id"].get_str(), "ckpt");
    BOOST_CHECK_EQUAL(models[0]["recipe"].get_str(), "recipe");
    BOOST_CHECK(models[0]["seed"].get_bool());
    BOOST_CHECK(!models[0]["private_acquire"].get_bool());
    BOOST_CHECK(models[1]["family"].get_bool());
    BOOST_CHECK(!models[1]["cohort"].get_bool());
    BOOST_CHECK(!models[1]["kv_share"].get_bool());
    BOOST_CHECK_EQUAL(models[1]["checkpoint_id"].get_str(), "ckpt");
    BOOST_CHECK_EQUAL(models[1]["recipe"].get_str(), "recipe");
    const std::string economy = modelnet::SwarmEconomyIdentity(models[0]["lineage_id"].get_str());
    BOOST_CHECK_EQUAL(models[0]["economy_id"].get_str(), economy);

    const modelnet::SwarmCohortDecision mismatched =
        modelnet::SwarmAssignCohort("full", "ckpt-a", "recipe", "ckpt-b", "recipe");
    BOOST_CHECK(mismatched.family);
    BOOST_CHECK(!mismatched.cohort);
    BOOST_CHECK(!mismatched.kv_share);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(presence_verifies_and_rejects_replay)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    modelnet::SwarmPresence presence;
    presence.peer_id = "peer-a";
    presence.endpoint = "127.0.0.1:8333";
    presence.capabilities = {"seed", "evaluate"};
    presence.trust_domain = "lab";
    presence.expiry_ms = 5'000;
    const uint256 hash = modelnet::SwarmPresenceHash(presence);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    presence.pubkey = key.GetPubKey();
    presence.signature_hex = HexStr(sig);
    std::string err;
    BOOST_CHECK(modelnet::SwarmAcceptPresence(presence, 1'000, err));

    presence.claims_checkpoint_only = true;
    BOOST_CHECK(!modelnet::SwarmAcceptPresence(presence, 1'000, err));
    BOOST_CHECK_EQUAL(err, "CHECKPOINT_CLAIM_IS_NOT_TRUST");
    presence.claims_checkpoint_only = false;

    const fs::path dir = Scratch();
    BOOST_REQUIRE(modelnet::SwarmNotePresence(dir, presence, 1'000, err));
    BOOST_CHECK(!modelnet::SwarmNotePresence(dir, presence, 1'000, err));
    BOOST_CHECK_EQUAL(err, "PRESENCE_REPLAY");
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(funding_refund_and_worker_redeem_stay_unbroadcast)
{
    std::string err;
    modelnet::SwarmFundingBundle bundle;
    BOOST_REQUIRE(modelnet::SwarmBuildFunding(Key(0x11), Key(0x22), 10000, 500, bundle, err));
    BOOST_CHECK(bundle.refund_bound);
    BOOST_CHECK(bundle.funded);
    BOOST_CHECK(bundle.refund.vin[0].prevout.hash == bundle.funding.GetHash());
    PartiallySignedTransaction psbt;
    BOOST_REQUIRE(modelnet::SwarmRefundPsbt(bundle, psbt, err));
    BOOST_CHECK(psbt.tx->vin[0].prevout.hash == bundle.funding.GetHash());

    CMutableTransaction payout;
    BOOST_REQUIRE(modelnet::SwarmBuildWorkerRedeem(bundle.funding.GetHash(), 10000, 1000, 4000, 100, 500, Key(0x22),
                                                   Key(0x11), payout, err));
    BOOST_CHECK(payout.vin[0].prevout.hash == bundle.funding.GetHash());
    BOOST_CHECK_EQUAL(payout.vout[0].nValue, 4000);
    BOOST_CHECK_EQUAL(payout.vout[1].nValue, 6000);
    BOOST_CHECK(!modelnet::SwarmBuildWorkerRedeem(bundle.funding.GetHash(), 10000, 4000, 3000, 100, 500, Key(0x22),
                                                   Key(0x11), payout, err));
    BOOST_CHECK_EQUAL(err, "DECREASING_PAYMENT");
    BOOST_CHECK(!modelnet::SwarmBuildWorkerRedeem(bundle.funding.GetHash(), 10000, 1000, 4000, 340, 500, Key(0x22),
                                                   Key(0x11), payout, err));
    BOOST_CHECK_EQUAL(err, "EXPIRY_MARGIN");

    const uint256 claimant = modelnet::SwarmPresenceHash(modelnet::SwarmPresence{});
    const std::vector<unsigned char> release =
        modelnet::SwarmCtvRelease(claimant, 2, {Key(1), Key(2), Key(3)}, err);
    BOOST_CHECK(!release.empty());

    CMutableTransaction parent;
    CMutableTransaction child;
    modelnet::SwarmClaimFees fees;
    BOOST_REQUIRE(modelnet::SwarmFeeBump(1000, 100, 50, parent, child, fees, err));
    BOOST_CHECK(!fees.wall_clock_is_confirmation);
    BOOST_CHECK_EQUAL(fees.claim_fee, 100);
    BOOST_CHECK(child.vin[0].prevout.hash == parent.GetHash());
}

BOOST_AUTO_TEST_CASE(route_rank_lease_license_and_holdout)
{
    std::vector<bool> held{true, true, true};
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmReleaseUpstream(held, 2, err));
    BOOST_CHECK(!held[0]);
    BOOST_CHECK(!held[1]);
    BOOST_CHECK(!held[2]);
    BOOST_CHECK_EQUAL(modelnet::SwarmIncomingSlack(3, 160), 480);

    modelnet::SwarmFullCost cost;
    cost.reward_per_hour = 80;
    cost.accept_ppm = 800000;
    cost.expense = 10;
    cost.mining = 25;
    cost.depreciation = 2;
    cost.idle = 3;
    cost.duration = 4;
    cost.settlement_fee = 5;
    cost.fx_risk = 6;
    cost.backing_verified = true;
    cost.payment_demonstrated = true;
    cost.terms_signed = true;
    int64_t net = 0;
    BOOST_REQUIRE(modelnet::SwarmRankFull(cost, net, err));
    BOOST_CHECK_EQUAL(net, 9);
    cost.terms_signed = false;
    BOOST_CHECK(!modelnet::SwarmRankFull(cost, net, err));
    BOOST_CHECK_EQUAL(err, "UNTRUSTED");

    BOOST_CHECK(modelnet::SwarmLeaseIsland("ckpt", "recipe", "ckpt", "recipe", err));
    BOOST_CHECK(!modelnet::SwarmLeaseIsland("ckpt", "recipe", "other", "recipe", err));
    BOOST_CHECK_EQUAL(err, "LEASE_INCOMPATIBLE");

    modelnet::SwarmGrants grants;
    grants.download = true;
    BOOST_CHECK(!modelnet::SwarmGrantAllowsTraining(grants));
    BOOST_CHECK(!modelnet::SwarmGrantAllowsRedistribution(grants));
    grants.training = true;
    BOOST_CHECK(modelnet::SwarmGrantAllowsTraining(grants));
    BOOST_CHECK(!modelnet::SwarmGrantAllowsRedistribution(grants));

    BOOST_CHECK(modelnet::SwarmRotateHoldout("old", "new", false, err));
    BOOST_CHECK(!modelnet::SwarmRotateHoldout("old", "old", false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT_REUSED");
    BOOST_CHECK(!modelnet::SwarmRotateHoldout("old", "new", true, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT_LEAKED");
}

BOOST_AUTO_TEST_CASE(records_a_second_process_can_read)
{
    const fs::path dir = Scratch();
    std::string err;
    modelnet::SwarmSepPolicy policy;
    policy.expiry_height = 100;
    policy.backing_manifest = "backing";
    policy.liquidity_policy = "bounded";
    policy.max_pending = 4;
    policy.settlement_policy = "cumulative";
    policy.reward_schedule = "mixed";
    policy.dispute_policy = "quorum";
    policy.evidence = {"SIGNED_WORK_RESULT"};
    policy.quorum = 2;
    policy.coordinator_id = "coord";
    policy.spend_limit = 0;
    policy.custody = "external";
    BOOST_CHECK(modelnet::SwarmValidateSepPolicy(policy, err));
    policy.spend_limit = 1;
    BOOST_CHECK(!modelnet::SwarmValidateSepPolicy(policy, err));

    BOOST_REQUIRE(modelnet::SwarmStoreSpecialistSignal(dir, "distillation", "signal", err));
    std::ifstream signals(dir / "swarm" / "specialist-signals.json");
    std::string raw((std::istreambuf_iterator<char>(signals)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK_EQUAL(root["general_stable"].get_str(), "unchanged");
    BOOST_CHECK(!root["signals"][0]["replaces_general"].get_bool());

    modelnet::SwarmPayoutQuote quote;
    BOOST_REQUIRE(modelnet::SwarmRecordPayoutQuote("provider", 50, 1'700'000'000, 1, "worker", "0.01", quote, err));
    BOOST_CHECK(!quote.usd_is_balance);
    BOOST_CHECK_EQUAL(quote.atoms, 50);
    BOOST_CHECK(!modelnet::SwarmModelFileCreatesObligation(true));

    BOOST_REQUIRE(modelnet::SwarmStoreMiningNote(dir, 10, 40, err));
    BOOST_REQUIRE(modelnet::SwarmStoreWatchtower(dir, "HASHLOCK_REMEDY", 7, "aa", err));
    BOOST_REQUIRE(modelnet::SwarmStoreAudit(dir, Id('c'), Id('d'), err));

    std::string action;
    int64_t sequence = 0;
    std::string secret;
    BOOST_REQUIRE(modelnet::SwarmLoadWatchtower(dir, action, sequence, secret, err));
    BOOST_CHECK_EQUAL(action, "HASHLOCK_REMEDY");
    BOOST_CHECK_EQUAL(sequence, 7);
    BOOST_CHECK_EQUAL(secret, "aa");

    std::string certificate;
    std::string economy;
    bool realm = true;
    bool replay = true;
    BOOST_REQUIRE(modelnet::SwarmLoadAudit(dir, certificate, economy, realm, replay, err));
    BOOST_CHECK_EQUAL(certificate, Id('c'));
    BOOST_CHECK(!realm);
    BOOST_CHECK(!replay);
    BOOST_CHECK_EQUAL(modelnet::SwarmMassExit(1000000, 8000, 24000000), 334);
    fs::remove_all(dir);
}

std::string Identity(const std::string& mask)
{
    return "\"weights\":\"w\",\"tokenizer\":\"tok\",\"adapter_order\":[\"a0\",\"a1\"],\"runtime\":\"rt\","
           "\"layout\":\"lay\",\"dtype\":\"fp32\",\"positional_encoding\":\"rope\",\"mask\":\"" +
           mask + "\"";
}

const UniValue* FindModel(const UniValue& models, const std::string& artifact)
{
    for (const UniValue& row : models.getValues()) {
        if (row["artifact_id"].get_str() == artifact) return &row;
    }
    return nullptr;
}

BOOST_AUTO_TEST_CASE(governor_snapshot_authorizes_seed_and_cpu)
{
    const fs::path root = Scratch();
    std::string err;
    const auto offer_of = [&](const fs::path& dir) {
        BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
        std::ifstream in(dir / "swarm" / "contribution.json");
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        UniValue parsed;
        BOOST_REQUIRE(parsed.read(raw));
        return parsed;
    };

    fs::create_directories(root / "off" / "swarm");
    Write(root / "off" / "swarm" / "device.json",
          "{\"idle_contribution\":false,\"slots\":4,\"cpu_threads\":4,\"vram_bytes\":8}");
    Write(root / "off" / "catalog.json",
          std::string("{\"models\":[{\"model_id\":\"") + Id('1') + "\",\"artifact_id\":\"" + Id('a') +
              "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    Write(root / "off" / "swarm" / "lineage-mappings.json",
          "{\"" + Id('a') + "\":{\"lineage_id\":\"" + Id('c') + "\",\"visibility\":\"public\"}}");
    const UniValue denied = offer_of(root / "off");
    BOOST_CHECK(!denied["cpu_evaluate"].get_bool());
    BOOST_CHECK(!denied["seed_public"].get_bool());
    BOOST_CHECK_EQUAL(denied["cpu_threads"].getInt<int>(), 0);
    BOOST_CHECK(denied["hardware_threads"].getInt<int>() >= 1);
    BOOST_CHECK_EQUAL(denied["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(!denied["models"][0]["seed"].get_bool());
    BOOST_REQUIRE(modelnet::SwarmRefreshLocalMesh(root / "off", err));
    std::ifstream mesh_in(root / "off" / "swarm" / "mesh-state.json");
    std::string mesh_raw((std::istreambuf_iterator<char>(mesh_in)), std::istreambuf_iterator<char>());
    UniValue mesh;
    BOOST_REQUIRE(mesh.read(mesh_raw));
    BOOST_CHECK(mesh["observer"].get_bool());
    BOOST_CHECK(!mesh["seeder"].get_bool());
    BOOST_CHECK(!mesh["evaluator"].get_bool());
    BOOST_CHECK(mesh["drained"].get_bool());

    fs::create_directories(root / "zero" / "swarm");
    Write(root / "zero" / "swarm" / "device.json",
          "{\"idle_contribution\":true,\"slots\":0,\"cpu_threads\":0,\"vram_bytes\":0}");
    const UniValue zero = offer_of(root / "zero");
    BOOST_CHECK(!zero["cpu_evaluate"].get_bool());
    BOOST_CHECK(!zero["seed_public"].get_bool());
    BOOST_CHECK(zero["models"].empty());

    fs::create_directories(root / "on" / "swarm");
    Write(root / "on" / "swarm" / "device.json",
          "{\"idle_contribution\":true,\"slots\":2,\"cpu_threads\":3,\"vram_bytes\":0}");
    Write(root / "on" / "catalog.json",
          std::string("{\"models\":[{\"model_id\":\"") + Id('1') + "\",\"artifact_id\":\"" + Id('a') +
              "\",\"bytes_verified\":true,\"incomplete\":false},"
              "{\"model_id\":\"" + Id('2') + "\",\"artifact_id\":\"" + Id('b') +
              "\",\"bytes_verified\":true,\"incomplete\":false}]}");
    Write(root / "on" / "swarm" / "lineage-mappings.json",
          "{\"" + Id('a') + "\":{\"lineage_id\":\"" + Id('c') + "\",\"visibility\":\"public\"}}");
    const UniValue granted = offer_of(root / "on");
    BOOST_CHECK(granted["cpu_evaluate"].get_bool());
    BOOST_CHECK(granted["seed_public"].get_bool());
    BOOST_CHECK_EQUAL(granted["cpu_threads"].getInt<int>(), 3);
    BOOST_CHECK(granted["hardware_threads"].getInt<int>() >= 1);
    BOOST_CHECK(!granted["gpu_train"].get_bool());
    const UniValue* pub = FindModel(granted["models"], Id('a'));
    const UniValue* priv = FindModel(granted["models"], Id('b'));
    BOOST_REQUIRE(pub != nullptr);
    BOOST_REQUIRE(priv != nullptr);
    BOOST_CHECK(pub->operator[]("seed").get_bool());
    BOOST_CHECK(!priv->operator[]("seed").get_bool());
    BOOST_CHECK(priv->operator[]("private_acquire").get_bool());
    fs::remove_all(root);
}

BOOST_AUTO_TEST_CASE(distinct_checkpoints_share_a_family_and_not_a_cohort)
{
    const fs::path dir = Scratch();
    const std::string lineage = Id('c');
    Write(dir / "catalog.json",
          std::string("{\"models\":[") +
              "{\"model_id\":\"" + Id('1') + "\",\"artifact_id\":\"" + Id('a') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"quantization\":\"full\","
              "\"checkpoint_id\":\"ckpt-a\",\"recipe\":\"recipe\"," + Identity("mask") + "}," +
              "{\"model_id\":\"" + Id('2') + "\",\"artifact_id\":\"" + Id('b') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"quantization\":\"full\","
              "\"checkpoint_id\":\"ckpt-b\",\"recipe\":\"recipe\"," + Identity("mask") + "}," +
              "{\"model_id\":\"" + Id('3') + "\",\"artifact_id\":\"" + Id('d') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"quantization\":\"full\","
              "\"checkpoint_id\":\"ckpt-a\",\"recipe\":\"recipe\"," + Identity("other") + "}," +
              "{\"model_id\":\"" + Id('4') + "\",\"artifact_id\":\"" + Id('e') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"quantization\":\"full\","
              "\"checkpoint_id\":\"ckpt-same\",\"recipe\":\"recipe\"," + Identity("mask") + "}," +
              "{\"model_id\":\"" + Id('5') + "\",\"artifact_id\":\"" + Id('f') +
              "\",\"bytes_verified\":true,\"incomplete\":false,\"quantization\":\"full\","
              "\"checkpoint_id\":\"ckpt-same\",\"recipe\":\"recipe\"," + Identity("mask") + "}" +
              "]}");
    fs::create_directories(dir / "swarm");
    Write(dir / "swarm" / "lineage-mappings.json",
          "{\"" + Id('a') + "\":{\"lineage_id\":\"" + lineage + "\",\"visibility\":\"public\"}," +
              "\"" + Id('b') + "\":{\"lineage_id\":\"" + lineage + "\",\"visibility\":\"public\"}," +
              "\"" + Id('d') + "\":{\"lineage_id\":\"" + lineage + "\",\"visibility\":\"public\"}," +
              "\"" + Id('e') + "\":{\"lineage_id\":\"" + lineage + "\",\"visibility\":\"public\"}," +
              "\"" + Id('f') + "\":{\"lineage_id\":\"" + lineage + "\",\"visibility\":\"public\"}}");
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmIntegrateCatalog(dir, err));
    std::ifstream in(dir / "swarm" / "contribution.json");
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    const UniValue& models = root["models"];
    const UniValue* ckpt_a = FindModel(models, Id('a'));
    const UniValue* ckpt_b = FindModel(models, Id('b'));
    const UniValue* mismatched = FindModel(models, Id('d'));
    const UniValue* same_left = FindModel(models, Id('e'));
    const UniValue* same_right = FindModel(models, Id('f'));
    BOOST_REQUIRE(ckpt_a && ckpt_b && mismatched && same_left && same_right);
    BOOST_CHECK(ckpt_a->operator[]("family").get_bool());
    BOOST_CHECK(ckpt_b->operator[]("family").get_bool());
    BOOST_CHECK(ckpt_a->operator[]("cohort").get_bool());
    BOOST_CHECK(ckpt_b->operator[]("cohort").get_bool());
    BOOST_CHECK_EQUAL((*ckpt_a)["checkpoint_id"].get_str(), "ckpt-a");
    BOOST_CHECK_EQUAL((*ckpt_b)["checkpoint_id"].get_str(), "ckpt-b");
    BOOST_CHECK_EQUAL((*ckpt_a)["recipe"].get_str(), "recipe");
    BOOST_CHECK((*ckpt_b)["kv_share"].get_bool());
    BOOST_CHECK((*mismatched)["cohort"].get_bool());
    BOOST_CHECK(!(*mismatched)["kv_share"].get_bool());
    BOOST_CHECK(!(*ckpt_a)["kv_share"].get_bool());
    BOOST_CHECK((*same_left)["kv_share"].get_bool());
    BOOST_CHECK((*same_right)["kv_share"].get_bool());
    BOOST_CHECK_EQUAL(same_left->operator[]("lineage_id").get_str(), lineage);
    BOOST_CHECK(ckpt_a->operator[]("seed").get_bool());

    BOOST_REQUIRE(modelnet::SwarmPublishLive(dir, err));
    std::ifstream networks_in(dir / "swarm" / "networks.json");
    std::string networks_raw((std::istreambuf_iterator<char>(networks_in)), std::istreambuf_iterator<char>());
    UniValue networks;
    BOOST_REQUIRE(networks.read(networks_raw));
    BOOST_CHECK_EQUAL(networks["family"]["lineage_id"].get_str(), lineage);
    BOOST_CHECK_EQUAL(networks["family"]["member_artifact_ids"].size(), 5U);
    BOOST_REQUIRE_EQUAL(networks["cohorts"].size(), 3U);
    BOOST_CHECK(networks["cohort"]["member_ids"].empty());
    bool paired = false;
    for (const UniValue& cohort : networks["cohorts"].getValues()) {
        BOOST_CHECK_EQUAL(cohort["lineage_id"].get_str(), lineage);
        BOOST_CHECK_EQUAL(cohort["recipe_id"].get_str(), "recipe");
        const UniValue& members = cohort["member_ids"];
        const bool has_a = [&] {
            for (const UniValue& id : members.getValues()) {
                if (id.get_str() == Id('a')) return true;
            }
            return false;
        }();
        const bool has_b = [&] {
            for (const UniValue& id : members.getValues()) {
                if (id.get_str() == Id('b')) return true;
            }
            return false;
        }();
        BOOST_CHECK(!(has_a && has_b));
        if (cohort["checkpoint_id"].get_str() == "ckpt-same") {
            paired = true;
            BOOST_CHECK_EQUAL(members.size(), 2U);
        }
    }
    BOOST_CHECK(paired);
    BOOST_REQUIRE_EQUAL(networks["families"].size(), 1U);
    BOOST_CHECK_EQUAL(networks["families"][0]["members"][0]["checkpoint_id"].get_str().empty(), false);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
