// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_codec.h>
#include <modelnet/swarm_records.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_records_tests, BasicTestingSetup)

namespace {

struct SwarmTemp {
    fs::path path;
    explicit SwarmTemp(const fs::path& base, const char* name) : path(base / name)
    {
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~SwarmTemp()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string ReadRaw(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

modelnet::SwarmRoutePeer Route(const char* id, const char* domain, bool authorized, bool available, int64_t rtt)
{
    modelnet::SwarmRoutePeer peer;
    peer.id = id;
    peer.domain = domain;
    peer.authorized = authorized;
    peer.available = available;
    peer.rtt_us = rtt;
    return peer;
}

} // namespace

BOOST_AUTO_TEST_CASE(training_requires_an_operator_grant)
{
    modelnet::ModelLineage download;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmMakeLineage("", {}, "", "mit", true, download, err));
    BOOST_CHECK_EQUAL(err, "ARCHITECTURE");
    BOOST_CHECK(!modelnet::SwarmMakeLineage("", {}, "transformer", "", false, download, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");

    BOOST_REQUIRE(modelnet::SwarmMakeLineage("", {}, "transformer", "download", false, download, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(download.parent_lineage.empty());
    BOOST_CHECK_EQUAL(download.ancestry.size(), 1U);
    BOOST_CHECK_EQUAL(download.ancestry[0], download.lineage_id);
    BOOST_CHECK(modelnet::SwarmFixedId(download.lineage_id));
    BOOST_CHECK(!modelnet::SwarmLineageAllowsTraining(download, true));
    BOOST_CHECK(!modelnet::SwarmLineageAllowsTraining(download, false));

    modelnet::ModelLineage trainable;
    BOOST_REQUIRE(modelnet::SwarmMakeLineage("", {}, "transformer", "mit-train", true, trainable, err));
    BOOST_CHECK(!modelnet::SwarmLineageAllowsTraining(trainable, false));
    BOOST_CHECK(modelnet::SwarmLineageAllowsTraining(trainable, true));

    modelnet::ModelLineage child;
    BOOST_REQUIRE(modelnet::SwarmMakeLineage(trainable.lineage_id, trainable.ancestry, "transformer", "mit-train", true,
                                             child, err));
    BOOST_CHECK_EQUAL(child.parent_lineage, trainable.lineage_id);
    BOOST_CHECK_EQUAL(child.ancestry.size(), 2U);
    BOOST_CHECK_EQUAL(child.ancestry[0], trainable.lineage_id);
    BOOST_CHECK_EQUAL(child.ancestry[1], child.lineage_id);
    BOOST_CHECK(child.lineage_id != trainable.lineage_id);
}

BOOST_AUTO_TEST_CASE(presence_rejects_a_checkpoint_only_claim)
{
    modelnet::SwarmPresence presence;
    presence.peer_id = "peer-a";
    presence.endpoint = "127.0.0.1:8333";
    presence.capabilities = {"execute"};
    presence.trust_domain = "lab";
    presence.expiry_ms = 2'000;
    presence.signature_hex = "ab";
    presence.claims_checkpoint_only = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAcceptPresence(presence, 1'000, err));
    BOOST_CHECK_EQUAL(err, "CHECKPOINT_CLAIM_IS_NOT_TRUST");

    presence.claims_checkpoint_only = false;
    presence.expiry_ms = 1'000;
    BOOST_CHECK(!modelnet::SwarmAcceptPresence(presence, 1'000, err));
    BOOST_CHECK_EQUAL(err, "PRESENCE_EXPIRED");

    presence.expiry_ms = 2'000;
    presence.signature_hex.clear();
    BOOST_CHECK(!modelnet::SwarmAcceptPresence(presence, 1'000, err));
    BOOST_CHECK_EQUAL(err, "PRESENCE_UNSIGNED");

    presence.signature_hex = "ab";
    BOOST_CHECK(!modelnet::SwarmAcceptPresence(presence, 1'000, err));
    BOOST_CHECK_EQUAL(err, "PRESENCE_SIGNATURE");
}

BOOST_AUTO_TEST_CASE(fallback_skips_the_chosen_neighborhood)
{
    const std::vector<modelnet::SwarmRoutePeer> peers = {
        Route("c", "near", true, true, 1),  Route("d", "near", true, false, 1), Route("e", "far", false, true, 2),
        Route("f", "far", true, true, 3),   Route("b", "mid", true, true, 5),  Route("a", "mid", true, true, 5),
    };
    const std::vector<modelnet::SwarmRoutePeer> routes = modelnet::SwarmFallbackRoutes(peers, {"c"}, 3);
    BOOST_REQUIRE_EQUAL(routes.size(), 3U);
    BOOST_CHECK_EQUAL(routes[0].id, "f");
    BOOST_CHECK_EQUAL(routes[1].id, "a");
    BOOST_CHECK_EQUAL(routes[2].id, "b");
    BOOST_CHECK(modelnet::SwarmFallbackRoutes(peers, {"c", "f", "a", "b"}, 3).empty());
}

BOOST_AUTO_TEST_CASE(acquire_specialist_does_not_replace_the_general_model)
{
    modelnet::SwarmAcquireState state;
    state.general_replaced = true;
    state.private_prompts = true;
    state.automatic_spend_atoms = "9";
    std::string err;
    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Verify, state, false, true, true, true, true, err);
    BOOST_CHECK_EQUAL(err, "ARTIFACT_UNVERIFIED");
    BOOST_CHECK(!state.verified);
    BOOST_CHECK(!state.joined);
    BOOST_CHECK(!state.general_replaced);
    BOOST_CHECK_EQUAL(state.automatic_spend_atoms, "0");

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Verify, state, true, true, false, false, false, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(state.verified);
    BOOST_CHECK(!state.joined);

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Join, state, false, true, false, false, false, err);
    BOOST_CHECK_EQUAL(err, "ARTIFACT_UNVERIFIED");
    BOOST_CHECK(!state.joined);

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Join, state, true, true, false, false, false, err);
    BOOST_CHECK(state.joined);
    BOOST_CHECK_EQUAL(state.visibility, "private");
    BOOST_CHECK(!state.private_prompts);
    BOOST_CHECK_EQUAL(state.automatic_spend_atoms, "0");

    modelnet::SwarmAcquireState unloaded;
    unloaded = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Load, unloaded, true, false, false, false, false,
                                             err);
    BOOST_CHECK(!unloaded.discovered_runtime);
    BOOST_CHECK_EQUAL(err, "NOT_JOINED");

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Load, state, true, true, false, false, false, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(state.discovered_runtime);

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Use, state, true, true, false, false, false, err);
    BOOST_CHECK(state.used);
    BOOST_CHECK(!state.private_prompts);

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Offer, state, true, true, false, false, false, err);
    BOOST_CHECK(!state.offered);
    BOOST_CHECK_EQUAL(err, "IDLE_OFF");
    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Offer, state, true, true, true, false, false, err);
    BOOST_CHECK(state.offered);

    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Stage, state, true, true, true, false, false, err);
    BOOST_CHECK(!state.staged);
    BOOST_CHECK_EQUAL(err, "GENERATION_FAILED");
    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Stage, state, true, true, true, false, true, err);
    BOOST_CHECK(state.staged);

    state.general_replaced = true;
    state = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Specialist, state, true, true, true, true, true, err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(state.specialist_published);
    BOOST_CHECK(!state.general_replaced);
    BOOST_CHECK(!state.private_prompts);
    BOOST_CHECK_EQUAL(state.automatic_spend_atoms, "0");

    modelnet::SwarmAcquireState pub;
    pub = modelnet::SwarmAdvanceAcquire(modelnet::SwarmAcquireStep::Join, pub, true, false, false, false, false, err);
    BOOST_CHECK_EQUAL(pub.visibility, "public");
}

BOOST_AUTO_TEST_CASE(four_bit_is_the_same_family_but_not_kv_compatible)
{
    const modelnet::SwarmCompat full{"lineage-a", "ckpt-1", "fp16", "recipe-a"};
    const modelnet::SwarmCompat q4{"lineage-a", "ckpt-1", "q4", "recipe-b"};
    const modelnet::SwarmCompat q4_same_recipe{"lineage-a", "ckpt-1", "q4", "recipe-a"};
    const modelnet::SwarmCompat other{"lineage-b", "ckpt-1", "q4", "recipe-b"};
    BOOST_CHECK(modelnet::SwarmSameFamily(full, q4));
    BOOST_CHECK(!modelnet::SwarmKvCompatible(full, q4));
    BOOST_CHECK(!modelnet::SwarmTrainCompatible(full, q4));
    BOOST_CHECK(modelnet::SwarmTrainCompatible(full, q4_same_recipe));
    BOOST_CHECK(!modelnet::SwarmKvCompatible(full, q4_same_recipe));
    BOOST_CHECK(!modelnet::SwarmSameFamily(full, other));
}

BOOST_AUTO_TEST_CASE(private_prompt_is_not_stored)
{
    const SwarmTemp dir(m_args.GetDataDirBase(), "swarm_records_knowledge");
    modelnet::SwarmKnowledge prompt;
    prompt.kind = "prompt";
    prompt.id = "prompt-1";
    prompt.body_digest = "digest-p";
    prompt.visibility = "private";
    std::string err;
    BOOST_CHECK(!modelnet::SwarmStoreKnowledge(dir.path, prompt, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_PROMPT");
    BOOST_CHECK(!fs::exists(dir.path / "swarm" / "knowledge.json"));

    modelnet::SwarmKnowledge finding;
    finding.kind = "finding";
    finding.id = "finding-1";
    finding.body_digest = "digest-f";
    finding.visibility = "public";
    modelnet::SwarmKnowledge strategy;
    strategy.kind = "strategy";
    strategy.id = "strategy-1";
    strategy.body_digest = "digest-s";
    strategy.visibility = "private";
    BOOST_REQUIRE(modelnet::SwarmStoreKnowledge(dir.path, finding, err));
    BOOST_REQUIRE(modelnet::SwarmStoreKnowledge(dir.path, strategy, err));
    BOOST_CHECK(!modelnet::SwarmStoreKnowledge(dir.path, prompt, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_PROMPT");

    std::vector<modelnet::SwarmKnowledge> loaded;
    BOOST_REQUIRE(modelnet::SwarmLoadKnowledge(dir.path, loaded, err));
    BOOST_REQUIRE_EQUAL(loaded.size(), 2U);
    BOOST_CHECK_EQUAL(loaded[0].kind, "finding");
    BOOST_CHECK_EQUAL(loaded[1].visibility, "private");
    const std::vector<modelnet::SwarmKnowledge> published = modelnet::SwarmPublicKnowledge(loaded);
    BOOST_REQUIRE_EQUAL(published.size(), 1U);
    BOOST_CHECK_EQUAL(published[0].id, "finding-1");
    const std::string raw = ReadRaw(dir.path / "swarm" / "knowledge.json");
    BOOST_CHECK(raw.find("\"prompt\"") == std::string::npos);
    BOOST_CHECK(raw.find("\"automatic_spend_atoms\":\"0\"") != std::string::npos);
    std::error_code ec;
    fs::remove_all(dir.path, ec);
}

BOOST_AUTO_TEST_CASE(local_only_islands_do_not_exchange_and_unevaluated_merge_is_refused)
{
    modelnet::SwarmIsland local;
    local.id = "island-local";
    local.checkpoint = "ckpt";
    local.recipe = "recipe";
    local.local_only = true;
    modelnet::SwarmIsland open_a;
    open_a.id = "island-a";
    open_a.checkpoint = "ckpt";
    open_a.recipe = "recipe";
    modelnet::SwarmIsland open_b = open_a;
    open_b.id = "island-b";
    modelnet::SwarmIsland other_recipe = open_a;
    other_recipe.id = "island-c";
    other_recipe.recipe = "other";
    BOOST_CHECK(!modelnet::SwarmMayExchangeUpdates(local, open_a));
    BOOST_CHECK(modelnet::SwarmMayExchangeUpdates(open_a, open_b));
    BOOST_CHECK(!modelnet::SwarmMayExchangeUpdates(open_a, other_recipe));

    std::string err;
    const modelnet::SwarmIsland fork = modelnet::SwarmForkBranch(open_a, "ckpt-2", "recipe-2", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!fork.compatible_average);
    BOOST_CHECK(!fork.local_only);
    const std::string canonical = modelnet::SwarmCanonical({
        {"checkpoint", "ckpt-2"},
        {"parent", open_a.id},
        {"recipe", "recipe-2"},
    });
    BOOST_CHECK_EQUAL(fork.id, modelnet::SwarmDigest("BTX/IslandFork/1", canonical));
    BOOST_CHECK(modelnet::SwarmFixedId(fork.id));

    const modelnet::SwarmMergeProposal unevaluated = modelnet::SwarmProposeMerge("EVALUATED_MERGE", false, err);
    BOOST_CHECK(!unevaluated.accepted);
    BOOST_CHECK_EQUAL(unevaluated.method, "EVALUATED_MERGE");
    BOOST_CHECK_EQUAL(err, "MERGE_UNEVALUATED");
    BOOST_CHECK_EQUAL(unevaluated.automatic_spend_atoms, "0");
    const modelnet::SwarmMergeProposal averaged = modelnet::SwarmProposeMerge("AVERAGE", true, err);
    BOOST_CHECK(!averaged.accepted);
    BOOST_CHECK(averaged.method.empty());
    BOOST_CHECK_EQUAL(err, "MERGE_METHOD");
    const modelnet::SwarmMergeProposal distilled = modelnet::SwarmProposeMerge("DISTILL", true, err);
    BOOST_CHECK(distilled.accepted);
    BOOST_CHECK_EQUAL(distilled.method, "DISTILL");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(kv_holder_mismatch_moves_no_bytes)
{
    modelnet::SwarmPageHolder holder;
    holder.peer_id = "holder-1";
    holder.fingerprint = "fp-a";
    holder.page_start = 0;
    holder.page_end = 10;
    modelnet::SwarmKvSelection selected;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmSelectKvHolder({holder}, "fp-b", 0, 4, selected, err));
    BOOST_CHECK_EQUAL(err, "KV_NO_HOLDER");
    BOOST_CHECK(selected.peer_id.empty());
    BOOST_CHECK(!selected.bytes_moved);

    BOOST_CHECK(!modelnet::SwarmSelectKvHolder({holder}, "fp-a", 8, 12, selected, err));
    BOOST_CHECK_EQUAL(err, "KV_NO_HOLDER");
    BOOST_CHECK(!selected.bytes_moved);

    BOOST_REQUIRE(modelnet::SwarmSelectKvHolder({holder}, "fp-a", 2, 8, selected, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(selected.peer_id, "holder-1");
    BOOST_CHECK(!selected.bytes_moved);
}

BOOST_AUTO_TEST_CASE(networks_round_trip_on_disk)
{
    const SwarmTemp dir(m_args.GetDataDirBase(), "swarm_records_networks");
    modelnet::SwarmNetworks empty;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmLoadNetworks(dir.path, empty, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(empty.family.lineage_id.empty());
    BOOST_CHECK(empty.neighborhood.peer_ids.empty());
    BOOST_CHECK(empty.cohort.member_ids.empty());
    BOOST_CHECK(empty.frontier.candidate_ids.empty());
    BOOST_CHECK_EQUAL(empty.automatic_spend_atoms, "0");

    modelnet::SwarmNetworks networks;
    networks.family.lineage_id = "lineage-1";
    networks.family.member_artifact_ids = {"art-a", "art-b"};
    networks.neighborhood.peer_ids = {"peer-1", "peer-2"};
    networks.cohort.checkpoint_id = "ckpt-1";
    networks.cohort.recipe_id = "recipe-1";
    networks.cohort.member_ids = {"member-1"};
    networks.cohort.lease_slots = 4;
    networks.cohort.lease_until_ms = 9'000;
    networks.frontier.candidate_ids = {"cand-1", "cand-2"};
    networks.automatic_spend_atoms = "9";
    BOOST_REQUIRE(modelnet::SwarmStoreNetworks(dir.path, networks, err));
    BOOST_CHECK(fs::exists(dir.path / "swarm" / "networks.json"));

    modelnet::SwarmNetworks loaded;
    BOOST_REQUIRE(modelnet::SwarmLoadNetworks(dir.path, loaded, err));
    BOOST_CHECK_EQUAL(loaded.family.lineage_id, "lineage-1");
    BOOST_CHECK_EQUAL(loaded.family.member_artifact_ids.size(), 2U);
    BOOST_CHECK_EQUAL(loaded.family.member_artifact_ids[1], "art-b");
    BOOST_CHECK_EQUAL(loaded.neighborhood.peer_ids[0], "peer-1");
    BOOST_CHECK_EQUAL(loaded.cohort.checkpoint_id, "ckpt-1");
    BOOST_CHECK_EQUAL(loaded.cohort.recipe_id, "recipe-1");
    BOOST_CHECK_EQUAL(loaded.cohort.member_ids[0], "member-1");
    BOOST_CHECK_EQUAL(loaded.cohort.lease_slots, 4);
    BOOST_CHECK_EQUAL(loaded.cohort.lease_until_ms, 9'000);
    BOOST_CHECK_EQUAL(loaded.frontier.candidate_ids[1], "cand-2");
    BOOST_CHECK_EQUAL(loaded.automatic_spend_atoms, "0");

    {
        std::ofstream out(dir.path / "swarm" / "networks.json", std::ios::trunc);
        out << "{not-json";
    }
    BOOST_CHECK(!modelnet::SwarmLoadNetworks(dir.path, loaded, err));
    BOOST_CHECK_EQUAL(err, "NETWORKS_JSON");
    BOOST_CHECK_EQUAL(loaded.automatic_spend_atoms, "0");
    std::error_code ec;
    fs::remove_all(dir.path, ec);
}

BOOST_AUTO_TEST_SUITE_END()
