// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/action_authority.h>
#include <modelnet/git_snapshot.h>
#include <modelnet/identity.h>
#include <modelnet/model_admission.h>
#include <modelnet/pq_delegation.h>
#include <modelnet/realm_channel.h>
#include <modelnet/research_graph.h>
#include <modelnet/training_evidence.h>
#include <modelnet/workspace_journal.h>
#include <span.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_journey_tests, BasicTestingSetup)

namespace {

const std::string kRng = "rng-frozen";
const std::string kOptimizer = "opt-frozen";
const std::string kCursor = "cursor-frozen";

modelnet::Interval Edge(uint64_t start, uint64_t end, std::string start_state, std::string end_state, std::string ancestry)
{
    modelnet::Interval interval;
    interval.start_inclusive = start;
    interval.end_exclusive = end;
    interval.start_state = std::move(start_state);
    interval.end_state = std::move(end_state);
    interval.profile = "EXACT_CHECKS";
    interval.rng = kRng;
    interval.optimizer = kOptimizer;
    interval.data_cursor = kCursor;
    interval.ancestry = std::move(ancestry);
    interval.publisher_only = false;
    return interval;
}

Span<const unsigned char> AsBytes(const std::vector<unsigned char>& bytes)
{
    return Span<const unsigned char>{bytes.data(), bytes.size()};
}

} // namespace

BOOST_AUTO_TEST_CASE(sovereign_lab_journey)
{
    using namespace modelnet;
    std::string err;

    BOOST_CHECK(!ResearchMaySpend());
    BOOST_CHECK(!ResearchMaySpendWallet());
    ActionGate gate;
    ActionPermit spend;
    spend.permit_id = "permit-spend";
    spend.grant_id = "grant-spend";
    spend.generation = 1;
    spend.effect = "spend";
    spend.not_after_ms = 10;
    spend.parameter_fingerprint = "fp";
    BOOST_CHECK(!gate.Issue(spend, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");

    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    IdentityChain chain;
    Digest48 root;
    BOOST_REQUIRE(chain.CreateRoot(AsBytes(pk), root, err));
    BOOST_CHECK(root == ResearchIdentityId(AsBytes(pk)));
    uint64_t epoch = 99;
    BOOST_REQUIRE(chain.CurrentEpoch(root, epoch, err));
    BOOST_CHECK_EQUAL(epoch, uint64_t{0});

    const std::string note = "lab-note";
    const std::vector<unsigned char> note_bytes(note.begin(), note.end());
    std::string digest;
    BOOST_REQUIRE(GitObjectDigest("blob", AsBytes(note_bytes), digest, err));
    BOOST_CHECK(IsStrongGitDigest(digest));
    BOOST_CHECK_EQUAL(digest.size(), 96);

    WorkspaceBook workspace;
    BOOST_REQUIRE(workspace.OpenTree("lab", err));
    BOOST_REQUIRE(workspace.Put("lab", 1, "note.txt", note_bytes, err));
    BOOST_REQUIRE(workspace.Publish("lab", 1, false, true, err));
    BOOST_CHECK_EQUAL(workspace.Generation("lab"), uint64_t{2});
    BOOST_REQUIRE(workspace.NotePrivate("lab", "do-not-export", err));
    const std::string exported = workspace.ExportPublic("lab");
    BOOST_CHECK(exported.find("note.txt") != std::string::npos);
    BOOST_CHECK(exported.find("do-not-export") == std::string::npos);

    ResearchBook research;
    Digest48 topic;
    BOOST_REQUIRE(TopicId("lab-results", topic, err));
    Digest48 contribution;
    contribution.data[0] = 1;
    BOOST_REQUIRE(research.Publish(topic, contribution, root, false, "held", err));
    BOOST_CHECK(research.HasPeer(root));
    ResearchContribution row;
    BOOST_REQUIRE(research.Find(topic, contribution, row));
    BOOST_CHECK_EQUAL(row.summary, "held");

    Digest48 child;
    child.data[0] = 2;
    BOOST_CHECK(!research.AdoptSuccessor(root, child, "parent-grant", "parent-grant", {contribution}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GRANT");
    BOOST_CHECK(research.MemoryOf(child).empty());
    BOOST_REQUIRE(research.AdoptSuccessor(root, child, "parent-grant", "child-grant", {contribution}, err));
    const std::vector<Digest48> memory = research.MemoryOf(child);
    BOOST_REQUIRE_EQUAL(memory.size(), 1U);
    BOOST_CHECK(memory[0] == contribution);

    const Interval covered = Edge(0, 8, "S0", "SF", "root-a");
    BOOST_CHECK(FullReplayCoverage(8, "S0", "SF", {covered}));
    const AdmissionResult one = Admit(Assurance::PUBLIC_STRICT, true, {covered}, 8, "S0", "SF", {"root-a"}, false);
    BOOST_CHECK(!one.admitted);
    BOOST_CHECK(!one.ServeAllowed());
    BOOST_CHECK_EQUAL(one.code, "BTX035_REPLAY");

    const Interval gapped = Edge(6, 8, "S6", "SF", "root-b");
    const AdmissionResult gap = Admit(Assurance::PUBLIC_STRICT, true, {Edge(0, 4, "S0", "S4", "root-a"), gapped}, 8, "S0", "SF",
                                      {"root-a", "root-b"}, false);
    BOOST_CHECK(!gap.admitted);
    BOOST_CHECK(!gap.ServeAllowed());
    BOOST_CHECK_EQUAL(gap.code, "BTX035_GAP");

    const Interval other = Edge(0, 8, "S0", "SF", "root-b");
    const AdmissionResult duplicated = Admit(Assurance::PUBLIC_STRICT, true, {covered, other}, 8, "S0", "SF",
                                             {"root-a", "root-a"}, false);
    BOOST_CHECK(!duplicated.admitted);
    BOOST_CHECK_EQUAL(duplicated.code, "BTX035_REPLAY");

    const AdmissionResult admitted = Admit(Assurance::PUBLIC_STRICT, true, {covered, other}, 8, "S0", "SF",
                                           {"root-a", "root-b"}, false);
    BOOST_CHECK(admitted.admitted);
    BOOST_CHECK(admitted.code.empty());
    BOOST_CHECK(admitted.ServeAllowed());
    BOOST_CHECK(!admitted.research_execution_permit);
}

BOOST_AUTO_TEST_CASE(wan_journey)
{
    using namespace modelnet;
    std::string err;

    const Interval covered = Edge(0, 8, "S0", "SF", "root-a");
    BOOST_CHECK(FullReplayCoverage(8, "S0", "SF", {covered}));
    const AdmissionResult none = Admit(Assurance::PUBLIC_STRICT, true, {covered}, 8, "S0", "SF", {}, false);
    BOOST_CHECK(none.code == "BTX035_REPLAY");
    BOOST_CHECK(!none.admitted);
    BOOST_CHECK(!none.ServeAllowed());

    RealmRollout same;
    BOOST_REQUIRE(same.RecordPromotion("solo", "solo", err));
    BOOST_CHECK(!same.ApprovePromotion(err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
    BOOST_CHECK_EQUAL(same.SourceExporter(), "solo");
    BOOST_CHECK_EQUAL(same.DestinationApprover(), "solo");

    RealmRollout roll;
    BOOST_REQUIRE(roll.SetPolicy("realm", 2, {"a", "b", "c"}, err));
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 2);
    BOOST_CHECK(roll.Quorum("realm", {"a", "b"}));
    BOOST_REQUIRE(roll.RevokeAttestor("realm", "a", err));
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 2);
    BOOST_CHECK(!roll.Quorum("realm", {"a", "b"}));
    BOOST_CHECK(!roll.Quorum("realm", {"b"}));
    BOOST_CHECK(roll.Quorum("realm", {"b", "c"}));
    BOOST_CHECK(!roll.SetPolicy("realm", 1, {"b", "c"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");
    BOOST_CHECK_EQUAL(roll.Threshold("realm"), 2);

    BOOST_REQUIRE(roll.ActivateOffline(9, 4, err));
    const int64_t ring = roll.RingGeneration("realm");
    BOOST_CHECK(!roll.AdvanceRingFromOffline(err));
    BOOST_CHECK_EQUAL(err, "BTX035_OFFLINE");
    BOOST_CHECK_EQUAL(roll.RingGeneration("realm"), ring);
    BOOST_CHECK_EQUAL(roll.OfflineBundleGeneration(), static_cast<int64_t>(9));

    BOOST_REQUIRE(roll.PublishChannel("realm", 0, "h0", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 1, "h1", err));
    BOOST_REQUIRE(roll.PublishChannel("realm", 2, "h2", err));
    BOOST_CHECK(!roll.RestoreBackup(1, 2, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(roll.CurrentSequence(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelSequence("realm"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(roll.ChannelBody("realm"), "h2");
}

BOOST_AUTO_TEST_SUITE_END()
