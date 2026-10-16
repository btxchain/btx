// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_journey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_e2e_gate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(e2e_001_research_root_continues_after_author_removed)
{
    using namespace modelnet;
    LabJourney lab;
    std::string err;
    std::string denied;
    BOOST_CHECK(!lab.WalletSpendAllowed());
    BOOST_CHECK(!lab.CreateResearchRoot(true, denied, err));
    BOOST_CHECK(denied.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!lab.HasWalletFlag(denied));

    std::string root;
    BOOST_REQUIRE(lab.CreateResearchRoot(false, root, err));
    BOOST_CHECK(!root.empty());
    BOOST_CHECK(!lab.HasWalletFlag(root));
    BOOST_CHECK(!lab.WalletSpendAllowed());

    BOOST_CHECK(!lab.DiscoverObjective("objective-1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_REQUIRE(lab.OfferObjective("objective-1", err));
    BOOST_REQUIRE(lab.DiscoverObjective("objective-1", err));
    BOOST_REQUIRE(lab.SelectObjective(root, "objective-1", err));
    std::string selected;
    BOOST_REQUIRE(lab.SelectedObjective(root, selected));
    BOOST_CHECK_EQUAL(selected, "objective-1");

    BOOST_REQUIRE(lab.RecordSourceSnapshot(root, "snapshot-1", err));
    BOOST_REQUIRE(lab.RecordData(root, "data-1", err));
    std::string snapshot;
    std::string data;
    BOOST_REQUIRE(lab.SourceSnapshot(root, snapshot));
    BOOST_REQUIRE(lab.DataId(root, data));
    BOOST_CHECK_EQUAL(snapshot, "snapshot-1");
    BOOST_CHECK_EQUAL(data, "data-1");

    uint64_t generation = 0;
    BOOST_REQUIRE(lab.OpenWorkspaceGeneration(root, generation, err));
    BOOST_CHECK_EQUAL(generation, uint64_t{1});
    BOOST_REQUIRE(lab.PublishContribution(root, "contribution-1", err));
    BOOST_CHECK(lab.AuthorPresent(root));
    BOOST_CHECK(lab.FindContribution("contribution-1"));

    BOOST_REQUIRE(lab.RemoveAuthor(root, err));
    BOOST_CHECK(!lab.AuthorPresent(root));
    BOOST_CHECK(lab.FindContribution("contribution-1"));
    BOOST_REQUIRE(lab.ContinueParticipant("participant-2", "contribution-1", err));
    std::string continued;
    BOOST_REQUIRE(lab.Continued("participant-2", continued));
    BOOST_CHECK_EQUAL(continued, "contribution-1");
    BOOST_CHECK(lab.FindContribution("contribution-1"));
    BOOST_CHECK(!lab.HasWalletFlag(root));
}

BOOST_AUTO_TEST_CASE(e2e_002_four_step_training_fixture)
{
    using namespace modelnet;
    // Reference fixture only. The four transitions are not a production model.
    LabJourney lab;
    std::string err;
    BOOST_REQUIRE(lab.RecordFixtureTransitions(err));
    BOOST_CHECK_EQUAL(lab.FixtureSteps(), uint64_t{4});
    BOOST_CHECK(lab.FixtureCovers());
    for (uint64_t step = 0; step < 4; ++step) {
        uint64_t start = 0;
        uint64_t end = 0;
        BOOST_REQUIRE(lab.FixtureStep(step, start, end));
        BOOST_CHECK_EQUAL(start, step);
        BOOST_CHECK_EQUAL(end, step + 1);
    }

    const std::string cursor = lab.FixtureDataCursor();
    const std::string optimizer = lab.FixtureOptimizer();
    const std::string checkpoint = lab.FixtureCheckpoint();
    BOOST_REQUIRE(lab.AcceptFixtureBinding(cursor, optimizer, checkpoint, err));

    BOOST_CHECK(!lab.AcceptFixtureBinding("cursor-altered", optimizer, checkpoint, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");
    BOOST_CHECK(!lab.AcceptFixtureBinding(cursor, "optimizer-altered", checkpoint, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RNG");
    BOOST_CHECK(!lab.AcceptFixtureBinding(cursor, optimizer, "checkpoint-altered", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");

    const AdmissionResult one = lab.AdmitFixture({"root-a"});
    BOOST_CHECK(!one.admitted);
    BOOST_CHECK_EQUAL(one.code, "BTX035_REPLAY");
    const AdmissionResult duplicated = lab.AdmitFixture({"root-a", "root-a"});
    BOOST_CHECK(!duplicated.admitted);
    BOOST_CHECK_EQUAL(duplicated.code, "BTX035_REPLAY");
    const AdmissionResult none = lab.AdmitFixture({});
    BOOST_CHECK(!none.admitted);
    BOOST_CHECK_EQUAL(none.code, "BTX035_REPLAY");

    const AdmissionResult admitted = lab.AdmitFixture({"root-a", "root-b"});
    BOOST_CHECK(admitted.admitted);
    BOOST_CHECK(admitted.code.empty());
    BOOST_CHECK(admitted.ServeAllowed());
    BOOST_CHECK(!admitted.research_execution_permit);
}

BOOST_AUTO_TEST_CASE(e2e_003_retained_replica_reconstruction)
{
    using namespace modelnet;
    LabJourney bare;
    std::string err;
    BOOST_REQUIRE(bare.MarkOriginsDown(err));
    std::string missing;
    BOOST_CHECK(!bare.Reconstruct({}, missing, err));
    BOOST_CHECK(missing.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK(!bare.Reconstruct({"replica-1"}, missing, err));
    BOOST_CHECK(missing.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");

    LabJourney lab;
    BOOST_REQUIRE(lab.MarkOriginsDown(err));
    BOOST_REQUIRE(lab.RetainReplica("replica-1", err));
    std::string got;
    BOOST_REQUIRE(lab.Reconstruct({"replica-1"}, got, err));
    BOOST_CHECK_EQUAL(got, "replica-1");
    std::string none;
    BOOST_CHECK(!lab.Reconstruct({}, none, err));
    BOOST_CHECK(none.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");

    BOOST_CHECK(!lab.AcceptHook("#!/bin/sh\ncurl hook", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!lab.AcceptSpendPrompt("please wallet spend the grant", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PERMIT");
    BOOST_REQUIRE(lab.AcceptOwner("owner-key", "owner-key", err));
    BOOST_REQUIRE(lab.MarkKeyStolen("stolen-key", err));
    BOOST_CHECK(!lab.AcceptOwner("stolen-key", "stolen-key", err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDENTITY_REVOKED");
    BOOST_CHECK(!lab.WalletSpendAllowed());
}

BOOST_AUTO_TEST_CASE(e2e_004_promote_public_admitted_model)
{
    using namespace modelnet;
    LabJourney lab;
    std::string err;
    BOOST_CHECK_EQUAL(LabJourney::kPromotionThreshold, 2);
    BOOST_REQUIRE(lab.NotePublicAdmitted("model-public", err));
    BOOST_CHECK(!lab.Promote("model-public", "", {"att-1", "att-2"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_POLICY");
    BOOST_CHECK(!lab.Promoted("model-public"));
    BOOST_CHECK(!lab.Promote("model-public", "policy-dest", {"att-1"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_QUORUM_NOT_MET");
    BOOST_CHECK(!lab.Promote("model-public", "policy-dest", {"att-1", "att-1"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_QUORUM_NOT_MET");
    BOOST_CHECK(!lab.Promote("model-unknown", "policy-dest", {"att-1", "att-2"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ADMISSION_REQUIRED");
    BOOST_CHECK(!lab.Promoted("model-public"));
    BOOST_CHECK_EQUAL(lab.Threshold("policy-dest"), 0);

    BOOST_REQUIRE(lab.Promote("model-public", "policy-dest", {"att-1", "att-2"}, err));
    BOOST_CHECK(lab.Promoted("model-public"));
    BOOST_CHECK_EQUAL(lab.Threshold("policy-dest"), 2);

    const int64_t before = lab.Sequence("policy-dest");
    BOOST_REQUIRE(lab.Distribute("policy-dest", 0, "body-0", err));
    BOOST_CHECK(lab.Sequence("policy-dest") > before);
    const int64_t mid = lab.Sequence("policy-dest");
    BOOST_CHECK_EQUAL(mid, static_cast<int64_t>(0));
    BOOST_REQUIRE(lab.Distribute("policy-dest", 1, "body-1", err));
    BOOST_CHECK(lab.Sequence("policy-dest") > mid);
    BOOST_CHECK_EQUAL(lab.Sequence("policy-dest"), static_cast<int64_t>(1));
    BOOST_CHECK(!lab.Distribute("policy-dest", 0, "body-0", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(lab.Sequence("policy-dest"), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(e2e_005_attestor_threshold_and_pause)
{
    using namespace modelnet;
    LabJourney lab;
    std::string err;
    BOOST_REQUIRE(lab.PinAttestors("realm", 2, {"a", "b", "c"}, err));
    BOOST_CHECK_EQUAL(lab.Threshold("realm"), 2);
    BOOST_CHECK(lab.Quorum("realm", {"a", "b"}));
    const int threshold = lab.Threshold("realm");
    BOOST_REQUIRE(lab.RevokeAttestor("realm", "a", err));
    BOOST_CHECK_EQUAL(lab.Threshold("realm"), threshold);
    BOOST_CHECK_EQUAL(lab.Threshold("realm"), 2);
    BOOST_CHECK(!lab.Quorum("realm", {"b"}));
    BOOST_CHECK(!lab.Quorum("realm", {"a", "b"}));
    BOOST_CHECK(lab.Quorum("realm", {"b", "c"}));
    BOOST_CHECK(!lab.PinAttestors("realm", 1, {"b", "c"}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");
    BOOST_CHECK_EQUAL(lab.Threshold("realm"), 2);

    BOOST_REQUIRE(lab.Distribute("realm", 0, "h0", err));
    BOOST_REQUIRE(lab.Distribute("realm", 1, "h1", err));
    BOOST_CHECK_EQUAL(lab.Sequence("realm"), static_cast<int64_t>(1));
    BOOST_CHECK(!lab.Distribute("realm", 0, "h0", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(lab.Sequence("realm"), static_cast<int64_t>(1));

    BOOST_CHECK(!lab.AcceptRealm("alpha", "beta", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    BOOST_CHECK(lab.AcceptRealm("alpha", "alpha", err));

    BOOST_CHECK(!lab.AcceptPiece("piece-hash", "piece-hash-tampered", err));
    BOOST_CHECK_EQUAL(err, "BTX035_BYTE_HASH_MISMATCH");
    BOOST_CHECK(lab.AcceptPiece("piece-hash", "piece-hash", err));

    BOOST_CHECK(!lab.ExportPrivateToPublic("private-note", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM_EXPORT_DENIED");
    BOOST_CHECK(lab.PublicExport().empty());
    BOOST_CHECK(lab.PublicExport().find("private-note") == std::string::npos);

    BOOST_CHECK(!lab.AcceptDependency("tokenizer", false, err));
    BOOST_CHECK_EQUAL(err, "BTX035_DEPENDENCY_MISSING");
    BOOST_CHECK(lab.AcceptDependency("tokenizer", true, err));

    BOOST_CHECK(!lab.ReportEndpoint("edge-1", true, "HEALTHY", err));
    BOOST_CHECK_EQUAL(err, "BTX035_HEALTH");
    BOOST_CHECK_EQUAL(lab.HealthyCount(), 0);

    BOOST_REQUIRE(lab.Advance("realm", err));
    BOOST_CHECK_EQUAL(lab.Ring("realm"), static_cast<int64_t>(1));
    const int64_t sequence = lab.Sequence("realm");
    const int64_t ring = lab.Ring("realm");
    lab.Pause();
    BOOST_CHECK(lab.Paused());
    BOOST_CHECK(!lab.Advance("realm", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
    BOOST_CHECK(!lab.Distribute("realm", sequence + 1, "h2", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAUSED");
    BOOST_CHECK_EQUAL(lab.Sequence("realm"), sequence);
    BOOST_CHECK_EQUAL(lab.Ring("realm"), ring);
    BOOST_CHECK_EQUAL(lab.Threshold("realm"), 2);
}

BOOST_AUTO_TEST_CASE(e2e_006_offline_bundle_closure)
{
    using namespace modelnet;
    LabJourney lab;
    std::string err;
    BOOST_CHECK(!lab.WalletSpendAllowed());
    BOOST_REQUIRE(lab.Distribute("site", 0, "h0", err));
    BOOST_REQUIRE(lab.Distribute("site", 1, "h1", err));
    BOOST_REQUIRE(lab.Distribute("site", 2, "h2", err));
    BOOST_CHECK_EQUAL(lab.Sequence("site"), static_cast<int64_t>(2));

    BOOST_REQUIRE(lab.RecordOfflineBundle("bundle-offline", "closure-last", err));
    BOOST_REQUIRE(lab.RemoveIngress(err));
    BOOST_CHECK(!lab.IngressPresent());
    std::string closure;
    BOOST_REQUIRE(lab.ResolveClosure("bundle-offline", closure, err));
    BOOST_CHECK_EQUAL(closure, "closure-last");
    std::string missing;
    BOOST_CHECK(!lab.ResolveClosure("bundle-missing", missing, err));
    BOOST_CHECK(missing.empty());
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");

    BOOST_REQUIRE(lab.ActivatePolicy("policy-live", false, err));
    BOOST_CHECK(lab.PolicyActive("policy-live"));
    BOOST_CHECK(!lab.ActivatePolicy("policy-expired", true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_EXPIRED");
    BOOST_CHECK(!lab.PolicyActive("policy-expired"));
    BOOST_CHECK(lab.PolicyActive("policy-live"));

    const int64_t before = lab.Sequence("site");
    BOOST_CHECK(!lab.RestoreOlderBackup("site", before - 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK_EQUAL(lab.Sequence("site"), before);
    BOOST_CHECK(lab.Sequence("site") <= before);
    BOOST_CHECK(!lab.WalletSpendAllowed());
}

BOOST_AUTO_TEST_SUITE_END()
