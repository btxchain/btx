// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc06/acc06.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_defense/codes.h>
#include <modelnet/swarm_defwork/codes.h>
#include <modelnet/swarm_planner/codes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::Acc06& eng)
{
    std::string err;
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(acc06_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc06 eng;
    std::string err = "stale";
    const int64_t history_before = eng.plan_history();

    // DS-PLAN-001: hypotheses, dependencies, and negative evidence stay stored.
    BOOST_REQUIRE(eng.AdmitWork("hyp", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.hypothesis_persisted("hyp"));
    BOOST_CHECK(!eng.AdmitWork("hyp", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerReplay);
    BOOST_CHECK(eng.hypothesis_persisted("hyp"));

    BOOST_REQUIRE(eng.AdmitWork("before", err));
    BOOST_REQUIRE(eng.AdmitWork("after", err));
    BOOST_REQUIRE(eng.Depend("before", "after", err));
    BOOST_CHECK(!eng.Dispatch("after", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerBlocked);
    BOOST_CHECK(!eng.Depend("before", "after", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerReplay);
    BOOST_CHECK(!eng.Dispatch("after", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerBlocked);

    BOOST_REQUIRE(eng.AdmitEvidence("neg", err));
    BOOST_CHECK(eng.evidence_persisted("neg"));
    BOOST_CHECK(!eng.evidence_retracted("neg"));
    const int64_t history_admitted = eng.plan_history();
    BOOST_CHECK(history_admitted > history_before);
    BOOST_REQUIRE(eng.RetractEvidence("neg", err));
    BOOST_CHECK(eng.evidence_persisted("neg"));
    BOOST_CHECK(eng.evidence_retracted("neg"));
    BOOST_CHECK(eng.plan_history() == history_admitted + static_cast<int64_t>(1));
    BOOST_CHECK(!eng.RetractEvidence("neg", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerReplay);
    BOOST_CHECK(eng.evidence_retracted("neg"));
    BOOST_CHECK(eng.hypothesis_persisted("hyp"));

    // DS-PLAN-002: independent work can dispatch together; a conflict waits.
    BOOST_REQUIRE(eng.AdmitWork("left", err));
    BOOST_REQUIRE(eng.AdmitWork("right", err));
    BOOST_CHECK(eng.Dispatch("left", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Dispatch("right", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(eng.AdmitWork("first", err));
    BOOST_REQUIRE(eng.AdmitWork("second", err));
    BOOST_REQUIRE(eng.Depend("first", "second", err));
    BOOST_CHECK(!eng.Dispatch("second", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerBlocked);
    BOOST_CHECK(eng.Dispatch("left", err));
    BOOST_REQUIRE(eng.Finish("first", err));
    BOOST_CHECK(eng.Dispatch("second", err));
    BOOST_CHECK(err.empty());

    // DS-PLAN-003: only the signal named for that workload counts.
    BOOST_REQUIRE(eng.DefineSignal("triage", "cases", err));
    BOOST_REQUIRE(eng.DefineSignal("hunt", "leads", err));
    BOOST_CHECK(!eng.DefineSignal("triage", "leads", err));
    BOOST_CHECK_EQUAL(err, "SIGNAL");
    BOOST_CHECK_EQUAL(eng.signal_of("triage"), "cases");
    BOOST_CHECK(!eng.RecordSignal("triage", "leads", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "SIGNAL");
    BOOST_CHECK_EQUAL(eng.progress_of("triage"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.progress_of("hunt"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.RecordSignal("triage", "cases", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "PROGRESS");
    BOOST_CHECK_EQUAL(eng.progress_of("triage"), static_cast<int64_t>(0));
    BOOST_REQUIRE(eng.RecordSignal("triage", "cases", static_cast<int64_t>(2), err));
    BOOST_REQUIRE(eng.RecordSignal("hunt", "leads", static_cast<int64_t>(1), err));
    BOOST_REQUIRE(eng.RecordSignal("triage", "cases", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(eng.progress_of("triage"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.progress_of("hunt"), static_cast<int64_t>(1));

    // DS-PLAN-004: a retracted evidence predecessor invalidates the dependent.
    BOOST_REQUIRE(eng.AdmitEvidence("ev4", err));
    BOOST_REQUIRE(eng.AdmitWork("ev4", err));
    BOOST_REQUIRE(eng.AdmitWork("job4", err));
    BOOST_REQUIRE(eng.Depend("ev4", "job4", err));
    BOOST_CHECK(!eng.Dispatch("job4", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerBlocked);
    BOOST_REQUIRE(eng.RetractEvidence("ev4", err));
    BOOST_CHECK(eng.evidence_persisted("ev4"));
    BOOST_CHECK(eng.evidence_retracted("ev4"));
    BOOST_CHECK(!eng.Dispatch("job4", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerInvalid);
    BOOST_CHECK(eng.hypothesis_persisted("job4"));

    // DS-PLAN-005: cost bound and backpressure both refuse, and the held plan stays.
    BOOST_CHECK(!eng.AdmitPlan("over", modelnet::Acc06::kPlanBound + static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.plan_held("over"));
    BOOST_CHECK(!eng.AdmitPlan("zero", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_REQUIRE(eng.AdmitPlan("held", static_cast<int64_t>(5), err));
    BOOST_CHECK(eng.plan_held("held"));
    BOOST_CHECK(!eng.AdmitPlan("rest", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.plan_held("rest"));
    BOOST_CHECK_EQUAL(eng.committed_plan_cost(), static_cast<int64_t>(5));
    BOOST_REQUIRE(eng.SetBackpressure(true, err));
    BOOST_CHECK(eng.saturated());
    BOOST_CHECK(!eng.AdmitPlan("late", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "BACKPRESSURE");
    BOOST_CHECK(!eng.plan_held("late"));
    BOOST_CHECK(eng.plan_held("held"));
    BOOST_CHECK_EQUAL(eng.committed_plan_cost(), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.AdmitPlan("held", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.committed_plan_cost(), static_cast<int64_t>(5));

    // DS-PLAN-006: a local procedure survives loss of quorum and runtime.
    BOOST_REQUIRE(eng.KeepProcedure("run", "steps-v1", err));
    BOOST_CHECK(eng.quorum_present());
    BOOST_CHECK(eng.runtime_present());
    BOOST_REQUIRE(eng.ReplaceProcedure("run", "steps-v2", err));
    BOOST_CHECK_EQUAL(eng.procedure_of("run"), "steps-v2");
    BOOST_REQUIRE(eng.LoseQuorum(err));
    BOOST_CHECK(!eng.quorum_present());
    BOOST_CHECK(!eng.ReplaceProcedure("run", "steps-v3", err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.procedure_of("run"), "steps-v2");
    BOOST_REQUIRE(eng.LoseRuntime(err));
    BOOST_CHECK(!eng.runtime_present());
    BOOST_CHECK(!eng.ReplaceProcedure("run", "steps-v4", err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_CHECK_EQUAL(eng.procedure_of("run"), "steps-v2");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    // DS-ACT-001: the typed broker accepts D0-D3 and refuses D4 and an unknown level.
    BOOST_CHECK(eng.ProposeEffect("case", "act-d0", modelnet::kSwarmDefWorkD0, "asset-0", static_cast<int64_t>(1), err));
    BOOST_CHECK(eng.proposed("act-d0"));
    BOOST_CHECK_EQUAL(eng.asset_of("act-d0"), "asset-0");
    BOOST_CHECK(eng.ProposeEffect("case", "act-d1", modelnet::kSwarmDefWorkD1, "asset-1", static_cast<int64_t>(1), err));
    BOOST_CHECK(eng.ProposeEffect("case", "act-d2", modelnet::kSwarmDefWorkD2, "asset-2", static_cast<int64_t>(1), err));
    BOOST_CHECK(!eng.ProposeEffect("case", "act-d3", modelnet::kSwarmDefWorkD3, "asset-3", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkNeedApproval);
    BOOST_CHECK(eng.proposed("act-d3"));
    BOOST_CHECK(!eng.approved("act-d3"));
    BOOST_CHECK(!eng.ProposeEffect("case", "act-d4", modelnet::kSwarmDefWorkD4, "asset-4", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkRefused);
    BOOST_CHECK(!eng.proposed("act-d4"));
    BOOST_CHECK(!eng.ProposeEffect("case", "act-x", "OTHER", "asset-x", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkLevel);
    BOOST_CHECK(!eng.proposed("act-x"));

    // DS-ACT-002: D3 executes only after a present human approves it.
    BOOST_CHECK(!eng.ApprovePresent("case", "act-d3", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkNeedApproval);
    BOOST_CHECK(!eng.approved("act-d3"));
    BOOST_CHECK(!eng.ExecuteExact("case", "act-d3", "asset-3", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkNeedApproval);
    BOOST_CHECK(!eng.has_receipt("act-d3"));
    BOOST_REQUIRE(eng.ApprovePresent("case", "act-d3", true, err));
    BOOST_CHECK(eng.approved("act-d3"));
    BOOST_REQUIRE(eng.ExecuteExact("case", "act-d3", "asset-3", static_cast<int64_t>(2), err));
    BOOST_CHECK(eng.has_receipt("act-d3"));

    // DS-ACT-003: asset and blast must match the proposal, and a negative blast is not stored.
    BOOST_CHECK(!eng.ProposeEffect("case", "act-neg", modelnet::kSwarmDefWorkD0, "asset-n", static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkBlast);
    BOOST_CHECK(!eng.proposed("act-neg"));
    BOOST_CHECK(!eng.ExecuteExact("case", "act-d0", "other-asset", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkPrecondition);
    BOOST_CHECK(!eng.has_receipt("act-d0"));
    BOOST_CHECK_EQUAL(eng.asset_of("act-d0"), "asset-0");
    BOOST_CHECK(!eng.ExecuteExact("case", "act-d0", "asset-0", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkPrecondition);
    BOOST_CHECK_EQUAL(eng.blast_of("act-d0"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.has_receipt("act-d0"));
    BOOST_REQUIRE(eng.ExecuteExact("case", "act-d0", "asset-0", static_cast<int64_t>(1), err));
    BOOST_CHECK(eng.has_receipt("act-d0"));
    BOOST_CHECK_EQUAL(eng.blast_of("act-d0"), static_cast<int64_t>(1));

    // DS-ACT-004: a second execute does not add a receipt, and an unknown effect is not retried.
    const int64_t receipts = eng.receipt_count();
    BOOST_CHECK(!eng.ExecuteExact("case", "act-d0", "asset-0", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkReplay);
    BOOST_CHECK_EQUAL(eng.receipt_count(), receipts);
    BOOST_CHECK(eng.has_receipt("act-d0"));
    BOOST_REQUIRE(eng.ProposeEffect("case", "act-unk", modelnet::kSwarmDefWorkD1, "asset-u", static_cast<int64_t>(1), err));
    BOOST_CHECK(!eng.ReconcileUnknown("act-unk", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkAmbiguous);
    BOOST_CHECK(eng.ambiguous("act-unk"));
    BOOST_CHECK(!eng.ExecuteExact("case", "act-unk", "asset-u", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkAmbiguous);
    BOOST_CHECK(!eng.has_receipt("act-unk"));
    BOOST_CHECK(eng.ambiguous("act-unk"));

    // DS-ACT-005: a failed canary rolls back without dropping the asset or the receipt.
    BOOST_CHECK_EQUAL(eng.asset_of("act-d0"), "asset-0");
    BOOST_CHECK(!eng.CheckCanary("act-d0", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkRollback);
    BOOST_CHECK(eng.rolled_back("act-d0"));
    BOOST_CHECK(eng.has_receipt("act-d0"));
    BOOST_CHECK_EQUAL(eng.asset_of("act-d0"), "asset-0");
    BOOST_CHECK_EQUAL(eng.blast_of("act-d0"), static_cast<int64_t>(1));
    BOOST_REQUIRE(eng.ProposeEffect("case", "act-ok", modelnet::kSwarmDefWorkD0, "asset-ok", static_cast<int64_t>(3), err));
    BOOST_CHECK(eng.CheckCanary("act-ok", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.rolled_back("act-ok"));
    BOOST_CHECK_EQUAL(eng.asset_of("act-ok"), "asset-ok");
    BOOST_CHECK_EQUAL(eng.blast_of("act-ok"), static_cast<int64_t>(3));

    // DS-ACT-006: retaliation stores nothing and leaves the receipt in place.
    const int64_t receipts_before_retaliation = eng.receipt_count();
    BOOST_CHECK(!eng.RefuseRetaliation("act-d0", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefWorkOutOfScope);
    BOOST_CHECK(eng.has_receipt("act-d0"));
    BOOST_CHECK_EQUAL(eng.receipt_count(), receipts_before_retaliation);
    BOOST_CHECK_EQUAL(eng.asset_of("act-d0"), "asset-0");
    BOOST_CHECK(!eng.broadcast());

    // DS-SHARE-001: exact recipient, purpose, and a TLP 2.0 marking.
    const std::vector<std::string> allowed{"alice"};
    BOOST_REQUIRE(eng.AuthorizeShare("origin", "alice", "notify", "RED", allowed, "notify", "org-a", "org-a", false, err));
    BOOST_CHECK(eng.share_authorized("origin", "alice", "notify", "RED"));
    BOOST_CHECK_EQUAL(eng.share_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.AuthorizeShare("origin", "bob", "notify", "RED", allowed, "notify", "org-a", "org-a", false, err));
    BOOST_CHECK_EQUAL(err, "RECIPIENT");
    BOOST_CHECK(!eng.share_authorized("origin", "bob", "notify", "RED"));
    BOOST_CHECK_EQUAL(eng.share_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.AuthorizeShare("origin", "alice", "other", "RED", allowed, "notify", "org-a", "org-a", false, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK(!eng.AuthorizeShare("origin", "alice", "notify", "RED", allowed, "notify", "org-a", "org-b", false, err));
    BOOST_CHECK_EQUAL(err, "TLP");
    BOOST_CHECK(!eng.AuthorizeShare("origin", "alice", "notify", "AMBER+STRICT", allowed, "notify", "org-a", "org-b", false, err));
    BOOST_CHECK_EQUAL(err, "TLP");
    BOOST_CHECK(!eng.AuthorizeShare("origin", "alice", "notify", "GREEN", allowed, "notify", "org-a", "org-a", true, err));
    BOOST_CHECK_EQUAL(err, "TLP");
    BOOST_CHECK(!eng.AuthorizeShare("origin", "alice", "notify", "PRIVATE", allowed, "notify", "org-a", "org-a", false, err));
    BOOST_CHECK_EQUAL(err, "TLP");
    BOOST_REQUIRE(eng.AuthorizeShare("origin", "alice", "notify", "CLEAR", allowed, "notify", "org-a", "org-a", true, err));
    BOOST_CHECK(eng.share_authorized("origin", "alice", "notify", "CLEAR"));
    BOOST_CHECK(!eng.AuthorizeShare("origin", "alice", "notify", "RED", allowed, "notify", "org-a", "org-a", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.share_count(), static_cast<int64_t>(2));

    // DS-SHARE-002 and DS-SHARE-003: embargo expiry alone does not publish; both protections do.
    BOOST_REQUIRE(eng.OpenCase("customer", "case-a", "asset-a", "pol-1", static_cast<int64_t>(100), static_cast<int64_t>(1), err));
    BOOST_CHECK(!eng.PublishShare("case-a", "art-embargo", true, false, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefenseNotPublished);
    BOOST_CHECK(!eng.published("art-embargo"));
    BOOST_CHECK(!eng.PublishShare("case-a", "art-half", true, true, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefenseNotPublished);
    BOOST_CHECK(!eng.published("art-half"));
    BOOST_CHECK(!eng.PublishShare("case-a", "art-open", false, false, true, err));
    BOOST_CHECK(!eng.published("art-open"));
    BOOST_REQUIRE(eng.PublishShare("case-a", "art-ok", false, true, true, err));
    BOOST_CHECK(eng.published("art-ok"));
    BOOST_REQUIRE(eng.PublishShare("case-a", "art-late", true, true, true, err));
    BOOST_CHECK(eng.published("art-late"));

    // DS-SHARE-006: sharing does not grant training consent.
    BOOST_CHECK(!eng.training_allowed("case-a"));
    BOOST_REQUIRE(eng.GrantTraining("case-a", err));
    BOOST_CHECK(eng.training_allowed("case-a"));
    BOOST_REQUIRE(eng.OpenCase("customer", "case-b", "asset-b", "pol-1", static_cast<int64_t>(100), static_cast<int64_t>(1), err));
    BOOST_REQUIRE(eng.PublishShare("case-b", "art-b", false, true, true, err));
    BOOST_CHECK(eng.published("art-b"));
    BOOST_CHECK(!eng.training_allowed("case-b"));
    BOOST_CHECK(eng.training_allowed("case-a"));

    // DS-SHARE-004: another case and a missing id return the same not-visible result.
    const std::vector<unsigned char> bytes{1, 2, 3};
    BOOST_REQUIRE(eng.KeepEvidence("case-a", "ev-a", bytes, err));
    BOOST_CHECK_EQUAL(eng.evidence_body("ev-a").size(), static_cast<std::size_t>(3));
    BOOST_CHECK(!eng.SearchEvidence("case-b", "ev-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefenseNotVisible);
    std::string missing_err;
    BOOST_CHECK(!eng.SearchEvidence("case-a", "missing", missing_err));
    BOOST_CHECK_EQUAL(missing_err, err);
    BOOST_CHECK_EQUAL(missing_err, modelnet::kSwarmDefenseNotVisible);
    BOOST_CHECK(eng.SearchEvidence("case-a", "ev-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    // DS-SHARE-005: a versioned retraction does not change another artifact.
    BOOST_REQUIRE(eng.PutArtifact("art-1", "body-a", err));
    BOOST_REQUIRE(eng.PutArtifact("art-2", "body-b", err));
    BOOST_CHECK(!eng.DisseminateRetraction("art-1", static_cast<int64_t>(1), "withdrawn", err));
    BOOST_CHECK_EQUAL(err, "VERSION");
    BOOST_CHECK(!eng.artifact_retracted("art-1"));
    BOOST_REQUIRE(eng.DisseminateRetraction("art-1", static_cast<int64_t>(2), "withdrawn", err));
    BOOST_CHECK(eng.artifact_retracted("art-1"));
    BOOST_CHECK_EQUAL(eng.artifact_body("art-1"), "body-a");
    BOOST_CHECK_EQUAL(eng.artifact_version("art-1"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.retraction_notices(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.DisseminateRetraction("art-1", static_cast<int64_t>(2), "withdrawn", err));
    BOOST_CHECK_EQUAL(err, "VERSION");
    BOOST_CHECK_EQUAL(eng.retraction_notices(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.artifact_retracted("art-2"));
    BOOST_CHECK_EQUAL(eng.artifact_body("art-2"), "body-b");
    BOOST_CHECK_EQUAL(eng.artifact_version("art-2"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.broadcast());

    // DS-STD-001: STIX versions 2.0 and 2.1, and one external id maps to one object.
    BOOST_REQUIRE(eng.MapExternalId("indicator--1", "2.1", "cve", "2024-1", err));
    BOOST_CHECK_EQUAL(eng.object_for_external("cve", "2024-1"), "indicator--1");
    BOOST_CHECK_EQUAL(eng.stix_version("indicator--1"), "2.1");
    BOOST_CHECK(!eng.MapExternalId("indicator--2", "2.2", "cve", "2024-2", err));
    BOOST_CHECK_EQUAL(err, "VERSION");
    BOOST_CHECK(eng.object_for_external("cve", "2024-2").empty());
    BOOST_CHECK(!eng.MapExternalId("indicator--9", "2.0", "cve", "2024-1", err));
    BOOST_CHECK_EQUAL(err, "MAPPING");
    BOOST_CHECK_EQUAL(eng.object_for_external("cve", "2024-1"), "indicator--1");
    BOOST_CHECK_EQUAL(eng.stix_version("indicator--1"), "2.1");
    BOOST_REQUIRE(eng.MapExternalId("indicator--2", "2.0", "cve", "2024-2", err));
    BOOST_CHECK_EQUAL(eng.stix_version("indicator--2"), "2.0");
    BOOST_CHECK(!eng.MapExternalId("indicator--1", "2.1", "cve", "2024-1", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.object_for_external("cve", "2024-1"), "indicator--1");

    // DS-STD-002: write permission, read permission, and a page bound.
    BOOST_REQUIRE(eng.OpenCollection("col", true, true, err));
    BOOST_REQUIRE(eng.AddToCollection("col", "o1", err));
    BOOST_REQUIRE(eng.AddToCollection("col", "o2", err));
    BOOST_REQUIRE(eng.AddToCollection("col", "o3", err));
    std::vector<std::string> page;
    bool more = true;
    BOOST_CHECK(!eng.SyncCollection("col", static_cast<int64_t>(0), page, more, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(page.empty());
    BOOST_REQUIRE(eng.SyncCollection("col", static_cast<int64_t>(2), page, more, err));
    BOOST_REQUIRE_EQUAL(page.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(page[0], "o1");
    BOOST_CHECK_EQUAL(page[1], "o2");
    BOOST_CHECK(more);
    BOOST_REQUIRE(eng.SyncCollection("col", static_cast<int64_t>(2), page, more, err));
    BOOST_REQUIRE_EQUAL(page.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(page[0], "o3");
    BOOST_CHECK(!more);
    BOOST_REQUIRE(eng.OpenCollection("ro", true, false, err));
    BOOST_CHECK(!eng.AddToCollection("ro", "blocked", err));
    BOOST_CHECK_EQUAL(err, "TAXII");
    BOOST_CHECK_EQUAL(eng.collection_size("ro"), static_cast<int64_t>(0));
    BOOST_REQUIRE(eng.OpenCollection("wo", false, true, err));
    BOOST_REQUIRE(eng.AddToCollection("wo", "hidden", err));
    BOOST_CHECK(!eng.SyncCollection("wo", static_cast<int64_t>(1), page, more, err));
    BOOST_CHECK_EQUAL(err, "TAXII");
    BOOST_CHECK(page.empty());
    BOOST_CHECK_EQUAL(eng.collection_size("wo"), static_cast<int64_t>(1));

    // DS-STD-003: mapping versions accumulate and the raw event stays.
    BOOST_REQUIRE(eng.PreserveOcsf("evt-1", "1.1.0", "raw-1", err));
    BOOST_CHECK_EQUAL(eng.ocsf_raw("evt-1"), "raw-1");
    BOOST_CHECK(eng.ocsf_has_version("evt-1", "1.1.0"));
    BOOST_REQUIRE(eng.PreserveOcsf("evt-1", "1.2.0", "raw-1", err));
    BOOST_CHECK(eng.ocsf_has_version("evt-1", "1.1.0"));
    BOOST_CHECK(eng.ocsf_has_version("evt-1", "1.2.0"));
    BOOST_CHECK_EQUAL(eng.ocsf_raw("evt-1"), "raw-1");
    BOOST_CHECK(!eng.PreserveOcsf("evt-1", "1.3.0", "raw-2", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK_EQUAL(eng.ocsf_raw("evt-1"), "raw-1");
    BOOST_CHECK(!eng.ocsf_has_version("evt-1", "1.3.0"));
    BOOST_CHECK(eng.ocsf_has_version("evt-1", "1.1.0"));

    // DS-STD-004: every advertised backend must accept the rule.
    BOOST_CHECK_EQUAL(eng.advertised_backends(), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.AdvertiseBackend("windows", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.AdvertiseBackend("macos", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.AdvertiseBackend("other", err));
    BOOST_CHECK_EQUAL(err, "BACKEND");
    BOOST_CHECK_EQUAL(eng.advertised_backends(), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.ValidateRule("rule-one", "condition:selection", err));
    BOOST_CHECK_EQUAL(err, "BACKEND");
    BOOST_CHECK(!eng.rule_validated("rule-one"));
    BOOST_REQUIRE(eng.ValidateRule("rule-one", "selection:proc condition:selection", err));
    BOOST_CHECK(eng.rule_validated("rule-one"));
    BOOST_CHECK(!eng.ValidateRule("rule-one", "selection:proc condition:selection", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.rule_validated("rule-one"));
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.gpu_passed());

    // DS-STD-005: malformed and oversized events are refused; a small event is kept.
    const std::string well = "{\"event_type\":\"alert\"}";
    BOOST_CHECK(!eng.ParseEve("bad", "{\"timestamp\":1}", err));
    BOOST_CHECK_EQUAL(err, "MALFORMED");
    BOOST_CHECK(eng.eve_body("bad").empty());
    std::string oversized(modelnet::Acc06::kEveMax + static_cast<std::size_t>(1), 'x');
    oversized.front() = '{';
    oversized.back() = '}';
    BOOST_CHECK(!eng.ParseEve("big", oversized, err));
    BOOST_CHECK_EQUAL(err, "OVERSIZE");
    BOOST_CHECK(eng.eve_body("big").empty());
    BOOST_REQUIRE(eng.ParseEve("good", well, err));
    BOOST_CHECK_EQUAL(eng.eve_body("good"), well);
    BOOST_CHECK(!eng.ParseEve("good", "{\"event_type\":\"other\"}", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.eve_body("good"), well);
    BOOST_CHECK(!eng.release_qualified());

    // DS-STD-006: only the approved typed subset is imported, and nothing launches.
    BOOST_CHECK(!eng.ImportTyped("exec", err));
    BOOST_CHECK_EQUAL(err, "CACAO");
    BOOST_CHECK(!eng.cacao_imported("exec"));
    BOOST_CHECK(!eng.launched());
    BOOST_REQUIRE(eng.ImportTyped("log", err));
    BOOST_CHECK(eng.cacao_imported("log"));
    BOOST_REQUIRE(eng.ImportTyped("contain", err));
    BOOST_REQUIRE(eng.ImportTyped("allow", err));
    BOOST_REQUIRE(eng.ImportTyped("deny", err));
    BOOST_CHECK(!eng.ImportTyped("log", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.cacao_imported("log"));
    BOOST_CHECK(!eng.ImportTyped("contain-extra", err));
    BOOST_CHECK_EQUAL(err, "CACAO");
    BOOST_CHECK(!eng.cacao_imported("contain-extra"));
    BOOST_CHECK(!eng.launched());

    ExpectQuiet(eng);
    BOOST_CHECK(eng.hypothesis_persisted("hyp"));
    BOOST_CHECK(eng.evidence_retracted("neg"));
    BOOST_CHECK_EQUAL(eng.procedure_of("run"), "steps-v2");
    BOOST_CHECK(eng.has_receipt("act-d0"));
    BOOST_CHECK(eng.published("art-ok"));
    BOOST_CHECK(!eng.training_allowed("case-b"));
    BOOST_CHECK_EQUAL(eng.artifact_body("art-2"), "body-b");
    BOOST_CHECK(eng.rule_validated("rule-one"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.passed());
}

BOOST_AUTO_TEST_SUITE_END()
