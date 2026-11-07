// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc07/acc07.h>
#include <modelnet/dt_ckpt/codes.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_defbudget/codes.h>
#include <modelnet/swarm_defbudget/limits.h>
#include <modelnet/swarm_generation/codes.h>
#include <modelnet/swarm_payreg/codes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Acc07& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(acc07_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc07 eng;
    std::string err = "stale";
    std::string value;
    Idle(eng);

    BOOST_CHECK(!eng.PutIncidentKv("tenant-a", static_cast<int64_t>(-1), "key-1", "value-1", true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.PutIncidentKv("tenant-a", static_cast<int64_t>(3), "key-1", "value-1", false, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK(!eng.ReadIncidentKv("tenant-a", static_cast<int64_t>(3), "tenant-a", "key-1", value, err));
    BOOST_CHECK(value.empty());
    BOOST_CHECK(eng.PutIncidentKv("tenant-a", static_cast<int64_t>(3), "key-1", "value-1", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.ReadIncidentKv("tenant-a", static_cast<int64_t>(3), "tenant-b", "key-1", value, err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK(value.empty());
    BOOST_CHECK(!eng.ReadIncidentKv("tenant-a", static_cast<int64_t>(4), "tenant-a", "key-1", value, err));
    BOOST_CHECK_EQUAL(err, "EPOCH");
    BOOST_CHECK(value.empty());
    BOOST_CHECK(eng.ReadIncidentKv("tenant-a", static_cast<int64_t>(3), "tenant-a", "key-1", value, err));
    BOOST_CHECK_EQUAL(value, "value-1");
    BOOST_CHECK(!eng.PutIncidentKv("tenant-a", static_cast<int64_t>(3), "key-1", "other", true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK(eng.ReadIncidentKv("tenant-a", static_cast<int64_t>(3), "tenant-a", "key-1", value, err));
    BOOST_CHECK_EQUAL(value, "value-1");

    BOOST_CHECK(!eng.ApprovePublic("ctx-1", "ann", "bo", "private suffix", "case-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.ApprovePublic("ctx-1", "ann", "ann", "public prefix", "case-a", err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK(eng.ApprovePublic("ctx-1", "ann", "bo", "public prefix", "case-a", err));
    BOOST_CHECK(!eng.ReusePublic("ctx-1", "case-a", err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK(!eng.ReusePublic("missing", "case-b", err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK(eng.ReusePublic("ctx-1", "case-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.ApprovePublic("ctx-1", "ann", "cy", "public prefix", "case-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.ReusePublic("ctx-1", "case-c", err));

    std::vector<unsigned char> dst;
    int64_t measured = static_cast<int64_t>(-1);
    BOOST_CHECK(!eng.MeasureCache({}, dst, measured, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK_EQUAL(measured, static_cast<int64_t>(0));
    const std::vector<unsigned char> cache{1, 2, 3, 4, 5};
    BOOST_CHECK(eng.MeasureCache(cache, dst, measured, err));
    BOOST_CHECK(dst == cache);
    BOOST_CHECK_EQUAL(measured, static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.transfer_measured(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    const std::vector<unsigned char> weights{1, 2, 3, 4};
    BOOST_CHECK(!eng.CompleteCheckpoint(weights, {}, {}, err));
    BOOST_CHECK_EQUAL(err, modelnet::kDtCkptPartial);
    BOOST_CHECK(!eng.checkpoint_exact());
    const std::vector<unsigned char> adam_m{9, 9};
    const std::vector<unsigned char> adam_v{8, 8};
    BOOST_CHECK(eng.CompleteCheckpoint(weights, adam_m, adam_v, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.checkpoint_exact());
    BOOST_CHECK(eng.checkpoint_weights() == weights);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.OpenIncident("case-1", "gen-1", err));
    BOOST_CHECK(!eng.SwapGeneration("case-1", "gen-2", err));
    BOOST_CHECK_EQUAL(err, "PIN");
    BOOST_CHECK(eng.incident_active("case-1"));
    BOOST_CHECK_EQUAL(eng.generation_of("case-1"), "gen-1");
    BOOST_CHECK(eng.CloseIncident("case-1", err));
    BOOST_CHECK(!eng.incident_active("case-1"));
    BOOST_CHECK_EQUAL(eng.generation_of("case-1"), "gen-1");
    BOOST_CHECK(eng.OpenIncident("case-1", "gen-2", err));
    BOOST_CHECK_EQUAL(eng.generation_of("case-1"), "gen-2");
    BOOST_CHECK(eng.incident_active("case-1"));

    BOOST_CHECK(!eng.Place("loc-a", "proc-a", err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(eng.RestrictPlacement("loc-a", "proc-a", err));
    BOOST_CHECK(!eng.Place("loc-a", "proc-b", err));
    BOOST_CHECK_EQUAL(err, "PROCESSOR");
    BOOST_CHECK(!eng.Place("loc-b", "proc-a", err));
    BOOST_CHECK_EQUAL(err, "LOCATION");
    BOOST_CHECK(eng.Place("loc-a", "proc-a", err));
    BOOST_CHECK(!eng.RestrictPlacement("loc-z", "proc-a", err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK(eng.Place("loc-a", "proc-a", err));

    BOOST_CHECK(eng.GrantCapability(err));
    BOOST_CHECK(eng.UseCapability(err));
    BOOST_CHECK(eng.PoisonCache("sample-1", err));
    BOOST_CHECK(!eng.UseCapability(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(!eng.GrantCapability(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(!eng.capability_granted());
    {
        modelnet::Acc07 qualify;
        BOOST_CHECK(qualify.GrantCapability(err));
        BOOST_CHECK(qualify.UseCapability(err));
        BOOST_CHECK(qualify.FailRuntimeQualification(err));
        BOOST_CHECK(!qualify.UseCapability(err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
        BOOST_CHECK(!qualify.qualified());
        BOOST_CHECK(!qualify.capability_granted());
    }

    BOOST_CHECK(!eng.IssueLearningRelease(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());

    BOOST_CHECK(eng.AssignHoldout("s1", "time", "line-a", err));
    BOOST_CHECK(eng.AssignHoldout("s2", "campaign", "line-b", err));
    BOOST_CHECK(eng.AssignHoldout("s3", "tenant", "line-c", err));
    BOOST_CHECK(eng.AssignHoldout("s4", "lineage", "line-d", err));
    BOOST_CHECK(eng.holdouts_separated());
    BOOST_CHECK(!eng.AssignHoldout("s5", "campaign", "line-a", err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK(eng.holdouts_separated());
    BOOST_CHECK(!eng.AssignHoldout("s1", "time", "line-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);

    BOOST_CHECK(!eng.PreserveCase("customer", "src", "mit", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.PreserveCase("synthetic", "", "mit", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!eng.PreserveCase("synthetic", "src-synth", "", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmGenerationLicense);
    BOOST_CHECK(eng.PreserveCase("synthetic", "src-synth", "mit", err));
    BOOST_CHECK_EQUAL(eng.provenance_of("synthetic"), "src-synth");
    BOOST_CHECK_EQUAL(eng.license_of("synthetic"), "mit");
    BOOST_CHECK(eng.PreserveCase("public", "src-pub", "apache", err));
    BOOST_CHECK_EQUAL(eng.provenance_of("public"), "src-pub");
    BOOST_CHECK(!eng.PreserveCase("synthetic", "src-synth", "mit", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.provenance_of("synthetic"), "src-synth");

    BOOST_CHECK(!eng.JointDecision(true, false, false, err));
    BOOST_CHECK_EQUAL(err, "HARM");
    BOOST_CHECK(!eng.JointDecision(false, true, false, err));
    BOOST_CHECK_EQUAL(err, "UTILITY");
    BOOST_CHECK(!eng.JointDecision(true, true, true, err));
    BOOST_CHECK_EQUAL(err, "HARM");
    BOOST_CHECK(!eng.joint_accepted());
    BOOST_CHECK(eng.JointDecision(true, true, false, err));
    BOOST_CHECK(eng.joint_accepted());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.JointDecision(false, true, false, err));
    BOOST_CHECK(eng.joint_accepted());

    BOOST_CHECK(eng.TrainCompeting(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.parent_hash().empty());
    BOOST_CHECK(eng.parent_hash() != eng.left_hash());
    BOOST_CHECK(eng.parent_hash() != eng.right_hash());
    BOOST_CHECK(eng.left_hash() != eng.right_hash());
    BOOST_CHECK(!eng.EvaluateDescendant("auditor", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmGenerationSelf);
    BOOST_CHECK(eng.EvaluateDescendant("auditor", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.gpu());

    BOOST_CHECK(!eng.SecondResearchCycle(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(eng.research_cycle(), 0);
    BOOST_CHECK(!eng.gpu());

    BOOST_CHECK(!eng.PromiseEmergency(static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK(eng.FundPool(modelnet::kSwarmDefBudgetPoolReadiness, "out-r", static_cast<int64_t>(10), err));
    BOOST_CHECK(eng.FundPool(modelnet::kSwarmDefBudgetPoolIncident, "out-i", static_cast<int64_t>(7), err));
    BOOST_CHECK(eng.FundPool(modelnet::kSwarmDefBudgetPoolImprovement, "out-f", static_cast<int64_t>(4), err));
    BOOST_CHECK(eng.PromiseEmergency(static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(eng.emergency_atoms(), static_cast<int64_t>(8));
    BOOST_CHECK(eng.PayMilestone(modelnet::kSwarmDefBudgetPoolReadiness, "mile-1", static_cast<int64_t>(3), static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolReadiness), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolIncident), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolImprovement), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.FundPool(modelnet::kSwarmDefBudgetPoolIncident, "out-r", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefBudgetOutpoint);
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolIncident), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolReadiness), static_cast<int64_t>(7));

    BOOST_CHECK(eng.ReconcileAtoms(static_cast<int64_t>(10), static_cast<int64_t>(1), static_cast<int64_t>(2), static_cast<int64_t>(3), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(eng.available(), static_cast<int64_t>(3));
    BOOST_CHECK(!eng.ReconcileAtoms(static_cast<int64_t>(5), static_cast<int64_t>(3), static_cast<int64_t>(3), static_cast<int64_t>(0), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BALANCE");
    BOOST_CHECK_EQUAL(eng.available(), static_cast<int64_t>(3));

    BOOST_CHECK(!eng.JoinPool(modelnet::kSwarmDefBudgetPoolReadiness, "member-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefBudgetNotPaid);
    BOOST_CHECK(eng.member_of(modelnet::kSwarmDefBudgetPoolReadiness, "member-a"));
    BOOST_CHECK_EQUAL(eng.earned_count(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.EarnWork(modelnet::kSwarmDefBudgetPoolReadiness, "work-1", "receipt-1", "member-a", static_cast<int64_t>(4), err));
    BOOST_CHECK(eng.earned("work-1"));
    BOOST_CHECK_EQUAL(eng.earned_atoms(modelnet::kSwarmDefBudgetPoolReadiness), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolReadiness), static_cast<int64_t>(7));

    std::vector<modelnet::Acc07Weight> weights_even{
        {"a", static_cast<int64_t>(1), static_cast<int64_t>(100)},
        {"b", static_cast<int64_t>(1), static_cast<int64_t>(100)},
        {"c", static_cast<int64_t>(1), static_cast<int64_t>(100)},
    };
    std::vector<int64_t> paid;
    int64_t unallocated = static_cast<int64_t>(-1);
    BOOST_CHECK(eng.AllocateMilestones(static_cast<int64_t>(10), weights_even, paid, unallocated, err));
    BOOST_CHECK_EQUAL(paid.size(), 3);
    BOOST_CHECK_EQUAL(paid[0], static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(paid[1], static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(paid[2], static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(unallocated, static_cast<int64_t>(0));
    std::vector<int64_t> paid_again;
    int64_t unallocated_again = static_cast<int64_t>(-1);
    BOOST_CHECK(eng.AllocateMilestones(static_cast<int64_t>(10), weights_even, paid_again, unallocated_again, err));
    BOOST_CHECK(paid_again == paid);
    BOOST_CHECK_EQUAL(unallocated_again, unallocated);
    std::vector<modelnet::Acc07Weight> capped{
        {"a", static_cast<int64_t>(1), static_cast<int64_t>(3)},
        {"b", static_cast<int64_t>(1), static_cast<int64_t>(10)},
        {"c", static_cast<int64_t>(1), static_cast<int64_t>(10)},
    };
    BOOST_CHECK(eng.AllocateMilestones(static_cast<int64_t>(10), capped, paid, unallocated, err));
    BOOST_CHECK_EQUAL(paid[0], static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(paid[1], static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(paid[2], static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(paid[0] + paid[1] + paid[2] + unallocated, static_cast<int64_t>(10));
    std::vector<modelnet::Acc07Weight> zero_weight{
        {"a", static_cast<int64_t>(0), static_cast<int64_t>(5)},
        {"b", static_cast<int64_t>(0), static_cast<int64_t>(5)},
    };
    BOOST_CHECK(eng.AllocateMilestones(static_cast<int64_t>(5), zero_weight, paid, unallocated, err));
    BOOST_CHECK_EQUAL(paid[0], static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(paid[1], static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(unallocated, static_cast<int64_t>(5));

    const int64_t earned_before = eng.earned_count();
    BOOST_CHECK(eng.SetPayer("payer-a", err));
    BOOST_CHECK(!eng.SelfDeal("payer-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefBudgetSelf);
    BOOST_CHECK_EQUAL(eng.earned_count(), earned_before);
    BOOST_CHECK(eng.SelfDeal("member-b", err));
    BOOST_CHECK_EQUAL(eng.earned_count(), earned_before);
    BOOST_CHECK(!eng.EarnWork(modelnet::kSwarmDefBudgetPoolIncident, "work-2", "receipt-1", "member-b", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefBudgetDuplicate);
    BOOST_CHECK_EQUAL(eng.earned_count(), earned_before);
    BOOST_CHECK(!eng.PayMilestone(modelnet::kSwarmDefBudgetPoolIncident, "mile-big", static_cast<int64_t>(100), static_cast<int64_t>(100), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDefBudgetNegative);
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolIncident), static_cast<int64_t>(7));
    const int64_t ready_before = eng.pool_balance(modelnet::kSwarmDefBudgetPoolReadiness);
    BOOST_CHECK(!eng.RaiseForUrgent(modelnet::kSwarmDefBudgetPoolReadiness, err));
    BOOST_CHECK_EQUAL(err, "RATE");
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolReadiness), ready_before);
    BOOST_CHECK_EQUAL(eng.earned_atoms(modelnet::kSwarmDefBudgetPoolReadiness), static_cast<int64_t>(4));

    modelnet::Acc07Disclosure disclosure;
    BOOST_CHECK(eng.DisclosePayment(disclosure, err));
    BOOST_CHECK_EQUAL(disclosure.mode, modelnet::kSwarmPayRegMode);
    BOOST_CHECK_EQUAL(disclosure.mode, "REGTEST_UNBROADCAST");
    BOOST_CHECK(!disclosure.enforceable);
    BOOST_CHECK(!disclosure.spendable);
    BOOST_CHECK_EQUAL(disclosure.oracle_trust, "ORACLE_NOT_SETTLEMENT");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.QualifyNativeFunding(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.ProvePaymentPaths(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(eng.ReserveBacking("incident-pool", "out-pay", static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(eng.funded_backing("incident-pool"), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.NoteCredit("incident-pool", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPayRegNotBacking);
    BOOST_CHECK_EQUAL(eng.credit_note("incident-pool"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.funded_backing("incident-pool"), static_cast<int64_t>(8));
    BOOST_CHECK(eng.RouteTerms("route-1", static_cast<int64_t>(3), static_cast<int64_t>(160), err));
    BOOST_CHECK_EQUAL(eng.route_atoms("route-1"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.funded_backing("incident-pool"), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.credit_note("incident-pool"), static_cast<int64_t>(5));

    BOOST_CHECK(!eng.PromiseEmergency(static_cast<int64_t>(8), err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK_EQUAL(eng.emergency_atoms(), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.PromiseEmergency(static_cast<int64_t>(11), err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK_EQUAL(eng.emergency_atoms(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolReadiness), ready_before);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.NotePending("pending-1", err));
    BOOST_CHECK(eng.KeepClaim("earned-1", err));
    eng.FailCompute();
    BOOST_CHECK(eng.compute_failed());
    BOOST_CHECK(eng.claim_kept("earned-1"));
    BOOST_CHECK(eng.pending("pending-1"));
    BOOST_CHECK(eng.Reorganize(err));
    BOOST_CHECK(!eng.pending("pending-1"));
    BOOST_CHECK(eng.claim_kept("earned-1"));
    BOOST_CHECK(eng.compute_failed());
    BOOST_CHECK(eng.Reorganize(err));
    BOOST_CHECK(eng.claim_kept("earned-1"));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(eng.ReadIncidentKv("tenant-a", static_cast<int64_t>(3), "tenant-a", "key-1", value, err));
    BOOST_CHECK_EQUAL(value, "value-1");
    BOOST_CHECK_EQUAL(eng.generation_of("case-1"), "gen-2");
    BOOST_CHECK(eng.ReusePublic("ctx-1", "case-b", err));
    BOOST_CHECK_EQUAL(eng.transfer_measured(), static_cast<int64_t>(5));
    BOOST_CHECK(eng.checkpoint_weights() == weights);
    BOOST_CHECK(eng.holdouts_separated());
    BOOST_CHECK(eng.joint_accepted());
    BOOST_CHECK_EQUAL(eng.available(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.emergency_atoms(), static_cast<int64_t>(8));
    BOOST_CHECK(eng.claim_kept("earned-1"));
    BOOST_CHECK(!eng.capability_granted());
    BOOST_CHECK(eng.parent_hash() != eng.left_hash());
    BOOST_CHECK_EQUAL(eng.pool_balance(modelnet::kSwarmDefBudgetPoolImprovement), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.research_cycle(), 0);
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
