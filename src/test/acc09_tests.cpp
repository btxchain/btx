// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc09/acc09.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(acc09_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc09 eng;
    std::string err = "stale";

    // P2P-SCN-O. Empty directory, no extra flag, stock lifecycle.
    modelnet::Acc09Lifecycle flagged;
    BOOST_CHECK(!eng.ActivateDefaultLifecycle("extra-flag", flagged, err));
    BOOST_CHECK_EQUAL(err, "FLAG");
    BOOST_CHECK(!flagged.observer);
    BOOST_CHECK(!flagged.trainer);
    BOOST_CHECK_EQUAL(flagged.workers, 0);
    modelnet::Acc09Lifecycle lifecycle;
    BOOST_CHECK(eng.ActivateDefaultLifecycle("", lifecycle, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(lifecycle.observer);
    BOOST_CHECK(!lifecycle.trainer);
    BOOST_CHECK(!lifecycle.evaluator);
    BOOST_CHECK_EQUAL(lifecycle.workers, 1);
    BOOST_CHECK_EQUAL(lifecycle.spend, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(lifecycle.spend, "0");
    BOOST_CHECK_EQUAL(lifecycle.code, "ADMITTED");

    // P2P-SCN-P. No VRAM. Observer, discovery, and CPU evaluation stay available.
    modelnet::Acc09CpuPlatform cpu;
    BOOST_CHECK(eng.SupportCpuWithoutGpu(cpu, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cpu.observer);
    BOOST_CHECK(cpu.evaluator);
    BOOST_CHECK(!cpu.trainer);
    BOOST_CHECK(!cpu.discovery_needs_public_address);
    BOOST_CHECK(cpu.lan_observed);
    BOOST_CHECK(!cpu.wan_observed);
    BOOST_CHECK_EQUAL(cpu.cpu_threads, 2);
    BOOST_CHECK_EQUAL(cpu.vram_bytes, static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.hardware_qualified());

    // P2P-SCN-R. Absent hardware, bytes, funding, authority, and path are not claimed.
    modelnet::Acc09Claims claims;
    BOOST_CHECK(eng.RefuseMissingClaims(claims, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!claims.trainer);
    BOOST_CHECK(!claims.engine_present);
    BOOST_CHECK(!claims.engine_advertised);
    BOOST_CHECK(!claims.model_verified);
    BOOST_CHECK(!claims.research_may_spend);
    BOOST_CHECK(!claims.unauthorized_executed);
    BOOST_CHECK(!claims.host_advertised);
    BOOST_CHECK(!claims.network_known);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.advertised());

    // P2P-SCN-A. One node, local community, no locator.
    modelnet::Acc09Community community;
    BOOST_CHECK(eng.CreateLocalCommunity("node-a", "family", "", community, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(community.local);
    BOOST_CHECK_EQUAL(community.creator, "node-a");
    BOOST_CHECK_EQUAL(community.id, "local/node-a/family");
    BOOST_CHECK_EQUAL(community.members.size(), 1U);
    BOOST_CHECK_EQUAL(community.members[0], "node-a");
    BOOST_CHECK_EQUAL(eng.community_count(), 1);
    modelnet::Acc09Community again;
    BOOST_CHECK(eng.CreateLocalCommunity("node-a", "family", "", again, err));
    BOOST_CHECK_EQUAL(again.id, community.id);
    BOOST_CHECK_EQUAL(again.members.size(), 1U);
    BOOST_CHECK_EQUAL(eng.community_count(), 1);
    modelnet::Acc09Community remote;
    BOOST_CHECK(!eng.CreateLocalCommunity("node-a", "family", "remote-locator", remote, err));
    BOOST_CHECK_EQUAL(err, "LOCATOR");
    BOOST_CHECK(remote.id.empty());
    BOOST_CHECK_EQUAL(eng.community_count(), 1);
    BOOST_CHECK_EQUAL(eng.recorded_peers(), 0);
    BOOST_CHECK(!eng.CreateLocalCommunity("", "family", "", remote, err));
    BOOST_CHECK_EQUAL(err, "NODE");
    BOOST_CHECK(!eng.CreateLocalCommunity("node-a", "", "", remote, err));
    BOOST_CHECK_EQUAL(err, "NAME");

    // P2P-SCN-J. Two derived descendants, author rejected, two evaluators qualify.
    modelnet::Acc09Descendants descendants;
    BOOST_CHECK(eng.CreateAndEvaluateDescendants(community.id, descendants, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(descendants.ids.size(), 2U);
    BOOST_CHECK_EQUAL(descendants.ids[0], community.id + "#1");
    BOOST_CHECK_EQUAL(descendants.ids[1], community.id + "#2");
    BOOST_CHECK(descendants.self_rejected);
    BOOST_CHECK(descendants.single_rejected);
    BOOST_CHECK(descendants.quorum);
    BOOST_CHECK_EQUAL(descendants.qualified, 2);
    BOOST_CHECK_EQUAL(descendants.frontier, 2);
    BOOST_CHECK(!eng.CreateAndEvaluateDescendants("missing", descendants, err));
    BOOST_CHECK_EQUAL(err, "COMMUNITY");

    // P2P-SCN-K. Qualified report, then stage, canary, activate, and rollback.
    modelnet::Acc09Generation generation;
    BOOST_CHECK(eng.StageActivateRollback(generation, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(generation.unsigned_stage_rejected);
    BOOST_CHECK(generation.qualified_report);
    BOOST_CHECK(generation.rolled_back);
    BOOST_CHECK_EQUAL(generation.active, "generation-0");
    BOOST_CHECK_EQUAL(generation.previous, "generation-1");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());

    // P2P-SCN-L. Local permit executes. A hosted locator does not.
    modelnet::Acc09Case hosted;
    BOOST_CHECK(!eng.OperateDefensiveCase("team-a", "case-a", "hosted-service", hosted, err));
    BOOST_CHECK_EQUAL(err, "SERVICE");
    BOOST_CHECK(hosted.receipt.empty());
    modelnet::Acc09Case denied;
    BOOST_CHECK(!eng.OperateDefensiveCase("", "case-a", "", denied, err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    modelnet::Acc09Case local_case;
    BOOST_CHECK(eng.OperateDefensiveCase("team-a", "case-a", "", local_case, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!local_case.receipt.empty());
    BOOST_CHECK(local_case.replay_rejected);
    BOOST_CHECK(local_case.spend_rejected);

    // P2P-SCN-N. Coordinator scope ends. Survivor reads the commitment.
    modelnet::Acc09Recovery recovery;
    BOOST_CHECK(eng.RecoverCommitted(recovery, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(recovery.continued);
    BOOST_CHECK_EQUAL(recovery.commitment_id, "c1");
    BOOST_CHECK(!recovery.scratch_visible);
    BOOST_CHECK(!recovery.empty_continues);
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    // Second host, second GPU, and regtest settlement are not claimed.
    const char* unqualified[] = {"P2P-SCN-B", "P2P-SCN-C", "P2P-SCN-D", "P2P-SCN-E", "P2P-SCN-F", "P2P-SCN-I", "P2P-SCN-M"};
    for (const char* id : unqualified) {
        BOOST_CHECK(!eng.RefuseUnqualified(id, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK_EQUAL(eng.final_acceptance(id), "UNQUALIFIED");
        BOOST_CHECK_EQUAL(eng.recorded_peers(), 0);
        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    }

    // G, H, and Q stay defined. The missing process is not faked.
    modelnet::Acc09ProcessNote local_model;
    BOOST_CHECK(!eng.NoteNeedsProcess("P2P-SCN-G", local_model, err));
    BOOST_CHECK_EQUAL(err, "NEEDS_PROCESS");
    BOOST_CHECK(!local_model.inference_ran);
    BOOST_CHECK(!local_model.engine_present);
    BOOST_CHECK_EQUAL(eng.final_acceptance("P2P-SCN-G"), "DEFINED_NEEDS_PROCESS");

    modelnet::Acc09ProcessNote kv;
    BOOST_CHECK(!eng.NoteNeedsProcess("P2P-SCN-H", kv, err));
    BOOST_CHECK_EQUAL(err, "NEEDS_PROCESS");
    BOOST_CHECK(!kv.shared);
    BOOST_CHECK(!kv.bytes_moved);
    BOOST_CHECK_EQUAL(kv.kv_code, "HELD");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.final_acceptance("P2P-SCN-H"), "DEFINED_NEEDS_PROCESS");

    modelnet::Acc09ProcessNote cloud;
    BOOST_CHECK(!eng.NoteNeedsProcess("P2P-SCN-Q", cloud, err));
    BOOST_CHECK_EQUAL(err, "NEEDS_PROCESS");
    BOOST_CHECK(cloud.discovery_without_cloud);
    BOOST_CHECK(cloud.guard_without_cloud);
    BOOST_CHECK(!cloud.inference_ran);
    BOOST_CHECK_EQUAL(cloud.peers_chosen, 0);
    BOOST_CHECK_EQUAL(eng.final_acceptance("P2P-SCN-Q"), "DEFINED_NEEDS_PROCESS");

    const char* closed[] = {"P2P-SCN-A", "P2P-SCN-J", "P2P-SCN-K", "P2P-SCN-L", "P2P-SCN-N", "P2P-SCN-O", "P2P-SCN-P", "P2P-SCN-R"};
    for (const char* id : closed) {
        BOOST_CHECK_EQUAL(eng.final_acceptance(id), "CLOSED_IN_PROCESS");
        BOOST_CHECK(!eng.evidence(id).empty());
        BOOST_CHECK_EQUAL(eng.native_status(id), "NOT_RUN_NATIVE");
    }
    for (const char* id : unqualified) {
        BOOST_CHECK(!eng.evidence(id).empty());
        BOOST_CHECK_EQUAL(eng.native_status(id), "NOT_RUN_NATIVE");
    }
    BOOST_CHECK_EQUAL(eng.native_status("P2P-SCN-G"), "NOT_RUN_NATIVE");
    BOOST_CHECK_EQUAL(eng.native_status("P2P-SCN-H"), "NOT_RUN_NATIVE");
    BOOST_CHECK_EQUAL(eng.native_status("P2P-SCN-Q"), "NOT_RUN_NATIVE");
    BOOST_CHECK(eng.final_acceptance("P2P-SCN-S").empty());
    BOOST_CHECK(eng.evidence("P2P-SCN-S").empty());
    BOOST_CHECK(eng.native_status("P2P-SCN-S").empty());

    const int communities = eng.community_count();
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.community_count(), communities);
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.community_count(), communities);

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.recorded_peers(), 0);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.passed());
}

BOOST_AUTO_TEST_SUITE_END()
