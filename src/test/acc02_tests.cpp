// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc02/acc02.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_discover/codes.h>
#include <modelnet/swarm_evidence/codes.h>
#include <modelnet/swarm_handoff/swarm_handoff.h>
#include <modelnet/swarm_progress/codes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(acc02_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc02 eng;
    std::string err = "stale";

    const char* const closed[] = {
        "ASR-EXE-007", "ASR-NET-001", "ASR-NET-002", "ASR-NET-003", "ASR-NET-004", "ASR-NET-005",
        "ASR-HND-001", "ASR-HND-002", "ASR-HND-003", "ASR-HND-004", "ASR-PRG-001", "ASR-PRG-002",
        "ASR-PRG-003", "ASR-PRG-004", "ASR-EVD-001", "ASR-EVD-002", "ASR-EVD-003", "ASR-EVD-004",
        "ASR-EVD-005", "ASR-CAP-001", "ASR-CAP-003", "ASR-CAP-004", "ASR-ART-001",
    };
    for (const char* id : closed) {
        BOOST_CHECK(!eng.covered(id));
    }
    BOOST_CHECK(!eng.covered("ASR-CAP-002"));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.process_present());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.passes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.authority_until(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");

    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Qualify(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());

    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.passes(), static_cast<int64_t>(1));
    for (const char* id : closed) {
        BOOST_CHECK(eng.covered(id));
    }
    BOOST_CHECK(!eng.covered("ASR-CAP-002"));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());

    // Sleep and a larger claimed bound do not extend the issued authority.
    BOOST_CHECK_EQUAL(eng.authority_until(), static_cast<int64_t>(100));
    BOOST_CHECK(!eng.TryExtendAuthority(static_cast<int64_t>(50), static_cast<int64_t>(9000), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.authority_until(), static_cast<int64_t>(100));
    BOOST_CHECK(!eng.TryUseAuthority(static_cast<int64_t>(101), err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK_EQUAL(eng.authority_until(), static_cast<int64_t>(100));

    // Discovery does not scan. A lower delay does not replace the grant.
    BOOST_CHECK(!eng.Scan(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDiscoverNotScan);
    BOOST_CHECK(!eng.discover().connected());
    BOOST_CHECK_EQUAL(eng.discover().bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.discover().granted("peer-a"));
    BOOST_CHECK(!eng.RouteOutsideScope(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmDiscoverScope);
    BOOST_CHECK_EQUAL(eng.discover().route_grant_id("obj"), "grant-1");
    BOOST_CHECK_EQUAL(eng.discover().route_peer("obj"), "peer-b");
    BOOST_CHECK_EQUAL(eng.discover().route_rtt_ms("obj"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.discover().status(), modelnet::kSwarmDiscoverPartition);
    BOOST_CHECK(eng.drain().drained());
    BOOST_CHECK_EQUAL(eng.drain().physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.drain().bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.handoff().scoped());
    BOOST_CHECK_EQUAL(eng.handoff().authority_destination(), "dest-ok");
    BOOST_CHECK(eng.handoff().authority_generation() != static_cast<uint64_t>(0));
    BOOST_CHECK(eng.handoff().committed("move-ok"));
    BOOST_CHECK(eng.handoff().atomic("move-ok"));
    BOOST_CHECK_EQUAL(eng.handoff().owner(), "dest-ok");
    BOOST_CHECK(eng.handoff().ambiguous("move-cross"));
    BOOST_CHECK(!eng.handoff().atomic("move-cross"));
    BOOST_CHECK(eng.handoff().owner_of("move-cross").empty());
    BOOST_CHECK(!eng.RefuseAmbiguousAgain(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffAmbiguous);
    BOOST_CHECK(!eng.handoff().atomic("move-cross"));
    BOOST_CHECK(!eng.handoff().spend_key_moved());
    BOOST_CHECK_EQUAL(eng.handoff().atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.resumed().State().step, static_cast<uint64_t>(2));
    BOOST_CHECK(eng.resumed().State().weight != eng.weight_before_resume());
    BOOST_CHECK(!eng.resumed().State().state_hash.empty());

    BOOST_CHECK(eng.progress().meaningful());
    BOOST_CHECK_EQUAL(eng.progress().loss_ppm(), static_cast<int64_t>(800));
    BOOST_CHECK_EQUAL(eng.progress().step(), static_cast<int64_t>(2));
    BOOST_CHECK(eng.progress().correcting());
    BOOST_CHECK(!eng.progress().killed());
    BOOST_CHECK_EQUAL(eng.progress().recipe(), "recipe-a");
    BOOST_CHECK_EQUAL(eng.progress().bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.evidence().stored("trace"));
    BOOST_CHECK(!eng.evidence().shareable("trace"));
    BOOST_CHECK(!eng.ShareTrace(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmEvidenceNotVisible);
    BOOST_CHECK_EQUAL(eng.evidence().summary_source("sum"), "trace");
    BOOST_CHECK(eng.evidence().tainted("note"));
    BOOST_CHECK(!eng.evidence().launched());
    BOOST_CHECK(eng.evidence().promised("promise"));
    BOOST_CHECK(eng.evidence().body("promise").empty());
    BOOST_CHECK(!eng.RetrievePromise(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmEvidenceNotRetrievable);
    BOOST_CHECK_EQUAL(eng.evidence().bytes_moved(), static_cast<int64_t>(0));

    const modelnet::SwarmRevokeGateResult gated = eng.FenceResult(err);
    BOOST_CHECK(!gated.allowed);
    BOOST_CHECK(!gated.bytes_moved);
    BOOST_CHECK_EQUAL(gated.code, "REVOKED");
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_CHECK(eng.resumed().State().step >= static_cast<uint64_t>(1));

    BOOST_CHECK(!eng.interpreters().admitted("package-author"));
    BOOST_CHECK(!eng.interpreters().launched());
    BOOST_CHECK(eng.sandbox().allowed("/work/unit"));
    BOOST_CHECK(!eng.sandbox().allowed("/else/unit"));
    BOOST_CHECK(!eng.sandbox().allowed("/work/../unit"));
    BOOST_CHECK(!eng.sandbox().launched());
    BOOST_CHECK_EQUAL(eng.updates().SourceExporter(), "runtime");
    BOOST_CHECK_EQUAL(eng.updates().DestinationApprover(), "model");
    BOOST_CHECK(eng.updates().SourceExporter() != eng.updates().DestinationApprover());
    BOOST_CHECK(eng.manifest().usable("root"));
    BOOST_CHECK(eng.manifest().usable("root-b"));
    BOOST_CHECK(!eng.manifest().usable("root-open"));
    BOOST_CHECK(!eng.manifest().bytes_streamed());

    BOOST_CHECK(!eng.Qualify(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    const int64_t step_after = static_cast<int64_t>(eng.resumed().State().step);
    const int64_t weight_after = eng.resumed().State().weight;
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.passes(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.resumed().State().step), step_after);
    BOOST_CHECK_EQUAL(eng.resumed().State().weight, weight_after);
    BOOST_CHECK_EQUAL(eng.authority_until(), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.drain().physical_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.covered("ASR-CAP-002"));
    BOOST_CHECK(eng.covered("ASR-EXE-007"));
    BOOST_CHECK(eng.covered("ASR-ART-001"));
}

BOOST_AUTO_TEST_SUITE_END()
