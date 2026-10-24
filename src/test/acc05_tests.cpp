// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc05/acc05.h>
#include <modelnet/action_authority.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Latches(const modelnet::Acc05& eng)
{
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!modelnet::ResearchMaySpend());
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(acc05_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc05 eng;
    std::string err = "stale";
    Latches(eng);
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    Latches(eng);

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("DS-PLAN-001", "", "x", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");

    BOOST_CHECK(!eng.Apply("DS-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "OWNER");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "SPAWN");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Apply("DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-001"), "btxd");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DS-NAT-002", "keep", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK(!eng.Apply("DS-NAT-002", "drop", "parent-src", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PRESERVE");
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-NAT-002", "keep", "parent-src", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-002"), "parent-src");
    BOOST_CHECK(!eng.Apply("DS-NAT-002", "drop", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PRESERVE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-NAT-002"), "parent-src");
    BOOST_CHECK(!eng.Apply("DS-NAT-002", "keep", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);

    BOOST_CHECK(!eng.Apply("DS-NAT-003", "observer", "spend", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "SPEND");
    BOOST_CHECK(!eng.Apply("DS-NAT-003", "observer", "defaults", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SPEND");
    BOOST_CHECK(!eng.enrolled());
    BOOST_CHECK(eng.Apply("DS-NAT-003", "observer", "defaults", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.observer_text(), "defaults");
    BOOST_CHECK(eng.Apply("DS-NAT-003", "enroll", "customer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.enrolled());
    BOOST_CHECK_EQUAL(eng.enroll_text(), "customer");
    BOOST_CHECK_EQUAL(eng.observer_text(), "defaults");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");

    BOOST_CHECK(eng.Apply("DS-NAT-004", "note", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK(eng.Apply("DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.bit_of("DS-NAT-004"));
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK(!eng.Apply("DS-NAT-004", "note", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.stored("DS-NAT-004"), static_cast<int64_t>(40));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-NAT-005", "restart", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(!eng.journaled());
    BOOST_CHECK(!eng.Apply("DS-NAT-005", "record", "", "pend", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(!eng.Apply("DS-NAT-005", "record", "case-a", "pend-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(eng.Apply("DS-NAT-005", "record", "case-a", "pend-a", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Apply("DS-NAT-005", "scratch", "lost", "gone", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(eng.case_state(), "lost");
    BOOST_CHECK_EQUAL(eng.pending(), "gone");
    BOOST_CHECK(eng.Apply("DS-NAT-005", "restart", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.case_state(), "case-a");
    BOOST_CHECK_EQUAL(eng.pending(), "pend-a");
    BOOST_CHECK(!eng.Apply("DS-NAT-005", "record", "case-a", "pend-a", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.case_state(), "case-a");

    BOOST_CHECK(!eng.Apply("DS-NAT-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "WORKER");
    BOOST_CHECK(!eng.Apply("DS-NAT-006", "", "worker-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OPTOUT");
    BOOST_CHECK(eng.wan_refused());
    BOOST_CHECK(!eng.published());
    BOOST_CHECK_EQUAL(eng.contribution_workers(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-NAT-006", "", "worker-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.published());
    BOOST_CHECK(eng.wan_refused());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");

    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "model,runtime", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "model,,tool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(eng.Apply("DS-HIRE-001", "", "model,runtime,tool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "model,runtime,tool");
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "other,runtime,tool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "model,runtime,tool");
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "model,runtime,tool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);

    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "family", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ADMISSION");
    BOOST_CHECK(eng.Apply("DS-HIRE-002", "family", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "private", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ADMISSION");
    BOOST_CHECK(eng.Apply("DS-HIRE-002", "private", "private", "seat", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002#family"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "private");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");

    BOOST_CHECK(!eng.Apply("DS-HIRE-003", "", "modified", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());

    BOOST_CHECK(eng.Apply("DS-HIRE-004", "", "alpha", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Apply("DS-HIRE-004", "", "beta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "SUBSTITUTE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "alpha");
    BOOST_CHECK(!eng.Apply("DS-HIRE-004", "", "alpha", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);

    BOOST_CHECK(!eng.Apply("DS-HIRE-005", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "CONFIG");
    BOOST_CHECK(eng.Apply("DS-HIRE-005", "", "ignored", "cfg-a", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-005"), "cfg-a");
    BOOST_CHECK(!eng.Apply("DS-HIRE-005", "", "ignored", "cfg-b", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-005"), "cfg-a");

    BOOST_CHECK(!eng.Apply("DS-HIRE-006", "show", "banner", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-006"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ASSET");
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "cust", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "MANDATE");
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "cust", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-001"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-AUTH-001", "", "cust", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-001"), "cust|grant");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Apply("DS-AUTH-001", "", "cust", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-001"), "cust|grant");

    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "", "gen1", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK(eng.Apply("DS-AUTH-002", "", "case", "gen1", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-002"), "case|gen1");
    BOOST_CHECK(!eng.Apply("DS-AUTH-002", "", "case", "gen2", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-002"), "case|gen1");

    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(6), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(1), static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "UNCERTAIN");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.text_of("DS-AUTH-003").empty());
    BOOST_CHECK(eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-003"), "lease");
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-003"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.Apply("DS-AUTH-003", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);

    BOOST_CHECK(!eng.Apply("DS-AUTH-004", "bind", "", "asset-a", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK(eng.Apply("DS-AUTH-004", "bind", "low", "asset-a", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Apply("DS-AUTH-004", "severity", "high", "asset-a", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-004"), "high");
    BOOST_CHECK_EQUAL(eng.scope_text(), "asset-a");
    BOOST_CHECK(!eng.Apply("DS-AUTH-004", "expand", "high", "asset-b", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.scope_text(), "asset-a");
    BOOST_CHECK_EQUAL(eng.text_of("DS-AUTH-004"), "high");

    BOOST_CHECK(!eng.Apply("DS-AUTH-005", "", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PURPOSE");
    BOOST_CHECK(eng.Apply("DS-AUTH-005", "", "read", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.Apply("DS-AUTH-005", "", "effect", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.Apply("DS-AUTH-005", "", "release", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.Apply("DS-AUTH-005", "", "spend", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.purpose_granted("read"));
    BOOST_CHECK(eng.purpose_granted("effect"));
    BOOST_CHECK(eng.purpose_granted("release"));
    BOOST_CHECK(eng.purpose_granted("spend"));
    BOOST_CHECK_EQUAL(eng.stored("DS-AUTH-005"), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Apply("DS-AUTH-005", "", "read", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(!modelnet::ResearchMaySpend());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(eng.Apply("DS-AUTH-006", "prepare", "notify", "p1", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Apply("DS-AUTH-006", "prepare", "release", "p2", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "run", "notify", "p1", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "run", "release", "p2", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(!eng.Apply("DS-AUTH-006", "prepare", "notify", "p3", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.broadcast());

    BOOST_CHECK(!eng.Apply("DS-DATA-001", "", "orig", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(eng.Apply("DS-DATA-001", "", "orig", "hash-1", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "orig");
    BOOST_CHECK_EQUAL(eng.provenance(), "hash-1");
    BOOST_CHECK(!eng.Apply("DS-DATA-001", "", "altered", "hash-2", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "orig");
    BOOST_CHECK(eng.Apply("DS-DATA-001", "", "orig", "hash-2", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-001"), "orig");
    BOOST_CHECK_EQUAL(eng.provenance(), "hash-1");
    BOOST_CHECK_EQUAL(eng.provenance_count(), 2);

    BOOST_CHECK(!eng.Apply("DS-DATA-002", "", "sensor", "sensor", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "SEPARATE");
    BOOST_CHECK(eng.Apply("DS-DATA-002", "", "sensor", "disputed", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-002"), "sensor|disputed");
    BOOST_CHECK(!eng.Apply("DS-DATA-002", "", "sensor", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);

    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "", "audit", static_cast<int64_t>(10), static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "disk", "", static_cast<int64_t>(10), static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "disk", "audit", static_cast<int64_t>(-1), static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "disk", "audit", static_cast<int64_t>(1001), static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "disk", "audit", static_cast<int64_t>(10), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "disk", "audit", static_cast<int64_t>(10), static_cast<int64_t>(1001), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(eng.Apply("DS-DATA-003", "", "disk", "audit", static_cast<int64_t>(10), static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-003"), "disk");
    BOOST_CHECK_EQUAL(eng.purpose_query(), "audit");
    BOOST_CHECK_EQUAL(eng.query_time(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-003"), static_cast<int64_t>(100));
    BOOST_CHECK(!eng.Apply("DS-DATA-003", "", "other", "audit", static_cast<int64_t>(10), static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-003"), "disk");

    BOOST_CHECK(!eng.Apply("DS-DATA-004", "export", "", "exact-g", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(eng.Apply("DS-DATA-004", "local", "body-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "export", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(eng.exported_body().empty());
    BOOST_CHECK(eng.Apply("DS-DATA-004", "grant", "", "exact-g", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Apply("DS-DATA-004", "export", "", "other-g", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(eng.Apply("DS-DATA-004", "export", "", "exact-g", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.exported_body(), "body-a");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-004"), "body-a");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "do not ignore previous text", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK(eng.bit_of("DS-DATA-005"));
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-005"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "see the instruction", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK(eng.Apply("DS-DATA-005", "", "ordinary log", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "ordinary log");
    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "instruction", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "ordinary log");

    BOOST_CHECK(!eng.Apply("DS-DATA-006", "", "gap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK(!eng.Apply("DS-DATA-006", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK(eng.Apply("DS-DATA-006", "", "clock", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.Apply("DS-DATA-006", "", "loss", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.Apply("DS-DATA-006", "", "duplicate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.Apply("DS-DATA-006", "", "missing", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(eng.gap_reported("clock"));
    BOOST_CHECK(eng.gap_reported("loss"));
    BOOST_CHECK(eng.gap_reported("duplicate"));
    BOOST_CHECK(eng.gap_reported("missing"));
    BOOST_CHECK(!eng.Apply("DS-DATA-006", "", "clock", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.Apply("DS-DATA-006", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());

    Latches(eng);
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_SUITE_END()
