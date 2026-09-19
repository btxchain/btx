// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01 Worker K — native MOE + CXL.
//   JIT-MOE-01..07  expert demand paging (portable CPU fixture PASS)
//   JIT-CXL-01..07  NUMA/CXL placement (sysfs discovery; real CXL NOT_RUN)
// J08 (MoE demand paging) and J09 (CXL/NUMA placement) portable paths.
// Coordinator owns CMakeLists.txt. Do not ninja from this lane.
// GPU MoE PASS is never faked. CXL hardware is never claimed from emulation.

#include <modelnet/capability.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_moe_tests, BasicTestingSetup)

namespace {

modelnet::ExpertUnit Expert(uint32_t layer, uint32_t expert, modelnet::LeaseLife life,
                            const std::string& id = {})
{
    modelnet::ExpertUnit e;
    e.layer = layer;
    e.expert = expert;
    e.life = life;
    e.expert_id = id;
    return e;
}

bool CxlBusPresent()
{
    return fs::exists("/sys/bus/cxl");
}

const char* EnvOrEmpty(const char* name)
{
    const char* v = std::getenv(name);
    return v ? v : "";
}

} // namespace

BOOST_AUTO_TEST_CASE(JIT_MOE_01)
{
    BOOST_TEST_CONTEXT("JIT-MOE-01") {
        BOOST_TEST_MESSAGE("JIT-MOE-01 expert map completeness (portable CPU paging)");
        std::string code, err;
        const std::vector<modelnet::ExpertUnit> required = {
            Expert(0, 0, modelnet::LeaseLife::VERIFIED, "L0E0.weight"),
            Expert(0, 0, modelnet::LeaseLife::VERIFIED, "L0E0.scale"),
        };
        const std::vector<modelnet::ExpertUnit> incomplete = {
            Expert(0, 0, modelnet::LeaseLife::VERIFIED, "L0E0.weight"),
        };
        BOOST_CHECK(!modelnet::MoEExpertMapComplete(required, incomplete, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_UNAVAILABLE");
        BOOST_CHECK(err.find("incomplete") != std::string::npos);

        const std::vector<modelnet::ExpertUnit> complete = {
            Expert(0, 0, modelnet::LeaseLife::VERIFIED, "L0E0.weight"),
            Expert(0, 0, modelnet::LeaseLife::VERIFIED, "L0E0.scale"),
        };
        BOOST_CHECK(modelnet::MoEExpertMapComplete(required, complete, code, err));
        BOOST_CHECK(modelnet::MoEExpertMapComplete({}, complete, code, err));
    }
}

BOOST_AUTO_TEST_CASE(JIT_MOE_02)
{
    BOOST_TEST_CONTEXT("JIT-MOE-02") {
        BOOST_TEST_MESSAGE("JIT-MOE-02 all-resident parity (portable CPU paging)");
        const unsigned char all_resident[] = {0x11, 0x22, 0x33, 0x44};
        const unsigned char paged_same[] = {0x11, 0x22, 0x33, 0x44};
        const unsigned char paged_zero[] = {0x00, 0x00, 0x00, 0x00};
        const unsigned char paged_short[] = {0x11, 0x22, 0x33};
        BOOST_CHECK(modelnet::MoEAllResidentParity(paged_same, all_resident));
        BOOST_CHECK(!modelnet::MoEAllResidentParity(paged_zero, all_resident));
        BOOST_CHECK(!modelnet::MoEAllResidentParity(paged_short, all_resident));

        // Routing is identity (layer, expert); cache policy must not skip.
        std::string code, err;
        const std::vector<modelnet::ExpertUnit> res = {
            Expert(1, 2, modelnet::LeaseLife::ACTIVE, "hot"),
        };
        BOOST_CHECK(modelnet::MoEDispatch(res, 1, 2, false, code, err));
        BOOST_CHECK(!modelnet::MoEDispatch(res, 1, 3, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");
    }
}

BOOST_AUTO_TEST_CASE(JIT_MOE_03)
{
    BOOST_TEST_CONTEXT("JIT-MOE-03") {
        BOOST_TEST_MESSAGE("JIT-MOE-03 missing expert (portable CPU paging)");
        std::string code, err;
        std::vector<modelnet::ExpertUnit> empty;
        BOOST_CHECK(!modelnet::MoEDispatch(empty, 0, 0, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");
        BOOST_CHECK(err.find("zero") != std::string::npos);

        const std::vector<modelnet::ExpertUnit> reserved = {
            Expert(0, 0, modelnet::LeaseLife::RESERVED, "cold"),
        };
        BOOST_CHECK(!modelnet::MoEDispatch(reserved, 0, 0, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");

        const std::vector<modelnet::ExpertUnit> retiring = {
            Expert(0, 0, modelnet::LeaseLife::RETIRING, "old"),
        };
        BOOST_CHECK(!modelnet::MoEDispatch(retiring, 0, 0, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");

        const std::vector<modelnet::ExpertUnit> active = {
            Expert(0, 0, modelnet::LeaseLife::ACTIVE, "e0"),
        };
        BOOST_CHECK(modelnet::MoEDispatch(active, 0, 0, false, code, err));

        const std::vector<modelnet::ExpertUnit> verified = {
            Expert(0, 1, modelnet::LeaseLife::VERIFIED, "e1"),
        };
        BOOST_CHECK(modelnet::MoEDispatch(verified, 0, 1, false, code, err));
    }
}

BOOST_AUTO_TEST_CASE(JIT_MOE_04)
{
    BOOST_TEST_CONTEXT("JIT-MOE-04") {
        BOOST_TEST_MESSAGE("JIT-MOE-04 working-set shift / J08 portable paging");
        std::string code, err;
        const uint64_t expert_bytes = 1024;
        const uint64_t budget = 2 * expert_bytes;
        std::vector<modelnet::ExpertUnit> working = {
            Expert(0, 0, modelnet::LeaseLife::ACTIVE, "hot"),
            Expert(0, 1, modelnet::LeaseLife::RESERVED, "cold"),
        };
        const auto incoming = Expert(0, 2, modelnet::LeaseLife::VERIFIED, "new");
        BOOST_CHECK(modelnet::MoEWorkingSetShift(working, incoming, budget, expert_bytes, code, err));
        BOOST_REQUIRE_EQUAL(working.size(), 2);
        bool saw_new = false;
        bool saw_active = false;
        bool saw_cold = false;
        for (const auto& e : working) {
            if (e.expert == 2) saw_new = true;
            if (e.expert == 0 && e.life == modelnet::LeaseLife::ACTIVE) saw_active = true;
            if (e.expert == 1 && e.life == modelnet::LeaseLife::RESERVED) saw_cold = true;
        }
        BOOST_CHECK(saw_new);
        BOOST_CHECK(saw_active);
        BOOST_CHECK(!saw_cold);

        // Already-resident incoming is a no-op (bounded, no extra prefetch).
        BOOST_CHECK(modelnet::MoEWorkingSetShift(working, incoming, budget, expert_bytes, code, err));
        BOOST_CHECK_EQUAL(working.size(), 2);

        // All remaining experts ACTIVE: report miss rather than hide stall / skip.
        working = {
            Expert(0, 0, modelnet::LeaseLife::ACTIVE, "a"),
            Expert(0, 2, modelnet::LeaseLife::ACTIVE, "b"),
        };
        const auto miss = Expert(0, 3, modelnet::LeaseLife::VERIFIED, "c");
        BOOST_CHECK(!modelnet::MoEWorkingSetShift(working, miss, budget, expert_bytes, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");
        BOOST_CHECK(err.find("stall") != std::string::npos);
        BOOST_CHECK_EQUAL(working.size(), 2);

        BOOST_CHECK(!modelnet::MoEWorkingSetShift(working, miss, /*device_budget_bytes=*/512, expert_bytes, code, err));
        BOOST_CHECK_EQUAL(code, "MEMORY_RESERVATION_FAILED");
    }
}

BOOST_AUTO_TEST_CASE(JIT_MOE_05)
{
    BOOST_TEST_CONTEXT("JIT-MOE-05") {
        BOOST_TEST_MESSAGE("JIT-MOE-05 execution eviction race (portable CPU paging)");
        std::string code, err;
        BOOST_CHECK(!modelnet::MoEEvictionRaceSafe(modelnet::LeaseLife::ACTIVE, true, code, err));
        BOOST_CHECK_EQUAL(code, "TRANSFER_STILL_IN_FLIGHT");
        BOOST_CHECK(err.find("executing") != std::string::npos);

        BOOST_CHECK(!modelnet::MoEEvictionRaceSafe(modelnet::LeaseLife::POPULATING, true, code, err));
        BOOST_CHECK_EQUAL(code, "TRANSFER_STILL_IN_FLIGHT");

        BOOST_CHECK(modelnet::MoEEvictionRaceSafe(modelnet::LeaseLife::ACTIVE, false, code, err));
        BOOST_CHECK(modelnet::MoEEvictionRaceSafe(modelnet::LeaseLife::QUIESCENT, true, code, err));
        BOOST_CHECK(modelnet::MoEEvictionRaceSafe(modelnet::LeaseLife::RETIRING, true, code, err));
    }
}

BOOST_AUTO_TEST_CASE(JIT_MOE_06)
{
    BOOST_TEST_CONTEXT("JIT-MOE-06") {
        BOOST_TEST_MESSAGE("JIT-MOE-06 no WAN token paging (portable CPU paging)");
        std::string code, err;
        const std::vector<modelnet::ExpertUnit> res = {
            Expert(0, 0, modelnet::LeaseLife::ACTIVE, "local"),
        };
        BOOST_CHECK(!modelnet::MoEDispatch(res, 0, 0, true, code, err));
        BOOST_CHECK_EQUAL(code, "WAN_INNER_TOKEN_FORBIDDEN");
        BOOST_CHECK(modelnet::MoEDispatch(res, 0, 0, false, code, err));
    }
}

BOOST_AUTO_TEST_CASE(JIT_MOE_07)
{
    BOOST_TEST_CONTEXT("JIT-MOE-07") {
        BOOST_TEST_MESSAGE("JIT-MOE-07 real runtime hook");
        std::string code, err;
        bool hook = false;
        BOOST_REQUIRE(modelnet::MoERuntimeHook("synthetic-cpu-fixture", hook, code, err));
        BOOST_CHECK(hook);
        BOOST_CHECK(code.empty());

        auto gpu_hook = [&](const char* runtime, const char* env_name) {
            bool present = false;
            code.clear();
            err.clear();
            const bool ok = modelnet::MoERuntimeHook(runtime, present, code, err);
            BOOST_CHECK_MESSAGE(!ok, std::string("never fake GPU MoE PASS for ") + runtime);
            if (!present) {
                BOOST_TEST_MESSAGE(std::string("JIT-MOE-07 ") + runtime +
                                   " hook NOT_RUN (" + env_name + "='" + EnvOrEmpty(env_name) + "')");
                BOOST_CHECK(code == "LIVE_RUNTIME_NOT_RUN" || code == "HARDWARE_NOT_RUN");
            } else {
                BOOST_TEST_MESSAGE(std::string("JIT-MOE-07 ") + runtime +
                                   " env path exists; live expert-dispatch NOT_RUN (no mock GPU PASS)");
                BOOST_CHECK_EQUAL(code, "HARDWARE_NOT_RUN");
            }
            BOOST_CHECK(err.find("NOT_RUN") != std::string::npos);
        };
        gpu_hook("llama.cpp", "BTX_LLAMA_CLI");
        gpu_hook("vLLM", "BTX_VLLM");
        gpu_hook("MLX", "BTX_MLX");

        bool unknown = true;
        BOOST_CHECK(!modelnet::MoERuntimeHook("not-a-runtime", unknown, code, err));
        BOOST_CHECK(!unknown);
        BOOST_CHECK_EQUAL(code, "UNSUPPORTED_RUNTIME_PROFILE");
    }
}

BOOST_AUTO_TEST_CASE(J08)
{
    BOOST_TEST_CONTEXT("J08") {
        std::string code, err;
        BOOST_CHECK(!modelnet::MoEDispatch({}, 0, 0, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");

        const std::vector<modelnet::ExpertUnit> active = {
            Expert(0, 0, modelnet::LeaseLife::ACTIVE, "L0E0"),
        };
        BOOST_CHECK(modelnet::MoEDispatch(active, 0, 0, false, code, err));

        const std::vector<modelnet::ExpertUnit> verified = {
            Expert(0, 0, modelnet::LeaseLife::VERIFIED, "L0E0"),
        };
        BOOST_CHECK(modelnet::MoEDispatch(verified, 0, 0, false, code, err));

        BOOST_CHECK(!modelnet::MoEDispatch(active, 0, 0, true, code, err));
        BOOST_CHECK_EQUAL(code, "WAN_INNER_TOKEN_FORBIDDEN");
        BOOST_CHECK(!modelnet::MoEDispatch(verified, 0, 0, true, code, err));
        BOOST_CHECK_EQUAL(code, "WAN_INNER_TOKEN_FORBIDDEN");

        const unsigned char all_resident[] = {0x11, 0x22, 0x33, 0x44};
        const unsigned char paged_same[] = {0x11, 0x22, 0x33, 0x44};
        const unsigned char paged_mismatch[] = {0x11, 0x22, 0x33, 0x00};
        BOOST_CHECK(modelnet::MoEAllResidentParity(paged_same, all_resident));
        BOOST_CHECK(!modelnet::MoEAllResidentParity(paged_mismatch, all_resident));

        BOOST_TEST_MESSAGE("J08 real MoE hardware paging NOT_RUN");
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_01)
{
    BOOST_TEST_CONTEXT("JIT-CXL-01") {
        BOOST_TEST_MESSAGE("JIT-CXL-01 topology truth");
        const auto topo = modelnet::DiscoverTopology();
        BOOST_CHECK(topo.json.exists("cxl_evidence") || topo.json.exists("topology") ||
                    topo.json.exists("unified_memory"));
        BOOST_CHECK(topo.json.exists("automatic_spend_atoms"));
        BOOST_CHECK_EQUAL(topo.json["automatic_spend_atoms"].getInt<int>(), 0);
        BOOST_CHECK(topo.json.exists("privileged_sysfs_write") && topo.json["privileged_sysfs_write"].isFalse());
        BOOST_CHECK(topo.json["assumed_link_rate"].isNull());
        BOOST_CHECK(topo.json["assumed_pool_capacity"].isNull());
        BOOST_CHECK(topo.json["cxl_emulation"].isFalse());
        if (topo.cxl) {
            BOOST_CHECK_EQUAL(topo.json["cxl_evidence"].get_str(), "DISCOVERED");
        } else {
            BOOST_CHECK_EQUAL(topo.json["cxl_evidence"].get_str(), "NOT_RUN");
            BOOST_TEST_MESSAGE("JIT-CXL-01 CXL properties UNKNOWN/UNSUPPORTED (cxl_evidence=NOT_RUN)");
        }
#ifdef __APPLE__
        BOOST_CHECK(topo.macos_unified);
        BOOST_CHECK(!topo.numa);
        BOOST_CHECK(!topo.cxl);
#endif
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_02)
{
    BOOST_TEST_CONTEXT("JIT-CXL-02") {
        BOOST_TEST_MESSAGE("JIT-CXL-02 physical pool uniqueness");
        std::string code, err;
        BOOST_CHECK(modelnet::PhysicalPoolUnique({"dram0", "cxl0"}, code, err));
        BOOST_CHECK(!modelnet::PhysicalPoolUnique({"uma", "uma"}, code, err));
        BOOST_CHECK_EQUAL(code, "POOL_ALIAS_FORBIDDEN");
        BOOST_CHECK(modelnet::PhysicalPoolUnique({}, code, err));
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_03)
{
    BOOST_TEST_CONTEXT("JIT-CXL-03") {
        BOOST_TEST_MESSAGE("JIT-CXL-03 NUMA placement");
        std::string code, err;
        BOOST_CHECK(modelnet::NumaPlaceRepresentation(0, 0, code, err));
        BOOST_CHECK(!modelnet::NumaPlaceRepresentation(0, 1, code, err));
        BOOST_CHECK_EQUAL(code, "NUMA_MISPLACE");

        const auto topo = modelnet::DiscoverTopology();
        if (topo.numa && topo.json.exists("numa_nodes") && topo.json["numa_nodes"].isArray() &&
            topo.json["numa_nodes"].size() > 0) {
            const int node = topo.json["numa_nodes"][0].getInt<int>();
            BOOST_CHECK(modelnet::NumaPlaceRepresentation(node, node, code, err));
            BOOST_CHECK_EQUAL(topo.json["numa_evidence"].get_str(), "DISCOVERED");
            if (topo.json.exists("numa_distance_sysfs")) {
                BOOST_CHECK(topo.json["numa_distance_sysfs"].isStr());
            }
            BOOST_TEST_MESSAGE("JIT-CXL-03 Linux NUMA sysfs DISCOVERED node=" + std::to_string(node));
        } else {
            BOOST_TEST_MESSAGE("JIT-CXL-03 NUMA sysfs NOT_RUN; portable mismatch still asserted");
        }
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_04)
{
    BOOST_TEST_CONTEXT("JIT-CXL-04") {
        std::string code, err;
        const auto topo = modelnet::DiscoverTopology();
        if (!CxlBusPresent()) {
            BOOST_TEST_MESSAGE("JIT-CXL-04 real CXL tier NOT_RUN: /sys/bus/cxl absent");
            BOOST_CHECK(!topo.cxl || topo.json["cxl_evidence"].get_str() == "NOT_RUN" ||
                        !topo.json["cxl_bus"].get_bool());
            BOOST_CHECK(!modelnet::PlaceInTier(modelnet::PlacementTier::CXL_NUMA,
                                               modelnet::PlacementTier::HOST_PAGEABLE, code, err));
            BOOST_CHECK_EQUAL(code, "TIER_UNAVAILABLE");
        } else {
            BOOST_CHECK(topo.cxl);
            BOOST_CHECK_EQUAL(topo.json["cxl_evidence"].get_str(), "DISCOVERED");
            BOOST_CHECK(modelnet::PlaceInTier(modelnet::PlacementTier::CXL_NUMA, modelnet::PlacementTier::CXL_NUMA,
                                               code, err));
            BOOST_TEST_MESSAGE("JIT-CXL-04 /sys/bus/cxl DISCOVERED; placement eligibility only (no invented bandwidth)");
        }
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_05)
{
    BOOST_TEST_CONTEXT("JIT-CXL-05") {
        BOOST_TEST_MESSAGE("JIT-CXL-05 tier loss / J09 portable recovery");
        std::string code, err;
        modelnet::PlacementTier used = modelnet::PlacementTier::UNKNOWN_TIER;
        BOOST_CHECK(modelnet::RecoverTierLoss(modelnet::PlacementTier::CXL_NUMA,
                                              modelnet::PlacementTier::HOST_PAGEABLE, used, code, err));
        BOOST_CHECK(used == modelnet::PlacementTier::HOST_PAGEABLE);

        used = modelnet::PlacementTier::CXL_NUMA;
        BOOST_CHECK(!modelnet::RecoverTierLoss(modelnet::PlacementTier::CXL_NUMA, modelnet::PlacementTier::CXL_NUMA,
                                                used, code, err));
        BOOST_CHECK_EQUAL(code, "TIER_UNAVAILABLE");
        BOOST_CHECK(used == modelnet::PlacementTier::UNKNOWN_TIER);

        BOOST_CHECK(modelnet::RecoverTierLoss(modelnet::PlacementTier::DEVICE, modelnet::PlacementTier::LOCAL_FILE,
                                              used, code, err));
        BOOST_CHECK(used == modelnet::PlacementTier::LOCAL_FILE);
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_06)
{
    BOOST_TEST_CONTEXT("JIT-CXL-06") {
        BOOST_TEST_MESSAGE("JIT-CXL-06 no privileged configuration");
        std::string code, err;
        BOOST_CHECK(!modelnet::PlaceInTier(modelnet::PlacementTier::CXL_NUMA, modelnet::PlacementTier::HOST_PAGEABLE,
                                              code, err));
        BOOST_CHECK_EQUAL(code, "TIER_UNAVAILABLE");
        BOOST_CHECK(modelnet::PlaceInTier(modelnet::PlacementTier::HOST_PAGEABLE,
                                           modelnet::PlacementTier::HOST_PAGEABLE, code, err));
        BOOST_CHECK(!modelnet::PlaceInTier(modelnet::PlacementTier::DEVICE, modelnet::PlacementTier::UNKNOWN_TIER,
                                            code, err));
        BOOST_CHECK_EQUAL(code, "UNKNOWN_COMPATIBILITY");

        const auto topo = modelnet::DiscoverTopology();
        BOOST_CHECK(topo.json["privileged_sysfs_write"].isFalse());
        modelnet::PlacementTier used = modelnet::PlacementTier::UNKNOWN_TIER;
        BOOST_CHECK(!modelnet::RecoverTierLoss(modelnet::PlacementTier::CXL_NUMA, modelnet::PlacementTier::CXL_NUMA,
                                               used, code, err));
    }
}

BOOST_AUTO_TEST_CASE(JIT_CXL_07)
{
    BOOST_TEST_CONTEXT("JIT-CXL-07") {
        BOOST_TEST_MESSAGE("JIT-CXL-07 placement comparison (measured, not mythology)");
        modelnet::PlacementTier chosen = modelnet::PlacementTier::UNKNOWN_TIER;
        BOOST_CHECK(modelnet::PlacementCompare(/*local_nvme_ms=*/5, /*remote_tier_ms=*/50, chosen));
        BOOST_CHECK(chosen == modelnet::PlacementTier::LOCAL_FILE);

        BOOST_CHECK(modelnet::PlacementCompare(50, 5, chosen));
        BOOST_CHECK(chosen == modelnet::PlacementTier::CXL_NUMA);

        BOOST_CHECK(modelnet::PlacementCompare(10, 10, chosen));
        BOOST_CHECK(chosen == modelnet::PlacementTier::LOCAL_FILE);

        BOOST_CHECK(!modelnet::PlacementCompare(-1, -1, chosen));
    }
}

BOOST_AUTO_TEST_SUITE_END()
