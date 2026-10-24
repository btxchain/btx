// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp42/grp42.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp42& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp42_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(gates_refuse_before_store)
{
    modelnet::Grp42 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "COMPONENT");
    BOOST_CHECK(eng.text_of("").empty());

    BOOST_CHECK(!eng.Apply("DS-REC-004", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-REC-004", "note", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("DS-REC-004", "private note", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-REC-004", "private note", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(0));

    BOOST_CHECK(!modelnet::NifDtEngineLinked("vllm"));
    BOOST_CHECK(!eng.Apply("DS-REC-004", "vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Apply("DS-REC-004", "cache vllm", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Apply("DS-REC-004", "vllm private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Apply("DS-REC-005", "rdma", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Apply("DS-REC-006", "nixl", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Apply("DS-DEL-001", "mooncake", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-001"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-REC-004", "private note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DS-REC-004"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.text_of("DS-REC-004").empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu_passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(p2p_scn_m_is_unknown)
{
    modelnet::Grp42 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("P2P-SCN-M", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("P2P-SCN-M", "note", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-M"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.text_of("P2P-SCN-M").empty());
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-M"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(p2p_scn_i_is_engine_absent)
{
    modelnet::Grp42 eng;
    std::string err = "stale";
    BOOST_CHECK_EQUAL(eng.classification("P2P-SCN-I"), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!eng.Apply("P2P-SCN-I", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Apply("P2P-SCN-I", "note", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-I"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("P2P-SCN-I", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-I"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.text_of("P2P-SCN-I").empty());
    BOOST_CHECK(!eng.Apply("P2P-SCN-I", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-I"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_stores_once)
{
    modelnet::Grp42 eng;
    std::string err = "stale";

    struct Item {
        const char* id;
        const char* text;
        int aux;
        bool p2p;
    };
    const Item items[] = {
        {"DS-REC-004", "invoice", 0, false},
        {"DS-REC-005", "receipt", 1, false},
        {"DS-REC-006", "ledger-note", 2, false},
        {"DS-DEL-001", "spec", 100, false},
        {"DS-DEL-002", "source", 1, false},
        {"DS-DEL-003", "binary", 3, false},
        {"DS-DEL-004", "checksum", 4, false},
        {"DS-DEL-005", "manifest", 5, false},
        {"DS-DEL-006", "memory", 6, false},
        {"P2P-SCN-A", "row-a", 1, true},
        {"P2P-SCN-B", "row-b", 1, true},
        {"P2P-SCN-C", "row-c", 1, true},
        {"P2P-SCN-D", "row-d", 1, true},
        {"P2P-SCN-E", "row-e", 1, true},
        {"P2P-SCN-F", "row-f", 1, true},
        {"P2P-SCN-G", "row-g", 1, true},
        {"P2P-SCN-H", "row-h", 1, true},
        {"P2P-SCN-J", "row-j", 1, true},
        {"P2P-SCN-K", "row-k", 1, true},
    };

    BOOST_CHECK(modelnet::NifDtEngineLinked("memory"));
    for (const Item& item : items) {
        if (item.p2p) {
            BOOST_CHECK_EQUAL(eng.classification(item.id), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
            BOOST_CHECK(!eng.Apply(item.id, item.text, static_cast<int64_t>(2), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.stored(item.id), static_cast<int64_t>(0));
            BOOST_CHECK(eng.text_of(item.id).empty());
            BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        } else {
            BOOST_CHECK_EQUAL(eng.classification(item.id), "COMPONENT");
        }

        BOOST_CHECK(eng.Apply(item.id, item.text, static_cast<int64_t>(item.aux), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(eng.stored(item.id), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.text_of(item.id), item.text);

        BOOST_CHECK(!eng.Apply(item.id, item.text, static_cast<int64_t>(item.aux), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(err, "REPLAY");
        BOOST_CHECK_EQUAL(eng.text_of(item.id), item.text);
        BOOST_CHECK_EQUAL(eng.stored(item.id), static_cast<int64_t>(1));

        const std::string other = std::string(item.text) + "-next";
        BOOST_CHECK(!eng.Apply(item.id, other, static_cast<int64_t>(item.aux), true, err));
        BOOST_CHECK_EQUAL(err, "UNCHANGED");
        BOOST_CHECK_EQUAL(eng.text_of(item.id), item.text);
        BOOST_CHECK_EQUAL(eng.stored(item.id), static_cast<int64_t>(1));

        if (item.p2p) {
            BOOST_CHECK(!eng.Apply(item.id, other, static_cast<int64_t>(2), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.text_of(item.id), item.text);
            BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        }

        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.release_qualified());
        BOOST_CHECK(!eng.gpu_passed());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }

    BOOST_CHECK_EQUAL(eng.stored("DS-REC-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-006"), "ledger-note");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-006"), "memory");
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-I"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.stored("P2P-SCN-A"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-K"), "row-k");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("P2P-SCN-A"), "row-a");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
