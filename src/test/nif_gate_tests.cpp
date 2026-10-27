// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_gate/nif_gate.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_gate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bad_kind_and_empty_name_store_nothing)
{
    modelnet::NifGate gate;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.release_qualified());
    BOOST_CHECK(!gate.hardware_qualified());
    BOOST_CHECK(!gate.qualified());
    BOOST_CHECK(!gate.launched());
    BOOST_CHECK(!gate.gpu());
    BOOST_CHECK(!gate.broadcast());
    BOOST_CHECK_EQUAL(gate.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(gate.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(gate.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(gate.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(gate.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!gate.Note("disk", "memory", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_GATE_CLASS);
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.Absent("memory"));
    BOOST_CHECK(!gate.kind_passed("gpu"));
    BOOST_CHECK(gate.noted_name("gpu").empty());

    BOOST_CHECK(!gate.Note("GPU", "local", err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK(!gate.Absent("local"));
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));

    BOOST_CHECK(!gate.Note("release", "rdma", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_GATE_CLASS);
    BOOST_CHECK(!gate.Absent("rdma"));
    BOOST_CHECK(!gate.kind_passed("gpu"));

    BOOST_CHECK(!gate.Note("", "memory", err));
    BOOST_CHECK_EQUAL(err, "CLASS");
    BOOST_CHECK(!gate.Absent("memory"));

    BOOST_CHECK(!gate.Note("gpu", "", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_GATE_NAME);
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.kind_passed("gpu"));
    BOOST_CHECK(!gate.Absent(""));

    BOOST_CHECK(!gate.Note("payment", "", err));
    BOOST_CHECK_EQUAL(err, "NAME");
    BOOST_CHECK(!gate.kind_passed("payment"));
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.release_qualified());
    BOOST_CHECK_EQUAL(gate.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(gate.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(unlinked_rdma_is_absent_and_does_not_pass)
{
    modelnet::NifGate gate;
    std::string err;

    BOOST_CHECK(!modelnet::NifDtEngineLinked("rdma"));
    BOOST_CHECK(modelnet::NifDtEngineLinked("memory"));
    BOOST_CHECK(modelnet::NifDtEngineLinked("local"));

    BOOST_CHECK(!gate.Note("gpu", "rdma", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(gate.Absent("rdma"));
    BOOST_CHECK(!gate.kind_passed("gpu"));
    BOOST_CHECK(gate.noted_name("gpu").empty());
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.gpu());
    BOOST_CHECK(!gate.launched());
    BOOST_CHECK(!gate.broadcast());

    BOOST_CHECK(!gate.Note("gpu", "rdma", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(gate.Absent("rdma"));
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));

    BOOST_CHECK(!gate.Note("lan", "deepinfer", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(gate.Absent("deepinfer"));
    BOOST_CHECK(!gate.kind_passed("lan"));
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));

    BOOST_CHECK(gate.Note("gpu", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.kind_passed("gpu"));
    BOOST_CHECK_EQUAL(gate.noted_name("gpu"), "memory");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(1));
    BOOST_CHECK(gate.Absent("rdma"));
    BOOST_CHECK(!gate.gpu());
    BOOST_CHECK(!gate.release_qualified());
    BOOST_CHECK(!gate.hardware_qualified());
    BOOST_CHECK(!gate.qualified());

    BOOST_CHECK(!gate.Note("gpu", "rdma", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(gate.Absent("rdma"));
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(gate.noted_name("gpu"), "memory");
    BOOST_CHECK(gate.kind_passed("gpu"));

    BOOST_CHECK(!gate.Note("gpu", "local", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(gate.noted_name("gpu"), "memory");
    BOOST_CHECK(!gate.Absent("local"));
    BOOST_CHECK_EQUAL(gate.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(gate.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(five_linked_kinds_remain_unqualified)
{
    modelnet::NifGate gate;
    std::string err;

    BOOST_CHECK(!gate.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(0));
    BOOST_CHECK(!gate.release_qualified());

    const char* kinds[] = {"gpu", "lan", "wan", "security", "payment"};
    const char* names[] = {"memory", "local", "memory", "local", "memory"};
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(gate.Note(kinds[i], names[i], err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(gate.kind_passed(kinds[i]));
        BOOST_CHECK_EQUAL(gate.noted_name(kinds[i]), names[i]);
        BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(i + 1));
    }

    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(5));
    BOOST_CHECK(!gate.Absent("memory"));
    BOOST_CHECK(!gate.Absent("local"));
    BOOST_CHECK(!gate.Absent("rdma"));

    BOOST_CHECK(!gate.Note("gpu", "local", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gate.noted_name("gpu"), "memory");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(5));

    BOOST_CHECK(!gate.Note("payment", "memory", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gate.noted_name("payment"), "memory");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(5));

    BOOST_CHECK(!gate.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(5));
    BOOST_CHECK(gate.kind_passed("gpu"));
    BOOST_CHECK(gate.kind_passed("lan"));
    BOOST_CHECK(gate.kind_passed("wan"));
    BOOST_CHECK(gate.kind_passed("security"));
    BOOST_CHECK(gate.kind_passed("payment"));
    BOOST_CHECK(!gate.release_qualified());
    BOOST_CHECK(!gate.hardware_qualified());
    BOOST_CHECK(!gate.qualified());
    BOOST_CHECK(!gate.launched());
    BOOST_CHECK(!gate.gpu());
    BOOST_CHECK(!gate.broadcast());
    BOOST_CHECK_EQUAL(gate.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(gate.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(gate.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(gate.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(gate.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!gate.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!gate.release_qualified());
    BOOST_CHECK_EQUAL(gate.PassedCount(), static_cast<int64_t>(5));
}

BOOST_AUTO_TEST_SUITE_END()
