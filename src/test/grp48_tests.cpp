// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp48/grp48.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp48& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

const char* const kIds[] = {
    "DT-OPT-002", "DT-OPT-003", "DT-OPT-005", "DT-OPT-006", "DT-OPT-007", "DT-OPT-008",
    "DT-DAT-001", "DT-DAT-002", "DT-DAT-003", "DT-DAT-004",
    "DT-DAT-005", "DT-DAT-006", "DT-DAT-007", "DT-DAT-008",
    "DT-RLP-001", "DT-RLP-002", "DT-RLP-003", "DT-RLP-004", "DT-RLP-005",
};

bool UnqualifiedId(const char* id)
{
    return std::string(id) == "DT-OPT-005" || std::string(id) == "DT-OPT-006";
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp48_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(each_id_stores_once_and_stays_unqualified)
{
    modelnet::Grp48 eng;
    for (const char* id : kIds) {
        std::string err = "stale";
        if (UnqualifiedId(id)) {
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
        } else {
            BOOST_CHECK(eng.Apply(id, "s1", static_cast<int64_t>(1), true, err));
            BOOST_CHECK(err.empty());
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(id), "s1");

            BOOST_CHECK(!eng.Apply(id, "s1", static_cast<int64_t>(0), true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
            BOOST_CHECK_EQUAL(err, "REPLAY");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.text_of(id), "s1");

            BOOST_CHECK(!eng.Apply(id, "s2", static_cast<int64_t>(100), true, err));
            BOOST_CHECK_EQUAL(err, "UNCHANGED");
            BOOST_CHECK_EQUAL(eng.text_of(id), "s1");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(1));
        }

        BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        BOOST_CHECK(!eng.Release(err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.release_qualified());
        BOOST_CHECK(!eng.qualified());
        BOOST_CHECK(!eng.hardware_qualified());
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    }
    std::string err = "stale";
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(refusals_store_nothing)
{
    modelnet::Grp48 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Apply("", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-OPT-001", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-OPT-004", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("DT-RLP-008", "s1", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DT-RLP-008"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-DAT-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "");

    BOOST_CHECK(!eng.Apply("DT-DAT-001", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-OPT-002", "s1", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-DAT-001", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "");

    BOOST_CHECK(!eng.Apply("DT-DAT-002", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-002"), "");
    BOOST_CHECK(!eng.Apply("DT-DAT-002", "fp4", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Apply("DT-DAT-003", "fp48", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-003"), "fp48");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-003"), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DT-DAT-004", "nan", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-004"), "");
    BOOST_CHECK(!eng.Apply("DT-DAT-004", "inf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!eng.Apply("DT-DAT-005", "s1nan", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-005"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-DAT-005", "s1inf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-005"), "");

    BOOST_CHECK(!eng.Apply("DT-OPT-005", "nan", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-005"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-OPT-006", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-OPT-005", "s1", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-005"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DT-DAT-006", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DT-DAT-007", "s1 private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-007"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-007"), "");

    BOOST_CHECK(eng.Apply("DT-DAT-001", "s1", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");
    BOOST_CHECK(eng.Apply("DT-OPT-002", "s1", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.text_of("DT-OPT-002"), "s1");
    BOOST_CHECK_EQUAL(eng.stored("DT-OPT-002"), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Apply("DT-DAT-001", "s1inf", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "fp8", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "fp4", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");
    BOOST_CHECK_EQUAL(eng.stored("DT-DAT-001"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");
    BOOST_CHECK(!eng.Apply("DT-DAT-001", "s1", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("DT-DAT-001"), "s1");

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
