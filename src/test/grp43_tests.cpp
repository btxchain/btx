// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp43/grp43.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

const char* const kIds[] = {
    "P2P-SCN-L",
    "P2P-SCN-M",
    "P2P-SCN-N",
    "P2P-SCN-O",
    "P2P-SCN-P",
    "P2P-SCN-Q",
    "P2P-SCN-R",
    "NIF-NAT-001",
    "NIF-NAT-004",
    "NIF-NAT-006",
    "NIF-FORK-001",
    "NIF-FORK-002",
    "NIF-FORK-003",
    "NIF-FORK-004",
    "NIF-FORK-005",
    "NIF-FORK-006",
    "NIF-PROF-001",
    "NIF-PROF-002",
    "NIF-PROF-003",
    "NIF-PROF-004",
};

const char* const kRemote[] = {
    "deepinfer",
    "vllm",
    "sglang",
    "lmcache",
    "deepep",
    "deepgemm",
    "dualpipe",
    "dualpipev",
    "nixl",
    "mooncake",
    "rdma",
};

bool IsP2p(const std::string& id)
{
    return id.rfind("P2P-", 0) == 0;
}

bool NeverStores(const std::string& id)
{
    return id == "P2P-SCN-M" || id == "NIF-FORK-004" || id == "NIF-FORK-005";
}

void Idle(modelnet::Grp43& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.release_qualified());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp43_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_or_empty_id)
{
    modelnet::Grp43 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.recorded(""));
    BOOST_CHECK_EQUAL(eng.text_of(""), "");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.recorded("NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(gates_keep_check_order)
{
    modelnet::Grp43 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.recorded("NIF-NAT-001"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "note", static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "note", static_cast<int64_t>(101), false, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "private-body", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "deepinfer", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.recorded("NIF-NAT-001"));
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "see deepinfer later", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "private-body", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.recorded("NIF-NAT-001"));
    BOOST_CHECK(!eng.Apply("P2P-SCN-L", "note", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(!eng.Apply("P2P-SCN-L", "note", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK(!eng.Apply("P2P-SCN-L", "note", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.recorded("P2P-SCN-L"));
    BOOST_CHECK(eng.Apply("NIF-NAT-001", "low", static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.recorded("NIF-NAT-001"));
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-001"), "low");
    BOOST_CHECK(!eng.Apply("NIF-NAT-001", "low", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.stored("NIF-NAT-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-NAT-001"), "low");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_names_store_nothing)
{
    modelnet::Grp43 eng;
    std::string err = "stale";
    for (const char* name : kRemote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("NIF-PROF-004", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.recorded("NIF-PROF-004"));
        BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-004"), "");
        BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-004"), static_cast<int64_t>(0));
    }
    BOOST_CHECK(eng.Apply("NIF-PROF-004", "high", static_cast<int64_t>(100), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("NIF-PROF-004"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.text_of("NIF-PROF-004"), "high");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id)
{
    BOOST_REQUIRE_EQUAL(sizeof(kIds) / sizeof(kIds[0]), 20U);
    modelnet::Grp43 eng;
    std::string err = "stale";
    for (const char* raw : kIds) {
        const std::string id(raw);
        const int64_t aux = IsP2p(id) ? static_cast<int64_t>(1) : static_cast<int64_t>(7);
        BOOST_CHECK(!eng.Apply(id, "", aux, true, err));
        BOOST_CHECK_EQUAL(err, "FIELD");
        BOOST_CHECK(!eng.recorded(id));
        BOOST_CHECK(!eng.Apply(id, "note", static_cast<int64_t>(-1), true, err));
        BOOST_CHECK_EQUAL(err, "BOUND");
        BOOST_CHECK(!eng.Apply(id, "note", static_cast<int64_t>(101), true, err));
        BOOST_CHECK_EQUAL(err, "CAP");
        BOOST_CHECK(!eng.Apply(id, "note", aux, false, err));
        BOOST_CHECK_EQUAL(err, "ABSENT");
        BOOST_CHECK(!eng.Apply(id, "deepinfer", aux, true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK(!eng.Apply(id, "private note", aux, true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
        BOOST_CHECK(!eng.recorded(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "");
        BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
        if (IsP2p(id)) {
            BOOST_CHECK_EQUAL(eng.classification(id), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
            BOOST_CHECK(!eng.Apply(id, "note", static_cast<int64_t>(2), true, err));
            BOOST_CHECK_EQUAL(err, "HOSTS");
            BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
            BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
        } else {
            BOOST_CHECK_EQUAL(eng.classification(id), "COMPONENT");
        }
        if (id == "P2P-SCN-M") {
            BOOST_CHECK(!eng.Apply(id, "note", aux, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
            BOOST_CHECK(!eng.recorded(id));
            BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.Apply(id, "other", aux, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
            BOOST_CHECK(!eng.recorded(id));
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
        } else if (id == "NIF-FORK-004" || id == "NIF-FORK-005") {
            BOOST_CHECK(!eng.Apply(id, "note", aux, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
            BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
            BOOST_CHECK(!eng.recorded(id));
            BOOST_CHECK_EQUAL(eng.text_of(id), "");
            BOOST_CHECK_EQUAL(eng.stored(id), static_cast<int64_t>(0));
            BOOST_CHECK(!eng.Apply(id, "other", aux, true, err));
            BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
            BOOST_CHECK(!eng.recorded(id));
        } else {
            BOOST_CHECK(!NeverStores(id));
            BOOST_CHECK(eng.Apply(id, "note", aux, true, err));
            BOOST_CHECK(err.empty());
            BOOST_CHECK(eng.recorded(id));
            BOOST_CHECK_EQUAL(eng.text_of(id), "note");
            BOOST_CHECK_EQUAL(eng.stored(id), aux);
            BOOST_CHECK(!eng.Apply(id, "note", aux, true, err));
            BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
            BOOST_CHECK_EQUAL(err, "REPLAY");
            BOOST_CHECK_EQUAL(eng.text_of(id), "note");
            BOOST_CHECK_EQUAL(eng.stored(id), aux);
            BOOST_CHECK(!eng.Apply(id, "other", aux, true, err));
            BOOST_CHECK_EQUAL(err, "UNCHANGED");
            BOOST_CHECK_EQUAL(eng.text_of(id), "note");
            BOOST_CHECK_EQUAL(eng.stored(id), aux);
            BOOST_CHECK(eng.recorded(id));
        }
        BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
        BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
        BOOST_CHECK(!eng.qualified_v41());
        BOOST_CHECK(!eng.release_qualified());
    }
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
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
