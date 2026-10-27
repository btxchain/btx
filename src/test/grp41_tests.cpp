// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp41/grp41.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp41& eng)
{
    std::string err;
    BOOST_CHECK(!eng.effect_sent());
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
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
}

const char* kPay[] = {
    "DS-PAY-002", "DS-PAY-003", "DS-PAY-004", "DS-PAY-005", "DS-PAY-006",
};

const char* kOps[] = {
    "DS-OPS-001", "DS-OPS-002", "DS-OPS-003", "DS-OPS-004", "DS-OPS-005", "DS-OPS-006",
};

const char* kEvalStore[] = {
    "DS-EVAL-001", "DS-EVAL-002", "DS-EVAL-003", "DS-EVAL-004", "DS-EVAL-005",
};

const char* kRec[] = {
    "DS-REC-001", "DS-REC-002", "DS-REC-003",
};

const char* kRemote[] = {
    "deepinfer", "vllm", "sglang", "lmcache", "deepep", "deepgemm",
    "dualpipe", "dualpipev", "nixl", "mooncake", "rdma",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp41_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_or_empty_id)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("", "benign", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_ID);
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("", "benign", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-PAY-001", "benign", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_ID);
    BOOST_CHECK(!eng.stored("DS-PAY-001"));
    BOOST_CHECK(!eng.Apply("DS-OPS-007", "benign", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("DS-EVAL-007", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.Apply("DS-REC-004", "note", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.stored("DS-REC-004"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(empty_text_is_field)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-REC-001", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_FIELD);
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-REC-001"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-OPS-001", "", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-OPS-001"));
    BOOST_CHECK(!eng.Apply("DS-PAY-002", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_FIELD);
    BOOST_CHECK(!eng.stored("DS-PAY-002"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("DS-EVAL-006"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(aux_bound_and_cap)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "note", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_BOUND);
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.stored("DS-EVAL-001"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "note", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_CAP);
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK(!eng.stored("DS-EVAL-001"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(flag_false_is_absent)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-REC-002", "note", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_ABSENT);
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.stored("DS-REC-002"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_names_are_engine_absent)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    for (const char* name : kRemote) {
        BOOST_CHECK(!modelnet::NifDtEngineLinked(name));
        BOOST_CHECK(!eng.Apply("DS-REC-001", name, static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK(!eng.stored("DS-REC-001"));
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(text_containing_private)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-PAY-003", "private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-PAY-003"));

    BOOST_CHECK(!eng.Apply("DS-OPS-002", "benign private", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DS-OPS-002"));

    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "keep private", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!eng.stored("DS-EVAL-006"));

    BOOST_CHECK(!eng.Apply("DS-REC-001", "not-private-data", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_PRIVATE_DATA);
    BOOST_CHECK(!eng.stored("DS-REC-001"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.effect_sent());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_pay_id_is_unqualified)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    for (const char* id : kPay) {
        BOOST_CHECK(!eng.Apply(id, "benign", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.stored(id));
        BOOST_CHECK(!eng.Apply(id, "benign", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.stored(id));
        BOOST_CHECK(!eng.Apply(id, "other", static_cast<int64_t>(100), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
        BOOST_CHECK(!eng.stored(id));
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.effect_sent());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(ops_fixture_and_benign_replay)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    for (const char* id : kOps) {
        BOOST_CHECK(!eng.Apply(id, "other", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::GRP41_FIXTURE);
        BOOST_CHECK_EQUAL(err, "FIXTURE");
        BOOST_CHECK(!eng.stored(id));
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));

    for (const char* id : kOps) {
        BOOST_CHECK(eng.Apply(id, "benign", static_cast<int64_t>(1), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "benign");
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(1));
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(6));

    BOOST_CHECK(!eng.Apply("DS-OPS-001", "benign", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-001"), "benign");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-OPS-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(6));

    BOOST_CHECK(!eng.Apply("DS-OPS-001", "other", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_FIXTURE);
    BOOST_CHECK_EQUAL(eng.text_of("DS-OPS-001"), "benign");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(6));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(eval_006_is_unqualified)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "score", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-EVAL-006"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "score", static_cast<int64_t>(100), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-EVAL-006"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "other", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.stored("DS-EVAL-006"));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.effect_sent());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(eval_and_rec_store_once)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    int64_t n = static_cast<int64_t>(0);
    for (const char* id : kEvalStore) {
        BOOST_CHECK(eng.Apply(id, "first", static_cast<int64_t>(0), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "first");
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(0));
        n += static_cast<int64_t>(1);
    }
    for (const char* id : kRec) {
        BOOST_CHECK(eng.Apply(id, "first", static_cast<int64_t>(100), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "first");
        BOOST_CHECK_EQUAL(eng.aux_of(id), static_cast<int64_t>(100));
        n += static_cast<int64_t>(1);
    }
    BOOST_CHECK_EQUAL(eng.count(), n);
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(8));

    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "first", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-001"), "first");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-EVAL-001"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "second", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_UNCHANGED);
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-001"), "first");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-EVAL-001"), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Apply("DS-REC-003", "second", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-003"), "first");
    BOOST_CHECK_EQUAL(eng.aux_of("DS-REC-003"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(8));

    BOOST_CHECK(!eng.Apply("DS-EVAL-002", "first", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "first");
    BOOST_CHECK(!eng.Apply("DS-EVAL-002", "second", static_cast<int64_t>(101), true, err));
    BOOST_CHECK_EQUAL(err, "CAP");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "first");
    BOOST_CHECK(!eng.Apply("DS-REC-001", "first", static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-REC-001"), "first");
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(8));

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.stored("DS-EVAL-005"));
    BOOST_CHECK(eng.stored("DS-REC-002"));
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_two_is_hosts)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Apply("DS-EVAL-003", "memory", static_cast<int64_t>(1), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::NifDtEngineLinked("memory"));
    BOOST_CHECK(eng.stored("DS-EVAL-003"));

    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::GRP41_HOSTS);
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.stored("DS-EVAL-003"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "memory");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.effect_sent());

    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(every_known_id_once)
{
    modelnet::Grp41 eng;
    std::string err = "stale";
    for (const char* id : kPay) {
        BOOST_CHECK(!eng.Apply(id, "benign", static_cast<int64_t>(0), true, err));
        BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
        BOOST_CHECK(!eng.stored(id));
    }
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "score", static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.stored("DS-EVAL-006"));

    for (const char* id : kOps) {
        BOOST_CHECK(eng.Apply(id, "benign", static_cast<int64_t>(0), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "benign");
    }
    for (const char* id : kEvalStore) {
        BOOST_CHECK(eng.Apply(id, "kept", static_cast<int64_t>(100), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
        BOOST_CHECK(!eng.Apply(id, "later", static_cast<int64_t>(1), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::GRP41_UNCHANGED);
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
    }
    for (const char* id : kRec) {
        BOOST_CHECK(eng.Apply(id, "kept", static_cast<int64_t>(50), true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.stored(id));
        BOOST_CHECK(!eng.Apply(id, "kept", static_cast<int64_t>(50), true, err));
        BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
        BOOST_CHECK_EQUAL(eng.text_of(id), "kept");
    }
    BOOST_CHECK_EQUAL(eng.count(), static_cast<int64_t>(14));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.effect_sent());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
