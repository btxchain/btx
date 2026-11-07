// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp18/grp18.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp18& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp18_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_DS_DATA_005)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "do not ignore previous text", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "");
    BOOST_CHECK(eng.bit_of("DS-DATA-005"));
    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "see the instruction", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "");
    BOOST_CHECK(eng.bit_of("DS-DATA-005"));
    BOOST_CHECK(eng.Apply("DS-DATA-005", "", "ordinary log", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "ordinary log");
    BOOST_CHECK(!eng.bit_of("DS-DATA-005"));
    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "ignore previous", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "ordinary log");
    BOOST_CHECK(eng.bit_of("DS-DATA-005"));
    BOOST_CHECK(!eng.Apply("DS-DATA-005", "", "later log", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-005"), "ordinary log");
    BOOST_CHECK(eng.bit_of("DS-DATA-005"));
    modelnet::Grp18 word;
    BOOST_CHECK(word.Apply("DS-DATA-005", "", "instructions", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(word.stored("DS-DATA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(word.text_of("DS-DATA-005"), "instructions");
    BOOST_CHECK(!word.bit_of("DS-DATA-005"));
    BOOST_CHECK(!word.Apply("DS-DATA-005", "", "instruction", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "TAINT");
    BOOST_CHECK_EQUAL(word.stored("DS-DATA-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(word.text_of("DS-DATA-005"), "instructions");
    BOOST_CHECK(word.bit_of("DS-DATA-005"));
    BOOST_CHECK_EQUAL(eng.classification("DS-DATA-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DATA_006)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DATA-006", "", "gap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-DATA-006"));
    BOOST_CHECK(eng.Apply("DS-DATA-006", "", "clock", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-006"), "clock");
    BOOST_CHECK(!eng.bit_of("DS-DATA-006"));
    BOOST_CHECK(!eng.Apply("DS-DATA-006", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-006"), "clock");
    BOOST_CHECK(!eng.Apply("DS-DATA-006", "", "loss", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DATA-006"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DATA-006"), "clock");
    const char* const kinds[] = {"loss", "duplicate", "missing"};
    for (const char* kind : kinds) {
        modelnet::Grp18 one;
        BOOST_CHECK(one.Apply("DS-DATA-006", "", kind, "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(one.stored("DS-DATA-006"), static_cast<int64_t>(1));
        BOOST_CHECK_EQUAL(one.text_of("DS-DATA-006"), kind);
        BOOST_CHECK(!one.bit_of("DS-DATA-006"));
    }
    BOOST_CHECK_EQUAL(eng.classification("DS-DATA-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DEL_001)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DEL-001", "", "spec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "OUTSIDE");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-001"));
    BOOST_CHECK(!eng.Apply("DS-DEL-001", "", "source", "extra", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "OUTSIDE");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-001"));
    BOOST_CHECK_EQUAL(eng.classification("DS-DEL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DEL_002)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DEL-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-002"));
    BOOST_CHECK(eng.Apply("DS-DEL-002", "", "MIT", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-002"), "MIT");
    BOOST_CHECK(!eng.bit_of("DS-DEL-002"));
    BOOST_CHECK(!eng.Apply("DS-DEL-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-002"), "MIT");
    BOOST_CHECK(!eng.Apply("DS-DEL-002", "", "Apache", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-002"), "MIT");
    BOOST_CHECK_EQUAL(eng.classification("DS-DEL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DEL_003)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DEL-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOC");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-003"));
    BOOST_CHECK(eng.Apply("DS-DEL-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-003"), "readme");
    BOOST_CHECK(!eng.bit_of("DS-DEL-003"));
    BOOST_CHECK(!eng.Apply("DS-DEL-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DOC");
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-003"), "readme");
    BOOST_CHECK(!eng.bit_of("DS-DEL-003"));
    BOOST_CHECK(!eng.Apply("DS-DEL-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-003"), "readme");
    BOOST_CHECK(!eng.bit_of("DS-DEL-003"));
    BOOST_CHECK_EQUAL(eng.classification("DS-DEL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DEL_004)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DEL-004", "", "pool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ASSURANCE");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-004"));
    BOOST_CHECK(eng.Apply("DS-DEL-004", "", "pool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-004"), "pool");
    BOOST_CHECK(!eng.Apply("DS-DEL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "ASSURANCE");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-004"), "pool");
    BOOST_CHECK(!eng.Apply("DS-DEL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-004"), "pool");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-DEL-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DEL_005)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DEL-005", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-005"), "");
    BOOST_CHECK(eng.Apply("DS-DEL-005", "", "native", "fp", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-005"), "native");
    BOOST_CHECK(!eng.Apply("DS-DEL-005", "", "changed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-005"), "native");
    BOOST_CHECK(!eng.Apply("DS-DEL-005", "", "changed", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-005"), "native");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-DEL-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_DEL_006)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-DEL-006", "", "push", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-006"));
    BOOST_CHECK(!eng.Apply("DS-DEL-006", "", "publish", "extra", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(eng.stored("DS-DEL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-DEL-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-DEL-006"));
    BOOST_CHECK_EQUAL(eng.classification("DS-DEL-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_EVAL_001)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "", "ablation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BASELINE");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-001"));
    BOOST_CHECK(eng.Apply("DS-EVAL-001", "", "ablation", "central", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-001"), "ablation");
    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "BASELINE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-001"), "ablation");
    BOOST_CHECK(!eng.Apply("DS-EVAL-001", "", "other", "single", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-001"), "ablation");
    BOOST_CHECK_EQUAL(eng.classification("DS-EVAL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_EVAL_002)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-EVAL-002", "", "fast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-002"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-002", "", "triage effect false", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "");
    BOOST_CHECK(eng.Apply("DS-EVAL-002", "", "triage effect false cost", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "triage effect false cost");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-002"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-002", "", "no", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "triage effect false cost");
    BOOST_CHECK(!eng.Apply("DS-EVAL-002", "", "cost false effect triage", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-002"), "triage effect false cost");
    BOOST_CHECK_EQUAL(eng.classification("DS-EVAL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_EVAL_003)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-EVAL-003", "", "late", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DELAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-003"));
    BOOST_CHECK(eng.Apply("DS-EVAL-003", "", "cold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "cold");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-003"));
    BOOST_CHECK(eng.Apply("DS-EVAL-003", "", "warm", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "warm");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-003"));
    BOOST_CHECK(eng.Apply("DS-EVAL-003", "", "external", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "external");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-003"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-003", "", "cold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "external");
    BOOST_CHECK(!eng.Apply("DS-EVAL-003", "", "warm", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "external");
    BOOST_CHECK(!eng.Apply("DS-EVAL-003", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "DELAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-003"), "external");
    BOOST_CHECK_EQUAL(eng.classification("DS-EVAL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_EVAL_004)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-EVAL-004", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-004"), "scope");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-004"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-004"), "scope");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-004"));
    BOOST_CHECK_EQUAL(eng.classification("DS-EVAL-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_EVAL_005)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-EVAL-005", "", "same", "same", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-005"));
    BOOST_CHECK(eng.Apply("DS-EVAL-005", "", "review", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-005"), "review");
    BOOST_CHECK(!eng.Apply("DS-EVAL-005", "", "same", "same", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-005"), "review");
    BOOST_CHECK(!eng.Apply("DS-EVAL-005", "", "next", "diff", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-005"), "review");
    modelnet::Grp18 blank;
    BOOST_CHECK(blank.Apply("DS-EVAL-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(blank.stored("DS-EVAL-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(blank.text_of("DS-EVAL-005"), "");
    BOOST_CHECK_EQUAL(eng.classification("DS-EVAL-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_EVAL_006)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-EVAL-006"));
    BOOST_CHECK(!eng.Apply("DS-EVAL-006", "", "production", "extra", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.stored("DS-EVAL-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-EVAL-006"), "");
    BOOST_CHECK_EQUAL(eng.classification("DS-EVAL-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_HIRE_001)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "model", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-001"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "model,runtime", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "");
    BOOST_CHECK(eng.Apply("DS-HIRE-001", "", "model,runtime,tool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "model,runtime,tool");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-001"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "model,runtime,tool");
    BOOST_CHECK(!eng.Apply("DS-HIRE-001", "", "x,y,z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-001"), "model,runtime,tool");
    BOOST_CHECK_EQUAL(eng.classification("DS-HIRE-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp18 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NO-SUCH", "", "text", "extra", static_cast<int64_t>(1), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("NO-SUCH"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("NO-SUCH"), "");
    BOOST_CHECK(!eng.bit_of("NO-SUCH"));
    BOOST_CHECK_EQUAL(eng.classification("NO-SUCH"), "COMPONENT");
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored(""), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
