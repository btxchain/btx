// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp19/grp19.h>
#include <test/util/setup_common.h>


#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp19& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp19_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_DS_HIRE_002)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "other", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ADMISSION");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "family", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ADMISSION");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "private", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ADMISSION");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002#private"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-HIRE-002", "family", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002#family"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002#family"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "family", "family", "again", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "private", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ADMISSION");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002#family"));
    BOOST_CHECK(eng.Apply("DS-HIRE-002", "private", "private", "seat", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "private");
    BOOST_CHECK(eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002#private"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#private"), "private");
    BOOST_CHECK(eng.bit_of("DS-HIRE-002#private"));
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-002#family"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002#family"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "private", "private", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002"), "private");
    BOOST_CHECK(eng.bit_of("DS-HIRE-002"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002#family"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-002", "family", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#family"), "family");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-002#family"));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-002#private"), "private");
    BOOST_CHECK(eng.bit_of("DS-HIRE-002#private"));
    BOOST_CHECK_EQUAL(eng.classification("DS-HIRE-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_HIRE_003)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-HIRE-003", "", "role", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-003"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("DS-HIRE-003", "", "role", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-003"), "role");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-003"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Apply("DS-HIRE-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-003"), "role");
    BOOST_CHECK(!eng.Apply("DS-HIRE-003", "", "role", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-003"), "role");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-HIRE-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_HIRE_004)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-HIRE-004", "", "alpha", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "alpha");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-004"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-004", "", "alpha", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "alpha");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-004"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-HIRE-004", "", "beta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SUBSTITUTE");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-004"), "alpha");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-004"));
    BOOST_CHECK_EQUAL(eng.classification("DS-HIRE-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_HIRE_005)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-HIRE-005", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONFIG");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-005"));
    BOOST_CHECK(eng.Apply("DS-HIRE-005", "", "ignored", "cfg", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-005"), "cfg");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-005"));
    BOOST_CHECK(!eng.Apply("DS-HIRE-005", "", "ignored", "later", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-005"), "cfg");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-005"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-HIRE-005", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "CONFIG");
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-005"), "cfg");
    BOOST_CHECK_EQUAL(eng.classification("DS-HIRE-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_HIRE_006)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-HIRE-006", "show", "banner", "extra", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-HIRE-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-HIRE-006"));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-HIRE-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DS-HIRE-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.classification("DS-HIRE-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_LEARN_001)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-LEARN-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "RELEASE");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-001"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-LEARN-001", "", "ship", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-001"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-LEARN-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_LEARN_002)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-LEARN-002", "", "hold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-002"));
    BOOST_CHECK(eng.Apply("DS-LEARN-002", "", "time", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "time");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002#time"), "time");
    BOOST_CHECK(eng.Apply("DS-LEARN-002", "", "campaign", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "campaign");
    BOOST_CHECK(!eng.Apply("DS-LEARN-002", "", "time", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "campaign");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002#time"), "time");
    BOOST_CHECK(eng.Apply("DS-LEARN-002", "", "tenant", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "tenant");
    BOOST_CHECK(eng.Apply("DS-LEARN-002", "", "lineage", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "lineage");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-002"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-002"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002"), "lineage");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-002#campaign"), "campaign");
    BOOST_CHECK_EQUAL(eng.classification("DS-LEARN-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_LEARN_003)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-LEARN-003", "", "secret", "x", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-003"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-003", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-003"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-LEARN-003", "", "synthetic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-LEARN-003", "", "public", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-003"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-003"), "public");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-003"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-003", "", "synthetic", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-003"), "public");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-003"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-LEARN-003", "", "secret", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-003"), "public");
    BOOST_CHECK_EQUAL(eng.classification("DS-LEARN-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_LEARN_004)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-LEARN-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HARM");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-004"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-004"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("DS-LEARN-004", "", "note", "x", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-004"), "note");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-004"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-LEARN-004", "", "other", "y", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-004"), "note");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-LEARN-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "HARM");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-004"), "note");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-LEARN-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_LEARN_005)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-LEARN-005", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-005"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-005"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-005"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-005", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-005"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-LEARN-005", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-005"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-005"), "left,right");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-005"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-005", "", "left", "down", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-005"), "left,right");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-005"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-LEARN-005", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-005"), "left,right");
    BOOST_CHECK_EQUAL(eng.classification("DS-LEARN-005"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_LEARN_006)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-006"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-006"), "");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-006"));
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-006"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Apply("DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-006"), "span");
    BOOST_CHECK(!eng.bit_of("DS-LEARN-006"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-006"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.text_of("DS-LEARN-006"), "span");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(eng.stored("DS-LEARN-006"), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.classification("DS-LEARN-006"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_MODEL_001)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", "", "south", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-001"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-001"), "");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-001"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", "north", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-001"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-001"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-MODEL-001", "", "north", "south", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-001"), "north|south");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-001"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", "east", "west", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-001"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-001"), "north|south");
    BOOST_CHECK(!eng.Apply("DS-MODEL-001", "", "", "south", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-001"), "north|south");
    BOOST_CHECK_EQUAL(eng.classification("DS-MODEL-001"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_MODEL_002)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-002"), "");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-002"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-002"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-002"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-002"), "");
    BOOST_CHECK(eng.Apply("DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-002"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-002"), "public");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-002"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-002"), "public");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-002"), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "APPROVAL");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-002"), "public");
    BOOST_CHECK(!eng.Apply("DS-MODEL-002", "", "private", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-002"), "public");
    BOOST_CHECK_EQUAL(eng.classification("DS-MODEL-002"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_MODEL_003)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "nixl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-003"), "");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-003"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "mooncake", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "rdma", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Apply("DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(3), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-003"), "mesh");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-003"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("DS-MODEL-003", "", "nixl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-003"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-003"), "mesh");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.classification("DS-MODEL-003"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DS_MODEL_004)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(eng.Apply("DS-MODEL-004", "", "pin-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-004"), "pin-a");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-004"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-004", "", "pin-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "PIN");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-004"), "pin-a");
    BOOST_CHECK(!eng.bit_of("DS-MODEL-004"));
    BOOST_CHECK(!eng.Apply("DS-MODEL-004", "", "pin-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.stored("DS-MODEL-004"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text_of("DS-MODEL-004"), "pin-a");
    BOOST_CHECK_EQUAL(eng.classification("DS-MODEL-004"), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp19 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DS-NONE", "", "text", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(eng.stored("DS-NONE"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.text_of("DS-NONE"), "");
    BOOST_CHECK(!eng.bit_of("DS-NONE"));
    BOOST_CHECK_EQUAL(eng.classification("DS-NONE"), "COMPONENT");
    BOOST_CHECK(!eng.Apply("", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK_EQUAL(eng.classification(""), "COMPONENT");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
