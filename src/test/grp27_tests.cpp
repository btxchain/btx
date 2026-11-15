// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp27/grp27.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp27& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
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

BOOST_FIXTURE_TEST_SUITE(grp27_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(three_versus_four_disagrees)
{
    modelnet::Grp27 eng;
    std::string err;
    BOOST_CHECK(!eng.agreed());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Compare(static_cast<int64_t>(3), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK(!eng.agreed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!eng.Compare(static_cast<int64_t>(3), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "DISAGREE");
    BOOST_CHECK(!eng.agreed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(equal_fives_agree)
{
    modelnet::Grp27 eng;
    std::string err;
    BOOST_CHECK(eng.Compare(static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.agreed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.classification(), "SIMULATION_NOT_HARDWARE_MEASUREMENT");
    BOOST_CHECK(!eng.Compare(static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.agreed());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.gpu());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(self_grade_is_self)
{
    modelnet::Grp27 eng;
    std::string err;
    BOOST_CHECK(!eng.Grade("exp", "cand", "same", "same", "domain-a", "domain-b", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!eng.eval_qualified("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.Grade("exp", "cand", "same", "same", "domain-a", "domain-b", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!eng.eval_qualified("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(same_domain_is_not_quorum)
{
    modelnet::Grp27 eng;
    std::string err;
    BOOST_CHECK(!eng.Grade("exp", "cand", "author", "eval", "domain", "domain", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
    BOOST_CHECK(!eng.eval_qualified("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.Grade("exp", "cand", "author", "eval", "domain", "domain", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
    BOOST_CHECK(!eng.eval_qualified("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(engine_rule_does_not_qualify_this_class)
{
    modelnet::Grp27 eng;
    std::string err;
    BOOST_CHECK(eng.Grade("exp", "cand", "author-a", "eval-a", "domain-a", "domain-b", false, false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.eval_qualified("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(eng.Grade("exp", "cand", "author-b", "eval-b", "domain-c", "domain-d", false, false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.eval_qualified("cand"));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
