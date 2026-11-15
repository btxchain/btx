// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hostinterp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hostinterp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_job_interp)
{
    modelnet::SwarmHostInterp interp;
    std::string err = "prior";

    BOOST_CHECK(!interp.Admit("", "interp-a", false, err));
    BOOST_CHECK_EQUAL(err, "INTERP");
    BOOST_CHECK(!interp.admitted(""));
    BOOST_CHECK(!interp.admitted("job-a"));
    BOOST_CHECK(!interp.launched());

    err = "prior";
    BOOST_CHECK(!interp.Admit("job-a", "", false, err));
    BOOST_CHECK_EQUAL(err, "INTERP");
    BOOST_CHECK(!interp.admitted("job-a"));
    BOOST_CHECK(!interp.launched());
}

BOOST_AUTO_TEST_CASE(host_path_refused)
{
    modelnet::SwarmHostInterp interp;
    std::string err = "prior";

    BOOST_CHECK(!interp.Admit("job-a", "interp-a", true, err));
    BOOST_CHECK_EQUAL(err, "HOST");
    BOOST_CHECK(!interp.admitted("job-a"));
    BOOST_CHECK(!interp.launched());
}

BOOST_AUTO_TEST_CASE(non_host_admits_without_launch)
{
    modelnet::SwarmHostInterp interp;
    std::string err = "prior";

    BOOST_REQUIRE(interp.Admit("job-a", "interp-a", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(interp.admitted("job-a"));
    BOOST_CHECK(!interp.launched());
}

BOOST_AUTO_TEST_CASE(duplicate_job_replay)
{
    modelnet::SwarmHostInterp interp;
    std::string err = "prior";

    BOOST_REQUIRE(interp.Admit("job-a", "interp-a", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(interp.admitted("job-a"));
    BOOST_CHECK(!interp.launched());

    err = "prior";
    BOOST_CHECK(!interp.Admit("job-a", "interp-a", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(interp.admitted("job-a"));
    BOOST_CHECK(!interp.launched());
}

BOOST_AUTO_TEST_SUITE_END()
