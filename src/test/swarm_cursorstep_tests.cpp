// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorstep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cursorstep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cursor_steps_forward_and_refuses_stale_and_gap)
{
    modelnet::SwarmCursorStep step;
    BOOST_CHECK_EQUAL(step.cursor(), uint64_t{0});

    std::string err = "prior";
    BOOST_CHECK(step.Advance(1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(step.cursor(), uint64_t{1});

    err = "prior";
    BOOST_CHECK(!step.Advance(1, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(step.cursor(), uint64_t{1});

    err = "prior";
    BOOST_CHECK(!step.Advance(0, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(step.cursor(), uint64_t{1});

    err = "prior";
    BOOST_CHECK(!step.Advance(3, err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(step.cursor(), uint64_t{1});

    err = "prior";
    BOOST_CHECK(step.Advance(2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(step.cursor(), uint64_t{2});
}

BOOST_AUTO_TEST_SUITE_END()
