// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_resultshare.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_resultshare_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(publish_attach_mismatch_replay)
{
    modelnet::SwarmResultShare share;
    std::string err = "stale";

    BOOST_CHECK(!share.Publish("", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "RESULT");
    BOOST_CHECK(!share.Attached("", "reader"));

    BOOST_CHECK(!share.Publish("res-1", "", err));
    BOOST_CHECK_EQUAL(err, "RESULT");
    BOOST_CHECK(!share.Attached("res-1", "reader"));

    BOOST_REQUIRE(share.Publish("res-1", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!share.Attached("res-1", "reader"));

    BOOST_CHECK(!share.Publish("res-1", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!share.Attach("missing", "reader", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "RESULT");
    BOOST_CHECK(!share.Attached("missing", "reader"));

    BOOST_CHECK(!share.Attach("res-1", "", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "CONSUMER");
    BOOST_CHECK(!share.Attached("res-1", ""));

    BOOST_CHECK(!share.Attach("res-1", "reader", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!share.Attached("res-1", "reader"));

    BOOST_REQUIRE(share.Attach("res-1", "reader", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(share.Attached("res-1", "reader"));
    BOOST_CHECK(!share.Attached("res-1", "writer"));

    BOOST_CHECK(!share.Attach("res-1", "reader", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(share.Attached("res-1", "reader"));

    BOOST_CHECK(!share.Attach("res-1", "reader", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(share.Attached("res-1", "reader"));

    BOOST_REQUIRE(share.Attach("res-1", "writer", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(share.Attached("res-1", "writer"));
    BOOST_CHECK(share.Attached("res-1", "reader"));
}

BOOST_AUTO_TEST_SUITE_END()
