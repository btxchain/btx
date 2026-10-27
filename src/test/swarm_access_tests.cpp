// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_access.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_access_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(revocation_keeps_plaintext_and_a_shared_key_is_not_per_recipient)
{
    modelnet::SwarmMembershipRevocation row;
    row.plaintext_erased = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmRevokeMembership(row, true, err));
    BOOST_CHECK_EQUAL(err, "SHARED_REALM_KEY");
    BOOST_CHECK(!row.future_access);
    BOOST_CHECK(!row.plaintext_erased);
    BOOST_CHECK(!row.per_recipient);

    modelnet::SwarmMembershipRevocation distinct;
    BOOST_REQUIRE(modelnet::SwarmRevokeMembership(distinct, false, err));
    BOOST_CHECK(!distinct.future_access);
    BOOST_CHECK(!distinct.plaintext_erased);

    BOOST_CHECK(!modelnet::SwarmAcceptProducer(true, true, err));
    BOOST_CHECK_EQUAL(err, "COMPILER_CACHE");
    BOOST_CHECK(!modelnet::SwarmAcceptProducer(false, false, err));
    BOOST_CHECK_EQUAL(err, "PRODUCER");
    BOOST_CHECK(modelnet::SwarmAcceptProducer(true, false, err));

    bool revealed = true;
    BOOST_CHECK(!modelnet::SwarmDedupAcrossRealms("a", "b", true, revealed, err));
    BOOST_CHECK_EQUAL(err, "DEDUP_PRIVATE");
    BOOST_CHECK(!revealed);
    BOOST_REQUIRE(modelnet::SwarmDedupAcrossRealms("a", "a", true, revealed, err));
    BOOST_CHECK(revealed);

    BOOST_CHECK(!modelnet::SwarmFamilyIsCompatible(true, false, true, true, err));
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
    BOOST_CHECK(modelnet::SwarmFamilyIsCompatible(false, true, true, true, err));

    BOOST_CHECK(!modelnet::SwarmBatchWithinCap(129, err));
    BOOST_CHECK_EQUAL(err, "BATCH_CAP");
    BOOST_CHECK(modelnet::SwarmBatchWithinCap(128, err));
}

BOOST_AUTO_TEST_SUITE_END()
