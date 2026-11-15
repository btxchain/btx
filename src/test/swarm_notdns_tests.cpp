// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdns.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdns_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_seed_id_is_seed)
{
    modelnet::SwarmNotDns note;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotDnsResult result = modelnet::SwarmNoteNotDns(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.seed_count, 0);
    BOOST_CHECK_EQUAL(result.code, "SEED");
    BOOST_CHECK_EQUAL(err, "SEED");
}

BOOST_AUTO_TEST_CASE(want_publish_is_empty)
{
    modelnet::SwarmNotDns note;
    note.seed_id = "seed-1";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotDnsResult result = modelnet::SwarmNoteNotDns(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.seed_count, 0);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDns note;
    note.seed_id = "seed-1";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotDnsResult result = modelnet::SwarmNoteNotDns(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.seed_count, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
