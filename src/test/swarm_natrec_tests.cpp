// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#include <modelnet/swarm_natrec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_natrec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_yields_node)
{
    std::string err = "prior";
    modelnet::SwarmNatRec rec;
    rec.want_publish = true;
    rec.want_open = true;
    const modelnet::SwarmNatRecResult result = modelnet::SwarmRecordNat(rec, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_publish_yields_held)
{
    std::string err = "prior";
    modelnet::SwarmNatRec rec;
    rec.node_id = "n1";
    rec.want_publish = true;
    rec.want_open = false;
    const modelnet::SwarmNatRecResult result = modelnet::SwarmRecordNat(rec, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_open_yields_held)
{
    std::string err = "prior";
    modelnet::SwarmNatRec rec;
    rec.node_id = "n1";
    rec.want_publish = false;
    rec.want_open = true;
    const modelnet::SwarmNatRecResult result = modelnet::SwarmRecordNat(rec, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(mapped_yields_noted)
{
    std::string err = "prior";
    modelnet::SwarmNatRec rec;
    rec.node_id = "n1";
    rec.mapped = true;
    rec.want_publish = false;
    rec.want_open = false;
    const modelnet::SwarmNatRecResult result = modelnet::SwarmRecordNat(rec, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
