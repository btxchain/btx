// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowearcost2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowearcost2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cost_id_yields_cost)
{
    modelnet::SwarmNotNoWearCost2 note;
    note.want_charge = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoWearCost2Result out = modelnet::SwarmNoteNotNoWearCost2(note, err);
    BOOST_CHECK_EQUAL(out.code, "COST");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.atoms, 0);
    BOOST_CHECK_EQUAL(err, "COST");
}

BOOST_AUTO_TEST_CASE(want_charge_yields_held)
{
    modelnet::SwarmNotNoWearCost2 note;
    note.cost_id = "wear-cost";
    note.want_charge = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoWearCost2Result out = modelnet::SwarmNoteNotNoWearCost2(note, err);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.atoms, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_with_err_empty)
{
    modelnet::SwarmNotNoWearCost2 note;
    note.cost_id = "wear-cost";
    note.want_charge = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoWearCost2Result out = modelnet::SwarmNoteNotNoWearCost2(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
