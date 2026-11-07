// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleaf2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoleaf2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_contract_id_is_contract)
{
    modelnet::SwarmNotNoLeaf2 note;
    note.contract_id.clear();
    note.want_third = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaf2Result result = modelnet::SwarmNoteNotNoLeaf2(note, err);
    BOOST_CHECK(!result.built);
    BOOST_CHECK_EQUAL(result.code, "CONTRACT");
    BOOST_CHECK_EQUAL(err, "CONTRACT");
}

BOOST_AUTO_TEST_CASE(want_third_is_held)
{
    modelnet::SwarmNotNoLeaf2 note;
    note.contract_id = "contract-1";
    note.want_third = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaf2Result result = modelnet::SwarmNoteNotNoLeaf2(note, err);
    BOOST_CHECK(!result.built);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoLeaf2 note;
    note.contract_id = "contract-1";
    note.want_third = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoLeaf2Result result = modelnet::SwarmNoteNotNoLeaf2(note, err);
    BOOST_CHECK(!result.built);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
