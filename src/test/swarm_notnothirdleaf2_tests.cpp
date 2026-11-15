// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothirdleaf2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnothirdleaf2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_yields_tx)
{
    modelnet::SwarmNotNoThirdLeaf2 note;
    note.tx_id.clear();
    note.want_build = false;
    std::string err;
    const modelnet::SwarmNotNoThirdLeaf2Result result = modelnet::SwarmNoteNotNoThirdLeaf2(note, err);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
    BOOST_CHECK(!result.built);
}

BOOST_AUTO_TEST_CASE(want_build_true_yields_held)
{
    modelnet::SwarmNotNoThirdLeaf2 note;
    note.tx_id = "noted";
    note.want_build = true;
    std::string err;
    const modelnet::SwarmNotNoThirdLeaf2Result result = modelnet::SwarmNoteNotNoThirdLeaf2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.built);
}

BOOST_AUTO_TEST_CASE(neither_yields_noted_with_err_empty)
{
    modelnet::SwarmNotNoThirdLeaf2 note;
    note.tx_id = "noted";
    note.want_build = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoThirdLeaf2Result result = modelnet::SwarmNoteNotNoThirdLeaf2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.built);
}

BOOST_AUTO_TEST_SUITE_END()
