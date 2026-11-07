// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgradleak.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notgradleak_tests, BasicTestingSetup)

static modelnet::SwarmNotGradLeak NotedNote()
{
    modelnet::SwarmNotGradLeak note;
    note.gradient_id = "grad-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_gradient_id_is_gradient)
{
    modelnet::SwarmNotGradLeak note = NotedNote();
    note.gradient_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotGradLeakResult result = modelnet::SwarmNoteNotGradLeak(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "GRADIENT");
    BOOST_CHECK_EQUAL(err, "GRADIENT");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    modelnet::SwarmNotGradLeak note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotGradLeakResult result = modelnet::SwarmNoteNotGradLeak(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotGradLeak note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotGradLeakResult result = modelnet::SwarmNoteNotGradLeak(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
