// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoablation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_bench_id_is_bench)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAblation note;
    note.want_publish = true;
    const modelnet::SwarmNotNoAblationResult result = modelnet::SwarmNoteNotNoAblation(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAblation note;
    note.bench_id = "bench-unit";
    note.want_publish = true;
    const modelnet::SwarmNotNoAblationResult result = modelnet::SwarmNoteNotNoAblation(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAblation note;
    note.bench_id = "bench-unit";
    note.want_publish = false;
    const modelnet::SwarmNotNoAblationResult result = modelnet::SwarmNoteNotNoAblation(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
