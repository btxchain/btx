// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcatalog.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcatalog_tests, BasicTestingSetup)

static modelnet::SwarmNotCatalog NotedNote()
{
    modelnet::SwarmNotCatalog note;
    note.model_id = "model-1";
    note.want_emit = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_model_id_is_model)
{
    modelnet::SwarmNotCatalog note = NotedNote();
    note.model_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotCatalogResult result = modelnet::SwarmNoteNotCatalog(note, err);
    BOOST_CHECK(!result.emitted);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(want_emit_is_not_emitted)
{
    modelnet::SwarmNotCatalog note = NotedNote();
    note.want_emit = true;
    std::string err = "prior";
    const modelnet::SwarmNotCatalogResult result = modelnet::SwarmNoteNotCatalog(note, err);
    BOOST_CHECK(!result.emitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_EMITTED");
    BOOST_CHECK_EQUAL(err, "NOT_EMITTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCatalog note = NotedNote();
    note.want_emit = false;
    std::string err = "prior";
    const modelnet::SwarmNotCatalogResult result = modelnet::SwarmNoteNotCatalog(note, err);
    BOOST_CHECK(!result.emitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
