// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdataset.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdataset_tests, BasicTestingSetup)

static modelnet::SwarmNotDataset NotedNote()
{
    modelnet::SwarmNotDataset note;
    note.dataset_id = "dataset-1";
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_dataset_id_is_dataset)
{
    modelnet::SwarmNotDataset note = NotedNote();
    note.dataset_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotDatasetResult result = modelnet::SwarmNoteNotDataset(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "DATASET");
    BOOST_CHECK_EQUAL(err, "DATASET");
}

BOOST_AUTO_TEST_CASE(want_train_is_not_started)
{
    modelnet::SwarmNotDataset note = NotedNote();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotDatasetResult result = modelnet::SwarmNoteNotDataset(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDataset note = NotedNote();
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotDatasetResult result = modelnet::SwarmNoteNotDataset(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
