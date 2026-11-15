// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradexport.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_gradexport_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_update_id_is_update)
{
    modelnet::SwarmGradExport update;
    std::string err = "prior";
    const modelnet::SwarmGradExportResult result = modelnet::SwarmNoteGradExport(update, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "UPDATE");
    BOOST_CHECK_EQUAL(err, "UPDATE");
}

BOOST_AUTO_TEST_CASE(gradient_true_want_export_false_is_not_exported)
{
    modelnet::SwarmGradExport update;
    update.update_id = "update-1";
    update.gradient = true;
    update.want_export = false;
    std::string err = "prior";
    const modelnet::SwarmGradExportResult result = modelnet::SwarmNoteGradExport(update, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOT_EXPORTED");
    BOOST_CHECK_EQUAL(err, "NOT_EXPORTED");
}

BOOST_AUTO_TEST_CASE(want_export_true_gradient_false_is_held)
{
    modelnet::SwarmGradExport update;
    update.update_id = "update-1";
    update.gradient = false;
    update.want_export = true;
    std::string err = "prior";
    const modelnet::SwarmGradExportResult result = modelnet::SwarmNoteGradExport(update, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmGradExport update;
    update.update_id = "update-1";
    update.gradient = false;
    update.want_export = false;
    std::string err = "prior";
    const modelnet::SwarmGradExportResult result = modelnet::SwarmNoteGradExport(update, err);
    BOOST_CHECK_EQUAL(result.exported, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
