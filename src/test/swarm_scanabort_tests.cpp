// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scanabort.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_scanabort_tests, BasicTestingSetup)

static modelnet::SwarmScanAbort NotedField()
{
    modelnet::SwarmScanAbort field;
    field.field_id = "field-1";
    field.wrong_type = false;
    field.want_continue = false;
    return field;
}

BOOST_AUTO_TEST_CASE(empty_field_id_is_field)
{
    modelnet::SwarmScanAbort field = NotedField();
    field.field_id.clear();
    std::string err = "prior";
    const modelnet::SwarmScanAbortResult result = modelnet::SwarmAbortWrongType(field, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "FIELD");
    BOOST_CHECK_EQUAL(err, "FIELD");
}

BOOST_AUTO_TEST_CASE(wrong_type_aborts_even_without_continue)
{
    modelnet::SwarmScanAbort field = NotedField();
    field.wrong_type = true;
    field.want_continue = false;
    std::string err = "prior";
    const modelnet::SwarmScanAbortResult result = modelnet::SwarmAbortWrongType(field, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ABORT");
    BOOST_CHECK_EQUAL(err, "ABORT");
}

BOOST_AUTO_TEST_CASE(want_continue_is_held)
{
    modelnet::SwarmScanAbort field = NotedField();
    field.wrong_type = false;
    field.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmScanAbortResult result = modelnet::SwarmAbortWrongType(field, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_field_is_noted)
{
    modelnet::SwarmScanAbort field = NotedField();
    field.wrong_type = false;
    field.want_continue = false;
    std::string err = "prior";
    const modelnet::SwarmScanAbortResult result = modelnet::SwarmAbortWrongType(field, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
