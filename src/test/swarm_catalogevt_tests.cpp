// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_catalogevt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_catalogevt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_event_id_or_candidate_id_is_catalog)
{
    std::string err = "prior";
    modelnet::SwarmCatalogEvent missing_event;
    missing_event.candidate_id = "candidate-a";
    missing_event.qualified = true;
    missing_event.want_adopt = true;
    const modelnet::SwarmCatalogEventResult no_event = modelnet::SwarmNoteCatalogEvent(missing_event, err);
    BOOST_CHECK(!no_event.noted);
    BOOST_CHECK(!no_event.adopted);
    BOOST_CHECK(!no_event.socket_opened);
    BOOST_CHECK_EQUAL(no_event.code, "CATALOG");
    BOOST_CHECK_EQUAL(err, "CATALOG");

    modelnet::SwarmCatalogEvent missing_candidate;
    missing_candidate.event_id = "event-a";
    missing_candidate.qualified = true;
    missing_candidate.want_socket = true;
    const modelnet::SwarmCatalogEventResult no_candidate = modelnet::SwarmNoteCatalogEvent(missing_candidate, err);
    BOOST_CHECK(!no_candidate.noted);
    BOOST_CHECK(!no_candidate.adopted);
    BOOST_CHECK(!no_candidate.socket_opened);
    BOOST_CHECK_EQUAL(no_candidate.code, "CATALOG");
    BOOST_CHECK_EQUAL(err, "CATALOG");
}

BOOST_AUTO_TEST_CASE(want_socket_is_no_socket)
{
    std::string err = "prior";
    modelnet::SwarmCatalogEvent event;
    event.event_id = "event-a";
    event.candidate_id = "candidate-a";
    event.qualified = true;
    event.want_socket = true;
    event.want_adopt = true;
    const modelnet::SwarmCatalogEventResult result = modelnet::SwarmNoteCatalogEvent(event, err);
    BOOST_CHECK(!result.noted);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "NO_SOCKET");
    BOOST_CHECK_EQUAL(err, "NO_SOCKET");
}

BOOST_AUTO_TEST_CASE(unqualified_adopt_is_not_adopted)
{
    std::string err = "prior";
    modelnet::SwarmCatalogEvent event;
    event.event_id = "event-a";
    event.candidate_id = "candidate-a";
    event.qualified = false;
    event.want_adopt = true;
    const modelnet::SwarmCatalogEventResult result = modelnet::SwarmNoteCatalogEvent(event, err);
    BOOST_CHECK(!result.noted);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADOPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ADOPTED");
}

BOOST_AUTO_TEST_CASE(noted_does_not_adopt_or_open_a_socket)
{
    std::string err = "prior";
    modelnet::SwarmCatalogEvent event;
    event.event_id = "event-a";
    event.candidate_id = "candidate-a";
    event.qualified = true;
    event.want_adopt = true;
    const modelnet::SwarmCatalogEventResult result = modelnet::SwarmNoteCatalogEvent(event, err);
    BOOST_CHECK(result.noted);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
