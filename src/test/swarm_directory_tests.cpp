// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_directory.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_directory_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_family_id_is_directory)
{
    std::string err;
    modelnet::SwarmDirectoryRequest request;
    request.family_id = "";
    const modelnet::SwarmDirectoryResult result = modelnet::SwarmListFamily(request, err);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK(!result.nat_opened);
    BOOST_CHECK_EQUAL(result.code, "DIRECTORY");
    BOOST_CHECK_EQUAL(err, "DIRECTORY");
}

BOOST_AUTO_TEST_CASE(want_socket_is_no_socket)
{
    std::string err;
    modelnet::SwarmDirectoryRequest request;
    request.family_id = "family-a";
    request.want_socket = true;
    const modelnet::SwarmDirectoryResult result = modelnet::SwarmListFamily(request, err);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK(!result.nat_opened);
    BOOST_CHECK_EQUAL(result.code, "NO_SOCKET");
    BOOST_CHECK_EQUAL(err, "NO_SOCKET");
}

BOOST_AUTO_TEST_CASE(want_nat_traversal_is_nat_absent)
{
    std::string err;
    modelnet::SwarmDirectoryRequest request;
    request.family_id = "family-a";
    request.want_nat_traversal = true;
    const modelnet::SwarmDirectoryResult result = modelnet::SwarmListFamily(request, err);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK(!result.nat_opened);
    BOOST_CHECK_EQUAL(result.code, "NAT_ABSENT");
    BOOST_CHECK_EQUAL(err, "NAT_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_public_directory_is_directory_private)
{
    std::string err;
    modelnet::SwarmDirectoryRequest request;
    request.family_id = "family-a";
    request.want_public_directory = true;
    const modelnet::SwarmDirectoryResult result = modelnet::SwarmListFamily(request, err);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK(!result.nat_opened);
    BOOST_CHECK_EQUAL(result.code, "DIRECTORY_PRIVATE");
    BOOST_CHECK_EQUAL(err, "DIRECTORY_PRIVATE");
}

BOOST_AUTO_TEST_CASE(local_catalog_lists_without_opening)
{
    std::string err = "prior";
    modelnet::SwarmDirectoryRequest request;
    request.family_id = "family-a";
    const modelnet::SwarmDirectoryResult result = modelnet::SwarmListFamily(request, err);
    BOOST_CHECK(result.listed);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK(!result.nat_opened);
    BOOST_CHECK_EQUAL(result.code, "LOCAL_CATALOG");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
