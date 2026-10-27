// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_preimage_tests, BasicTestingSetup)

static modelnet::SwarmPreimage NotedPreimage()
{
    modelnet::SwarmPreimage preimage;
    preimage.invoice_id = "invoice-preimage";
    preimage.preimage_len = 32;
    preimage.want_route = false;
    return preimage;
}

static void ExpectUnqualified(const modelnet::SwarmPreimageResult& result)
{
    BOOST_CHECK(!result.qualified);
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_preimage)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.invoice_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(negative_preimage_len_is_preimage)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = -1;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_wins_over_len_and_want_route)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.invoice_id.clear();
    preimage.preimage_len = 16;
    preimage.want_route = true;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(negative_preimage_len_wins_over_want_route)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = -1;
    preimage.want_route = true;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(zero_preimage_len_is_len)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = 0;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "LEN");
    BOOST_CHECK_EQUAL(err, "LEN");
}

BOOST_AUTO_TEST_CASE(short_preimage_len_is_len)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = 31;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "LEN");
    BOOST_CHECK_EQUAL(err, "LEN");
}

BOOST_AUTO_TEST_CASE(long_preimage_len_is_len)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = 33;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "LEN");
    BOOST_CHECK_EQUAL(err, "LEN");
}

BOOST_AUTO_TEST_CASE(len_wins_when_want_route_is_true)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = 31;
    preimage.want_route = true;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "LEN");
    BOOST_CHECK_EQUAL(err, "LEN");
}

BOOST_AUTO_TEST_CASE(want_route_with_32_byte_preimage_is_held)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = 32;
    preimage.want_route = true;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(thirty_two_byte_preimage_without_route_is_noted)
{
    modelnet::SwarmPreimage preimage = NotedPreimage();
    preimage.preimage_len = 32;
    preimage.want_route = false;
    std::string err = "prior";
    const modelnet::SwarmPreimageResult result = modelnet::SwarmNotePreimage(preimage, err);
    ExpectUnqualified(result);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
