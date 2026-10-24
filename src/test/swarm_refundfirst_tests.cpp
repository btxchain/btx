// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundfirst.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_refundfirst_tests, BasicTestingSetup)

static modelnet::SwarmRefundFirst NotedRefundFirst()
{
    modelnet::SwarmRefundFirst note;
    note.channel_id = "channel-refund-first";
    note.refund_signed = true;
    note.want_count_funding = false;
    return note;
}

static void ExpectNeither(const modelnet::SwarmRefundFirstResult& result)
{
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_fund)
{
    modelnet::SwarmRefundFirst note = NotedRefundFirst();
    note.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmRefundFirstResult result = modelnet::SwarmNoteRefundFirst(note, err);
    ExpectNeither(result);
    BOOST_CHECK_EQUAL(result.code, "FUND");
    BOOST_CHECK_EQUAL(err, "FUND");
}

BOOST_AUTO_TEST_CASE(empty_channel_id_wins_over_unsigned_and_count)
{
    modelnet::SwarmRefundFirst note;
    note.channel_id.clear();
    note.refund_signed = false;
    note.want_count_funding = true;
    std::string err = "prior";
    const modelnet::SwarmRefundFirstResult result = modelnet::SwarmNoteRefundFirst(note, err);
    ExpectNeither(result);
    BOOST_CHECK_EQUAL(result.code, "FUND");
    BOOST_CHECK_EQUAL(err, "FUND");
}

BOOST_AUTO_TEST_CASE(unsigned_refund_is_unsigned)
{
    modelnet::SwarmRefundFirst note = NotedRefundFirst();
    note.refund_signed = false;
    std::string err = "prior";
    const modelnet::SwarmRefundFirstResult result = modelnet::SwarmNoteRefundFirst(note, err);
    ExpectNeither(result);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(unsigned_wins_when_want_count_funding_is_true)
{
    modelnet::SwarmRefundFirst note = NotedRefundFirst();
    note.refund_signed = false;
    note.want_count_funding = true;
    std::string err = "prior";
    const modelnet::SwarmRefundFirstResult result = modelnet::SwarmNoteRefundFirst(note, err);
    ExpectNeither(result);
    BOOST_CHECK_EQUAL(result.code, "UNSIGNED");
    BOOST_CHECK_EQUAL(err, "UNSIGNED");
}

BOOST_AUTO_TEST_CASE(want_count_funding_with_signed_refund_is_held)
{
    modelnet::SwarmRefundFirst note = NotedRefundFirst();
    note.refund_signed = true;
    note.want_count_funding = true;
    std::string err = "prior";
    const modelnet::SwarmRefundFirstResult result = modelnet::SwarmNoteRefundFirst(note, err);
    ExpectNeither(result);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(signed_refund_without_count_is_noted)
{
    modelnet::SwarmRefundFirst note = NotedRefundFirst();
    note.refund_signed = true;
    note.want_count_funding = false;
    std::string err = "prior";
    const modelnet::SwarmRefundFirstResult result = modelnet::SwarmNoteRefundFirst(note, err);
    ExpectNeither(result);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
