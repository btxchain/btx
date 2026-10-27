// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_voucher.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_voucher_tests, BasicTestingSetup)

static modelnet::SwarmVoucher NotedVoucher()
{
    modelnet::SwarmVoucher voucher;
    voucher.channel_id = "channel";
    voucher.sequence = 2;
    voucher.stored_sequence = 2;
    voucher.amount = 5;
    voucher.stored_amount = 5;
    return voucher;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(sequence_below_one_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 0;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(negative_sequence_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = -1;
    voucher.stored_sequence = 2;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(stored_sequence_below_one_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.stored_sequence = 0;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(negative_stored_sequence_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 1;
    voucher.stored_sequence = -1;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(negative_amount_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.amount = -1;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(negative_stored_amount_is_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.stored_amount = -1;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(invalid_voucher_wins_over_stale_and_decreasing)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.channel_id.clear();
    voucher.sequence = 1;
    voucher.stored_sequence = 2;
    voucher.amount = 1;
    voucher.stored_amount = 5;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "VOUCHER");
    BOOST_CHECK_EQUAL(err, "VOUCHER");
}

BOOST_AUTO_TEST_CASE(lower_sequence_with_lower_amount_is_stale_voucher)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 1;
    voucher.stored_sequence = 2;
    voucher.amount = 1;
    voucher.stored_amount = 5;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "STALE_VOUCHER");
    BOOST_CHECK_EQUAL(err, "STALE_VOUCHER");
}

BOOST_AUTO_TEST_CASE(lower_amount_with_equal_sequence_is_decreasing_payment)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 2;
    voucher.stored_sequence = 2;
    voucher.amount = 1;
    voucher.stored_amount = 5;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "DECREASING_PAYMENT");
    BOOST_CHECK_EQUAL(err, "DECREASING_PAYMENT");
}

BOOST_AUTO_TEST_CASE(lower_amount_with_higher_sequence_is_decreasing_payment)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 3;
    voucher.stored_sequence = 2;
    voucher.amount = 4;
    voucher.stored_amount = 5;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "DECREASING_PAYMENT");
    BOOST_CHECK_EQUAL(err, "DECREASING_PAYMENT");
}

BOOST_AUTO_TEST_CASE(equal_sequence_and_equal_amount_are_noted)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 2;
    voucher.stored_sequence = 2;
    voucher.amount = 5;
    voucher.stored_amount = 5;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(higher_sequence_and_higher_amount_are_noted)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 3;
    voucher.stored_sequence = 2;
    voucher.amount = 6;
    voucher.stored_amount = 5;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_amounts_with_equal_sequence_are_noted)
{
    modelnet::SwarmVoucher voucher = NotedVoucher();
    voucher.sequence = 1;
    voucher.stored_sequence = 1;
    voucher.amount = 0;
    voucher.stored_amount = 0;
    std::string err = "prior";
    const modelnet::SwarmVoucherResult result = modelnet::SwarmNoteVoucher(voucher, err);
    BOOST_CHECK_EQUAL(result.accepted, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
