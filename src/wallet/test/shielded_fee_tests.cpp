// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_fees.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(shielded_fee_tests)

BOOST_AUTO_TEST_CASE(auto_fee_bucket_rounds_common_values)
{
    BOOST_CHECK_EQUAL(wallet::BucketShieldedAutoFee(5'000), 5'000);
    BOOST_CHECK_EQUAL(wallet::BucketShieldedAutoFee(5'001), 10'000);
    BOOST_CHECK_EQUAL(wallet::BucketShieldedAutoFee(65'218), 80'000);
    BOOST_CHECK_EQUAL(wallet::BucketShieldedAutoFee(106'918), 160'000);
    BOOST_CHECK_EQUAL(wallet::BucketShieldedAutoFee(640'001), 640'001);
}

BOOST_AUTO_TEST_CASE(direct_send_vsize_matches_runtime_reference_shapes)
{
    BOOST_CHECK_EQUAL(wallet::EstimateDirectShieldedSendVirtualSize(1, 2), 60'218U);
    BOOST_CHECK_EQUAL(wallet::EstimateDirectShieldedSendVirtualSize(2, 2), 70'272U);
    BOOST_CHECK_EQUAL(wallet::EstimateDirectShieldedSendVirtualSize(2, 4), 101'918U);
}

BOOST_AUTO_TEST_SUITE_END()
