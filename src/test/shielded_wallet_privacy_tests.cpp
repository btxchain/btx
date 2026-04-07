// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <policy/policy.h>
#include <shielded/bundle.h>
#include <shielded/lattice/params.h>
#include <shielded/ringct/ring_selection.h>
#include <test/util/setup_common.h>
#include <wallet/shielded_privacy.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <numeric>
#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(shielded_wallet_privacy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shared_ring_seed_ignores_build_nonce_before_activation)
{
    const std::vector<Nullifier> nullifiers{uint256{0x11}, uint256{0x22}};
    const std::vector<unsigned char> spend_key_material{0x41, 0x42, 0x43, 0x44};
    const uint256 seed_a{0x90};
    const uint256 seed_b{0x91};
    const int32_t pre_activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight - 1;

    const uint256 derived_a = wallet::DeriveShieldedSharedRingSeed(
        nullifiers,
        spend_key_material,
        seed_a,
        pre_activation_height);
    const uint256 derived_b = wallet::DeriveShieldedSharedRingSeed(
        nullifiers,
        spend_key_material,
        seed_b,
        pre_activation_height);

    BOOST_CHECK_EQUAL(derived_a, derived_b);
}

BOOST_AUTO_TEST_CASE(shared_ring_seed_binds_build_nonce_after_activation)
{
    const std::vector<Nullifier> nullifiers{uint256{0x11}, uint256{0x22}};
    const std::vector<unsigned char> spend_key_material{0x41, 0x42, 0x43, 0x44};
    const uint256 seed_a{0x90};
    const uint256 seed_b{0x91};
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;

    const uint256 derived_a = wallet::DeriveShieldedSharedRingSeed(
        nullifiers,
        spend_key_material,
        seed_a,
        activation_height);
    const uint256 derived_b = wallet::DeriveShieldedSharedRingSeed(
        nullifiers,
        spend_key_material,
        seed_b,
        activation_height);

    BOOST_CHECK_NE(derived_a, derived_b);
}

BOOST_AUTO_TEST_CASE(decoy_tip_exclusion_window_is_disabled_at_activation)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_CHECK_EQUAL(wallet::GetShieldedDecoyTipExclusionWindowForHeight(activation_height - 1), 100U);
    BOOST_CHECK_EQUAL(wallet::GetShieldedDecoyTipExclusionWindowForHeight(activation_height), 0U);
}

BOOST_AUTO_TEST_CASE(shielded_dust_threshold_activates_at_disable_height)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    const CFeeRate relay_dust_fee{DUST_RELAY_TX_FEE};
    BOOST_CHECK_EQUAL(wallet::GetShieldedDustThresholdForHeight(relay_dust_fee, activation_height - 1), 0);
    BOOST_CHECK_GT(wallet::GetShieldedDustThresholdForHeight(relay_dust_fee, activation_height), 0);
    BOOST_CHECK_EQUAL(wallet::GetShieldedMinimumChangeReserveForHeight(relay_dust_fee, activation_height - 1), 1);
    BOOST_CHECK_GE(wallet::GetShieldedMinimumChangeReserveForHeight(relay_dust_fee, activation_height),
                   wallet::GetShieldedDustThresholdForHeight(relay_dust_fee, activation_height));
}

BOOST_AUTO_TEST_CASE(shielded_minimum_privacy_tree_size_activates_at_disable_height)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_CHECK_EQUAL(wallet::GetShieldedMinimumPrivacyTreeSizeForHeight(
                          shielded::lattice::RING_SIZE,
                          activation_height - 1),
                      0U);
    BOOST_CHECK_EQUAL(wallet::GetShieldedMinimumPrivacyTreeSizeForHeight(
                          shielded::lattice::RING_SIZE,
                          activation_height),
                      shielded::ringct::GetMinimumPrivacyTreeSize(shielded::lattice::RING_SIZE));
}

BOOST_AUTO_TEST_CASE(shielded_rpc_sensitive_fields_require_redaction_after_activation)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;

    BOOST_CHECK(!wallet::RequireSensitiveShieldedRpcOptInAtHeight(activation_height - 1));
    BOOST_CHECK(wallet::RequireSensitiveShieldedRpcOptInAtHeight(activation_height));
    BOOST_CHECK(!wallet::RedactSensitiveShieldedRpcFieldsAtHeight(activation_height - 1, /*include_sensitive=*/false));
    BOOST_CHECK(!wallet::RedactSensitiveShieldedRpcFieldsAtHeight(activation_height, /*include_sensitive=*/true));
    BOOST_CHECK(wallet::RedactSensitiveShieldedRpcFieldsAtHeight(activation_height, /*include_sensitive=*/false));
}

BOOST_AUTO_TEST_CASE(direct_public_flow_v2_send_is_disabled_at_activation)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;

    BOOST_CHECK(wallet::AllowMixedTransparentShieldedSendAtHeight(activation_height - 1));
    BOOST_CHECK(!wallet::AllowMixedTransparentShieldedSendAtHeight(activation_height));
    BOOST_CHECK(wallet::AllowTransparentShieldingInDirectSendAtHeight(activation_height - 1));
    BOOST_CHECK(!wallet::AllowTransparentShieldingInDirectSendAtHeight(activation_height));
}

BOOST_AUTO_TEST_CASE(shielded_fee_bucket_rounding_activates_at_fork)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;

    BOOST_CHECK_EQUAL(shielded::RoundShieldedFeeToCanonicalBucket(1501, consensus, activation_height - 1), 1501);
    BOOST_CHECK_EQUAL(shielded::RoundShieldedFeeToCanonicalBucket(1501, consensus, activation_height), 2000);
    BOOST_CHECK(shielded::IsCanonicalShieldedFee(0, consensus, activation_height));
    BOOST_CHECK(!shielded::IsCanonicalShieldedFee(1501, consensus, activation_height));
    BOOST_CHECK(shielded::IsCanonicalShieldedFee(2000, consensus, activation_height));
}

BOOST_AUTO_TEST_CASE(shielded_historical_ring_exclusion_limit_activates_at_fork)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    BOOST_CHECK_EQUAL(wallet::GetShieldedHistoricalRingExclusionLimit(shielded::lattice::RING_SIZE,
                                                                      activation_height - 1),
                      0U);
    BOOST_CHECK_GT(wallet::GetShieldedHistoricalRingExclusionLimit(shielded::lattice::RING_SIZE,
                                                                   activation_height),
                   0U);
}

BOOST_AUTO_TEST_CASE(shielded_historical_ring_exclusion_cache_deduplicates_and_trims)
{
    std::vector<uint64_t> cache{2, 4, 6};
    const std::vector<uint64_t> ring_positions{4, 8, 10, 12};
    const std::vector<size_t> real_indices{1};

    wallet::UpdateShieldedHistoricalRingExclusionCache(
        cache,
        Span<const uint64_t>{ring_positions.data(), ring_positions.size()},
        Span<const size_t>{real_indices.data(), real_indices.size()},
        /*limit=*/4);

    BOOST_CHECK((cache == std::vector<uint64_t>{6, 4, 10, 12}));
}

BOOST_AUTO_TEST_CASE(shielded_historical_ring_exclusions_reduce_sequential_overlap)
{
    constexpr uint64_t TREE_SIZE = 4096;
    constexpr uint64_t FIRST_REAL_POSITION = 3900;
    constexpr uint64_t SECOND_REAL_POSITION = 3901;

    const auto first_selection = shielded::ringct::SelectRingPositions(
        FIRST_REAL_POSITION,
        TREE_SIZE,
        uint256{0x11},
        shielded::lattice::RING_SIZE);
    BOOST_REQUIRE_EQUAL(first_selection.positions.size(), shielded::lattice::RING_SIZE);

    std::vector<uint64_t> historical_cache;
    const std::vector<size_t> first_real_index{first_selection.real_index};
    wallet::UpdateShieldedHistoricalRingExclusionCache(
        historical_cache,
        Span<const uint64_t>{first_selection.positions.data(), first_selection.positions.size()},
        Span<const size_t>{first_real_index.data(), first_real_index.size()},
        wallet::GetShieldedHistoricalRingExclusionLimit(shielded::lattice::RING_SIZE,
                                                        Params().GetConsensus().nShieldedMatRiCTDisableHeight));

    const auto combined_exclusions = wallet::BuildShieldedHistoricalRingExclusions(
        Span<const uint64_t>{},
        Span<const uint64_t>{historical_cache.data(), historical_cache.size()},
        TREE_SIZE);
    const auto second_selection = shielded::ringct::SelectRingPositionsWithExclusions(
        SECOND_REAL_POSITION,
        TREE_SIZE,
        uint256{0x22},
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{combined_exclusions.data(), combined_exclusions.size()});
    BOOST_REQUIRE_EQUAL(second_selection.positions.size(), shielded::lattice::RING_SIZE);

    std::set<uint64_t> first_decoys;
    for (size_t i = 0; i < first_selection.positions.size(); ++i) {
        if (i != first_selection.real_index) {
            first_decoys.insert(first_selection.positions[i]);
        }
    }

    size_t overlap{0};
    for (size_t i = 0; i < second_selection.positions.size(); ++i) {
        if (i == second_selection.real_index) continue;
        if (first_decoys.count(second_selection.positions[i]) != 0) {
            ++overlap;
        }
    }
    BOOST_CHECK_EQUAL(overlap, 0U);
}

BOOST_AUTO_TEST_CASE(shielded_output_order_is_randomized_after_activation)
{
    const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    const auto pre_activation = wallet::ComputeShieldedOutputOrder(
        /*recipient_count=*/2,
        /*has_change=*/true,
        uint256{0x01},
        activation_height - 1);
    BOOST_CHECK((pre_activation == std::vector<size_t>{0, 1, 2}));

    bool found_non_identity{false};
    for (unsigned char tweak = 1; tweak < 64; ++tweak) {
        const auto order = wallet::ComputeShieldedOutputOrder(
            /*recipient_count=*/2,
            /*has_change=*/true,
            uint256{tweak},
            activation_height);
        std::vector<size_t> sorted = order;
        std::sort(sorted.begin(), sorted.end());
        BOOST_CHECK((sorted == std::vector<size_t>{0, 1, 2}));
        if (order != std::vector<size_t>{0, 1, 2}) {
            found_non_identity = true;
            break;
        }
    }

    BOOST_CHECK(found_non_identity);
}

BOOST_AUTO_TEST_SUITE_END()
