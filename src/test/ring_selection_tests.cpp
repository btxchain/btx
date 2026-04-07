// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <crypto/common.h>
#include <shielded/lattice/params.h>
#include <shielded/ringct/ring_selection.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <random>
#include <set>

BOOST_FIXTURE_TEST_SUITE(ring_selection_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(select_ring_positions_size_and_real_member)
{
    const uint256 seed = GetRandHash();
    const auto selection = shielded::ringct::SelectRingPositions(
        /*real_position=*/42,
        /*tree_size=*/1000,
        seed,
        shielded::lattice::RING_SIZE);
    const auto& positions = selection.positions;

    BOOST_CHECK_EQUAL(positions.size(), shielded::lattice::RING_SIZE);
    BOOST_CHECK(selection.real_index < positions.size());
    BOOST_CHECK_EQUAL(positions[selection.real_index], 42U);
    BOOST_CHECK(std::all_of(positions.begin(), positions.end(), [](uint64_t pos) { return pos < 1000; }));
}

BOOST_AUTO_TEST_CASE(select_ring_positions_is_deterministic_for_seed)
{
    const uint256 seed = GetRandHash();
    const auto a = shielded::ringct::SelectRingPositions(8, 512, seed, shielded::lattice::RING_SIZE);
    const auto b = shielded::ringct::SelectRingPositions(8, 512, seed, shielded::lattice::RING_SIZE);
    BOOST_CHECK(a.positions == b.positions);
    BOOST_CHECK_EQUAL(a.real_index, b.real_index);
}

BOOST_AUTO_TEST_CASE(select_ring_positions_clamps_real_position)
{
    const uint256 seed = GetRandHash();
    const auto selection = shielded::ringct::SelectRingPositions(
        /*real_position=*/9999,
        /*tree_size=*/50,
        seed,
        shielded::lattice::RING_SIZE);
    const auto& positions = selection.positions;

    BOOST_CHECK(selection.real_index < positions.size());
    BOOST_CHECK_EQUAL(positions[selection.real_index], 49U);
    BOOST_CHECK(std::all_of(positions.begin(), positions.end(), [](uint64_t pos) { return pos < 50; }));
}

BOOST_AUTO_TEST_CASE(select_ring_positions_handles_empty_tree)
{
    const uint256 seed = GetRandHash();
    const auto selection = shielded::ringct::SelectRingPositions(0, 0, seed, shielded::lattice::RING_SIZE);
    const auto& positions = selection.positions;

    BOOST_CHECK_EQUAL(positions.size(), shielded::lattice::RING_SIZE);
    BOOST_CHECK_EQUAL(selection.real_index, 0U);
    BOOST_CHECK(std::all_of(positions.begin(), positions.end(), [](uint64_t pos) { return pos == 0; }));
}

BOOST_AUTO_TEST_CASE(select_ring_positions_unique_when_tree_large_enough)
{
    const uint256 seed = GetRandHash();
    const auto selection = shielded::ringct::SelectRingPositions(
        /*real_position=*/17,
        /*tree_size=*/1000,
        seed,
        shielded::lattice::RING_SIZE);

    std::vector<uint64_t> sorted = selection.positions;
    std::sort(sorted.begin(), sorted.end());
    const auto it = std::unique(sorted.begin(), sorted.end());
    BOOST_CHECK_EQUAL(std::distance(sorted.begin(), it), shielded::lattice::RING_SIZE);
}

BOOST_AUTO_TEST_CASE(select_ring_positions_covers_available_members_when_tree_small)
{
    const uint256 seed = GetRandHash();
    const uint64_t tree_size = 5;
    const auto selection = shielded::ringct::SelectRingPositions(
        /*real_position=*/2,
        tree_size,
        seed,
        shielded::lattice::RING_SIZE);

    std::vector<uint64_t> sorted = selection.positions;
    std::sort(sorted.begin(), sorted.end());
    const auto it = std::unique(sorted.begin(), sorted.end());
    BOOST_CHECK_EQUAL(std::distance(sorted.begin(), it), static_cast<std::ptrdiff_t>(tree_size));
}

BOOST_AUTO_TEST_CASE(select_ring_positions_keeps_unique_first_sample_without_shift)
{
    const uint64_t tree_size = 4096;
    const uint64_t real_position = 0;
    uint256 seed;
    shielded::ringct::RingSelection selection;

    // Find a deterministic seed where the selector returns a non-real decoy.
    for (uint32_t tweak = 1; tweak < 256; ++tweak) {
        seed = uint256{};
        seed.begin()[0] = static_cast<unsigned char>(tweak);
        selection = shielded::ringct::SelectRingPositions(real_position, tree_size, seed, /*ring_size=*/2);
        const size_t decoy_index = selection.real_index == 0 ? 1 : 0;
        if (selection.positions.size() == 2 && selection.positions[decoy_index] != real_position) {
            break;
        }
    }

    BOOST_REQUIRE_EQUAL(selection.positions.size(), 2U);
    BOOST_REQUIRE(selection.real_index < selection.positions.size());
    BOOST_CHECK_EQUAL(selection.positions[selection.real_index], real_position);
    const size_t decoy_index = selection.real_index == 0 ? 1 : 0;
    BOOST_CHECK_NE(selection.positions[decoy_index], real_position);
}

BOOST_AUTO_TEST_CASE(select_ring_positions_practical_trees_avoid_oldest_bucket_collapse)
{
    constexpr uint64_t TREE_SIZE = 200;
    constexpr uint64_t REAL_POSITION = TREE_SIZE - 1;
    constexpr uint64_t OLDEST_BUCKET = 15;
    constexpr size_t TRIALS = 512;
    constexpr size_t DECOY_COUNT = shielded::lattice::RING_SIZE - 1;
    constexpr size_t MIN_RECENT_DECOYS = (DECOY_COUNT / 2) + 1;

    size_t oldest_bucket_hits{0};
    size_t total_decoys{0};
    size_t mixed_half_rings{0};

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 1));
        const auto selection = shielded::ringct::SelectRingPositions(
            REAL_POSITION,
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE);

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE(selection.real_index < selection.positions.size());

        size_t recent_positions{0};
        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (i == selection.real_index) continue;
            const uint64_t pos = selection.positions[i];
            if (pos < OLDEST_BUCKET) ++oldest_bucket_hits;
            if (pos >= (TREE_SIZE / 2)) {
                ++recent_positions;
            }
            ++total_decoys;
        }
        // Gamma-weighted selection should keep the majority of decoys recent
        // across the supported ring-size range, including the default 8-member
        // launch policy.
        if (recent_positions >= MIN_RECENT_DECOYS) {
            ++mixed_half_rings;
        }
    }

    const double oldest_share = static_cast<double>(oldest_bucket_hits) /
                                static_cast<double>(std::max<size_t>(1, total_decoys));
    BOOST_TEST_MESSAGE("Oldest-bucket decoy share at tree_size=200: " << oldest_share);
    // With gamma distribution, oldest bucket should be rare
    BOOST_CHECK_LT(oldest_share, 0.30);
    // Most rings should have mostly recent decoys (H3 audit requirement)
    BOOST_CHECK_GT(mixed_half_rings, TRIALS * 3 / 4);
}

BOOST_AUTO_TEST_CASE(select_shared_ring_positions_practical_trees_do_not_isolate_recent_real_members)
{
    constexpr uint64_t TREE_SIZE = 256;
    constexpr size_t TRIALS = 256;
    constexpr uint64_t OLDEST_BUCKET = 15;
    constexpr size_t REAL_MEMBER_COUNT = 2;
    constexpr size_t DECOY_COUNT = shielded::lattice::RING_SIZE - REAL_MEMBER_COUNT;
    constexpr size_t MIN_RECENT_DECOYS = (DECOY_COUNT / 2) + 1;

    size_t oldest_bucket_hits{0};
    size_t total_decoys{0};
    size_t mixed_half_rings{0};

    const std::array<uint64_t, 2> real_positions{240, 241};

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 17));
        const auto selection = shielded::ringct::SelectSharedRingPositionsWithExclusions(
            Span<const uint64_t>{real_positions.data(), real_positions.size()},
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE,
            {});

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE_EQUAL(selection.real_indices.size(), real_positions.size());

        std::set<size_t> real_index_set(selection.real_indices.begin(), selection.real_indices.end());
        size_t recent_positions{0};
        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (real_index_set.count(i) != 0) continue;
            const uint64_t pos = selection.positions[i];
            if (pos < OLDEST_BUCKET) ++oldest_bucket_hits;
            if (pos >= (TREE_SIZE / 2)) {
                ++recent_positions;
            }
            ++total_decoys;
        }
        // Gamma-weighted selection should keep the majority of decoys recent
        // even when a shared ring reserves slots for multiple real members.
        if (recent_positions >= MIN_RECENT_DECOYS) {
            ++mixed_half_rings;
        }
    }

    const double oldest_share = static_cast<double>(oldest_bucket_hits) /
                                static_cast<double>(std::max<size_t>(1, total_decoys));
    BOOST_TEST_MESSAGE("Shared-ring oldest-bucket decoy share at tree_size=256: " << oldest_share);
    BOOST_CHECK_LT(oldest_share, 0.30);
    // Most rings should have mostly recent decoys
    BOOST_CHECK_GT(mixed_half_rings, TRIALS * 3 / 4);
}

BOOST_AUTO_TEST_CASE(select_ring_positions_practical_trees_cover_recent_maturation_window)
{
    constexpr uint64_t TREE_SIZE = 200;
    constexpr uint64_t REAL_POSITION = TREE_SIZE - 1;
    constexpr size_t TRIALS = 256;
    constexpr uint64_t WINDOW_BEGIN = TREE_SIZE - 20;
    constexpr uint64_t WINDOW_END = TREE_SIZE - 11;

    std::array<size_t, WINDOW_END - WINDOW_BEGIN + 1> window_hits{};

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 0x6000));
        const auto selection = shielded::ringct::SelectRingPositions(
            REAL_POSITION,
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE);

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE(selection.real_index < selection.positions.size());
        BOOST_CHECK_EQUAL(selection.positions[selection.real_index], REAL_POSITION);

        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (i == selection.real_index) continue;
            const uint64_t pos = selection.positions[i];
            if (pos >= WINDOW_BEGIN && pos <= WINDOW_END) {
                ++window_hits[pos - WINDOW_BEGIN];
            }
        }
    }

    for (size_t i = 0; i < window_hits.size(); ++i) {
        BOOST_TEST_MESSAGE("Recent-maturation window position "
                           << (WINDOW_BEGIN + i)
                           << " hit count: " << window_hits[i]);
        BOOST_CHECK_GT(window_hits[i], 0U);
    }
}

BOOST_AUTO_TEST_CASE(select_ring_positions_age_spread_covers_all_quartiles)
{
    constexpr uint64_t TREE_SIZE = 1024;
    constexpr uint64_t REAL_POSITION = TREE_SIZE - 1;
    constexpr size_t BIN_COUNT = 4;
    constexpr size_t TRIALS = 128;

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 0x9000));
        const auto selection = shielded::ringct::SelectRingPositions(
            REAL_POSITION,
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE);

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE(selection.real_index < selection.positions.size());

        std::array<bool, BIN_COUNT> saw_bin{};
        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (i == selection.real_index) continue;
            const uint64_t pos = selection.positions[i];
            const size_t bin = std::min<size_t>((pos * BIN_COUNT) / TREE_SIZE, BIN_COUNT - 1);
            saw_bin[bin] = true;
        }
        BOOST_CHECK(std::all_of(saw_bin.begin(), saw_bin.end(), [](bool seen) { return seen; }));
    }
}

BOOST_AUTO_TEST_CASE(select_shared_ring_positions_age_spread_covers_all_quartiles)
{
    constexpr uint64_t TREE_SIZE = 1024;
    constexpr size_t BIN_COUNT = 4;
    constexpr size_t TRIALS = 128;
    const std::array<uint64_t, 2> real_positions{900, 901};

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 0xA000));
        const auto selection = shielded::ringct::SelectSharedRingPositionsWithExclusions(
            Span<const uint64_t>{real_positions.data(), real_positions.size()},
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE,
            {});

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE_EQUAL(selection.real_indices.size(), real_positions.size());

        std::set<size_t> real_index_set(selection.real_indices.begin(), selection.real_indices.end());
        std::array<bool, BIN_COUNT> saw_bin{};
        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (real_index_set.count(i) != 0) continue;
            const uint64_t pos = selection.positions[i];
            const size_t bin = std::min<size_t>((pos * BIN_COUNT) / TREE_SIZE, BIN_COUNT - 1);
            saw_bin[bin] = true;
        }
        BOOST_CHECK(std::all_of(saw_bin.begin(), saw_bin.end(), [](bool seen) { return seen; }));
    }
}

BOOST_AUTO_TEST_CASE(select_ring_positions_shifted_pareto_sampler_avoids_newest_bucket_collapse)
{
    constexpr uint64_t TREE_SIZE = 512;
    constexpr uint64_t REAL_POSITION = TREE_SIZE - 1;
    constexpr uint64_t NEWEST_BUCKET_BEGIN = TREE_SIZE - 8;
    constexpr size_t TRIALS = 512;

    size_t newest_bucket_hits{0};
    size_t total_decoys{0};

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 0xB000));
        const auto selection = shielded::ringct::SelectRingPositions(
            REAL_POSITION,
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE);

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE(selection.real_index < selection.positions.size());

        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (i == selection.real_index) continue;
            if (selection.positions[i] >= NEWEST_BUCKET_BEGIN) {
                ++newest_bucket_hits;
            }
            ++total_decoys;
        }
    }

    const double newest_share = static_cast<double>(newest_bucket_hits) /
                                static_cast<double>(std::max<size_t>(1, total_decoys));
    BOOST_TEST_MESSAGE("Newest-bucket decoy share at tree_size=512: " << newest_share);
    BOOST_CHECK_LT(newest_share, 0.35);
    BOOST_CHECK_GT(newest_share, 0.01);
}

BOOST_AUTO_TEST_CASE(select_shared_ring_positions_shifted_pareto_sampler_avoids_newest_bucket_collapse)
{
    constexpr uint64_t TREE_SIZE = 512;
    constexpr uint64_t NEWEST_BUCKET_BEGIN = TREE_SIZE - 8;
    constexpr size_t TRIALS = 512;
    const std::array<uint64_t, 2> real_positions{TREE_SIZE - 1, TREE_SIZE - 2};

    size_t newest_bucket_hits{0};
    size_t total_decoys{0};

    for (size_t trial = 0; trial < TRIALS; ++trial) {
        uint256 seed{};
        WriteLE32(seed.begin(), static_cast<uint32_t>(trial + 0xC000));
        const auto selection = shielded::ringct::SelectSharedRingPositionsWithExclusions(
            Span<const uint64_t>{real_positions.data(), real_positions.size()},
            TREE_SIZE,
            seed,
            shielded::lattice::RING_SIZE,
            {});

        BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
        BOOST_REQUIRE_EQUAL(selection.real_indices.size(), real_positions.size());

        std::set<size_t> real_index_set(selection.real_indices.begin(), selection.real_indices.end());
        for (size_t i = 0; i < selection.positions.size(); ++i) {
            if (real_index_set.count(i) != 0) continue;
            if (selection.positions[i] >= NEWEST_BUCKET_BEGIN) {
                ++newest_bucket_hits;
            }
            ++total_decoys;
        }
    }

    const double newest_share = static_cast<double>(newest_bucket_hits) /
                                static_cast<double>(std::max<size_t>(1, total_decoys));
    BOOST_TEST_MESSAGE("Shared-ring newest-bucket decoy share at tree_size=512: " << newest_share);
    BOOST_CHECK_LT(newest_share, 0.35);
    BOOST_CHECK_GT(newest_share, 0.01);
}

BOOST_AUTO_TEST_CASE(select_ring_positions_with_exclusions_avoids_overlap_when_possible)
{
    const uint64_t tree_size = 2048;
    const uint64_t real_position = 100;
    const uint256 seed_a = GetRandHash();
    const uint256 seed_b = GetRandHash();

    const auto first = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position,
        tree_size,
        seed_a,
        shielded::lattice::RING_SIZE,
        {});
    BOOST_REQUIRE_EQUAL(first.positions.size(), shielded::lattice::RING_SIZE);

    const auto second = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position + 1,
        tree_size,
        seed_b,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{first.positions.data(), first.positions.size()});
    BOOST_REQUIRE_EQUAL(second.positions.size(), shielded::lattice::RING_SIZE);

    std::set<uint64_t> first_set(first.positions.begin(), first.positions.end());
    std::set<uint64_t> overlap_positions;
    for (const uint64_t pos : second.positions) {
        if (first_set.count(pos) != 0) overlap_positions.insert(pos);
    }
    BOOST_CHECK(overlap_positions.size() <= 1U);
    if (!overlap_positions.empty()) {
        // If the first ring already contains the second spend's real position,
        // that single overlap is unavoidable.
        BOOST_CHECK_EQUAL(*overlap_positions.begin(), real_position + 1);
    }
}

BOOST_AUTO_TEST_CASE(select_ring_positions_with_exclusions_is_deterministic)
{
    const uint64_t tree_size = 1024;
    const uint64_t real_position = 77;
    const uint256 seed = GetRandHash();
    const std::array<uint64_t, 5> excluded{4, 9, 12, 77, 888};

    const auto a = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position,
        tree_size,
        seed,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{excluded.data(), excluded.size()});
    const auto b = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position,
        tree_size,
        seed,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{excluded.data(), excluded.size()});
    BOOST_CHECK(a.positions == b.positions);
    BOOST_CHECK_EQUAL(a.real_index, b.real_index);
}

BOOST_AUTO_TEST_CASE(select_ring_positions_with_exclusions_preserves_diversity_target)
{
    const uint64_t tree_size = 3;
    const uint64_t real_position = 1;
    const uint256 seed = GetRandHash();
    const std::array<uint64_t, 9> excluded{0, 1, 2, 0, 1, 2, 0, 1, 2};

    const auto selection = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position,
        tree_size,
        seed,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{excluded.data(), excluded.size()});

    BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
    BOOST_REQUIRE(selection.real_index < selection.positions.size());
    BOOST_CHECK_EQUAL(selection.positions[selection.real_index], real_position);

    std::set<uint64_t> unique_positions(selection.positions.begin(), selection.positions.end());
    BOOST_CHECK_EQUAL(unique_positions.size(), static_cast<size_t>(tree_size));
}

BOOST_AUTO_TEST_CASE(select_ring_positions_with_tip_exclusions_avoids_recent_members_when_possible)
{
    const uint64_t tree_size = 500;
    const uint64_t real_position = 123;
    const uint256 seed = GetRandHash();
    const std::array<uint64_t, 10> recent_tip_positions{499, 498, 497, 496, 495, 494, 493, 492, 491, 490};

    const auto selection = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position,
        tree_size,
        seed,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{recent_tip_positions.data(), recent_tip_positions.size()});

    BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
    BOOST_REQUIRE(selection.real_index < selection.positions.size());
    BOOST_CHECK_EQUAL(selection.positions[selection.real_index], real_position);
    for (const auto pos : selection.positions) {
        BOOST_CHECK(std::find(recent_tip_positions.begin(), recent_tip_positions.end(), pos) == recent_tip_positions.end());
    }
}

BOOST_AUTO_TEST_CASE(select_ring_positions_with_tip_exclusions_keeps_real_member_if_recent)
{
    const uint64_t tree_size = 500;
    const uint64_t real_position = 499;
    const uint256 seed = GetRandHash();
    const std::array<uint64_t, 10> recent_tip_positions{499, 498, 497, 496, 495, 494, 493, 492, 491, 490};

    const auto selection = shielded::ringct::SelectRingPositionsWithExclusions(
        real_position,
        tree_size,
        seed,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{recent_tip_positions.data(), recent_tip_positions.size()});

    BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
    BOOST_REQUIRE(selection.real_index < selection.positions.size());
    BOOST_CHECK_EQUAL(selection.positions[selection.real_index], real_position);
    bool saw_recent_decoy{false};
    for (size_t i = 0; i < selection.positions.size(); ++i) {
        const auto pos = selection.positions[i];
        if (i == selection.real_index) continue;
        if (std::find(recent_tip_positions.begin(), recent_tip_positions.end(), pos) != recent_tip_positions.end()) {
            saw_recent_decoy = true;
        }
    }
    BOOST_CHECK(saw_recent_decoy);
}

BOOST_AUTO_TEST_CASE(select_shared_ring_positions_with_tip_exclusions_adds_recent_decoy_when_real_is_recent)
{
    const uint64_t tree_size = 500;
    const std::array<uint64_t, 2> real_positions{499, 350};
    const uint256 seed = GetRandHash();
    const std::array<uint64_t, 10> recent_tip_positions{499, 498, 497, 496, 495, 494, 493, 492, 491, 490};

    const auto selection = shielded::ringct::SelectSharedRingPositionsWithExclusions(
        Span<const uint64_t>{real_positions.data(), real_positions.size()},
        tree_size,
        seed,
        shielded::lattice::RING_SIZE,
        Span<const uint64_t>{recent_tip_positions.data(), recent_tip_positions.size()});

    BOOST_REQUIRE_EQUAL(selection.positions.size(), shielded::lattice::RING_SIZE);
    BOOST_REQUIRE_EQUAL(selection.real_indices.size(), real_positions.size());

    std::set<size_t> real_index_set(selection.real_indices.begin(), selection.real_indices.end());
    bool saw_recent_decoy{false};
    for (size_t i = 0; i < selection.positions.size(); ++i) {
        if (real_index_set.count(i) != 0) continue;
        if (std::find(recent_tip_positions.begin(), recent_tip_positions.end(), selection.positions[i]) !=
            recent_tip_positions.end()) {
            saw_recent_decoy = true;
        }
    }
    BOOST_CHECK(saw_recent_decoy);
}

// ---------------------------------------------------------------------------
// P2-22: Privacy property test — real_index uniformity
// Verify the real member's index is uniformly distributed across ring slots,
// preventing position-based deanonymization attacks.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_index_uniform_distribution)
{
    constexpr size_t NUM_TRIALS = 10000;
    constexpr size_t RING_SIZE = shielded::lattice::RING_SIZE;
    constexpr uint64_t TREE_SIZE = 100000;

    std::array<size_t, RING_SIZE> index_counts{};

    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) {
        // Use a different real_position and seed each trial
        const uint256 seed = GetRandHash();
        const uint64_t real_pos = trial * 7 % TREE_SIZE;

        const auto selection = shielded::ringct::SelectRingPositions(
            real_pos, TREE_SIZE, seed, RING_SIZE);
        BOOST_REQUIRE(selection.real_index < RING_SIZE);
        ++index_counts[selection.real_index];
    }

    // Chi-squared test for uniformity at p=0.01 (critical value ~30.58 for df=15)
    const double expected = static_cast<double>(NUM_TRIALS) / RING_SIZE;
    double chi_squared = 0.0;
    for (size_t i = 0; i < RING_SIZE; ++i) {
        const double diff = static_cast<double>(index_counts[i]) - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Reject if chi-squared exceeds critical value for df=RING_SIZE-1 at p=0.001
    // For df=15, chi-squared critical at p=0.001 is ~37.70
    BOOST_TEST_MESSAGE("Real index chi-squared (df=" << RING_SIZE - 1 << "): " << chi_squared);
    BOOST_CHECK_LT(chi_squared, 37.70);

    // Also verify no slot has zero selections (would indicate bias)
    for (size_t i = 0; i < RING_SIZE; ++i) {
        BOOST_CHECK_GT(index_counts[i], 0U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
