// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <test/util/setup_common.h>
#include <wallet/shielded_coins.h>

#include <boost/test/unit_test.hpp>

namespace {

wallet::ShieldedCoin MakeCoin(CAmount value)
{
    wallet::ShieldedCoin coin;
    coin.note.value = value;
    coin.note.recipient_pk_hash = uint256{1};
    coin.note.rho = uint256{2};
    coin.note.rcm = uint256{3};
    return coin;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_coin_selection_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(branch_and_bound_exact_match)
{
    const std::vector<wallet::ShieldedCoin> available{
        MakeCoin(3 * COIN),
        MakeCoin(2 * COIN),
        MakeCoin(1 * COIN),
    };

    const auto selected = wallet::ShieldedCoinSelection(available, 3 * COIN, /*fee_per_weight=*/1);
    BOOST_REQUIRE(!selected.empty());

    CAmount sum{0};
    for (const auto& coin : selected) sum += coin.note.value;
    BOOST_CHECK(sum >= 3 * COIN);
}

BOOST_AUTO_TEST_CASE(raw_knapsack_fallback_keeps_exact_balance_reserve_notes)
{
    const std::vector<wallet::ShieldedCoin> available{
        MakeCoin(50'000'002),
        MakeCoin(1),
    };

    const auto selected = wallet::ShieldedCoinSelection(available, 50'000'003, /*fee_per_weight=*/1);
    BOOST_REQUIRE_EQUAL(selected.size(), 2U);

    CAmount sum{0};
    for (const auto& coin : selected) sum += coin.note.value;
    BOOST_CHECK_EQUAL(sum, 50'000'003);
}

BOOST_AUTO_TEST_CASE(knapsack_fallback_selects_enough)
{
    const std::vector<wallet::ShieldedCoin> available{
        MakeCoin(5 * COIN),
        MakeCoin(4 * COIN),
        MakeCoin(2 * COIN),
    };

    const auto selected = wallet::ShieldedKnapsackSolver(available, 6 * COIN);
    BOOST_REQUIRE(!selected.empty());

    CAmount sum{0};
    for (const auto& coin : selected) sum += coin.note.value;
    BOOST_CHECK(sum >= 6 * COIN);
}

BOOST_AUTO_TEST_CASE(dust_note_filtering)
{
    auto a = MakeCoin(1000);
    auto b = MakeCoin(2000);
    auto c = MakeCoin(5000);
    c.is_spent = true;

    const std::vector<wallet::ShieldedCoin> notes{a, b, c};
    const auto dust = wallet::GetDustNotes(notes, 3000);
    BOOST_CHECK_EQUAL(dust.size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
