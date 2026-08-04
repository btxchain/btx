// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <wallet/coinselection.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <policy/policy.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(group_outputs_tests, TestingSetup)

static int nextLockTime = 0;

static std::shared_ptr<CWallet> NewWallet(const node::NodeContext& m_node)
{
    std::unique_ptr<CWallet> wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetupDescriptorScriptPubKeyMans();
    return wallet;
}

static void addCoin(CoinsResult& coins,
                     CWallet& wallet,
                     const CTxDestination& dest,
                     const CAmount& nValue,
                     bool is_from_me,
                     CFeeRate fee_rate = CFeeRate(0),
                     int depth = 6)
{
    CMutableTransaction tx;
    tx.nLockTime = nextLockTime++;        // so all transactions get different hashes
    tx.vout.resize(1);
    tx.vout[0].nValue = nValue;
    tx.vout[0].scriptPubKey = GetScriptForDestination(dest);

    const auto txid{tx.GetHash().ToUint256()};
    LOCK(wallet.cs_wallet);
    auto ret = wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(txid), std::forward_as_tuple(MakeTransactionRef(std::move(tx)), TxStateInactive{}));
    assert(ret.second);
    CWalletTx& wtx = (*ret.first).second;
    const auto& txout = wtx.tx->vout.at(0);
    coins.Add(*Assert(OutputTypeFromDestination(dest)),
              {COutPoint(wtx.GetHash(), 0),
                   txout,
                   depth,
                   CalculateMaximumSignedInputSize(txout, &wallet, /*coin_control=*/nullptr),
                   /*spendable=*/ true,
                   /*solvable=*/ true,
                   /*safe=*/ true,
                   wtx.GetTxTime(),
                   is_from_me,
                   fee_rate});
}

 CoinSelectionParams makeSelectionParams(FastRandomContext& rand, bool avoid_partial_spends)
{
    return CoinSelectionParams{
            rand,
            /*change_output_size=*/ 0,
            /*change_spend_size=*/ 0,
            /*min_change_target=*/ CENT,
            /*effective_feerate=*/ CFeeRate(0),
            /*long_term_feerate=*/ CFeeRate(0),
            /*discard_feerate=*/ CFeeRate(0),
            /*tx_noinputs_size=*/ 0,
            /*avoid_partial=*/ avoid_partial_spends,
    };
}

class GroupVerifier
{
public:
    std::shared_ptr<CWallet> wallet{nullptr};
    CoinsResult coins_pool;
    FastRandomContext rand;

    void GroupVerify(const OutputType type,
                     const CoinEligibilityFilter& filter,
                     bool avoid_partial_spends,
                     bool positive_only,
                     int expected_size)
    {
        OutputGroupTypeMap groups = GroupOutputs(*wallet, coins_pool, makeSelectionParams(rand, avoid_partial_spends), {{filter}})[filter];
        std::vector<OutputGroup>& groups_out = positive_only ? groups.groups_by_type[type].positive_group :
                                               groups.groups_by_type[type].mixed_group;
        BOOST_CHECK_EQUAL(groups_out.size(), expected_size);
    }

    void GroupAndVerify(const OutputType type,
                        const CoinEligibilityFilter& filter,
                        int expected_with_partial_spends_size,
                        int expected_without_partial_spends_size,
                        bool positive_only)
    {
        // First avoid partial spends
        GroupVerify(type, filter, /*avoid_partial_spends=*/false, positive_only,  expected_with_partial_spends_size);
        // Second don't avoid partial spends
        GroupVerify(type, filter, /*avoid_partial_spends=*/true, positive_only, expected_without_partial_spends_size);
    }
};

BOOST_AUTO_TEST_CASE(outputs_grouping_tests)
{
    const auto& wallet = NewWallet(m_node);
    GroupVerifier group_verifier;
    group_verifier.wallet = wallet;

    const CoinEligibilityFilter& BASIC_FILTER{1, 6, 0};

    // #################################################################################
    // 10 outputs from different txs going to the same script
    // 1) if partial spends is enabled --> must not be grouped
    // 2) if partial spends is not enabled --> must be grouped into a single OutputGroup
    // #################################################################################

    unsigned long GROUP_SIZE = 10;
    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    for (unsigned long i = 0; i < GROUP_SIZE; i++) {
        addCoin(group_verifier.coins_pool, *wallet, dest, 10 * COIN, /*is_from_me=*/true);
    }

    group_verifier.GroupAndVerify(OutputType::P2MR,
                                  BASIC_FILTER,
                                  /*expected_with_partial_spends_size=*/ GROUP_SIZE,
                                  /*expected_without_partial_spends_size=*/ 1,
                                  /*positive_only=*/ true);

    // ####################################################################################
    // 3) 10 more UTXO are added with a different script --> must be grouped into a single
    //    group for avoid partial spends and 10 different output groups for partial spends
    // ####################################################################################

    const CTxDestination dest2 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    for (unsigned long i = 0; i < GROUP_SIZE; i++) {
        addCoin(group_verifier.coins_pool, *wallet, dest2, 5 * COIN, /*is_from_me=*/true);
    }

    group_verifier.GroupAndVerify(OutputType::P2MR,
            BASIC_FILTER,
            /*expected_with_partial_spends_size=*/ GROUP_SIZE * 2,
            /*expected_without_partial_spends_size=*/ 2,
            /*positive_only=*/ true);

    // ################################################################################
    // 4) Now add a negative output --> which will be skipped if "positive_only" is set
    // ################################################################################

    const CTxDestination dest3 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    addCoin(group_verifier.coins_pool, *wallet, dest3, 1, true, CFeeRate(100));
    BOOST_CHECK(group_verifier.coins_pool.coins[OutputType::P2MR].back().GetEffectiveValue() <= 0);

    // First expect no changes with "positive_only" enabled
    group_verifier.GroupAndVerify(OutputType::P2MR,
            BASIC_FILTER,
            /*expected_with_partial_spends_size=*/ GROUP_SIZE * 2,
            /*expected_without_partial_spends_size=*/ 2,
            /*positive_only=*/ true);

    // Then expect changes with "positive_only" disabled
    group_verifier.GroupAndVerify(OutputType::P2MR,
            BASIC_FILTER,
            /*expected_with_partial_spends_size=*/ GROUP_SIZE * 2 + 1,
            /*expected_without_partial_spends_size=*/ 3,
            /*positive_only=*/ false);


    // ##############################################################################
    // 5) Try to add a non-eligible UTXO (due not fulfilling the min depth target for
    //    "not mine" UTXOs) --> it must not be added to any group
    // ##############################################################################

    const CTxDestination dest4 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    addCoin(group_verifier.coins_pool, *wallet, dest4, 6 * COIN,
            /*is_from_me=*/false, CFeeRate(0), /*depth=*/5);

    // Expect no changes from this round and the previous one (point 4)
    group_verifier.GroupAndVerify(OutputType::P2MR,
            BASIC_FILTER,
            /*expected_with_partial_spends_size=*/ GROUP_SIZE * 2 + 1,
            /*expected_without_partial_spends_size=*/ 3,
            /*positive_only=*/ false);


    // ##############################################################################
    // 6) Try to add a non-eligible UTXO (due not fulfilling the min depth target for
    //    "mine" UTXOs) --> it must not be added to any group
    // ##############################################################################

    const CTxDestination dest5 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    addCoin(group_verifier.coins_pool, *wallet, dest5, 6 * COIN,
            /*is_from_me=*/true, CFeeRate(0), /*depth=*/0);

    // Expect no changes from this round and the previous one (point 5)
    group_verifier.GroupAndVerify(OutputType::P2MR,
            BASIC_FILTER,
            /*expected_with_partial_spends_size=*/ GROUP_SIZE * 2 + 1,
            /*expected_without_partial_spends_size=*/ 3,
            /*positive_only=*/ false);

    // ###########################################################################################
    // 7) Surpass the OUTPUT_GROUP_MAX_ENTRIES and verify that a second partial group gets created.
    // ###########################################################################################

    const CTxDestination dest7 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    uint16_t NUM_SINGLE_ENTRIES = 101;
    for (unsigned long i = 0; i < NUM_SINGLE_ENTRIES; i++) { // OUTPUT_GROUP_MAX_ENTRIES{100}
        addCoin(group_verifier.coins_pool, *wallet, dest7, 9 * COIN, /*is_from_me=*/true);
    }

    // Exclude partial groups only adds one more group to the previous test case (point 6).
    int PREVIOUS_ROUND_COUNT = GROUP_SIZE * 2 + 1;
    group_verifier.GroupAndVerify(OutputType::P2MR,
            BASIC_FILTER,
            /*expected_with_partial_spends_size=*/ PREVIOUS_ROUND_COUNT + NUM_SINGLE_ENTRIES,
            /*expected_without_partial_spends_size=*/ 4,
            /*positive_only=*/ false);

    // Include partial groups should add one more group inside the avoid-partial-spends count.
    const CoinEligibilityFilter include_partial_filter{1, 6, 0, 0, /*include_partial=*/true};
    group_verifier.GroupAndVerify(OutputType::P2MR,
            include_partial_filter,
            /*expected_with_partial_spends_size=*/ PREVIOUS_ROUND_COUNT + NUM_SINGLE_ENTRIES,
            /*expected_without_partial_spends_size=*/ 5,
            /*positive_only=*/ false);

    // Weight-descending first-fit must fill earlier residual capacity instead of exposing an
    // arbitrary underfilled group. Include 40 first to exercise ordering independently of input
    // insertion order; the 40/70/30 case must become [70+30], [40].
    const auto verify_adversarial_packing = [&](const std::vector<int>& input_weights,
                                                const std::vector<size_t>& expected_all_sizes,
                                                const std::vector<size_t>& expected_full_sizes) {
        CoinsResult adversarial_coins;
        const CTxDestination destination = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
        for (const int input_weight : input_weights) {
            addCoin(adversarial_coins, *wallet, destination, 9 * COIN, /*is_from_me=*/true);
            adversarial_coins.coins[OutputType::P2MR].back().input_bytes = input_weight;
        }

        FastRandomContext adversarial_rand;
        CoinSelectionParams adversarial_params{makeSelectionParams(adversarial_rand, /*avoid_partial_spends=*/true)};
        adversarial_params.m_max_tx_weight = 140;
        adversarial_params.tx_noinputs_size = 40;
        const CoinEligibilityFilter exclude_partial_filter{1, 6, 0, 0, /*include_partial=*/false};
        const FilteredOutputGroups packed{GroupOutputs(
            *wallet,
            adversarial_coins,
            adversarial_params,
            {{exclude_partial_filter}, {include_partial_filter}})};

        const auto collect_sizes = [&](const CoinEligibilityFilter& filter) {
            std::vector<size_t> sizes;
            const auto& groups = packed.at(filter).groups_by_type.at(OutputType::P2MR).mixed_group;
            for (const OutputGroup& group : groups) {
                sizes.push_back(group.m_outputs.size());
                BOOST_CHECK_LE(group.m_weight + adversarial_params.tx_noinputs_size * WITNESS_SCALE_FACTOR,
                               *adversarial_params.m_max_tx_weight);
            }
            std::sort(sizes.begin(), sizes.end());
            return sizes;
        };

        const std::vector<size_t> all_sizes{collect_sizes(include_partial_filter)};
        BOOST_CHECK_EQUAL_COLLECTIONS(all_sizes.begin(), all_sizes.end(),
                                      expected_all_sizes.begin(), expected_all_sizes.end());
        const std::vector<size_t> full_sizes{collect_sizes(exclude_partial_filter)};
        BOOST_CHECK_EQUAL_COLLECTIONS(full_sizes.begin(), full_sizes.end(),
                                      expected_full_sizes.begin(), expected_full_sizes.end());
    };

    verify_adversarial_packing(/*input_weights=*/{70, 70, 30, 30},
                               /*expected_all_sizes=*/{2, 2},
                               /*expected_full_sizes=*/{2, 2});
    verify_adversarial_packing(/*input_weights=*/{40, 70, 30},
                               /*expected_all_sizes=*/{1, 2},
                               /*expected_full_sizes=*/{2});
}

BOOST_AUTO_TEST_SUITE_END()
} // end namespace wallet
