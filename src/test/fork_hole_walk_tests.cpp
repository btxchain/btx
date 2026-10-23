// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// FindUniqueCompetingAttestedIndex() walks each signed-frontier hint down to
// the active tip looking for the lowest block without a usable body. On a
// trusted mirror in IBD every hint repeats the same walk (H hints × D-block
// gap per call). ForkHoleWalkMemo shares the walk across hints within one
// call. These tests check that the memo returns exactly what the full walk
// returns, on the walk alone and through FindUniqueCompetingAttestedIndex(),
// and show the drop in walk length.

#include <chain.h>
#include <key.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/matmul_trusted_attestations.h>
#include <random.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <set>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

//! The walk FindUniqueCompetingAttestedIndex() ran before the memo, verbatim
//! (with a step counter), kept here as the reference the memo must match.
ForkHoleWalkMemo::Result FullHoleWalk(const CBlockIndex* idx,
                                      const CBlockIndex* path_lca,
                                      uint64_t& steps)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    const CBlockIndex* lowest_unconnectable{nullptr};
    for (const CBlockIndex* walk{idx}; walk != path_lca; walk = walk->pprev) {
        if (walk == nullptr || (walk->nStatus & BLOCK_FAILED_MASK) != 0) {
            return {.aborted = true, .lowest_unconnectable = nullptr};
        }
        ++steps;
        if (!(walk->nStatus & BLOCK_HAVE_DATA) ||
            !walk->IsValid(BLOCK_VALID_TRANSACTIONS) ||
            !walk->HaveNumChainTxs()) {
            lowest_unconnectable = walk;
        }
    }
    return {.aborted = false, .lowest_unconnectable = lowest_unconnectable};
}

bool SameResult(const ForkHoleWalkMemo::Result& a, const ForkHoleWalkMemo::Result& b)
{
    return a.aborted == b.aborted && a.lowest_unconnectable == b.lowest_unconnectable;
}

//! Random body state for one index: usable body, HEADER_ONLY, body not yet
//! VALID_TRANSACTIONS, body above a hole (chain-tx 0), pruned body (no
//! HAVE_DATA, chain-tx kept), occasionally FAILED, plus unrelated flag bits.
void SetRandomBodyState(CBlockIndex& block, FastRandomContext& rng,
                        int usable_pct, int failed_permille)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    uint32_t status{BLOCK_VALID_TREE};
    uint64_t chain_tx{0};
    if (static_cast<int>(rng.randrange(100)) < usable_pct) {
        status = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        chain_tx = 1 + static_cast<uint64_t>(block.nHeight);
    } else {
        switch (rng.randrange(5)) {
        case 0:
        case 1:
            break; // HEADER_ONLY
        case 2:
            status = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
            break;
        case 3:
            status = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
            break;
        default:
            status = BLOCK_VALID_TRANSACTIONS;
            chain_tx = 1 + static_cast<uint64_t>(block.nHeight);
            break;
        }
    }
    if (static_cast<int>(rng.randrange(1000)) < failed_permille) {
        status |= rng.randbool() ? BLOCK_FAILED_VALID : BLOCK_FAILED_CHILD;
    }
    if (rng.randrange(8) == 0) {
        static constexpr uint32_t EXTRA[]{BLOCK_HAVE_UNDO, BLOCK_OPT_WITNESS,
                                          BLOCK_EXACT_REPLAY_VERIFIED,
                                          BLOCK_TRUSTED_REPLAY_ATTESTED,
                                          BLOCK_MANUALLY_INVALIDATED};
        status |= EXTRA[rng.randrange(std::size(EXTRA))];
    }
    block.nStatus = status;
    block.m_chain_tx_count = chain_tx;
}

//! Standalone block tree (no chainstate) for walk-level tests.
struct Tree {
    std::deque<CBlockIndex> nodes;

    CBlockIndex* Add(CBlockIndex* parent) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CBlockIndex& block{nodes.emplace_back()};
        block.pprev = parent;
        block.nHeight = parent == nullptr ? 0 : parent->nHeight + 1;
        block.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        block.m_chain_tx_count = 1 + static_cast<uint64_t>(block.nHeight);
        block.BuildSkip();
        return &block;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(fork_hole_walk_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(memo_matches_full_walk_on_random_trees)
{
    // Random trees with forks, holes, FAILED blocks and arbitrary flag bits.
    // Query orders: ascending frontier runs (the IBD shape), random,
    // descending and repeated starts; stops: LCA(tip, start) as in FUCAI,
    // plus arbitrary indexes and nullptr. Every memo answer must equal the
    // full walk, and the memo must never take more steps.
    FastRandomContext rng{uint256{uint8_t{0x5e}}};
    LOCK(::cs_main);
    uint64_t queries{0}, aborted{0}, with_hole{0}, memo_steps{0}, full_steps{0};
    constexpr int SCENARIOS{3000};
    for (int s = 0; s < SCENARIOS; ++s) {
        Tree tree;
        std::vector<CBlockIndex*> all;
        CBlockIndex* const genesis{tree.Add(nullptr)};
        all.push_back(genesis);
        const int main_len{50 + static_cast<int>(rng.randrange(s % 50 == 0 ? 3000 : 400))};
        const int tip_height{static_cast<int>(rng.randrange(main_len))};
        const int failed_permille{rng.randbool() ? 0 : static_cast<int>(rng.randrange(20))};
        std::vector<CBlockIndex*> main_chain{genesis};
        for (int h = 1; h <= main_len; ++h) {
            CBlockIndex* const block{tree.Add(main_chain.back())};
            if (h > tip_height) {
                const int usable{h - tip_height < 32 ? 70 : 10};
                SetRandomBodyState(*block, rng, usable, failed_permille);
            } else if (rng.randrange(50) == 0) {
                SetRandomBodyState(*block, rng, 90, failed_permille);
            }
            main_chain.push_back(block);
            all.push_back(block);
        }
        const int forks{static_cast<int>(rng.randrange(5))};
        for (int f = 0; f < forks; ++f) {
            CBlockIndex* parent{all[rng.randrange(all.size())]};
            const int len{1 + static_cast<int>(rng.randrange(300))};
            for (int i = 0; i < len; ++i) {
                parent = tree.Add(parent);
                SetRandomBodyState(*parent, rng, 50, failed_permille);
                all.push_back(parent);
            }
        }
        const CBlockIndex* const tip{rng.randrange(4) == 0 ? all[rng.randrange(all.size())]
                                                           : main_chain[tip_height]};

        std::vector<const CBlockIndex*> starts;
        switch (rng.randrange(4)) {
        case 0: { // ascending frontier run above the tip, possibly with dual entries
            const int top{tip_height + 1 + static_cast<int>(rng.randrange(main_len - tip_height))};
            const int run{1 + static_cast<int>(rng.randrange(600))};
            for (int h = std::max(tip_height + 1, top - run + 1); h <= std::min(top, main_len); ++h) {
                starts.push_back(main_chain[h]);
                if (rng.randrange(20) == 0) starts.push_back(all[rng.randrange(all.size())]);
            }
            break;
        }
        case 1: // random order
            for (int i = 0, n = 1 + static_cast<int>(rng.randrange(200)); i < n; ++i) {
                starts.push_back(all[rng.randrange(all.size())]);
            }
            break;
        case 2: // descending (memo cannot help; must still match)
            for (int h = main_len; h > tip_height && starts.size() < 300; --h) {
                starts.push_back(main_chain[h]);
            }
            break;
        default: // ascending by height over the whole tree, with repeats
            for (int i = 0, n = 1 + static_cast<int>(rng.randrange(300)); i < n; ++i) {
                starts.push_back(all[rng.randrange(all.size())]);
            }
            std::sort(starts.begin(), starts.end(), [](const CBlockIndex* a, const CBlockIndex* b) {
                return a->nHeight < b->nHeight;
            });
            for (size_t i = 0, n = starts.size() / 10; i < n; ++i) {
                starts.push_back(starts[rng.randrange(starts.size())]);
            }
            break;
        }

        ForkHoleWalkMemo memo;
        ForkHoleWalkMemo disabled{/*enabled=*/false};
        uint64_t scenario_full{0};
        for (const CBlockIndex* start : starts) {
            const CBlockIndex* stop{LastCommonAncestor(tip, start)};
            const auto pick{rng.randrange(20)};
            if (pick == 0) {
                stop = all[rng.randrange(all.size())]; // may not be an ancestor
            } else if (pick == 1) {
                stop = nullptr;
            } else if (pick == 2 && start != nullptr && start->nHeight > 0) {
                stop = start->GetAncestor(static_cast<int>(rng.randrange(start->nHeight)));
            }
            const auto want{FullHoleWalk(start, stop, scenario_full)};
            const auto got{memo.Walk(start, stop)};
            const auto got_disabled{disabled.Walk(start, stop)};
            BOOST_CHECK_MESSAGE(SameResult(want, got), "scenario " << s << " start height "
                                                                   << start->nHeight);
            BOOST_CHECK_MESSAGE(SameResult(want, got_disabled), "scenario " << s << " (disabled)");
            ++queries;
            if (want.aborted) ++aborted;
            if (!want.aborted && want.lowest_unconnectable != nullptr) ++with_hole;
        }
        BOOST_CHECK_EQUAL(disabled.Steps(), scenario_full);
        BOOST_CHECK_LE(memo.Steps(), scenario_full);
        memo_steps += memo.Steps();
        full_steps += scenario_full;
    }
    BOOST_TEST_MESSAGE("walk differential: " << SCENARIOS << " trees, " << queries << " walks ("
                       << aborted << " aborted, " << with_hole << " with a hole); steps full="
                       << full_steps << " memo=" << memo_steps);
    BOOST_CHECK_GT(aborted, queries / 50);
    BOOST_CHECK_GT(with_hole, queries / 5);
    BOOST_CHECK_LT(memo_steps, full_steps);
}

BOOST_AUTO_TEST_CASE(memo_walk_length_on_ibd_shape)
{
    // Lars-shape: a long HEADER_ONLY gap above the tip with 513 ascending
    // frontier hints at the top (the full hint window). The full walk costs
    // H * D steps; the memo costs D + H.
    constexpr int GAP{200'000};
    constexpr int HINTS{513};
    LOCK(::cs_main);
    Tree tree;
    CBlockIndex* walk{tree.Add(nullptr)};
    for (int h = 1; h <= 1000; ++h) walk = tree.Add(walk);
    const CBlockIndex* const tip{walk};
    std::vector<const CBlockIndex*> gap;
    for (int h = 0; h < GAP; ++h) {
        walk = tree.Add(walk);
        if (h >= 16) { // a short connectable download window, then headers only
            walk->nStatus = BLOCK_VALID_TREE;
            walk->m_chain_tx_count = 0;
        }
        gap.push_back(walk);
    }
    std::vector<const CBlockIndex*> hints(gap.end() - HINTS, gap.end());

    uint64_t full_steps{0};
    std::vector<ForkHoleWalkMemo::Result> full;
    const auto t0{std::chrono::steady_clock::now()};
    for (const CBlockIndex* hint : hints) full.push_back(FullHoleWalk(hint, tip, full_steps));
    const auto t1{std::chrono::steady_clock::now()};
    ForkHoleWalkMemo memo;
    std::vector<ForkHoleWalkMemo::Result> memoized;
    for (const CBlockIndex* hint : hints) memoized.push_back(memo.Walk(hint, tip));
    const auto t2{std::chrono::steady_clock::now()};

    for (size_t i = 0; i < hints.size(); ++i) {
        BOOST_CHECK(SameResult(full[i], memoized[i]));
        BOOST_CHECK(!memoized[i].aborted);
        BOOST_CHECK_EQUAL(memoized[i].lowest_unconnectable, gap[16]);
    }
    BOOST_CHECK_GE(full_steps, uint64_t{HINTS} * (GAP - HINTS));
    BOOST_CHECK_LE(memo.Steps(), uint64_t{GAP} + HINTS);
    const auto us = [](auto d) { return std::chrono::duration_cast<std::chrono::microseconds>(d).count(); };
    BOOST_TEST_MESSAGE("walk length, gap " << GAP << " x " << HINTS << " hints: full " << full_steps
                       << " steps in " << us(t1 - t0) << " us, memo " << memo.Steps() << " steps in "
                       << us(t2 - t1) << " us");
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

struct MemoRestore {
    ~MemoRestore()
    {
        ChainstateManager::SetFindUniqueCompetingAttestedIndexHoleWalkMemoForTest(true);
        node::matmul_trusted::ResetForTest();
    }
};

enum class StoreMode { TRUSTED_LOCAL_SIGNER, CONSENSUS_LOCAL_SIGNER, CONSENSUS_PIN_ONLY, TRUSTED_NO_SIGNER };

void ConfigureStore(StoreMode mode, const CKey& signer)
{
    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig config;
    config.chain_id = uint256::ONE;
    config.replay_authority_context = uint256::FromHex(std::string(64, 'a')).value();
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    if (mode == StoreMode::TRUSTED_LOCAL_SIGNER || mode == StoreMode::CONSENSUS_LOCAL_SIGNER) {
        config.local_signer = signer;
    }
    const bool trusted_mirror{mode == StoreMode::TRUSTED_LOCAL_SIGNER || mode == StoreMode::TRUSTED_NO_SIGNER};
    std::string error;
    BOOST_REQUIRE_MESSAGE(node::matmul_trusted::Configure(std::move(config), trusted_mirror, /*serve=*/false,
                                                          std::chrono::milliseconds{50}, error),
                          error);
}

//! Header added straight into the block index (no body on disk). Erased again
//! by EraseSynthetic before the scenario ends.
CBlockIndex* AddSynthetic(ChainstateManager& chainman, CBlockIndex* parent, FastRandomContext& rng)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    auto [it, inserted]{chainman.m_blockman.m_block_index.try_emplace(rng.rand256())};
    BOOST_REQUIRE(inserted);
    CBlockIndex& block{it->second};
    block.phashBlock = &it->first;
    block.pprev = parent;
    block.nHeight = parent->nHeight + 1;
    block.nBits = parent->nBits;
    block.nTime = parent->nTime + 90;
    block.nChainWork = parent->nChainWork + GetBlockProof(block);
    block.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    block.m_chain_tx_count = parent->m_chain_tx_count + 1;
    block.BuildSkip();
    return &block;
}

void EraseSynthetic(ChainstateManager& chainman, const std::vector<CBlockIndex*>& blocks)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    for (CBlockIndex* block : blocks) {
        const uint256 hash{block->GetBlockHash()};
        chainman.m_blockman.m_block_index.erase(hash);
    }
}

void AddHint(const CBlockIndex* block, bool quorum)
{
    if (quorum && node::matmul_trusted::SignAuthoritative(block->GetBlockHash(), block->nHeight) ==
                      matmul::trusted::AddResult::Accepted) {
        return;
    }
    // Dual hash at a signed height, or no quorum wanted: hint only.
    node::matmul_trusted::NoteAcceptedAttestationHeight(block->nHeight, block->GetBlockHash());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fork_hole_walk_selection_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(fucai_memo_matches_full_walk_on_random_scenarios)
{
    // FindUniqueCompetingAttestedIndex() with the memo and with the full
    // per-hint walk, on random block-index states around the real 100-block
    // chain: forks from the tip and below it, HEADER_ONLY gaps, bodies above
    // holes, pruned and FAILED blocks; frontier hint runs with and without
    // quorum, dual hashes at one height, hints on the active chain, unknown
    // hashes; a moved active tip; trusted-mirror, consensus+signer,
    // pin-only and signer-less mirror stores. FUCAI is const, and FMWC and
    // every other caller use only its return value, so equal returns mean
    // equal fork choice.
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    MemoRestore restore;
    FastRandomContext rng{uint256{uint8_t{0xfc}}};
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    CBlockIndex* const real_tip{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    BOOST_REQUIRE(real_tip != nullptr);

    constexpr int SCENARIOS{2000};
    int nonnull{0}, derived_prefix{0}, off_tip{0};
    for (int s = 0; s < SCENARIOS; ++s) {
        const auto mode_pick{rng.randrange(20)};
        const StoreMode mode{mode_pick < 14  ? StoreMode::TRUSTED_LOCAL_SIGNER :
                             mode_pick < 18 ? StoreMode::CONSENSUS_LOCAL_SIGNER :
                             mode_pick < 19 ? StoreMode::CONSENSUS_PIN_ONLY :
                                              StoreMode::TRUSTED_NO_SIGNER};
        ConfigureStore(mode, signer);
        // One cs_main section per scenario: nothing else can see the
        // synthetic headers, and they are erased before it ends.
        LOCK(::cs_main);

        std::vector<CBlockIndex*> synthetic;
        std::vector<CBlockIndex*> branch_main;
        std::vector<const CBlockIndex*> active_ancestors;
        {
            LOCK(::cs_main);
            for (const CBlockIndex* p{real_tip}; p != nullptr && active_ancestors.size() < 40; p = p->pprev) {
                active_ancestors.push_back(p);
            }
            // Main branch from the real tip: a connectable download window,
            // then a mostly HEADER_ONLY gap.
            const int main_len{1 + static_cast<int>(rng.randrange(s % 40 == 0 ? 3000 : 700))};
            const int window{static_cast<int>(rng.randrange(40))};
            const int failed_permille{rng.randrange(3) == 0 ? static_cast<int>(rng.randrange(10)) : 0};
            CBlockIndex* parent{real_tip};
            for (int i = 0; i < main_len; ++i) {
                parent = AddSynthetic(chainman, parent, rng);
                if (i >= window || rng.randrange(25) == 0) {
                    SetRandomBodyState(*parent, rng, i < window ? 80 : 8, failed_permille);
                }
                synthetic.push_back(parent);
                branch_main.push_back(parent);
            }
            // Forks: off the real chain (reorg shapes) or off the main branch.
            for (int f = 0, forks = static_cast<int>(rng.randrange(5)); f < forks; ++f) {
                CBlockIndex* fork_parent{rng.randbool()
                                             ? const_cast<CBlockIndex*>(active_ancestors[rng.randrange(
                                                   std::min<size_t>(active_ancestors.size(), 12))])
                                             : synthetic[rng.randrange(synthetic.size())]};
                for (int i = 0, len = 1 + static_cast<int>(rng.randrange(200)); i < len; ++i) {
                    fork_parent = AddSynthetic(chainman, fork_parent, rng);
                    SetRandomBodyState(*fork_parent, rng, 60, failed_permille);
                    synthetic.push_back(fork_parent);
                }
            }
        }

        // Hints. A frontier run on the main branch (ascending, the top one
        // with quorum), plus random extras.
        std::set<const CBlockIndex*> hinted;
        {
            const int top{static_cast<int>(rng.randrange(branch_main.size()))};
            const int run{1 + static_cast<int>(rng.randrange(600))};
            const int quorum_pct{static_cast<int>(rng.randrange(40))};
            AddHint(branch_main[top], /*quorum=*/rng.randrange(10) != 0);
            hinted.insert(branch_main[top]);
            for (int i = std::max(0, top - run + 1); i < top; ++i) {
                AddHint(branch_main[i], static_cast<int>(rng.randrange(100)) < quorum_pct);
                hinted.insert(branch_main[i]);
            }
            for (int i = 0, extras = static_cast<int>(rng.randrange(12)); i < extras; ++i) {
                const auto kind{rng.randrange(4)};
                if (kind == 0) {
                    const CBlockIndex* a{active_ancestors[rng.randrange(active_ancestors.size())]};
                    AddHint(a, rng.randbool());
                    hinted.insert(a);
                } else if (kind == 1) {
                    node::matmul_trusted::NoteAcceptedAttestationHeight(
                        real_tip->nHeight + 1 + static_cast<int>(rng.randrange(800)), rng.rand256());
                } else {
                    const CBlockIndex* x{synthetic[rng.randrange(synthetic.size())]};
                    AddHint(x, rng.randbool());
                    hinted.insert(x);
                }
            }
        }

        {
            LOCK(::cs_main);
            CBlockIndex* tip{real_tip};
            const auto tip_pick{rng.randrange(8)};
            if (tip_pick == 0) {
                tip = const_cast<CBlockIndex*>(active_ancestors[1 + rng.randrange(active_ancestors.size() - 1)]);
            } else if (tip_pick == 1) {
                tip = synthetic[rng.randrange(synthetic.size())];
            }
            if (tip != real_tip) chainstate.m_chain.SetTip(*tip);

            ChainstateManager::SetFindUniqueCompetingAttestedIndexHoleWalkMemoForTest(false);
            const CBlockIndex* const full{chainman.FindUniqueCompetingAttestedIndex()};
            ChainstateManager::SetFindUniqueCompetingAttestedIndexHoleWalkMemoForTest(true);
            const CBlockIndex* const memo{chainman.FindUniqueCompetingAttestedIndex()};
            BOOST_CHECK_MESSAGE(full == memo, "scenario " << s << ": full walk "
                                    << (full ? full->nHeight : -1) << " memo " << (memo ? memo->nHeight : -1));
            if (full != nullptr) {
                ++nonnull;
                if (!hinted.contains(full)) ++derived_prefix;
                if (LastCommonAncestor(tip, full) != tip) ++off_tip;
            }

            if (tip != real_tip) chainstate.m_chain.SetTip(*real_tip);
            EraseSynthetic(chainman, synthetic);
        }
    }
    BOOST_TEST_MESSAGE("FUCAI differential: " << SCENARIOS << " scenarios, " << nonnull << " selections ("
                       << derived_prefix << " derived below a hole, " << off_tip << " off the tip)");
    BOOST_CHECK_GT(nonnull, SCENARIOS / 10);
    BOOST_CHECK_GT(derived_prefix, SCENARIOS / 50);
}

BOOST_AUTO_TEST_CASE(fucai_memo_cost_on_ibd_shape)
{
    // Trusted mirror in IBD: 100k-block gap above the tip, 16 connectable
    // bodies, then HEADER_ONLY; 513 frontier hints at the top (the top one
    // with quorum). Same answer with and without the memo; time both.
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    MemoRestore restore;
    FastRandomContext rng{uint256{uint8_t{0x1b}}};
    CKey signer;
    signer.MakeNewKey(/*fCompressed=*/true);
    ConfigureStore(StoreMode::TRUSTED_LOCAL_SIGNER, signer);
    LOCK(::cs_main);
    constexpr int GAP{100'000};
    constexpr int HINTS{513};
    std::vector<CBlockIndex*> gap;
    {
        LOCK(::cs_main);
        CBlockIndex* parent{chainstate.m_chain.Tip()};
        for (int i = 0; i < GAP; ++i) {
            parent = AddSynthetic(chainman, parent, rng);
            if (i >= 16) {
                parent->nStatus = BLOCK_VALID_TREE;
                parent->m_chain_tx_count = 0;
            }
            gap.push_back(parent);
        }
    }
    AddHint(gap.back(), /*quorum=*/true);
    for (int i = GAP - HINTS; i < GAP - 1; ++i) AddHint(gap[i], /*quorum=*/false);
    BOOST_REQUIRE_EQUAL(node::matmul_trusted::AttestedFrontierHints().size(), size_t{HINTS});

    LOCK(::cs_main);
    using Clock = std::chrono::steady_clock;
    ChainstateManager::SetFindUniqueCompetingAttestedIndexHoleWalkMemoForTest(false);
    const auto t0{Clock::now()};
    const CBlockIndex* const full{chainman.FindUniqueCompetingAttestedIndex()};
    const auto t1{Clock::now()};
    ChainstateManager::SetFindUniqueCompetingAttestedIndexHoleWalkMemoForTest(true);
    const CBlockIndex* const memo{chainman.FindUniqueCompetingAttestedIndex()};
    const auto t2{Clock::now()};
    BOOST_CHECK(full != nullptr);
    BOOST_CHECK(full == memo);
    BOOST_CHECK(std::find(gap.begin(), gap.begin() + 16, full) != gap.begin() + 16);
    const auto ms = [](auto d) { return std::chrono::duration<double, std::milli>(d).count(); };
    BOOST_TEST_MESSAGE("FUCAI cost, gap " << GAP << " x " << HINTS << " hints: full walk " << ms(t1 - t0)
                       << " ms, memo " << ms(t2 - t1) << " ms");
    BOOST_CHECK_LT(ms(t2 - t1), ms(t1 - t0));
    EraseSynthetic(chainman, gap);
}

BOOST_AUTO_TEST_SUITE_END()
