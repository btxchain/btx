// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <blockfilter.h>
#include <chain.h>
#include <consensus/validation.h>
#include <index/blockfilterindex.h>
#include <interfaces/chain.h>
#include <key.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

namespace {

/** Stall immediately before the filter index's BlockConnected callback. */
class PreFilterBlocker final : public CValidationInterface
{
public:
    void Arm() { m_armed = true; }
    void WaitForEntry() { m_entered.get_future().wait(); }
    void Release()
    {
        if (!m_released.exchange(true)) m_release.set_value();
    }

protected:
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>&,
                        const CBlockIndex*) override
    {
        if (role == ChainstateRole::ASSUMEDVALID) return;
        if (m_armed.exchange(false)) {
            m_entered.set_value();
            m_release_fut.wait();
        }
    }

private:
    std::atomic_bool m_armed{false};
    std::atomic_bool m_released{false};
    std::promise<void> m_entered;
    std::promise<void> m_release;
    std::shared_future<void> m_release_fut{m_release.get_future()};
};

template <typename Pred>
bool WaitUpTo(std::chrono::milliseconds budget, Pred pred)
{
    const auto deadline{std::chrono::steady_clock::now() + budget};
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return pred();
}

void StopRaceFixture(node::NodeContext& node, BlockFilterIndex& index,
                     const std::shared_ptr<PreFilterBlocker>& blocker)
{
    node.validation_signals->SyncWithValidationInterfaceQueue();
    node.validation_signals->UnregisterSharedValidationInterface(blocker);
    index.Interrupt();
    index.Stop();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(cfilter_race_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(cfilter_available_during_append_window)
{
    auto blocker{std::make_shared<PreFilterBlocker>()};
    m_node.validation_signals->RegisterSharedValidationInterface(blocker);
    BlockFilterIndex index{interfaces::MakeChain(m_node), BlockFilterType::BASIC,
                           1_MiB, /*f_memory=*/true};
    BOOST_REQUIRE(index.Init());
    index.Sync();

    const CBlockIndex* old_tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
    BlockFilter old_filter;
    BOOST_REQUIRE(index.LookupFilter(old_tip, old_filter));

    blocker->Arm();
    const CScript script{GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    const CBlock block{CreateAndProcessBlock({}, script)};
    blocker->WaitForEntry();
    const CBlockIndex* tip{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash()))};
    BOOST_REQUIRE(tip);

    std::atomic_bool finished{false};
    bool result{false};
    BlockFilter filter;
    std::thread worker{[&] {
        result = index.LookupFilter(tip, filter);
        finished = true;
    }};
    BOOST_CHECK_MESSAGE(!WaitUpTo(250ms, [&] { return finished.load(); }),
                        "LookupFilter should wait for the queued index write");
    blocker->Release();
    worker.join();
    BOOST_CHECK(result);
    if (result) BOOST_CHECK(filter.GetBlockHash() == block.GetHash());
    StopRaceFixture(m_node, index, blocker);
}

BOOST_AUTO_TEST_CASE(cfilter_range_available_during_append_window)
{
    auto blocker{std::make_shared<PreFilterBlocker>()};
    m_node.validation_signals->RegisterSharedValidationInterface(blocker);
    BlockFilterIndex index{interfaces::MakeChain(m_node), BlockFilterType::BASIC,
                           1_MiB, /*f_memory=*/true};
    BOOST_REQUIRE(index.Init());
    index.Sync();

    blocker->Arm();
    const CScript script{GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    const CBlock block{CreateAndProcessBlock({}, script)};
    blocker->WaitForEntry();
    const CBlockIndex* tip{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash()))};
    BOOST_REQUIRE(tip);

    std::atomic_bool finished{false};
    bool result{false};
    std::vector<BlockFilter> filters;
    std::thread worker{[&] {
        result = index.LookupFilterRange(tip->nHeight - 3, tip, filters);
        finished = true;
    }};
    BOOST_CHECK_MESSAGE(!WaitUpTo(250ms, [&] { return finished.load(); }),
                        "LookupFilterRange should wait for the queued index write");
    blocker->Release();
    worker.join();
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(filters.size(), 4U);
    StopRaceFixture(m_node, index, blocker);
}

BOOST_AUTO_TEST_CASE(cfilter_header_available_during_append_window)
{
    auto blocker{std::make_shared<PreFilterBlocker>()};
    m_node.validation_signals->RegisterSharedValidationInterface(blocker);
    BlockFilterIndex index{interfaces::MakeChain(m_node), BlockFilterType::BASIC,
                           1_MiB, /*f_memory=*/true};
    BOOST_REQUIRE(index.Init());
    index.Sync();

    blocker->Arm();
    const CScript script{GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    const CBlock block{CreateAndProcessBlock({}, script)};
    blocker->WaitForEntry();
    const CBlockIndex* tip{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash()))};
    BOOST_REQUIRE(tip);

    std::atomic_bool finished{false};
    bool result{false};
    uint256 header;
    std::thread worker{[&] {
        result = index.LookupFilterHeader(tip, header);
        finished = true;
    }};
    BOOST_CHECK_MESSAGE(!WaitUpTo(250ms, [&] { return finished.load(); }),
                        "LookupFilterHeader should wait for the queued index write");
    blocker->Release();
    worker.join();
    BOOST_CHECK(result);
    BOOST_CHECK(header != uint256{});
    StopRaceFixture(m_node, index, blocker);
}

BOOST_AUTO_TEST_CASE(cfilter_available_during_same_height_reorg)
{
    auto blocker{std::make_shared<PreFilterBlocker>()};
    m_node.validation_signals->RegisterSharedValidationInterface(blocker);
    BlockFilterIndex index{interfaces::MakeChain(m_node), BlockFilterType::BASIC,
                           1_MiB, /*f_memory=*/true};
    BOOST_REQUIRE(index.Init());
    index.Sync();

    const CScript script_a{GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()))};
    const CBlock block_a{CreateAndProcessBlock({}, script_a)};
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    CBlockIndex* index_a{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block_a.GetHash()))};
    BOOST_REQUIRE(index_a);
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, index_a));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    blocker->Arm();
    const CKey other_key{GenerateRandomKey()};
    const CScript script_b{GetScriptForDestination(PKHash(other_key.GetPubKey()))};
    const CBlock block_b{CreateAndProcessBlock({}, script_b)};
    blocker->WaitForEntry();
    const CBlockIndex* index_b{WITH_LOCK(cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block_b.GetHash()))};
    BOOST_REQUIRE(index_b);
    BOOST_REQUIRE_EQUAL(index_b->nHeight, index_a->nHeight);

    std::atomic_bool finished{false};
    bool result{false};
    BlockFilter filter;
    std::thread worker{[&] {
        result = index.LookupFilter(index_b, filter);
        finished = true;
    }};
    BOOST_CHECK_MESSAGE(!WaitUpTo(250ms, [&] { return finished.load(); }),
                        "same-height sibling lookup should wait for queued reorg write");
    blocker->Release();
    worker.join();
    BOOST_CHECK(result);
    if (result) BOOST_CHECK(filter.GetBlockHash() == block_b.GetHash());
    StopRaceFixture(m_node, index, blocker);
}

BOOST_AUTO_TEST_SUITE_END()
