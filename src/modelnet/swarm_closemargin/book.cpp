// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/book.h>

#include <modelnet/swarm_closemargin/limits.h>

#include <cstddef>
#include <cstdint>
#include <utility>

namespace modelnet {

bool SwarmCloseMarginHoldBook::contains(int64_t blocks) const
{
    if (blocks != kSwarmCloseMarginHoldMarginBlocks) return false;
    return m_requests.find(blocks) != m_requests.end();
}

int64_t SwarmCloseMarginHoldBook::blocks_of(int64_t blocks) const
{
    const auto found = m_requests.find(blocks);
    if (found == m_requests.end()) return 0;
    return found->second.blocks();
}

std::size_t SwarmCloseMarginHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmCloseMarginHoldBook::shrunk() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.shrunk()) return true;
    }
    return kSwarmCloseMarginHoldShrunk;
}

int64_t SwarmCloseMarginHoldBook::bytes_moved() const
{
    int64_t total = kSwarmCloseMarginHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmCloseMarginHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmCloseMarginHoldGpu;
}

bool SwarmCloseMarginHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmCloseMarginHoldLaunched;
}

bool SwarmCloseMarginHoldBook::mined() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.mined()) return true;
    }
    return kSwarmCloseMarginHoldMined;
}

bool SwarmCloseMarginHoldBook::store(int64_t blocks)
{
    if (contains(blocks)) return false;
    SwarmCloseMarginHoldRecord record = SwarmCloseMarginHoldRecord::Make(blocks);
    if (!SwarmCloseMarginHoldRecordUsable(record)) return false;
    m_requests.emplace(blocks, std::move(record));
    return true;
}

} // namespace modelnet
