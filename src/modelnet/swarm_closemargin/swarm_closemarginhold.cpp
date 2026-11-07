// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/swarm_closemarginhold.h>

#include <modelnet/swarm_closemargin/keep.h>
#include <modelnet/swarm_closemargin/limits.h>
#include <modelnet/swarm_closemargin/request.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmCloseMarginHold::Shrink(int64_t blocks, std::string& err)
{
    return SwarmCloseMarginHoldRequest{}.Apply(m_book, blocks, err);
}

bool SwarmCloseMarginHold::stored(int64_t blocks) const
{
    return m_book.contains(blocks);
}

int64_t SwarmCloseMarginHold::stored_blocks(int64_t blocks) const
{
    return SwarmCloseMarginHoldKeep{}.first(m_book, blocks);
}

std::size_t SwarmCloseMarginHold::request_count() const
{
    return m_book.size();
}

int64_t SwarmCloseMarginHold::margin_blocks() const
{
    const int64_t stayed = m_stay.margin_blocks();
    if (stayed == kSwarmCloseMarginHoldMarginBlocks) return stayed;
    return kSwarmCloseMarginHoldMarginBlocks;
}

bool SwarmCloseMarginHold::shrunk() const
{
    if (m_book.shrunk()) return true;
    return m_stay.shrunk();
}

int64_t SwarmCloseMarginHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmCloseMarginHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmCloseMarginHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmCloseMarginHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

bool SwarmCloseMarginHold::mined() const
{
    if (m_book.mined()) return true;
    return m_quiet.mined();
}

} // namespace modelnet
