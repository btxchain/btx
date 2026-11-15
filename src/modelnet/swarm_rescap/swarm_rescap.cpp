// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/swarm_rescap.h>

#include <modelnet/swarm_rescap/apply.h>
#include <modelnet/swarm_rescap/limits.h>

namespace modelnet {

bool SwarmResCap::Raise(int64_t threads, std::string& err)
{
    return SwarmResCapApply{}.Apply(m_book, threads, err);
}

bool SwarmResCap::stored(int64_t threads) const
{
    return m_book.contains(threads);
}

int64_t SwarmResCap::stored_threads(int64_t threads) const
{
    return m_book.stored_threads(threads);
}

std::size_t SwarmResCap::raise_count() const
{
    return m_book.size();
}

bool SwarmResCap::raised() const
{
    if (m_book.raised()) return true;
    return m_stay.raised();
}

int64_t SwarmResCap::cap_threads() const
{
    return m_stay.cap_threads();
}

int64_t SwarmResCap::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmResCapBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmResCap::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmResCap::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
