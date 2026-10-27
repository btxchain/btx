// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/swarm_gradhold.h>

#include <modelnet/swarm_gradhold/egress.h>
#include <modelnet/swarm_gradhold/keep.h>
#include <modelnet/swarm_gradhold/limits.h>
#include <modelnet/swarm_gradhold/offer.h>

namespace modelnet {

bool SwarmGradHold::Offer(const std::string& update_id, std::string& err)
{
    return SwarmGradHoldOffer{}.Apply(m_book, update_id, err);
}

bool SwarmGradHold::Export(const std::string& update_id, std::string& err)
{
    return SwarmGradHoldEgress{}.Apply(update_id, err);
}

bool SwarmGradHold::offered(const std::string& update_id) const
{
    return m_book.contains(update_id);
}

std::string SwarmGradHold::stored_id(const std::string& update_id) const
{
    return SwarmGradHoldKeep{}.first(m_book, update_id);
}

std::size_t SwarmGradHold::offer_count() const
{
    return m_book.size();
}

bool SwarmGradHold::exported() const
{
    if (m_book.exported()) return true;
    return m_seal.exported();
}

int64_t SwarmGradHold::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmGradHoldBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmGradHold::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmGradHold::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
