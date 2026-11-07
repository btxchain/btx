// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/keep.h>

namespace modelnet {

std::string SwarmNatPubKeep::first(const SwarmNatPubBook& book, const std::string& endpoint) const
{
    if (!book.contains(endpoint)) return {};
    return book.endpoint_of(endpoint);
}

} // namespace modelnet
