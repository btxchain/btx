// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/prefetch.h>

#include <modelnet/swarm_kvplace/codes.h>
#include <modelnet/swarm_kvplace/offer.h>

#include <string>

namespace modelnet {

bool SwarmKvPlacePrefetch(const SwarmKvPlaceBook& book, const std::string& fingerprint, std::string& err)
{
    if (!book.Has(fingerprint) || !book.in_kv(fingerprint)) {
        err = SWARM_KVPLACE_NOT_COMPAT;
        return false;
    }
    err = SWARM_KVPLACE_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
