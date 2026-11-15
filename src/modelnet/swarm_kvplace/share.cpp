// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/share.h>

#include <modelnet/swarm_kvplace/codes.h>
#include <modelnet/swarm_kvplace/offer.h>

#include <set>
#include <string>

namespace modelnet {

bool SwarmKvPlaceShares::Share(const SwarmKvPlaceBook& book, const std::string& left_fingerprint,
                               const std::string& right_fingerprint, std::string& err)
{
    if (left_fingerprint != right_fingerprint || !book.in_kv(left_fingerprint) || !book.in_kv(right_fingerprint)) {
        err = SWARM_KVPLACE_NOT_COMPAT;
        return false;
    }
    m_shared.insert(left_fingerprint);
    err.clear();
    return true;
}

bool SwarmKvPlaceShares::shared(const std::string& fingerprint) const
{
    return m_shared.count(fingerprint) != 0;
}

} // namespace modelnet
