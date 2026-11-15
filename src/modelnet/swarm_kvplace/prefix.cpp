// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/prefix.h>

#include <modelnet/swarm_kvplace/codes.h>
#include <modelnet/swarm_kvplace/offer.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmKvPlaceApplyPrefix(SwarmKvPlaceBook& book, const std::string& fingerprint, std::int64_t length,
                             const std::string& parent, bool parent_known, std::string& err)
{
    if (length < 1) {
        err = SWARM_KVPLACE_PREFIX;
        return false;
    }
    SwarmKvPlaceRecord* row = book.Find(fingerprint);
    if (row == nullptr) {
        // A fingerprint that was never offered is a mismatch, not a missing engine.
        err = SWARM_KVPLACE_PREFIX_MISMATCH;
        return false;
    }
    if (!parent.empty() && !parent_known) {
        err = SWARM_KVPLACE_CAUSAL_GAP;
        return false;
    }

    row->has_prefix = true;
    row->prefix_length = length;
    row->parent = parent;
    row->parent_known = parent_known;
    err.clear();
    return true;
}

} // namespace modelnet
