// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nichesep.h>

namespace modelnet {

// Niches stay separate.
SwarmNicheSepResult SwarmKeepNiches(const SwarmNicheSep& niche, std::string& err)
{
    SwarmNicheSepResult out;
    out.merged = false;
    if (niche.niche_id.empty()) {
        out.code = "NICHE";
        err = "NICHE";
        return out;
    }
    if (niche.other_id.empty()) {
        out.code = "OTHER";
        err = "OTHER";
        return out;
    }
    if (niche.niche_id == niche.other_id) {
        out.code = "SAME";
        err = "SAME";
        return out;
    }
    if (niche.want_merge) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
