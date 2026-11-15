// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PREFIXBOOK_H
#define BTX_MODELNET_SWARM_PREFIXBOOK_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmPrefixBook {
    std::string page_id;
    bool same_prefix{false};
    bool same_family{false};
    bool engine_present{false};
    bool want_share{false};
};

struct SwarmPrefixBookResult {
    std::string code;
    bool compatible{false};
    bool shared{false};
    int64_t bytes_moved{0};
};

/** A matching prefix can be noted locally. Family membership does not share a page, and no bytes move. */
SwarmPrefixBookResult SwarmMatchPrefix(const SwarmPrefixBook& page, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PREFIXBOOK_H
