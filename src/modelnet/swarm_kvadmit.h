// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVADMIT_H
#define BTX_MODELNET_SWARM_KVADMIT_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmKvAdmit {
    std::string page_id;
    std::string family_id;
    bool same_prefix{false};
    bool engine_present{false};
    bool revoked{false};
    bool want_move{false};
    int64_t bytes{0};
};

struct SwarmKvAdmitResult {
    std::string code;
    bool admitted{false};
    bool moved{false};
    int64_t bytes_moved{0};
};

/** Local KV admission. A missing engine moves no bytes. */
SwarmKvAdmitResult SwarmAdmitKvPage(const SwarmKvAdmit& page, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVADMIT_H
