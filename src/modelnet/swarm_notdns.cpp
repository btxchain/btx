// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdns.h>

#include <string>

namespace modelnet {

SwarmNotDnsResult SwarmNoteNotDns(const SwarmNotDns& note, std::string& err)
{
    SwarmNotDnsResult result;
    result.published = false;
    result.seed_count = 0;
    // This note publishes no seed and no address. ModelDNSSeeds stays empty.
    if (note.seed_id.empty()) {
        result.code = "SEED";
        result.published = false;
        result.seed_count = 0;
        err = "SEED";
        return result;
    }
    if (note.want_publish) {
        result.code = "EMPTY";
        result.published = false;
        result.seed_count = 0;
        err = "EMPTY";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.seed_count = 0;
    err.clear();
    return result;
}

} // namespace modelnet
