// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTNOUNFUNDAD2_H
#define BITCOIN_MODELNET_SWARM_NOTNOUNFUNDAD2_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmNotNoUnfundAd2 {
    std::string pool_id;
    bool unfunded{false};
    bool want_advertise{false};
};

struct SwarmNotNoUnfundAd2Result {
    std::string code;
    bool advertised{false};
    int64_t atoms{0};
};

SwarmNotNoUnfundAd2Result SwarmNoteNotNoUnfundAd2(const SwarmNotNoUnfundAd2& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTNOUNFUNDAD2_H
