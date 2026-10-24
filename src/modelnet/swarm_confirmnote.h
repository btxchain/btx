// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CONFIRMNOTE_H
#define BITCOIN_MODELNET_SWARM_CONFIRMNOTE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmConfirmNote {
    std::string channel_id;
    int64_t confirmations;
    bool want_broadcast;
};

struct SwarmConfirmNoteResult {
    std::string code;
    bool broadcast;
    int64_t confirmations;
};

SwarmConfirmNoteResult SwarmNoteConfirmLocal(const SwarmConfirmNote& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CONFIRMNOTE_H
