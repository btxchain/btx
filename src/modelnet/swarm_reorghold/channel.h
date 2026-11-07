// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_CHANNEL_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_CHANNEL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One open channel on the reorganization-exit plane.
 * Open stores it unfrozen. Reorg is the only path that sets frozen.
 * paid and exited stay false: this record has no field that can pay or remove it.
 */
struct ReorgHoldChannel {
    std::string id;
    int64_t earned{0};
    bool frozen{false};
};

ReorgHoldChannel ReorgHoldMakeChannel(const std::string& id, int64_t earned);
void ReorgHoldFreezeChannel(ReorgHoldChannel& channel);
bool ReorgHoldChannelPaid(const ReorgHoldChannel& channel);
bool ReorgHoldChannelExited(const ReorgHoldChannel& channel);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_CHANNEL_H
