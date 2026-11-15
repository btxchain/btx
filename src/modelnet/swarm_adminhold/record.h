// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_RECORD_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One opened channel and the refund fields stored with it.
 * The height and the sponsor key are the values from the successful Open.
 * Nothing here replaces either field.
 */
struct SwarmAdminHoldRecord {
    std::string channel;
    int64_t refund_height{0};
    std::vector<unsigned char> sponsor_key;
};

SwarmAdminHoldRecord SwarmAdminHoldMakeRecord(const std::string& channel,
                                               int64_t refund_height,
                                               const std::vector<unsigned char>& sponsor_key);

/**
 * The channel is non-empty, the height is at least 1, and the key is
 * 1312 bytes. The key bytes are not examined.
 */
bool SwarmAdminHoldRecordUsable(const SwarmAdminHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_RECORD_H
