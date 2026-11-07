// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_CHANNEL_H
#define BITCOIN_MODELNET_SWARM_FORWARD_CHANNEL_H

#include <modelnet/swarm_forward/open.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory liquidity of opened channels.
 * A second Open of the same channel is REPLAY and leaves the first
 * liquidity. Debit subtracts only when the amount still fits.
 */
class SwarmForwardChannel {
public:
    bool Open(const std::string& channel, int64_t liquidity, std::string& err);
    bool Known(const std::string& channel) const;
    int64_t Remaining(const std::string& channel) const;
    /** Subtract amount. A short or unknown channel is left unchanged. */
    bool Debit(const std::string& channel, int64_t amount);

private:
    SwarmForwardOpen m_open;
    std::map<std::string, int64_t> m_remaining;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_CHANNEL_H
