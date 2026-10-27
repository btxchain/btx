// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_SPLIT_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_SPLIT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Caller-supplied ppm split. The six parts must be >= 0 and sum to 1000000.
 * A refusal leaves the previously stored split in place. This is not a tax.
 */
class SwarmPaySplitBook {
public:
    bool Store(int64_t rollout, int64_t negative, int64_t reproduction, int64_t evaluation, int64_t challengers,
               int64_t milestone, std::string& err);

    bool ok() const;
    int64_t part(const std::string& name) const;

private:
    bool m_ok{false};
    int64_t m_rollout{0};
    int64_t m_negative{0};
    int64_t m_reproduction{0};
    int64_t m_evaluation{0};
    int64_t m_challengers{0};
    int64_t m_milestone{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_SPLIT_H
