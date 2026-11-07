// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_SCORE_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_SCORE_H

#include <cstdint>

namespace modelnet {

/**
 * The latest stored score on the row.
 * lower_than is true only when a score is already stored and the next
 * score is strictly lower. An equal score is not lower. store replaces
 * the latest value and does not drop the row.
 */
class SwarmEarlyHaltScore {
public:
    bool held() const { return m_held; }
    int64_t value() const { return m_value; }

    bool lower_than(int64_t next) const;
    void store(int64_t next);

private:
    bool m_held{false};
    int64_t m_value{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_SCORE_H
