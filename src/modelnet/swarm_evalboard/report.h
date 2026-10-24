// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_REPORT_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_REPORT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One stored evaluation row.
 * The score is the submitted value. This board does not replace rows
 * with a mean.
 */
struct SwarmEvalReport {
    std::string subject;
    std::string author;
    std::string domain;
    int64_t score{0};
    bool independent{false};
    bool rotating{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_REPORT_H
