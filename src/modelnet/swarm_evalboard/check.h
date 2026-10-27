// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_CHECK_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_CHECK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Decide whether one report may be stored.
 * Order, first match wins:
 * an empty subject, author, or domain is REPORT.
 * author equal to subject is NOT_SCORED.
 * independent false is HELD.
 * rotating false is NOT_ROTATING.
 * a score outside 0..1000000 is RANGE.
 * A passing report does not write err. Replay is a separate check.
 */
bool SwarmEvalAdmitReport(const std::string& subject, const std::string& author, const std::string& domain,
                          int64_t score, bool independent, bool rotating, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_CHECK_H
