// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTASSUMPTION_H
#define BTX_MODELNET_SWARM_NOTASSUMPTION_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one close. want_measure asks this note to measure
 * that close.
 *
 * An 8000-byte close size is an assumption and is not a measurement.
 * measured stays false and assumed_bytes stays 0 on every path.
 */
struct SwarmNotAssumption {
    std::string close_id;
    bool want_measure{false};
};

/**
 * Outcome of noting a close. measured stays false and assumed_bytes stays
 * 0 on every path. An 8000-byte close size is an assumption and is not a
 * measurement.
 */
struct SwarmNotAssumptionResult {
    std::string code;
    bool measured{false};
    int64_t assumed_bytes{0};
};

/**
 * Note a close without measuring it or recording an assumed size.
 * Order, first match wins: an empty close_id is CLOSE.
 * want_measure is MEASURE_REFUSED.
 * Otherwise the note is NOTED and err is clear.
 * measured stays false and assumed_bytes stays 0 on every path.
 * An 8000-byte close size is an assumption and is not a measurement.
 */
SwarmNotAssumptionResult SwarmNoteNotAssumption(const SwarmNotAssumption& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTASSUMPTION_H
