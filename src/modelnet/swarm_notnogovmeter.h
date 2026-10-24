// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGOVMETER_H
#define BTX_MODELNET_SWARM_NOTNOGOVMETER_H

#include <string>

namespace modelnet {

/**
 * A local note about one node on a metered link. metered records that the
 * governor should drain workers. want_run asks this note to run workers.
 *
 * The governor drains workers to zero on a metered link. running stays
 * false and workers stays 0 on every path.
 */
struct SwarmNotNoGovMeter {
    std::string node_id;
    bool metered{false};
    bool want_run{false};
};

/**
 * Outcome of noting a metered-link drain. running stays false and workers
 * stays 0 on every path. The governor drains workers to zero on a metered
 * link.
 */
struct SwarmNotNoGovMeterResult {
    std::string code;
    bool running{false};
    int workers{0};
};

/**
 * Note a metered-link drain without starting workers.
 * Order, first match wins: an empty node_id is NODE. If metered is
 * true, the note is ZERO even when want_run is false. want_run is
 * HELD. Otherwise the note is NOTED and err is cleared. running stays
 * false and workers stays 0 on every path. The governor drains workers
 * to zero on a metered link.
 */
SwarmNotNoGovMeterResult SwarmNoteNotNoGovMeter(const SwarmNotNoGovMeter& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGOVMETER_H
