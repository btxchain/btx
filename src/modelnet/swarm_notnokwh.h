// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOKWH_H
#define BTX_MODELNET_SWARM_NOTNOKWH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a run might publish an energy figure.
 * want_publish asks this note to publish one.
 *
 * This note publishes no energy figure. published stays false and
 * milliwatt_hours stays 0 on every path.
 */
struct SwarmNotNoKwh {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting that no energy figure is published. published stays
 * false and milliwatt_hours stays 0 on every path.
 */
struct SwarmNotNoKwhResult {
    std::string code;
    bool published{false};
    int64_t milliwatt_hours{0};
};

/**
 * Note that this note publishes no energy figure.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and milliwatt_hours stays 0 on every path.
 */
SwarmNotNoKwhResult SwarmNoteNotNoKwh(const SwarmNotNoKwh& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOKWH_H
