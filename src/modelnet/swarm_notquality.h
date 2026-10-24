// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTQUALITY_H
#define BTX_MODELNET_SWARM_NOTQUALITY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about quality for one job. want_publish asks this note to
 * publish a quality measurement.
 *
 * This note does not publish a quality measurement or reach a quality
 * target. published and reached stay false, and seconds stays 0, on every
 * path.
 */
struct SwarmNotQuality {
    std::string job_id;
    bool want_publish{false};
};

/**
 * Outcome of noting quality. published and reached stay false, and seconds
 * stays 0, on every path.
 */
struct SwarmNotQualityResult {
    std::string code;
    bool published{false};
    int64_t seconds{0};
    bool reached{false};
};

/**
 * Note quality without publishing it or reaching a target.
 * Order, first match wins: an empty job_id is JOB.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published and reached stay false, and seconds stays 0, on every path.
 */
SwarmNotQualityResult SwarmNoteNotQuality(const SwarmNotQuality& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTQUALITY_H
