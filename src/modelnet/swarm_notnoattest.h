// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOATTEST_H
#define BTX_MODELNET_SWARM_NOTNOATTEST_H

#include <string>

namespace modelnet {

/**
 * A local note about one report. want_pass asks this note to treat a
 * unit note as a passed hardware stage.
 *
 * A unit note does not pass a hardware stage, so passed and gpu stay
 * false on every path.
 */
struct SwarmNotNoAttest {
    std::string report_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a report. passed and gpu stay false on every path:
 * a unit note does not pass a hardware stage.
 */
struct SwarmNotNoAttestResult {
    std::string code;
    bool passed{false};
    bool gpu{false};
};

/**
 * Note a report without passing a hardware stage.
 * Order, first match wins: an empty report_id is REPORT. want_pass is
 * UNQUALIFIED. Otherwise the note is NOTED and err is cleared.
 * passed and gpu stay false on every path. A unit note does not pass a
 * hardware stage.
 */
SwarmNotNoAttestResult SwarmNoteNotNoAttest(const SwarmNotNoAttest& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOATTEST_H
