// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCALLERQUAL_H
#define BTX_MODELNET_SWARM_NOTCALLERQUAL_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. tokens_per_sec is a caller-supplied rate.
 * want_qualify asks this note to qualify that engine.
 *
 * A caller-supplied token rate does not start a runtime and does not
 * qualify an engine. qualified and advertised stay false on every path.
 */
struct SwarmNotCallerQual {
    std::string engine_id;
    bool want_qualify{false};
    double tokens_per_sec{0};
};

/**
 * Outcome of noting a qualify request. qualified and advertised stay false
 * on every path. tokens_per_sec is not copied into this result.
 */
struct SwarmNotCallerQualResult {
    std::string code;
    bool qualified{false};
    bool advertised{false};
};

/**
 * Note a qualify request without starting a runtime or qualifying an engine.
 * Order, first match wins: an empty engine_id is ENGINE.
 * want_qualify is UNMEASURED, even when tokens_per_sec is finite and positive.
 * Otherwise the note is NOTED and err is clear.
 * qualified and advertised stay false on every path.
 * A caller-supplied token rate does not start a runtime and does not
 * qualify an engine. tokens_per_sec is not copied into the result.
 */
SwarmNotCallerQualResult SwarmNoteNotCallerQual(const SwarmNotCallerQual& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCALLERQUAL_H
