// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUALIFY2_H
#define BTX_MODELNET_SWARM_NOTNOQUALIFY2_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. caller_rate is a caller-supplied token
 * rate. want_qualify asks this note to qualify the engine.
 *
 * qualified stays false on every path. A caller-supplied token rate does
 * not qualify an engine.
 */
struct SwarmNotNoQualify2 {
    std::string engine_id;
    bool caller_rate{false};
    bool want_qualify{false};
};

/**
 * Outcome of noting an engine. qualified stays false on every path. A
 * caller-supplied token rate does not qualify an engine.
 */
struct SwarmNotNoQualify2Result {
    std::string code;
    bool qualified{false};
};

/**
 * Note an engine without qualifying it. Order, first match wins: an empty
 * engine_id is ENGINE. caller_rate is NOT_QUALIFIED even when want_qualify
 * is false. want_qualify is HELD. Otherwise the note is NOTED and err is
 * cleared. qualified stays false on every path. A caller-supplied token
 * rate does not qualify an engine.
 */
SwarmNotNoQualify2Result SwarmNoteNotNoQualify2(const SwarmNotNoQualify2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUALIFY2_H
