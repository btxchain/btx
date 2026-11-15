// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTACQUIRE_H
#define BTX_MODELNET_SWARM_NOTACQUIRE_H

#include <string>

namespace modelnet {

/**
 * A local note that a node might verify an openly licensed model artifact.
 * want_verify asks this note to treat the artifact as verified.
 *
 * No node has verified an openly licensed model artifact from this note, so
 * verified stays false on every path.
 */
struct SwarmNotAcquire {
    std::string artifact_id;
    bool want_verify{false};
};

/**
 * Outcome of noting an unverified openly licensed model artifact. verified
 * stays false on every path: no node has verified one from this note.
 */
struct SwarmNotAcquireResult {
    std::string code;
    bool verified{false};
};

/**
 * Note that no node has verified an openly licensed model artifact.
 * Order, first match wins: an empty artifact_id is ARTIFACT. want_verify is
 * UNVERIFIED. Otherwise the note is NOTED and err is clear.
 * verified stays false on every path. No node has verified an openly licensed
 * model artifact from this note.
 */
SwarmNotAcquireResult SwarmNoteNotAcquire(const SwarmNotAcquire& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTACQUIRE_H
