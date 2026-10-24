// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPARTIAL_H
#define BTX_MODELNET_SWARM_NOTPARTIAL_H

#include <string>

namespace modelnet {

/**
 * A local note that a caller might accept a partially transferred model
 * artifact. want_accept asks this note to accept one.
 *
 * A partially transferred model artifact has not been shown, so this note
 * does not accept one and does not move bytes. accepted and bytes_moved
 * stay false on every path.
 */
struct SwarmNotPartial {
    std::string artifact_id;
    bool want_accept{false};
};

/**
 * Outcome of noting an unshown partially transferred model artifact.
 * accepted and bytes_moved stay false on every path: a partially transferred
 * model artifact has not been shown.
 */
struct SwarmNotPartialResult {
    std::string code;
    bool accepted{false};
    bool bytes_moved{false};
};

/**
 * Note that no partially transferred model artifact is accepted and no bytes
 * are moved. Order, first match wins: an empty artifact_id is ARTIFACT.
 * want_accept is NOT_SHOWN. Otherwise the note is NOTED and err is clear.
 * accepted and bytes_moved stay false on every path. A partially transferred
 * model artifact has not been shown.
 */
SwarmNotPartialResult SwarmNoteNotPartial(const SwarmNotPartial& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPARTIAL_H
