// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOIDREMAP_H
#define BTX_MODELNET_SWARM_NOTNOIDREMAP_H

#include <string>

namespace modelnet {

/**
 * A local note about one key. compromised marks the key as untrusted.
 * want_remap asks this note to remap the key onto a spend path.
 *
 * A compromised key is not remapped onto a spend path and spends
 * nothing. remapped and spent stay false on every path.
 */
struct SwarmNotNoIdRemap {
    std::string key_id;
    bool compromised{false};
    bool want_remap{false};
};

/**
 * Outcome of noting a key remap. remapped and spent stay false on
 * every path. A compromised key is not remapped onto a spend path
 * and spends nothing.
 */
struct SwarmNotNoIdRemapResult {
    std::string code;
    bool remapped{false};
    bool spent{false};
};

/**
 * Note a key remap without remapping or spending. Order, first match
 * wins: an empty key_id is KEY. compromised is IDENTITY_REMAP even
 * when want_remap is false. want_remap is HELD. Otherwise the note is
 * NOTED and err is clear. remapped and spent stay false on every
 * path. A compromised key is not remapped onto a spend path and
 * spends nothing.
 */
SwarmNotNoIdRemapResult SwarmNoteNotNoIdRemap(const SwarmNotNoIdRemap& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOIDREMAP_H
