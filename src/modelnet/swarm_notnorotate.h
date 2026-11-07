// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOROTATE_H
#define BTX_MODELNET_SWARM_NOTNOROTATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one key. want_rotate asks this note to rotate the key.
 *
 * This note rotates no key and broadcasts nothing. rotated and broadcast
 * stay false on every path.
 */
struct SwarmNotNoRotate {
    std::string key_id;
    bool want_rotate{false};
};

/**
 * Outcome of noting a key. rotated and broadcast stay false on every path.
 * This note rotates no key and broadcasts nothing.
 */
struct SwarmNotNoRotateResult {
    std::string code;
    bool rotated{false};
    bool broadcast{false};
};

/**
 * Note a key without rotating it or broadcasting a rotation. Order, first
 * match wins: an empty key_id is KEY. want_rotate is REFUSED. Otherwise
 * the note is NOTED and err is clear. rotated and broadcast stay false on
 * every path. This note rotates no key and broadcasts nothing.
 */
SwarmNotNoRotateResult SwarmNoteNotNoRotate(const SwarmNotNoRotate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOROTATE_H
