// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PEERPATH_H
#define BTX_MODELNET_SWARM_PEERPATH_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer-relative path. peer_id names the peer.
 * relative_path is a single path token. want_open asks this note to
 * open the path.
 *
 * This note does not open a path and does not read from disk. opened
 * stays false on every path. No hostnames or IPs are used.
 */
struct SwarmPeerPath {
    std::string peer_id;
    std::string relative_path;
    bool want_open{false};
};

/**
 * Outcome of noting a peer path. opened stays false: this note does
 * not open a path.
 */
struct SwarmPeerPathResult {
    bool opened{false};
    std::string code;
};

/**
 * Note a peer path without opening it.
 * Order, first match wins:
 * an empty peer_id or an empty relative_path is PATH.
 * a relative_path that contains a slash, a backslash, or the
 * two-character sequence ".." is PEER_PATH, including when want_open
 * is true.
 * want_open is HELD and err is cleared. This note does not open a path.
 * Otherwise the note is NOTED and err is cleared. A single token such
 * as piece.bin with want_open false is NOTED.
 * opened stays false. Nothing is read from disk.
 */
SwarmPeerPathResult SwarmNotePeerPath(const SwarmPeerPath& path, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PEERPATH_H
