// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMANIFEST_H
#define BTX_MODELNET_SWARM_NOTNOMANIFEST_H

#include <string>

namespace modelnet {

/**
 * A local note about one flat manifest. want_accept asks this note to
 * accept the manifest.
 *
 * A flat manifest over 16384 entries is not accepted and moves no bytes.
 * accepted and bytes_moved stay false on every path.
 */
struct SwarmNotNoManifest {
    std::string manifest_id;
    bool over_cap{false};
    bool want_accept{false};
};

/**
 * Outcome of noting a flat manifest. accepted and bytes_moved stay false
 * on every path. A flat manifest over 16384 entries is not accepted and
 * moves no bytes.
 */
struct SwarmNotNoManifestResult {
    std::string code;
    bool accepted{false};
    bool bytes_moved{false};
};

/**
 * Note a flat manifest without accepting it. Order, first match wins: an
 * empty manifest_id is MANIFEST. over_cap is CAPPED even when want_accept
 * is false. want_accept is CAPPED. Otherwise the note is NOTED and err is
 * cleared. accepted and bytes_moved stay false on every path. A flat
 * manifest over 16384 entries is not accepted and moves no bytes.
 */
SwarmNotNoManifestResult SwarmNoteNotNoManifest(const SwarmNotNoManifest& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMANIFEST_H
