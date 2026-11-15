// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ORIGINNOTE_H
#define BTX_MODELNET_SWARM_ORIGINNOTE_H

#include <string>

namespace modelnet {

/**
 * A local note about an import or publish-back origin. url is the origin
 * string. import_origin records that the caller treats the string as an
 * import origin. want_lineage asks this note to treat that origin as
 * lineage authority.
 *
 * This note does not fetch a URL, does not open a socket, and does not
 * assign lineage. An import or publish-back origin is not lineage
 * authority. No hostnames or IPs are used.
 */
struct SwarmImportOrigin {
    std::string url;
    bool import_origin{false};
    bool want_lineage{false};
};

/**
 * Outcome of noting an import origin. lineage_authority stays false on
 * every path: this note does not assign lineage.
 */
struct SwarmImportOriginResult {
    bool lineage_authority{false};
    std::string code;
};

/**
 * Note an import origin without assigning lineage.
 * Order, first match wins: an empty url is ORIGIN. want_lineage is
 * NOT_AUTHORITY, including when import_origin is true. Otherwise the
 * note is NOTED and err is clear.
 * lineage_authority stays false on every path. This note does not fetch
 * a URL, does not open a socket, and does not assign lineage. An import
 * or publish-back origin is not lineage authority.
 */
SwarmImportOriginResult SwarmNoteImportOrigin(const SwarmImportOrigin& origin, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ORIGINNOTE_H
