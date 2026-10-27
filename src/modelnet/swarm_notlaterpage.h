// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTLATERPAGE_H
#define BTX_MODELNET_SWARM_NOTLATERPAGE_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache page. revoked records that the page is
 * revoked. want_read asks this note to read that page.
 *
 * This note does not read a cache page. read is the bool named read, not
 * a filesystem call. read and bytes_moved stay false on every path.
 */
struct SwarmNotLaterPage {
    std::string page_id;
    bool revoked{false};
    bool want_read{false};
};

/**
 * Outcome of noting a later page. read and bytes_moved stay false on every
 * path: this note does not read a cache page. read is the bool named read,
 * not a filesystem call.
 */
struct SwarmNotLaterPageResult {
    std::string code;
    bool read{false};
    bool bytes_moved{false};
};

/**
 * Note a later page without reading a cache page.
 * Order, first match wins: an empty page_id is PAGE. revoked is REVOKED
 * even when want_read is false. want_read is REVOKED. Otherwise the note
 * is NOTED and err is clear. read and bytes_moved stay false on every
 * path. This note does not read a cache page. read is the bool named
 * read, not a filesystem call.
 */
SwarmNotLaterPageResult SwarmNoteNotLaterPage(const SwarmNotLaterPage& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTLATERPAGE_H
