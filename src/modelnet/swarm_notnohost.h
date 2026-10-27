// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOST_H
#define BTX_MODELNET_SWARM_NOTNOHOST_H

#include <string>

namespace modelnet {

/**
 * A local note that might name an operator host or ask to publish.
 * names_host records whether the note names an operator host.
 * want_publish asks this note to publish.
 *
 * A note that names an operator host is refused. published and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoHost {
    std::string note_id;
    bool names_host{false};
    bool want_publish{false};
};

/**
 * Outcome of noting an unpublished host name. published and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoHostResult {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note that no operator host is named or published.
 * Order, first match wins: an empty note_id is NOTE. names_host true is
 * REFUSED, even when want_publish is false. want_publish is REFUSED.
 * Otherwise the note is NOTED and err is cleared. published and
 * bytes_moved stay false on every path. A note that names an operator
 * host is refused.
 */
SwarmNotNoHostResult SwarmNoteNotNoHost(const SwarmNotNoHost& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOST_H
