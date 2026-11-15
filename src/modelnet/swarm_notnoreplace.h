// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREPLACE_H
#define BTX_MODELNET_SWARM_NOTNOREPLACE_H

#include <string>

namespace modelnet {

/**
 * A local note about one coordinator. gone records that the coordinator
 * is permanently lost. want_install asks this note to install a
 * replacement.
 *
 * Permanent coordinator loss does not install a replacement. installed
 * and bytes_moved stay false on every path.
 */
struct SwarmNotNoReplace {
    std::string coord_id;
    bool gone{false};
    bool want_install{false};
};

/**
 * Outcome of noting a replacement request. installed and bytes_moved stay
 * false on every path. Permanent coordinator loss does not install a
 * replacement.
 */
struct SwarmNotNoReplaceResult {
    std::string code;
    bool installed{false};
    bool bytes_moved{false};
};

/**
 * Note a replacement request without installing a replacement.
 * Order, first match wins:
 * 1. An empty coord_id is COORD. installed stays false, bytes_moved stays
 *    false, and err is COORD.
 * 2. If gone is true, the note is NOT_INSTALLED even when want_install is
 *    false. installed stays false, bytes_moved stays false, and err is
 *    NOT_INSTALLED.
 * 3. want_install is HELD. installed stays false, bytes_moved stays false,
 *    and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. installed stays false
 *    and bytes_moved stays false.
 * installed and bytes_moved stay false on every path. Permanent
 * coordinator loss does not install a replacement.
 */
SwarmNotNoReplaceResult SwarmNoteNotNoReplace(const SwarmNotNoReplace& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREPLACE_H
