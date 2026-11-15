// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_GRADEXPORT_H
#define BTX_MODELNET_SWARM_GRADEXPORT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a gradient update might be exported.
 * gradient marks the update as a gradient. want_export asks this note
 * to export one.
 *
 * A gradient update is not exported. It moves no bytes. exported stays
 * false and bytes_moved stays 0 on every path.
 */
struct SwarmGradExport {
    std::string update_id;
    bool gradient{false};
    bool want_export{false};
};

/**
 * Outcome of noting that a gradient update is not exported.
 * exported stays false and bytes_moved stays 0 on every path.
 */
struct SwarmGradExportResult {
    std::string code;
    bool exported{false};
    int64_t bytes_moved{0};
};

/**
 * Note that a gradient update is not exported.
 * Order, first match wins: an empty update_id is UPDATE. gradient true
 * is NOT_EXPORTED even when want_export is false. want_export is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * exported stays false and bytes_moved stays 0 on every path. A gradient
 * update is not exported.
 */
SwarmGradExportResult SwarmNoteGradExport(const SwarmGradExport& update, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_GRADEXPORT_H
