// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOABORTSCAN_H
#define BTX_MODELNET_SWARM_NOTNOABORTSCAN_H

#include <string>

namespace modelnet {

/**
 * A local note about one stored field. want_scan asks this note to scan
 * that field.
 *
 * A stored field of the wrong type aborts a scan. scanned and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoAbortScan {
    std::string field_id;
    bool wrong_type{false};
    bool want_scan{false};
};

/**
 * Outcome of noting a field. scanned and bytes_moved stay false on every
 * path. A stored field of the wrong type aborts a scan.
 */
struct SwarmNotNoAbortScanResult {
    std::string code;
    bool scanned{false};
    bool bytes_moved{false};
};

/**
 * Note a field without moving bytes. Order, first match wins: an empty
 * field_id is FIELD. wrong_type is ABORT even when want_scan is false.
 * want_scan is HELD. Otherwise the note is NOTED and err is clear.
 * scanned and bytes_moved stay false on every path. A stored field of
 * the wrong type aborts a scan.
 */
SwarmNotNoAbortScanResult SwarmNoteNotNoAbortScan(const SwarmNotNoAbortScan& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOABORTSCAN_H
