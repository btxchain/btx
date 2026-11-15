// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWRONGTYPE2_H
#define BTX_MODELNET_SWARM_NOTNOWRONGTYPE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one stored field. wrong_type marks that the field
 * type does not match. want_scan asks this note to scan that field.
 *
 * A wrong-type field aborts a scan, so scanned stays false on every path.
 */
struct SwarmNotNoWrongType2 {
    std::string field_id;
    bool wrong_type{false};
    bool want_scan{false};
};

/**
 * Outcome of noting a field. scanned stays false on every path. A
 * wrong-type field aborts a scan.
 */
struct SwarmNotNoWrongType2Result {
    std::string code;
    bool scanned{false};
};

/**
 * Note a field without scanning it. Order, first match wins: an empty
 * field_id is FIELD. wrong_type is ABORT even when want_scan is false.
 * want_scan is HELD. Otherwise the note is NOTED and err is cleared.
 * scanned stays false on every path. A wrong-type field aborts a scan.
 */
SwarmNotNoWrongType2Result SwarmNoteNotNoWrongType2(const SwarmNotNoWrongType2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWRONGTYPE2_H
