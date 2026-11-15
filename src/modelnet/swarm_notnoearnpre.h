// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEARNPRE_H
#define BTX_MODELNET_SWARM_NOTNOEARNPRE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one row. unsettled marks the row as unsettled.
 * want_record asks this note to record earnings.
 *
 * Earnings are not recorded before settlement. recorded stays false and
 * atoms stays 0 on every path.
 */
struct SwarmNotNoEarnPre {
    std::string row_id;
    bool unsettled{false};
    bool want_record{false};
};

/**
 * Outcome of noting a row. recorded stays false and atoms stays 0 on
 * every path. Earnings are not recorded before settlement.
 */
struct SwarmNotNoEarnPreResult {
    std::string code;
    bool recorded{false};
    int64_t atoms{0};
};

/**
 * Note a row without recording earnings. Order, first match wins: an
 * empty row_id is ROW. If unsettled is true, the note is NOT_RECORDED
 * even when want_record is false. want_record is HELD. Otherwise the
 * note is NOTED and err is cleared. recorded stays false and atoms
 * stays 0 on every path. Earnings are not recorded before settlement.
 */
SwarmNotNoEarnPreResult SwarmNoteNotNoEarnPre(const SwarmNotNoEarnPre& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEARNPRE_H
