// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREPORTREC2_H
#define BTX_MODELNET_SWARM_NOTNOREPORTREC2_H

#include <string>

namespace modelnet {

/**
 * A local note about a regression report. report_id names the report.
 * want_record asks this note to record it.
 *
 * A regression report has not been recorded and this note records nothing.
 * recorded stays false on every path.
 */
struct SwarmNotNoReportRec2 {
    std::string report_id;
    bool want_record{false};
};

/**
 * Outcome of noting a regression report. recorded stays false on every path.
 * A regression report has not been recorded and this note records nothing.
 */
struct SwarmNotNoReportRec2Result {
    std::string code;
    bool recorded{false};
};

/**
 * Note a regression report without recording it.
 * Order, first match wins: an empty report_id is REPORT. want_record is
 * HELD. Otherwise the note is NOTED and err is cleared. recorded stays
 * false on every path. A regression report has not been recorded and this
 * note records nothing.
 */
SwarmNotNoReportRec2Result SwarmNoteNotNoReportRec2(const SwarmNotNoReportRec2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREPORTREC2_H
