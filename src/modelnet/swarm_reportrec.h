// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REPORTREC_H
#define BTX_MODELNET_SWARM_REPORTREC_H

#include <string>

namespace modelnet {

/**
 * A regression-report record request. report_id names the report.
 * want_record asks this request to record it.
 *
 * A regression report record request is held and records nothing.
 * It does not attach a report to graduation. recorded stays false.
 */
struct SwarmReportRec {
    std::string report_id;
    bool want_record{false};
};

/**
 * Outcome of a regression-report record request. recorded stays false
 * on every path. A regression report record request is held and records
 * nothing.
 */
struct SwarmReportRecResult {
    std::string code;
    bool recorded{false};
};

/**
 * Hold a regression-report record request. It records nothing and does
 * not attach a report to graduation.
 * Order, first match wins: an empty report_id is REPORT. want_record is
 * HELD. Otherwise the note is NOTED and err is cleared. recorded stays
 * false on every path.
 */
SwarmReportRecResult SwarmNoteReportRec(const SwarmReportRec& report, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REPORTREC_H
