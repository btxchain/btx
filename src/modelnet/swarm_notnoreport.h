// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREPORT_H
#define BTX_MODELNET_SWARM_NOTNOREPORT_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not accept their own report.
 * want_accept asks this note to accept the report and sign it.
 *
 * An author does not accept their own report. This note accepts nothing
 * and signs nothing. accepted and signed_report stay false on every path.
 */
struct SwarmNotNoReport {
    std::string report_id;
    bool same_author{false};
    bool want_accept{false};
};

/**
 * Outcome of noting that an author does not accept their own report.
 * accepted and signed_report stay false on every path.
 */
struct SwarmNotNoReportResult {
    std::string code;
    bool accepted{false};
    bool signed_report{false};
};

/**
 * Note that an author does not accept their own report. This note accepts
 * nothing and signs nothing. Order, first match wins: an empty report_id
 * is REPORT. same_author is SAME_EVALUATOR, even when want_accept is false.
 * want_accept is NOT_ACCEPTED. Otherwise the note is NOTED and err is clear.
 * accepted and signed_report stay false on every path.
 */
SwarmNotNoReportResult SwarmNoteNotNoReport(const SwarmNotNoReport& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREPORT_H
