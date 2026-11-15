// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREPORT_H
#define BTX_MODELNET_SWARM_NOTREPORT_H

#include <string>

namespace modelnet {

/**
 * A local note about one evaluation. want_attach asks this note to attach
 * an evaluation report and graduate a model.
 *
 * This note does not attach an evaluation report or graduate a model.
 * attached and graduated stay false on every path.
 */
struct SwarmNotReport {
    std::string eval_id;
    bool want_attach{false};
};

/**
 * Outcome of noting a report request. attached and graduated stay
 * false on every path: this note does not attach an evaluation report
 * or graduate a model.
 */
struct SwarmNotReportResult {
    std::string code;
    bool attached{false};
    bool graduated{false};
};

/**
 * Note a report request without attaching an evaluation report or
 * graduating a model.
 * Order, first match wins: an empty eval_id is EVAL. want_attach is
 * NOT_ATTACHED. Otherwise the note is NOTED and err is clear.
 * attached and graduated stay false on every path. This note does not
 * attach an evaluation report or graduate a model.
 */
SwarmNotReportResult SwarmNoteNotReport(const SwarmNotReport& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREPORT_H
