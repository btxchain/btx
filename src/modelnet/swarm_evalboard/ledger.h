// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_LEDGER_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_LEDGER_H

#include <modelnet/swarm_evalboard/report.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Stored rows keyed by subject, in submission order.
 * A second row from the same author on the same subject is REPLAY and
 * the first row stays. Rows are not replaced by a mean.
 * Store expects a report that already passed SwarmEvalAdmitReport.
 */
class SwarmEvalLedger {
public:
    bool Store(const SwarmEvalReport& report, std::string& err);
    std::vector<SwarmEvalReport> scores(const std::string& subject) const;

private:
    std::map<std::string, std::vector<SwarmEvalReport>> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_LEDGER_H
