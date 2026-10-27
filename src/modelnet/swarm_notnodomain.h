// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODOMAIN_H
#define BTX_MODELNET_SWARM_NOTNODOMAIN_H

#include <string>

namespace modelnet {

/**
 * A local note about one report. same_domain records whether the note
 * shares one trust domain. want_settle asks this note to settle.
 *
 * The same trust domain does not settle a report. settled and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoDomain {
    std::string report_id;
    bool same_domain{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a report. settled and bytes_moved stay false on every
 * path. The same trust domain does not settle a report.
 */
struct SwarmNotNoDomainResult {
    std::string code;
    bool settled{false};
    bool bytes_moved{false};
};

/**
 * Note a report without settling it. Order, first match wins: an empty
 * report_id is REPORT. same_domain true is SAME_DOMAIN, even when
 * want_settle is false. want_settle is HELD. Otherwise the note is NOTED
 * and err is cleared. settled and bytes_moved stay false on every path.
 * The same trust domain does not settle a report.
 */
SwarmNotNoDomainResult SwarmNoteNotNoDomain(const SwarmNotNoDomain& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODOMAIN_H
