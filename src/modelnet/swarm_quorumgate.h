// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_QUORUMGATE_H
#define BTX_MODELNET_SWARM_QUORUMGATE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory quorum of stored reports. Open accepts only when at least two
 * stored reports have distinct authors and distinct domains. One author is
 * not a quorum. The same trust domain twice is not a quorum. Reports are
 * stored as given and are not averaged or blended.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmQuorumGate {
public:
    /**
     * An empty report, author, or domain is REPORT and stores nothing.
     * A report string already stored is REPLAY and leaves the first author
     * and domain in place. Otherwise the report is stored and err is cleared.
     */
    bool Submit(const std::string& report, const std::string& author, const std::string& domain, std::string& err);

    /**
     * True, and err cleared, only when at least two stored reports have
     * distinct authors and distinct domains. Otherwise QUORUM. Stored reports
     * are left in place.
     */
    bool Open(std::string& err);

private:
    struct ReportRow {
        std::string author;
        std::string domain;
    };

    std::map<std::string, ReportRow> m_reports;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_QUORUMGATE_H
