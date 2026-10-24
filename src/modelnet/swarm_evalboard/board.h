// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_BOARD_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_BOARD_H

#include <modelnet/swarm_evalboard/attach.h>
#include <modelnet/swarm_evalboard/ledger.h>
#include <modelnet/swarm_evalboard/realm.h>
#include <modelnet/swarm_evalboard/report.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Independent evaluation board.
 *
 * Submit stores a row or refuses it. Empty subject, author, or domain
 * is REPORT. author equal to subject is NOT_SCORED. independent false
 * is HELD. rotating false is NOT_ROTATING. A score outside 0..1000000
 * is RANGE. A second row from the same author on the same subject is
 * REPLAY and keeps the first score. Refusals store nothing.
 * accepted(subject) is true only when at least two stored rows have
 * distinct authors and distinct domains and the score spread is at most
 * 10000. One row, or two rows from the same domain, leaves accepted
 * false. Scores are stored, not averaged.
 * Attach returns true only when accepted is true and the subject is not
 * regressed. Otherwise it is ATTACH and nothing new is attached.
 * Regress sets a flag and returns REGRESSION. A later Attach returns
 * REGRESSION even when accepted is still true. The scores stay stored.
 * Graduate always returns REALM. graduated() stays false. The active id
 * stays "base".
 * bytes_moved() is 0. gpu() is false. This board does not graduate,
 * mine, or broadcast.
 */
class SwarmEvalProbeBoard {
public:
    bool Submit(const std::string& subject, const std::string& author, const std::string& domain, int64_t score,
                bool independent, bool rotating, std::string& err);

    bool accepted(const std::string& subject) const;
    std::vector<SwarmEvalReport> scores(const std::string& subject) const;

    bool Attach(const std::string& subject, std::string& err);
    bool Regress(const std::string& subject, std::string& err);
    bool attached(const std::string& subject) const;
    bool regressed(const std::string& subject) const;

    bool Graduate(const std::string& subject, std::string& err);

    bool graduated() const { return m_realm.graduated(); }
    const char* active_id() const { return m_realm.active_id(); }
    uint64_t bytes_moved() const { return m_realm.bytes_moved(); }
    bool gpu() const { return m_realm.gpu(); }
    bool mines() const { return m_realm.mines(); }
    bool broadcasts() const { return m_realm.broadcasts(); }

private:
    SwarmEvalLedger m_ledger;
    SwarmEvalAttachGate m_attach;
    SwarmEvalRealm m_realm;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_BOARD_H
