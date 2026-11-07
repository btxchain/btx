// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_EXPORT_DT_EXPORT_H
#define BITCOIN_MODELNET_DT_EXPORT_DT_EXPORT_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_evalengine/engine.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>
#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** Piece-verified candidate, independent evaluation, unchanged bytes are not a new generation. */
class DtExport {
public:
    bool Submit(const std::string& candidate, const std::vector<unsigned char>& body, std::string& err);
    bool Report(const std::string& candidate,
                const std::string& author,
                const std::string& evaluator,
                const std::string& author_domain,
                const std::string& evaluator_domain,
                bool holdout,
                bool safety,
                bool broad,
                std::string& err);
    bool StageAdopt(const std::string& channel, const std::string& candidate, std::string& err);
    bool SecondCycle(const std::string& candidate, const std::vector<unsigned char>& body, std::string& err);
    bool Settle(std::string& err);

    bool qualified(const std::string& candidate) const { return m_eval.qualified(candidate); }
    bool new_generation() const { return m_new_generation; }
    bool settlement_qualified() const { return m_settle.qualified(); }
    bool realm_promoted() const { return m_eval.realm_promoted(); }
    std::string active(const std::string& channel) const { return m_eval.active(channel); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmPiecePipe m_pipe;
    SwarmEvaluationEngine m_eval;
    SwarmSettleBuild m_settle;
    std::map<std::string, std::string> m_digest;
    std::set<std::string> m_bound;
    bool m_opened{false};
    bool m_suite{false};
    bool m_new_generation{false};
};

} // namespace modelnet

#endif
