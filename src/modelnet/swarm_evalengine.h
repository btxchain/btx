// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EVALENGINE_H
#define BTX_MODELNET_SWARM_EVALENGINE_H

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace modelnet {

/**
 * Independent scores for one subject. An author cannot score their own
 * subject. A fixed holdout is refused. A subject is accepted only when at
 * least two stored reports come from two different authors and the highest
 * score minus the lowest score is within 10000 ppm. Scores are not averaged.
 *
 * Reports stay in this process. Submit does not broadcast, spend, spawn a
 * child process, or use the network.
 */
class SwarmEvalEngine {
public:
    bool Submit(const std::string& report_id, const std::string& author, const std::string& subject, int64_t score_ppm, bool holdout_rotating, bool independent, std::string& err);
    bool Accepted(const std::string& subject) const;
    bool Attach(const std::string& subject, bool safety_regression, bool broad_regression, std::string& err);
    bool attached(const std::string& subject) const;

private:
    struct Report {
        std::string author;
        std::string subject;
        int64_t score_ppm{0};
    };

    std::map<std::string, Report> m_reports;
    std::set<std::string> m_attached;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EVALENGINE_H
