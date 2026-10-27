// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLUTION_H
#define BITCOIN_MODELNET_SWARM_EVOLUTION_H

#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmCounts {
    int64_t n00{0};
    int64_t n01{0};
    int64_t n10{0};
    int64_t n11{0};
};

struct SwarmBound {
    bool ok{false};
    std::string code;
    int64_t n{0};
    int64_t delta_ppm{0};
    int64_t lower_ppm{0};
    int64_t upper_ppm{0};
    int64_t alpha_ppm{0};
    int64_t max_trials{0};
    std::string method;
};

SwarmBound SwarmPairedBound(const SwarmCounts& counts, int64_t alpha_ppm, int64_t max_trials);

struct SwarmPolicy {
    std::string suite_id;
    std::string holdout_commitment;
    int64_t alpha_ppm{50000};
    int64_t max_trials{1};
    int64_t min_examples{1};
    int64_t min_gain_ppm{0};
    std::map<std::string, int64_t> max_regression_ppm;
};

struct SwarmReport {
    std::string suite_id;
    std::string holdout_commitment;
    SwarmCounts counts;
    std::map<std::string, int64_t> regressions_ppm;
    bool reproducible{false};
    bool safety_regression{false};
};

bool SwarmQualify(const SwarmReport& report, const SwarmPolicy& policy, SwarmBound& bound, std::string& err);

struct SwarmCandidate {
    std::string id;
    std::string niche;
    int64_t quality{0};
    int64_t novelty{0};
    int64_t cost{0};
};

std::vector<SwarmCandidate> SwarmPareto(const std::vector<SwarmCandidate>& candidates);
std::map<std::string, int> SwarmAllocate(const std::vector<SwarmCandidate>& candidates, int slots, int exploration_percent);

struct SwarmEvaluator {
    std::string evaluator;
    std::string domain;
    std::string author;
    bool revoked{false};
};

bool SwarmQuorum(const std::vector<SwarmEvaluator>& reports, int min_evaluators, int min_domains,
                 const std::string& author, std::string& err);

bool SwarmChallengerAffectsFitness(bool independent_verifier_accepted);

struct SwarmChannel {
    std::string name;
    std::string active;
    std::string previous;
    std::string staged;
    std::string state{"IDLE"};
    int sequence{0};
};

bool SwarmStage(SwarmChannel& channel, const std::string& candidate, int sequence, bool certificate_ok, std::string& err);
bool SwarmCanary(SwarmChannel& channel, int sequence, std::string& err);
bool SwarmActivate(SwarmChannel& channel, int sequence, std::string& err);
bool SwarmRollback(SwarmChannel& channel, int sequence, std::string& err);

bool SwarmRetain(const fs::path& src, const fs::path& dst, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLUTION_H
