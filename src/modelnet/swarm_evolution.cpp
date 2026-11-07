// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolution.h>

#include <algorithm>
#include <cmath>
#include <fstream>
#include <set>

namespace modelnet {
namespace {

constexpr int64_t kScale = 1000000;

bool CopyFile(const fs::path& from, const fs::path& to)
{
    std::ifstream in(from, std::ios::binary);
    if (!in) return false;
    std::ofstream out(to, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << in.rdbuf();
    return static_cast<bool>(out);
}

} // namespace

SwarmBound SwarmPairedBound(const SwarmCounts& counts, int64_t alpha_ppm, int64_t max_trials)
{
    SwarmBound bound;
    bound.method = "PAIRED_HOEFFDING_BONFERRONI_V1";
    if (counts.n00 < 0 || counts.n01 < 0 || counts.n10 < 0 || counts.n11 < 0) {
        bound.code = "PAIR_COUNTS";
        return bound;
    }
    const int64_t n = counts.n00 + counts.n01 + counts.n10 + counts.n11;
    if (n <= 0) {
        bound.code = "EMPTY_EVALUATION";
        return bound;
    }
    if (alpha_ppm < 1 || alpha_ppm > 500000 || max_trials < 1 || max_trials > 1000000) {
        bound.code = "PAIR_COUNTS";
        return bound;
    }
    const long double ln_arg = (static_cast<long double>(max_trials) * static_cast<long double>(kScale)) / static_cast<long double>(alpha_ppm);
    const long double eps = std::sqrt((2.0L * std::log(ln_arg)) / static_cast<long double>(n)) * static_cast<long double>(kScale);
    const int64_t radius = static_cast<int64_t>(std::ceil(eps - 1e-9L));
    bound.n = n;
    bound.delta_ppm = ((counts.n01 - counts.n10) * kScale) / n;
    bound.lower_ppm = std::max<int64_t>(-kScale, bound.delta_ppm - radius);
    bound.upper_ppm = std::min<int64_t>(kScale, bound.delta_ppm + radius);
    bound.alpha_ppm = alpha_ppm;
    bound.max_trials = max_trials;
    bound.ok = true;
    bound.code = "BOUND";
    return bound;
}

bool SwarmQualify(const SwarmReport& report, const SwarmPolicy& policy, SwarmBound& bound, std::string& err)
{
    if (report.suite_id != policy.suite_id) {
        err = "EVALUATION_SUITE";
        return false;
    }
    if (report.holdout_commitment != policy.holdout_commitment) {
        err = "HOLDOUT";
        return false;
    }
    bound = SwarmPairedBound(report.counts, policy.alpha_ppm, policy.max_trials);
    if (!bound.ok) {
        err = bound.code;
        return false;
    }
    if (bound.n < policy.min_examples) {
        err = "EVALUATION_SMALL";
        return false;
    }
    if (bound.delta_ppm < policy.min_gain_ppm || bound.lower_ppm <= 0) {
        err = "NO_SIGNIFICANT_GAIN";
        return false;
    }
    if (report.regressions_ppm.size() != policy.max_regression_ppm.size()) {
        err = "REGRESSION_COVERAGE";
        return false;
    }
    for (const auto& [metric, cap] : policy.max_regression_ppm) {
        const auto it = report.regressions_ppm.find(metric);
        if (it == report.regressions_ppm.end()) {
            err = "REGRESSION_COVERAGE";
            return false;
        }
        if (it->second > cap) {
            err = "REGRESSION";
            return false;
        }
    }
    if (!report.reproducible) {
        err = "REPRODUCIBILITY";
        return false;
    }
    if (report.safety_regression) {
        err = "SAFETY_REGRESSION";
        return false;
    }
    err.clear();
    return true;
}

std::vector<SwarmCandidate> SwarmPareto(const std::vector<SwarmCandidate>& candidates)
{
    std::vector<SwarmCandidate> out;
    for (const SwarmCandidate& left : candidates) {
        bool dominated = false;
        for (const SwarmCandidate& right : candidates) {
            if (left.niche != right.niche || left.id == right.id) continue;
            const bool ge = right.quality >= left.quality && right.novelty >= left.novelty && right.cost <= left.cost;
            const bool gt = right.quality > left.quality || right.novelty > left.novelty || right.cost < left.cost;
            if (ge && gt) {
                dominated = true;
                break;
            }
        }
        if (!dominated) out.push_back(left);
    }
    std::sort(out.begin(), out.end(), [](const SwarmCandidate& a, const SwarmCandidate& b) {
        if (a.niche != b.niche) return a.niche < b.niche;
        if (a.quality != b.quality) return a.quality > b.quality;
        return a.id < b.id;
    });
    return out;
}

std::map<std::string, int> SwarmAllocate(const std::vector<SwarmCandidate>& candidates, int slots, int exploration_percent)
{
    std::map<std::string, int> result;
    for (const SwarmCandidate& candidate : candidates) result[candidate.id] = 0;
    if (candidates.empty() || slots <= 0 || exploration_percent < 0 || exploration_percent > 100) return result;
    const std::vector<SwarmCandidate> frontier = SwarmPareto(candidates);
    if (frontier.empty()) return result;
    int explore = 0;
    if (exploration_percent) explore = std::min(slots, std::max(1, slots * exploration_percent / 100));
    std::vector<SwarmCandidate> novelty = candidates;
    std::sort(novelty.begin(), novelty.end(), [](const SwarmCandidate& a, const SwarmCandidate& b) {
        if (a.novelty != b.novelty) return a.novelty > b.novelty;
        return a.id < b.id;
    });
    for (int i = 0; i < explore; ++i) result[novelty[static_cast<size_t>(i % novelty.size())].id] += 1;
    for (int i = 0; i < slots - explore; ++i) result[frontier[static_cast<size_t>(i % frontier.size())].id] += 1;
    return result;
}

bool SwarmQuorum(const std::vector<SwarmEvaluator>& reports, int min_evaluators, int min_domains,
                 const std::string& author, std::string& err)
{
    std::set<std::string> evaluators;
    std::set<std::string> domains;
    for (const SwarmEvaluator& report : reports) {
        if (report.revoked) continue;
        if (report.evaluator.empty() || report.evaluator == author || report.author == report.evaluator) {
            err = "SELF_EVALUATION";
            return false;
        }
        if (report.author != author && !report.author.empty()) {
            err = "AUTHOR";
            return false;
        }
        evaluators.insert(report.evaluator);
        domains.insert(report.domain);
    }
    if (static_cast<int>(evaluators.size()) < min_evaluators || static_cast<int>(domains.size()) < min_domains) {
        err = "QUORUM";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmChallengerAffectsFitness(bool independent_verifier_accepted)
{
    return independent_verifier_accepted;
}

bool SwarmStage(SwarmChannel& channel, const std::string& candidate, int sequence, bool certificate_ok, std::string& err)
{
    if (!certificate_ok || candidate.empty() || sequence <= channel.sequence) {
        err = "STAGE";
        return false;
    }
    channel.staged = candidate;
    channel.state = "STAGED";
    channel.sequence = sequence;
    err.clear();
    return true;
}

bool SwarmCanary(SwarmChannel& channel, int sequence, std::string& err)
{
    if (channel.state != "STAGED" || channel.staged.empty() || sequence <= channel.sequence) {
        err = "CANARY";
        return false;
    }
    channel.state = "CANARY";
    channel.sequence = sequence;
    err.clear();
    return true;
}

bool SwarmActivate(SwarmChannel& channel, int sequence, std::string& err)
{
    if (channel.state != "CANARY" || channel.staged.empty() || sequence <= channel.sequence) {
        err = "ACTIVATE";
        return false;
    }
    channel.previous = channel.active;
    channel.active = channel.staged;
    channel.staged.clear();
    channel.state = "ACTIVE";
    channel.sequence = sequence;
    err.clear();
    return true;
}

bool SwarmRollback(SwarmChannel& channel, int sequence, std::string& err)
{
    if (channel.previous.empty() || sequence <= channel.sequence) {
        err = "ROLLBACK";
        return false;
    }
    channel.active.swap(channel.previous);
    channel.state = "ACTIVE";
    channel.sequence = sequence;
    err.clear();
    return true;
}

bool SwarmRetain(const fs::path& src, const fs::path& dst, std::string& err)
{
    fs::create_directories(dst);
    if (!fs::exists(dst)) {
        err = "RETAIN_DIR";
        return false;
    }
    const char* names[] = {"observers.json", "checkpoint.bin", "channel-state.json", "obligations.json"};
    bool any = false;
    for (const char* name : names) {
        const fs::path from = src / name;
        if (!fs::exists(from)) continue;
        if (!CopyFile(from, dst / name)) {
            err = "RETAIN_COPY";
            return false;
        }
        any = true;
    }
    if (!any || !fs::exists(dst / "checkpoint.bin")) {
        err = "RETAIN_CHECKPOINT";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
