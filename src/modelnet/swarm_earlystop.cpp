// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlystop.h>

namespace modelnet {

bool SwarmEarlyStop::Open(const std::string& experiment, int64_t budget, std::string& err)
{
    if (experiment.empty()) {
        err = "EXPERIMENT";
        return false;
    }
    if (budget < 1) {
        err = "BUDGET";
        return false;
    }
    if (m_runs.find(experiment) != m_runs.end()) {
        err = "REPLAY";
        return false;
    }
    Run run;
    run.remaining = budget;
    m_runs.emplace(experiment, run);
    err.clear();
    return true;
}

bool SwarmEarlyStop::Step(const std::string& experiment, int64_t score_ppm, std::string& err)
{
    const auto it = m_runs.find(experiment);
    if (it == m_runs.end()) {
        err = "EXPERIMENT";
        return false;
    }
    Run& run = it->second;
    if (run.remaining == 0) {
        err = "STOPPED";
        return false;
    }
    if (score_ppm < 0) {
        err = "RANGE";
        return false;
    }
    const bool worse = run.has_score && score_ppm < run.score_ppm;
    run.remaining -= 1;
    run.score_ppm = score_ppm;
    run.has_score = true;
    if (worse) {
        run.early_stop = true;
        run.remaining = 0;
    }
    err.clear();
    return true;
}

bool SwarmEarlyStop::Promote(const std::string& experiment, std::string& err)
{
    const auto it = m_runs.find(experiment);
    if (it == m_runs.end()) {
        err = "EXPERIMENT";
        return false;
    }
    const Run& run = it->second;
    if (run.early_stop) {
        err = "STOPPED";
        return false;
    }
    if (!run.has_score) {
        err = "STEP";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmEarlyStop::stopped(const std::string& experiment) const
{
    const auto it = m_runs.find(experiment);
    if (it == m_runs.end()) return false;
    return it->second.early_stop;
}

int64_t SwarmEarlyStop::remaining(const std::string& experiment) const
{
    const auto it = m_runs.find(experiment);
    if (it == m_runs.end()) return -1;
    return it->second.remaining;
}

int64_t SwarmEarlyStop::score(const std::string& experiment) const
{
    const auto it = m_runs.find(experiment);
    if (it == m_runs.end() || !it->second.has_score) return -1;
    return it->second.score_ppm;
}

} // namespace modelnet
