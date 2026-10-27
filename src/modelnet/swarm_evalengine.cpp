// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine.h>

#include <set>
#include <string>

namespace modelnet {

namespace {

constexpr int64_t kSpreadPpm = 10000;
constexpr int64_t kScoreMaxPpm = 1000000;

} // namespace

bool SwarmEvalEngine::Submit(const std::string& report_id, const std::string& author, const std::string& subject, int64_t score_ppm, bool holdout_rotating, bool independent, std::string& err)
{
    if (report_id.empty() || author.empty() || subject.empty()) {
        err = "REPORT";
        return false;
    }
    if (m_reports.find(report_id) != m_reports.end()) {
        err = "REPLAY";
        return false;
    }
    if (author == subject) {
        err = "NOT_SCORED";
        return false;
    }
    if (!independent) {
        err = "HELD";
        return false;
    }
    if (!holdout_rotating) {
        err = "NOT_ROTATING";
        return false;
    }
    if (score_ppm < 0 || score_ppm > kScoreMaxPpm) {
        err = "RANGE";
        return false;
    }
    m_reports[report_id] = Report{author, subject, score_ppm};
    err.clear();
    return true;
}

bool SwarmEvalEngine::Accepted(const std::string& subject) const
{
    bool any = false;
    int64_t lowest = 0;
    int64_t highest = 0;
    std::set<std::string> authors;
    size_t count = 0;
    for (const auto& item : m_reports) {
        const Report& report = item.second;
        if (report.subject != subject) continue;
        if (!any || report.score_ppm < lowest) lowest = report.score_ppm;
        if (!any || report.score_ppm > highest) highest = report.score_ppm;
        any = true;
        authors.insert(report.author);
        ++count;
    }
    if (count < 2 || authors.size() < 2) return false;
    // Agreement is the spread between the stored scores. The mean is not a pass.
    return highest - lowest <= kSpreadPpm;
}

bool SwarmEvalEngine::Attach(const std::string& subject, bool safety_regression, bool broad_regression, std::string& err)
{
    if (safety_regression || broad_regression) {
        err = "REGRESSION";
        return false;
    }
    if (!Accepted(subject)) {
        err = "QUORUM";
        return false;
    }
    m_attached.insert(subject);
    err.clear();
    return true;
}

bool SwarmEvalEngine::attached(const std::string& subject) const
{
    return m_attached.count(subject) != 0;
}

} // namespace modelnet
