// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/measure.h>

#include <utility>

namespace modelnet {

void SwarmEvolveMeasure::SetSubject(std::string subject)
{
    m_subject = std::move(subject);
}

void SwarmEvolveMeasure::SetTrained(bool trained)
{
    m_trained = trained;
}

void SwarmEvolveMeasure::Reset()
{
    m_engine = SwarmEvalEngine{};
    m_evaluators.clear();
    m_scores.clear();
    m_trained = false;
}

bool SwarmEvolveMeasure::Submit(const SwarmEvolveScoreReport& report, std::string& err)
{
    if (!m_trained) {
        err = "TRAIN";
        return false;
    }
    if (m_subject.empty()) {
        err = "MEASURE";
        return false;
    }
    if (!report.subject.empty() && report.subject != m_subject) {
        err = "MEASURE";
        return false;
    }
    if (report.domain.empty()) {
        err = "MEASURE";
        return false;
    }

    const std::string report_id = report.author + "|" + report.domain + "|" + m_subject;
    if (!m_engine.Submit(report_id, report.author, m_subject, report.score, report.rotating, report.independent, err)) {
        return false;
    }

    SwarmEvaluator evaluator;
    evaluator.evaluator = report.author;
    evaluator.domain = report.domain;
    evaluator.author = m_subject;
    evaluator.revoked = false;
    m_evaluators.push_back(std::move(evaluator));
    m_scores.push_back(report.score);
    err.clear();
    return true;
}

bool SwarmEvolveMeasure::Accepted() const
{
    if (!m_trained || m_subject.empty()) return false;
    if (!m_engine.Accepted(m_subject)) return false;
    std::string err;
    return SwarmQuorum(m_evaluators, 2, 2, m_subject, err);
}

} // namespace modelnet
