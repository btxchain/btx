// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_export/dt_export.h>

#include <modelnet/swarm_piecepipe/digest.h>

namespace modelnet {

bool DtExport::Submit(const std::string& candidate, const std::vector<unsigned char>& body, std::string& err)
{
    if (candidate.empty() || body.empty()) {
        err = "WEIGHTS";
        return false;
    }
    if (!m_pipe.Split(body, err)) return false;
    const std::string id = SwarmPiecePipeDigest(body);
    if (!m_pipe.Resume(id, err)) return false;
    if (!m_pipe.usable(id)) {
        err = "MANIFEST";
        return false;
    }
    m_digest[candidate] = id;
    err.clear();
    return true;
}

bool DtExport::Report(const std::string& candidate,
                      const std::string& author,
                      const std::string& evaluator,
                      const std::string& author_domain,
                      const std::string& evaluator_domain,
                      bool holdout,
                      bool safety,
                      bool broad,
                      std::string& err)
{
    if (!m_digest.count(candidate)) {
        err = "WEIGHTS";
        return false;
    }
    if (!m_opened) {
        if (!m_eval.OpenExperiment("exp", err)) return false;
        m_opened = true;
    }
    if (!m_bound.count(candidate)) {
        if (!m_eval.BindCandidate("exp", candidate, err)) return false;
        m_bound.insert(candidate);
    }
    if (!m_suite) {
        if (!m_eval.CommitSuite("exp", "suite", err)) return false;
        m_suite = true;
    }
    return m_eval.Report("exp", candidate, author, evaluator, author_domain, evaluator_domain, holdout, safety, broad, err);
}

bool DtExport::StageAdopt(const std::string& channel, const std::string& candidate, std::string& err)
{
    if (!m_eval.qualified(candidate)) {
        err = "NOT_GRADUATED";
        return false;
    }
    if (!m_eval.Promote(candidate, err)) return false;
    if (!m_eval.Stage(channel, candidate, "follow", err)) return false;
    return m_eval.Adopt(channel, err);
}

bool DtExport::SecondCycle(const std::string& candidate, const std::vector<unsigned char>& body, std::string& err)
{
    const auto it = m_digest.find(candidate);
    if (it == m_digest.end()) {
        err = "WEIGHTS";
        return false;
    }
    if (SwarmPiecePipeDigest(body) == it->second) {
        err = "UNCHANGED";
        return false;
    }
    if (!Submit(candidate + "-next", body, err)) return false;
    m_new_generation = true;
    err.clear();
    return true;
}

bool DtExport::Settle(std::string& err)
{
    return m_settle.Settle(err);
}

} // namespace modelnet
