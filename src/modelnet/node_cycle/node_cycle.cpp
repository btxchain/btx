// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/node_cycle/node_cycle.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp25/grp25.h>
#include <modelnet/grp26/grp26.h>
#include <modelnet/grp27/grp27.h>
#include <modelnet/grp28/grp28.h>
#include <modelnet/grp29/grp29.h>
#include <modelnet/swarm_evalengine/codes.h>
#include <modelnet/swarm_paycycle/codes.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {
namespace {

constexpr char kSession[] = "s";
constexpr char kPrompt[] = "abcdefghi";
constexpr int kPullBound = 8;

bool Refused(bool ok, const std::string& err, const char* code)
{
    return !ok && err == code;
}

} // namespace

bool NodeCycle::Closed() const
{
    return !qualified() && !release_qualified() && !hardware_qualified() &&
           !launched() && !gpu() && !broadcast() && !passed() &&
           hosts() == 1 && physical_hosts() == 1 &&
           bytes_moved() == static_cast<int64_t>(0);
}

bool NodeCycle::Claim(const char* name, std::string& err)
{
    if (!Closed()) {
        err = gpu() ? std::string(NIFDT_ENGINE_ABSENT) : std::string(NIFDT_UNQUALIFIED);
        return false;
    }
    m_steps.emplace_back(name);
    return true;
}

bool NodeCycle::Run(std::string& err)
{
    if (m_started) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_started = true;

    if (hosts() != 1) {
        err = "HOSTS";
        return false;
    }
    if (launched()) {
        err = "LAUNCHED";
        return false;
    }
    if (!Claim("form", err)) return false;

    if (!m_grp25.Open(kSession, "memory", err)) return false;
    if (m_grp25.engine_of(kSession) != "memory") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (!m_grp25.Prompt(kSession, kPrompt, false, err)) return false;
    int pulls = 0;
    while (m_grp25.Pull(kSession, err)) {
        ++pulls;
        if (pulls > kPullBound) {
            err = "BOUND";
            return false;
        }
    }
    if (pulls != kPullBound || err != "DONE") return false;
    if (m_grp25.text().size() != static_cast<std::size_t>(kPullBound)) {
        err = "BOUND";
        return false;
    }
    if (!Claim("workload", err)) return false;

    if (!m_grp26.Echo(kSession, kPrompt, err)) return false;
    if (err != "DONE" || m_grp26.text().size() != static_cast<std::size_t>(kPullBound)) {
        if (err.empty()) err = "BOUND";
        return false;
    }
    if (!Claim("accelerate", err)) return false;

    if (!m_grp26.Step(err)) return false;
    if (m_grp26.pairs() != static_cast<int64_t>(kPullBound)) {
        if (err.empty()) err = "PAIRS";
        return false;
    }
    if (!Claim("experience", err)) return false;

    if (!m_grp27.Compare(static_cast<int64_t>(5), static_cast<int64_t>(5), err)) return false;
    if (!m_grp27.agreed() || m_grp27.gpu() || gpu()) {
        if (err.empty()) err = "DISAGREE";
        return false;
    }
    if (!Claim("compare", err)) return false;

    {
        const bool graded = m_grp27.Grade("exp", "cand", "author", "reader", "domain", "domain",
                                          false, false, false, err);
        if (!Refused(graded, err, kSwarmEvaluationNotQuorum)) return false;
    }
    if (qualified() || m_grp27.qualified() || m_grp27.eval_qualified("cand")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!Claim("descendants", err)) return false;

    {
        const bool graded = m_grp27.Grade("exp", "cand", "same", "same", "side-a", "side-b",
                                          false, false, false, err);
        if (!Refused(graded, err, kSwarmEvaluationSelf)) return false;
    }
    if (qualified() || m_grp27.qualified() || m_grp27.eval_qualified("cand")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!Claim("measure", err)) return false;

    {
        const bool promoted = m_grp28.Promote("cand", err);
        if (!Refused(promoted, err, kSwarmEvaluationNotGraduated)) return false;
    }
    if (m_grp28.promoted("cand") || m_grp28.qualified() || qualified()) {
        err = kSwarmEvaluationNotGraduated;
        return false;
    }
    if (!Claim("graduate", err)) return false;

    {
        const bool staged = m_grp28.Stage("stage", "cand", kSwarmEvaluationPolicyFollow, err);
        if (!Refused(staged, err, kSwarmEvaluationNotGraduated)) return false;
    }
    if (!m_grp28.staged("stage").empty() || !m_grp28.active("stage").empty()) {
        err = kSwarmEvaluationNotGraduated;
        return false;
    }
    if (!Claim("stage", err)) return false;

    if (!m_grp28.OpenChannel("pay", "pool-a", "pool-b", err)) return false;
    {
        const bool paid = m_grp28.PayWork("pool-a", "work", "worker", err);
        if (!Refused(paid, err, SWARM_PAYCYCLE_HELD)) return false;
    }
    if (qualified() || m_grp28.qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (!Claim("pay", err)) return false;

    if (!m_grp29.Store(static_cast<int64_t>(40), err)) return false;
    if (!m_grp29.FailWorker(err)) return false;
    if (m_grp29.stored() != static_cast<int64_t>(40) || stored() != static_cast<int64_t>(40) ||
        !m_grp29.monetary_ok() || !monetary_ok()) {
        if (err.empty()) err = GRP29_BYTES;
        return false;
    }
    if (!Claim("failure", err)) return false;

    {
        const bool advanced = m_grp29.Advance(false, err);
        if (!Refused(advanced, err, GRP29_JOURNAL) ||
            m_grp29.generation() != static_cast<int64_t>(0) ||
            generation() != static_cast<int64_t>(0)) {
            if (advanced && err.empty()) err = GRP29_JOURNAL;
            return false;
        }
    }
    if (!Claim("generation", err)) return false;

    err.clear();
    return true;
}

bool NodeCycle::AcceptJournal(std::string& err)
{
    if (!m_grp29.Advance(true, err)) return false;
    if (generation() != static_cast<int64_t>(1)) return false;
    err.clear();
    return true;
}

bool NodeCycle::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool NodeCycle::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool NodeCycle::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool NodeCycle::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
