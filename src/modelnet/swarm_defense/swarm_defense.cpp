// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_defense/swarm_defense.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmDefense::HasCase(const std::string& case_id) const
{
    return m_mandates.find(case_id) != m_mandates.end();
}

bool SwarmDefense::EvidenceInCase(const std::string& case_id, const std::string& evidence_id) const
{
    const auto it = m_evidence.find(evidence_id);
    return it != m_evidence.end() && it->second.case_id == case_id;
}

bool SwarmDefense::Mandate(const std::string& customer, const std::string& case_id, const std::string& asset,
                           const std::string& policy_gen, int64_t until_ms, int64_t now_ms, std::string& err)
{
    if (customer.empty() || case_id.empty() || asset.empty() || policy_gen.empty()) {
        err = kSwarmDefenseMandate;
        return false;
    }
    if (now_ms >= until_ms) {
        err = kSwarmDefenseExpired;
        return false;
    }
    if (HasCase(case_id)) {
        err = kSwarmDefenseReplay;
        return false;
    }

    MandateRecord record;
    record.customer = customer;
    record.asset = asset;
    record.policy_gen = policy_gen;
    record.until_ms = until_ms;
    m_mandates.emplace(case_id, std::move(record));
    err.clear();
    return true;
}

bool SwarmDefense::JoinFamily(const std::string& peer, std::string& err)
{
    if (peer.empty()) {
        err = kSwarmDefensePeer;
        return false;
    }
    m_family.insert(peer);
    err.clear();
    return true;
}

bool SwarmDefense::Admit(const std::string& peer, const std::string& case_id, std::string& err)
{
    if (!HasCase(case_id)) {
        err = kSwarmDefenseCase;
        return false;
    }
    if (m_family.find(peer) == m_family.end()) {
        err = kSwarmDefenseNotAdmitted;
        return false;
    }
    m_admitted[peer].insert(case_id);
    err.clear();
    return true;
}

bool SwarmDefense::Evidence(const std::string& case_id, const std::string& evidence_id,
                            const std::vector<unsigned char>& bytes, std::string& err)
{
    if (!HasCase(case_id)) {
        err = kSwarmDefenseCase;
        return false;
    }
    if (evidence_id.empty() || bytes.empty()) {
        err = kSwarmDefenseEvidence;
        return false;
    }
    if (m_evidence.find(evidence_id) != m_evidence.end()) {
        err = kSwarmDefenseReplay;
        return false;
    }

    EvidenceRecord record;
    record.case_id = case_id;
    record.bytes = bytes;
    m_evidence.emplace(evidence_id, std::move(record));
    err.clear();
    return true;
}

bool SwarmDefense::Export(const std::string& case_id, const std::string& evidence_id, bool granted, std::string& err)
{
    if (!granted) {
        err = kSwarmDefensePrivateData;
        return false;
    }
    if (!HasCase(case_id)) {
        err = kSwarmDefenseCase;
        return false;
    }
    if (!EvidenceInCase(case_id, evidence_id)) {
        err = kSwarmDefenseEvidence;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDefense::Act(const std::string& case_id, const std::string& text, std::string& err)
{
    (void)case_id;
    TaintedNote note;
    note.text = text;
    note.tainted = true;
    m_tainted.push_back(std::move(note));
    err = kSwarmDefenseNotAuthorized;
    return false;
}

bool SwarmDefense::Publish(const std::string& case_id, const std::string& artifact_id, bool embargo_expired,
                           bool sanitized, bool validated, std::string& err)
{
    if (!HasCase(case_id)) {
        err = kSwarmDefenseCase;
        return false;
    }
    if (artifact_id.empty()) {
        err = kSwarmDefenseNotPublished;
        return false;
    }
    if (embargo_expired && (!sanitized || !validated)) {
        err = kSwarmDefenseNotPublished;
        return false;
    }
    if (!sanitized || !validated) {
        err = kSwarmDefenseNotPublished;
        return false;
    }
    const auto existing = m_artifacts.find(artifact_id);
    if (existing != m_artifacts.end()) {
        if (existing->second != case_id) {
            err = kSwarmDefenseReplay;
            return false;
        }
        err.clear();
        return true;
    }
    m_artifacts.emplace(artifact_id, case_id);
    err.clear();
    return true;
}

bool SwarmDefense::AllowTraining(const std::string& case_id, std::string& err)
{
    if (!HasCase(case_id)) {
        err = kSwarmDefenseCase;
        return false;
    }
    m_training.insert(case_id);
    err.clear();
    return true;
}

bool SwarmDefense::Search(const std::string& case_id, const std::string& evidence_id, std::string& err)
{
    if (!EvidenceInCase(case_id, evidence_id)) {
        err = kSwarmDefenseNotVisible;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDefense::family(const std::string& peer) const
{
    return m_family.find(peer) != m_family.end();
}

bool SwarmDefense::admitted(const std::string& peer) const
{
    const auto it = m_admitted.find(peer);
    return it != m_admitted.end() && !it->second.empty();
}

bool SwarmDefense::admitted(const std::string& peer, const std::string& case_id) const
{
    const auto it = m_admitted.find(peer);
    if (it == m_admitted.end()) {
        return false;
    }
    return it->second.find(case_id) != it->second.end();
}

const std::vector<unsigned char>& SwarmDefense::body(const std::string& evidence_id) const
{
    const auto it = m_evidence.find(evidence_id);
    if (it == m_evidence.end()) {
        static const std::vector<unsigned char> kEmpty;
        return kEmpty;
    }
    return it->second.bytes;
}

bool SwarmDefense::published() const
{
    return !m_artifacts.empty();
}

bool SwarmDefense::published(const std::string& artifact_id) const
{
    return m_artifacts.find(artifact_id) != m_artifacts.end();
}

bool SwarmDefense::training_allowed() const
{
    return !m_training.empty();
}

bool SwarmDefense::training_allowed(const std::string& case_id) const
{
    return m_training.find(case_id) != m_training.end();
}

std::size_t SwarmDefense::tainted_bytes() const
{
    std::size_t total = 0;
    for (const TaintedNote& note : m_tainted) {
        if (note.tainted) {
            total += note.text.size();
        }
    }
    return total;
}

bool SwarmDefense::launched() const
{
    return kSwarmDefenseLaunched;
}

bool SwarmDefense::gpu() const
{
    return kSwarmDefenseGpu;
}

bool SwarmDefense::broadcast() const
{
    return kSwarmDefenseBroadcast;
}

bool SwarmDefense::connected() const
{
    return kSwarmDefenseConnected;
}

bool SwarmDefense::windows_passed() const
{
    return kSwarmDefenseWindowsPassed;
}

std::string SwarmDefense::automatic_spend() const
{
    return std::string{kSwarmDefenseAutomaticSpend};
}

int64_t SwarmDefense::bytes_moved() const
{
    return kSwarmDefenseBytesMoved;
}

} // namespace modelnet
