// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evidence/swarm_evidence.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmEvidence::Store(const std::string& id, const std::vector<unsigned char>& bytes, bool is_private, std::string& err)
{
    if (id.empty() || bytes.empty()) {
        err = kSwarmEvidenceEvidence;
        return false;
    }
    if (m_evidence.find(id) != m_evidence.end() || m_summaries.find(id) != m_summaries.end()) {
        err = kSwarmEvidenceReplay;
        return false;
    }

    EvidenceRecord record;
    record.bytes = bytes;
    record.is_private = is_private;
    m_evidence.emplace(id, std::move(record));
    err.clear();
    return true;
}

bool SwarmEvidence::shareable(const std::string& id) const
{
    const auto it = m_evidence.find(id);
    return it != m_evidence.end() && !it->second.is_private;
}

bool SwarmEvidence::Share(const std::string& id, std::string& err)
{
    // Unknown and private fail this same check, so the code is one value.
    if (!shareable(id)) {
        err = kSwarmEvidenceNotVisible;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmEvidence::Summarize(const std::string& id, const std::string& summary, const std::string& source_id, std::string& err)
{
    if (id.empty() || summary.empty() || source_id.empty()) {
        err = kSwarmEvidenceSummary;
        return false;
    }
    if (m_evidence.find(source_id) == m_evidence.end()) {
        err = kSwarmEvidenceSource;
        return false;
    }
    if (m_summaries.find(id) != m_summaries.end() || m_evidence.find(id) != m_evidence.end()) {
        err = kSwarmEvidenceReplay;
        return false;
    }

    SummaryRecord record;
    record.summary = summary;
    record.source_id = source_id;
    m_summaries.emplace(id, std::move(record));
    err.clear();
    return true;
}

bool SwarmEvidence::Inject(const std::string& id, const std::string& text, std::string& err)
{
    // The text is kept as data. It is not parsed and it is not executed.
    TaintedNote note;
    note.id = id;
    note.text = text;
    note.tainted = true;
    m_tainted.push_back(std::move(note));
    err = kSwarmEvidenceNotAuthority;
    return false;
}

bool SwarmEvidence::Promise(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = kSwarmEvidenceId;
        return false;
    }
    m_promises.insert(id);
    err.clear();
    return true;
}

bool SwarmEvidence::Retrieve(const std::string& id, std::string& err)
{
    // A promise is not data. The call returns no bytes.
    (void)id;
    err = kSwarmEvidenceNotRetrievable;
    return false;
}

bool SwarmEvidence::stored(const std::string& id) const
{
    return m_evidence.find(id) != m_evidence.end();
}

const std::vector<unsigned char>& SwarmEvidence::body(const std::string& id) const
{
    const auto it = m_evidence.find(id);
    if (it == m_evidence.end()) {
        static const std::vector<unsigned char> kEmpty;
        return kEmpty;
    }
    return it->second.bytes;
}

std::string SwarmEvidence::summary(const std::string& id) const
{
    const auto it = m_summaries.find(id);
    if (it == m_summaries.end()) {
        return {};
    }
    return it->second.summary;
}

std::string SwarmEvidence::summary_source(const std::string& id) const
{
    const auto it = m_summaries.find(id);
    if (it == m_summaries.end()) {
        return {};
    }
    return it->second.source_id;
}

bool SwarmEvidence::promised(const std::string& id) const
{
    return m_promises.find(id) != m_promises.end();
}

bool SwarmEvidence::tainted(const std::string& id) const
{
    for (const TaintedNote& note : m_tainted) {
        if (note.id == id && note.tainted) {
            return true;
        }
    }
    return false;
}

std::size_t SwarmEvidence::tainted_bytes() const
{
    std::size_t total = 0;
    for (const TaintedNote& note : m_tainted) {
        if (note.tainted) {
            total += note.text.size();
        }
    }
    return total;
}

bool SwarmEvidence::launched() const
{
    return kSwarmEvidenceLaunched;
}

bool SwarmEvidence::gpu() const
{
    return kSwarmEvidenceGpu;
}

bool SwarmEvidence::broadcast() const
{
    return kSwarmEvidenceBroadcast;
}

std::string SwarmEvidence::automatic_spend() const
{
    return std::string{kSwarmEvidenceAutomaticSpend};
}

int64_t SwarmEvidence::bytes_moved() const
{
    return kSwarmEvidenceBytesMoved;
}

} // namespace modelnet
