// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/manifest.h>

#include <modelnet/swarm_piecepipe/codes.h>

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

void SwarmPiecePipeManifestBook::NoteRequired(const std::vector<std::string>& slice_ids)
{
    // Identical slices in one body share one id. Count that id once.
    std::set<std::string> seen;
    for (const std::string& id : slice_ids) {
        if (!seen.insert(id).second) {
            continue;
        }
        m_required[id] += 1;
    }
}

bool SwarmPiecePipeManifestBook::Put(const std::string& artifact, const std::vector<std::string>& slice_ids, std::string& err)
{
    const auto found = m_rows.find(artifact);
    if (found != m_rows.end()) {
        if (found->second.slices == slice_ids) {
            err.clear();
            return true;
        }
        err = kSwarmPiecePipeConflict;
        return false;
    }
    Row row;
    row.slices = slice_ids;
    row.usable = false;
    m_rows.emplace(artifact, std::move(row));
    NoteRequired(slice_ids);
    err.clear();
    return true;
}

bool SwarmPiecePipeManifestBook::contains(const std::string& artifact) const
{
    return m_rows.find(artifact) != m_rows.end();
}

bool SwarmPiecePipeManifestBook::same_slices(const std::string& artifact, const std::vector<std::string>& slice_ids) const
{
    const auto found = m_rows.find(artifact);
    return found != m_rows.end() && found->second.slices == slice_ids;
}

bool SwarmPiecePipeManifestBook::requires_slice(const std::string& id) const
{
    const auto found = m_required.find(id);
    return found != m_required.end() && found->second > 0;
}

bool SwarmPiecePipeManifestBook::marked_usable(const std::string& artifact) const
{
    const auto found = m_rows.find(artifact);
    return found != m_rows.end() && found->second.usable;
}

void SwarmPiecePipeManifestBook::mark_usable(const std::string& artifact)
{
    const auto found = m_rows.find(artifact);
    if (found == m_rows.end()) {
        return;
    }
    found->second.usable = true;
}

void SwarmPiecePipeManifestBook::clear_usable(const std::string& artifact)
{
    const auto found = m_rows.find(artifact);
    if (found == m_rows.end()) {
        return;
    }
    found->second.usable = false;
}

std::vector<std::string> SwarmPiecePipeManifestBook::slice_ids(const std::string& artifact) const
{
    const auto found = m_rows.find(artifact);
    if (found == m_rows.end()) {
        return {};
    }
    return found->second.slices;
}

std::size_t SwarmPiecePipeManifestBook::count() const
{
    return m_rows.size();
}

} // namespace modelnet
