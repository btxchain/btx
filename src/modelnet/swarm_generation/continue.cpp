// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/continue.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {
namespace {

std::string QualifiedActive(const SwarmGenerationChannels& channels, const SwarmGenerationCommitment& commitment, const std::string& channel)
{
    const std::string& id = channels.active(channel);
    if (!id.empty() && commitment.qualified(id)) return id;
    return {};
}

std::string ChosenParent(const SwarmGenerationChannels& channels, const SwarmGenerationCommitment& commitment)
{
    const std::string code = QualifiedActive(channels, commitment, kSwarmGenerationCodeStable);
    if (!code.empty()) return code;
    const std::string general = QualifiedActive(channels, commitment, kSwarmGenerationGeneralStable);
    if (!general.empty()) return general;
    for (const auto& item : channels.actives()) {
        if (!item.second.empty() && commitment.qualified(item.second)) return item.second;
    }
    return {};
}

} // namespace

bool SwarmGenerationContinue::Apply(SwarmGenerationLineage& lineage, const SwarmGenerationChannels& channels,
                                    const SwarmGenerationCommitment& commitment, std::string& err) const
{
    const std::string next = ChosenParent(channels, commitment);
    if (next.empty()) {
        return SwarmGenerationFail(err, kSwarmGenerationUnqualified);
    }
    lineage.advance(next);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
