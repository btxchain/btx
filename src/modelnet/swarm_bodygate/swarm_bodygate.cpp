// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/swarm_bodygate.h>

#include <modelnet/swarm_bodygate/join.h>
#include <modelnet/swarm_bodygate/piece.h>

namespace modelnet {

bool SwarmBodyGate::AddPiece(int64_t index, int64_t size, bool last)
{
    const SwarmBodyPieceFault fault = SwarmBodyClassifyPiece(index, size, last);
    if (fault == SwarmBodyPieceFault::Index) {
        m_code = kSwarmBodyGateIndex;
        return false;
    }
    if (fault == SwarmBodyPieceFault::Short) {
        m_code = kSwarmBodyGateShort;
        return false;
    }
    std::string code;
    if (!m_ledger.Admit(index, size, last, code)) {
        m_code = code;
        return false;
    }
    m_joined = false;
    m_code = kSwarmBodyGateOk;
    return true;
}

bool SwarmBodyGate::Join()
{
    const SwarmBodyJoinView view = SwarmBodyEvaluateJoin(m_ledger.pieces(), m_ledger.sum());
    m_code = view.code;
    m_joined = view.joined;
    return m_joined;
}

bool SwarmBodyGate::SetManifestEntries(int64_t count)
{
    if (!m_manifest.SetEntries(count)) {
        m_code = kSwarmBodyGateFlat;
        return false;
    }
    m_code = kSwarmBodyGateOk;
    return true;
}

} // namespace modelnet
