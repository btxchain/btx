// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_pieceout/dt_pieceout.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_piecepipe/codes.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

static_assert(kSwarmPiecePipeBodyLimit == 33554432, "pieceout body cap is 33554432 bytes");
static_assert(NIFDT_AUTOMATIC_SPEND[0] == '0' && NIFDT_AUTOMATIC_SPEND[1] == '\0', "spend stays 0");

bool DtPieceOut::Put(const std::vector<unsigned char>& body, std::string& err)
{
    const std::size_t before = m_pipe.ManifestCount();
    if (!m_pipe.Split(body, err)) {
        return false;
    }
    const std::string id = SwarmPiecePipeDigest(body);
    if (id.empty()) {
        err.clear();
        return true;
    }
    m_artifact = id;
    if (m_pipe.ManifestCount() > before) {
        return m_pipe.Resume(id, err);
    }
    err.clear();
    return true;
}

bool DtPieceOut::Resume(const std::string& artifact, std::string& err)
{
    return m_pipe.Resume(artifact, err);
}

bool DtPieceOut::DropRequired(const std::string& id, std::string& err)
{
    if (m_pipe.Drop(id, err)) {
        return true;
    }
    if (err == kSwarmPiecePipeManifest) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    return false;
}

bool DtPieceOut::Claim(std::string& err)
{
    err = DT_PIECEOUT_CLAIM;
    return false;
}

std::vector<std::string> DtPieceOut::slice_ids() const
{
    if (m_artifact.empty()) {
        return {};
    }
    return m_pipe.SliceIds(m_artifact);
}

bool DtPieceOut::has_piece(const std::string& id) const
{
    return m_pipe.HasPiece(id);
}

bool DtPieceOut::usable(const std::string& artifact) const
{
    return m_pipe.usable(artifact);
}

std::size_t DtPieceOut::piece_count() const
{
    return m_pipe.PieceCount();
}

std::size_t DtPieceOut::manifest_count() const
{
    return m_pipe.ManifestCount();
}

std::int64_t DtPieceOut::bytes_moved() const
{
    return m_pipe.bytes_moved();
}

bool DtPieceOut::launched() const
{
    return m_pipe.launched();
}

bool DtPieceOut::gpu() const
{
    return m_pipe.gpu();
}

bool DtPieceOut::broadcast() const
{
    return m_pipe.broadcast();
}

} // namespace modelnet
