// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACTRUN_H
#define BITCOIN_MODELNET_SWARM_ARTIFACTRUN_H

#include <modelnet/swarm_artifactrun/limits.h>
#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process artifact run over the piece pipeline.
 *
 * Accept, Split, and Resume are SwarmPiecePipe. This class does not hash.
 * Slice bytes stay in the pipeline. SplitBody does not keep another full
 * copy of the body. A piece is at most 4194304 bytes.
 *
 * bytes_moved() stays 0. This plane does not move bytes off the node.
 * launched(), gpu(), and broadcast() stay false. automatic_spend() stays
 * "0". No method starts a process, opens a socket, or spends.
 *
 * AcceptBody forwards to Accept. The piece id is digest_hex when that
 * string is non-empty, and id otherwise. An empty body is PIECE.
 *
 * SplitBody forwards to Split. An empty body is PIECE.
 *
 * Close returns true only when Resume says every piece is present. That
 * id is then closed. Otherwise the result is MANIFEST and that id stays
 * unclosed. closed() is true only after at least one id has been closed.
 * Complete returns false with MANIFEST until that id is closed.
 *
 * Generation stores one immutable body for an id only after Close has
 * succeeded for that id. Before that, the result is MANIFEST and nothing
 * is stored. An empty body is PIECE and nothing is stored. The same body
 * again is REPLAY. A different body is CONFLICT and the first bytes stay.
 *
 * Load returns true only when that id is closed and the stored generation
 * is non-empty. It sets loaded() true and does not start a process. If
 * the id is not closed, the result is MANIFEST and loaded() is not set,
 * so a load that has never succeeded stays false.
 */
class SwarmArtifactRun {
public:
    bool AcceptBody(const std::string& id, const std::vector<unsigned char>& body, const std::string& digest_hex,
                    std::string& err);
    bool SplitBody(const std::vector<unsigned char>& body, std::string& err);
    bool Close(const std::string& id, std::string& err);
    bool Complete(const std::string& id, std::string& err);
    bool Generation(const std::string& id, const std::vector<unsigned char>& bytes, std::string& err);
    bool Load(const std::string& id, std::string& err);

    bool closed() const;
    bool closed(const std::string& id) const;
    bool loaded() const;
    std::vector<unsigned char> generation_bytes(const std::string& id) const;

    std::int64_t bytes_moved() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;

private:
    SwarmPiecePipe m_pipe;
    std::set<std::string> m_closed;
    std::map<std::string, std::vector<unsigned char>> m_generations;
    bool m_loaded{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACTRUN_H
