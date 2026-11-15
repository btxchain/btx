// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_H

#include <modelnet/swarm_bodygate/ledger.h>
#include <modelnet/swarm_bodygate/limits.h>
#include <modelnet/swarm_bodygate/manifest.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Body and piece-size gate.
 *
 * Stores piece sizes and a flat manifest entry count. Stores no payloads
 * and moves no bytes. bytes_moved() stays 0.
 *
 * AddPiece(index, size, last):
 * index < 0 is INDEX and stores nothing.
 * size < 1 is SHORT and stores nothing.
 * A non-last piece whose size is not 4194304 is SHORT and stores nothing.
 * A last piece larger than 4194304 is SHORT and stores nothing.
 * A duplicate index is REPLAY and keeps the first size.
 * A sum of stored sizes that would rise above 33554432 is BODY and that
 * piece is not stored. A sum equal to 33554432 is stored.
 * A stored piece clears joined.
 *
 * Join requires indexes exactly 0..n-1, exactly one last piece, and that
 * last piece at the highest index. A gap is GAP. A missing last piece,
 * more than one last piece, or a last piece that is not highest is LAST.
 * The empty set is LAST. Success sets joined. Joined bytes() returns the
 * sum of stored sizes. Otherwise bytes() is 0.
 *
 * SetManifestEntries(count): count < 0 or count > 16384 is FLAT and leaves
 * the stored count unchanged. A negative is not stored. 16384 is stored.
 */
class SwarmBodyGate {
public:
    bool AddPiece(int64_t index, int64_t size, bool last);
    bool Join();
    bool SetManifestEntries(int64_t count);

    int64_t piece_bytes() const { return kSwarmBodyGatePieceBytes; }
    int64_t body_cap() const { return kSwarmBodyGateBodyCap; }
    int64_t manifest_cap() const { return kSwarmBodyGateManifestCap; }

    bool joined() const { return m_joined; }
    int64_t bytes() const { return m_joined ? m_ledger.sum() : 0; }
    int64_t bytes_moved() const { return 0; }
    const std::string& code() const { return m_code; }

    int64_t manifest_entries() const { return m_manifest.entries(); }
    int64_t piece_count() const { return m_ledger.count(); }
    int64_t stored_bytes() const { return m_ledger.sum(); }
    bool has_piece(int64_t index) const { return m_ledger.contains(index); }
    int64_t piece_size(int64_t index) const { return m_ledger.size_of(index); }
    bool piece_last(int64_t index) const { return m_ledger.last_of(index); }

private:
    SwarmBodyLedger m_ledger;
    SwarmBodyManifest m_manifest;
    bool m_joined{false};
    std::string m_code;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_H
