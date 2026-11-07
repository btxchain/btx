// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_CHUNK_NIF_CHUNK_H
#define BITCOIN_MODELNET_NIF_CHUNK_NIF_CHUNK_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Bind or Accept ran with no current bound state. Nothing is stored. */
inline constexpr char NIF_CHUNK_STATE[] = "STATE";

/** Accept refused an empty chunk id. Nothing is stored. */
inline constexpr char NIF_CHUNK_CHUNK[] = "CHUNK";

/** Accept refused a byte count below 1. Nothing is stored. */
inline constexpr char NIF_CHUNK_BYTES[] = "BYTES";

/** Accept named a state other than the current bound state. Nothing is stored. */
inline constexpr char NIF_CHUNK_STALE[] = "STALE";

/** Adding the byte count would overflow int64. accepted_bytes() stays unchanged. */
inline constexpr char NIF_CHUNK_OVERFLOW[] = "OVERFLOW";

/**
 * NIF-EXEC-001. Every chunk is authorized against the current bound state.
 *
 * Bind stores one non-empty state. An empty state is STATE and stores
 * nothing, including when a state is already bound. A later Bind of a
 * different non-empty state replaces the current state and leaves already
 * accepted chunk ids in place.
 *
 * Accept requires a successful Bind. Before that, Accept is STATE and
 * stores nothing. An empty chunk id is CHUNK. A byte count below 1 is
 * BYTES. A chunk id already accepted is NIFDT_REPLAY and does not add
 * bytes again. Replay is decided before the state comparison, so a replay
 * cannot change the stored body. A state other than the current bound
 * state is STALE and stores nothing. Otherwise the chunk is accepted and
 * its byte count is added to accepted_bytes(). The addition is checked
 * for int64 overflow first. Overflow is OVERFLOW and leaves
 * accepted_bytes() unchanged. The refused id is not stored.
 *
 * Spend returns false with NIFDT_AUTOMATIC_SPEND and does not change a
 * balance. balance() stays 0. bytes_moved() stays 0. launched(), gpu(),
 * and broadcast() stay false. automatic_spend() is NIFDT_AUTOMATIC_SPEND
 * ("0"). qualified() stays false. An accepted chunk is not a
 * qualification. This class opens no socket and starts no process.
 */
class NifChunk {
public:
    bool Bind(const std::string& state, std::string& err);
    bool Accept(const std::string& chunk_id, const std::string& state, int64_t bytes, std::string& err);
    bool Spend(std::string& err);

    int64_t accepted_bytes() const { return m_accepted; }
    bool chunk_stored(const std::string& chunk_id) const;
    /** Frozen byte count for an accepted chunk. 0 when the id is absent. */
    int64_t stored_bytes(const std::string& chunk_id) const;

    bool bound() const { return m_bound; }
    const std::string& state() const { return m_state; }

    int64_t balance() const { return static_cast<int64_t>(0); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    const int64_t* Find(const std::string& chunk_id) const;

    bool m_bound{false};
    std::string m_state;
    int64_t m_accepted{0};
    /** Accepted chunk id to its frozen byte count. Replay does not write this map. */
    std::map<std::string, int64_t> m_chunks;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_CHUNK_NIF_CHUNK_H
