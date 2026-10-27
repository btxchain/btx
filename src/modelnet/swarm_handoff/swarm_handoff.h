// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HANDOFF_H
#define BITCOIN_MODELNET_SWARM_HANDOFF_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty id or payload, or an intent that was never stored. Nothing is stored. */
inline constexpr char kSwarmHandoffIntent[] = "INTENT";

/** The same id and the same payload again. The attempt stays 1. */
inline constexpr char kSwarmHandoffReplay[] = "REPLAY";

/** The same id and a different payload. The first payload stays. Not a success. */
inline constexpr char kSwarmHandoffConflict[] = "CONFLICT";

/** Empty worker. Nothing is stored. */
inline constexpr char kSwarmHandoffWorker[] = "WORKER";

/**
 * now_ms >= until_ms, including equality, or until_ms < 1.
 * A missing or boundary-time lease is the same code. Nothing new is stored.
 */
inline constexpr char kSwarmHandoffExpired[] = "EXPIRED";

/** Fence names an intent that has no open handoff. */
inline constexpr char kSwarmHandoffHandoff[] = "HANDOFF";

/**
 * The destination refused, or Fence is called again after that refusal.
 * The transfer is not atomic. The effect is not repeated.
 */
inline constexpr char kSwarmHandoffAmbiguous[] = "AMBIGUOUS";

/** Holder before a committed fence. Cleared when ownership moves or the transfer is ambiguous. */
inline constexpr char kSwarmHandoffSource[] = "source";

/** automatic_spend() returns this. Nothing is spent. */
inline constexpr char kSwarmHandoffAutomaticSpend[] = "0";

/** atoms_moved() stays 0. */
inline constexpr int64_t kSwarmHandoffAtomsMoved = 0;

/** First stored payload. Later calls do not advance this. */
inline constexpr int kSwarmHandoffFirstAttempt = 1;

/**
 * In-process handoff of one intent.
 *
 * Intent identity and the attempt counter are separate fields.
 * The first non-empty payload for an id is attempt 1 and returns true.
 * The same payload again is REPLAY and the attempt stays 1.
 * A different payload is CONFLICT: the first payload stays, and the call
 * does not count as success. Idempotency does not hide a changed request.
 *
 * Lease stores a worker only when until_ms >= 1 and now_ms < until_ms.
 * now_ms >= until_ms is EXPIRED, including now_ms == until_ms, and stores
 * nothing. now_ms == until_ms - 1 stores the lease when until_ms >= 1.
 * An empty worker is WORKER.
 *
 * Begin requires a stored intent and a live lease for the destination.
 * An unknown intent is INTENT. No live lease, or a lease that is already
 * at its bound (now_ms >= until_ms), is EXPIRED. Success records the
 * handoff as open and gives the destination a fresh authority scoped to
 * that intent. The destination does not own it yet. The source still does.
 *
 * Fence commits ownership only when the destination accepts an open
 * handoff. That commit clears the source owner. A refusal sets the
 * handoff AMBIGUOUS, returns false, and does not claim atomic success.
 * owner() is empty while the handoff is ambiguous. A second Fence on an
 * ambiguous handoff returns AMBIGUOUS and does not retry the effect.
 *
 * spend_key_moved() stays false. There is no key field.
 * launched(), gpu(), broadcast(), and connected() stay false.
 * automatic_spend() returns "0". atoms_moved() stays 0.
 * This class does not spawn a process.
 */
class SwarmHandoff {
public:
    /**
     * Store the first payload for id as attempt 1.
     * An empty id or payload is INTENT and stores nothing.
     * The same payload again is REPLAY and leaves the attempt at 1.
     * A different payload is CONFLICT, keeps the first payload, and
     * does not count as success.
     */
    bool Intent(const std::string& id, const std::string& payload, std::string& err);

    /**
     * Store a lease for worker.
     * An empty worker is WORKER and stores nothing.
     * now_ms >= until_ms is EXPIRED, including equality, and stores nothing.
     * until_ms < 1 is EXPIRED and stores nothing.
     * now_ms == until_ms - 1 stores the lease and returns true when until_ms >= 1.
     * A later expired call does not erase a lease already stored.
     */
    bool Lease(const std::string& worker, int64_t until_ms, int64_t now_ms, std::string& err);

    /**
     * Open a handoff. The destination receives a fresh authority scoped to
     * this intent and this until_ms. Ownership stays with the source.
     * An unknown intent is INTENT. No live lease for destination, or
     * now_ms >= until_ms, is EXPIRED and records nothing.
     * A second open of the same destination is REPLAY.
     * A second open that names another destination is CONFLICT.
     * An ambiguous handoff stays AMBIGUOUS and is not opened again.
     */
    bool Begin(const std::string& intent_id, const std::string& destination, int64_t until_ms, int64_t now_ms, std::string& err);

    /**
     * Commit or refuse the open handoff.
     * An unknown open handoff is HANDOFF.
     * destination_accepts true commits ownership to the destination,
     * clears the source owner, and returns true.
     * destination_accepts false sets the handoff AMBIGUOUS, returns false,
     * and does not claim atomic success. owner() is empty while ambiguous.
     * A second Fence on an ambiguous handoff returns AMBIGUOUS and does
     * not retry the effect.
     */
    bool Fence(const std::string& intent_id, bool destination_accepts, std::string& err);

    /** Payload stored for id, or empty when the id was not stored. */
    const std::string& payload(const std::string& id) const;

    /** Attempt stored for id. 0 when the id was not stored. The first store is 1. */
    int attempt(const std::string& id) const;

    /** True when a lease for worker is stored. */
    bool leased(const std::string& worker) const;

    /** Stored lease bound, or 0 when the worker has no lease. */
    int64_t lease_until(const std::string& worker) const;

    /** True when the lease is stored and now_ms < until_ms. Equality is not live. */
    bool live(const std::string& worker, int64_t now_ms) const;

    /** True when this intent has an open handoff that is not yet fenced. */
    bool open(const std::string& intent_id) const;

    /** True when the destination refused this handoff. */
    bool ambiguous(const std::string& intent_id) const;

    /** True when a fence committed this handoff to the destination. */
    bool committed(const std::string& intent_id) const;

    /** True only after a committed fence. False while open or ambiguous. */
    bool atomic(const std::string& intent_id) const;

    /**
     * Owner of the current handoff.
     * The source while the handoff is open, the destination after a
     * committed fence, and empty while the handoff is ambiguous.
     */
    const std::string& owner() const;

    /** Owner of one intent. Empty when that handoff is ambiguous or absent. */
    const std::string& owner_of(const std::string& intent_id) const;

    /** Source owner of the current handoff. Empty after a commit or a refusal. */
    const std::string& source_owner() const;

    /** True when the current handoff carries a fresh authority scoped to its destination. */
    bool scoped() const;

    /** Destination named by the current fresh authority, or empty. */
    const std::string& authority_destination() const;

    /** Generation of the current fresh authority. 0 when none was issued. */
    uint64_t authority_generation() const;

    /**
     * How many times the fence effect was applied to the current handoff.
     * A second Fence on an ambiguous handoff does not increase this.
     */
    int effects() const;

    /** Stays false. There is no key field. */
    bool spend_key_moved() const;

    /** Stays false. */
    bool launched() const;

    /** Stays false. */
    bool gpu() const;

    /** Stays false. */
    bool broadcast() const;

    /** Stays false. */
    bool connected() const;

    /** Returns "0". */
    std::string automatic_spend() const;

    /** Stays 0. */
    int64_t atoms_moved() const;

private:
    enum class Phase {
        Open,
        Committed,
        Ambiguous,
    };

    struct IntentRecord {
        std::string payload;
        int attempt{0};
    };

    struct LeaseRecord {
        int64_t until_ms{0};
    };

    struct HandoffRecord {
        Phase phase{Phase::Open};
        std::string destination;
        std::string source_owner;
        std::string owner;
        int64_t authority_until_ms{0};
        uint64_t authority_generation{0};
        int effects{0};
        bool scoped{false};
    };

    const HandoffRecord* Current() const;
    const std::string& OwnerOf(const HandoffRecord* handoff) const;

    std::map<std::string, IntentRecord> m_intents;
    std::map<std::string, LeaseRecord> m_leases;
    std::map<std::string, HandoffRecord> m_handoffs;
    std::string m_current;
    std::string m_blank;
    uint64_t m_next_authority{1};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HANDOFF_H
