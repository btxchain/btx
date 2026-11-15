// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_DRAIN_NIF_DRAIN_H
#define BITCOIN_MODELNET_NIF_DRAIN_NIF_DRAIN_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Open refused an empty id. Nothing is stored. */
inline constexpr char NIF_DRAIN_REQUEST[] = "REQUEST";

/** Open refused a deadline below 1 ms. Nothing is stored. */
inline constexpr char NIF_DRAIN_DEADLINE[] = "DEADLINE";

/** Hold refused a byte count below 1. physical_bytes() stays. */
inline constexpr char NIF_DRAIN_BYTES[] = "BYTES";

/** Hold would pass int64 max. The previous total stays. */
inline constexpr char NIF_DRAIN_OVERFLOW[] = "OVERFLOW";

/** Drain ran before Cancel. physical_bytes() stays. */
inline constexpr char NIF_DRAIN_ORDER[] = "ORDER";

/** Drain ran at or after the deadline. physical_bytes() stays. */
inline constexpr char NIF_DRAIN_EXPIRED[] = "EXPIRED";

/** That effect already happened. The stored total stays. */
inline constexpr char NIF_DRAIN_UNCHANGED[] = "UNCHANGED";

/** Release ran before a successful Drain. physical_bytes() stays. */
inline constexpr char NIF_DRAIN_PINNED[] = "PINNED";

/**
 * Deadline drain for one worker record. NIF-EXEC-005.
 *
 * Cancel does not free. Cancel marks the record and leaves
 * physical_bytes() unchanged. Physical bytes return to 0 only from Drain
 * while the record is canceled and now_ms is still before deadline_ms.
 *
 * Open stores one id and one deadline. An empty id is REQUEST and stores
 * nothing. deadline_ms below 1 is DEADLINE and stores nothing. A second
 * Open of the same id is NIFDT_REPLAY and keeps the first deadline.
 *
 * Hold adds bytes to that id. An unknown id is REQUEST. bytes below 1 is
 * BYTES and does not change physical_bytes(). The sum is checked against
 * int64 max before adding. Overflow is OVERFLOW and leaves the previous
 * total. Hold after a successful Drain is UNCHANGED.
 *
 * Cancel on an unknown id is REQUEST. The first Cancel sets canceled and
 * leaves physical_bytes() unchanged. A second Cancel is NIFDT_REPLAY and
 * the record stays canceled.
 *
 * Drain on an unknown id is REQUEST. Drain before Cancel is ORDER and
 * leaves physical_bytes() unchanged. Drain at or after deadline_ms is
 * EXPIRED, including equality, and leaves physical_bytes() unchanged. Drain
 * of a canceled record with now_ms before deadline_ms returns true, drops
 * that record's held bytes, and sets drained. A second Drain of that record
 * is UNCHANGED and physical bytes stay 0. physical_bytes() is the sum of
 * bytes still held.
 *
 * Release before a successful Drain is PINNED and leaves physical_bytes()
 * unchanged. Release after Drain returns true and leaves the zero total.
 *
 * children() stays 0. This class does not call posix_spawn, open a socket,
 * or start a child process. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. qualified() stays false.
 * bytes_moved() stays 0.
 */
class NifDrain {
public:
    bool Open(const std::string& id, int64_t deadline_ms, std::string& err);
    bool Hold(const std::string& id, int64_t bytes, std::string& err);
    bool Cancel(const std::string& id, std::string& err);
    bool Drain(const std::string& id, int64_t now_ms, std::string& err);
    bool Release(const std::string& id, std::string& err);

    int64_t physical_bytes() const;
    int64_t deadline_ms(const std::string& id) const;
    bool canceled(const std::string& id) const;
    bool drained(const std::string& id) const;
    /** True when every stored record has completed Drain. False when empty. */
    bool drained() const;
    int64_t count() const { return static_cast<int64_t>(m_rows.size()); }

    int64_t children() const { return static_cast<int64_t>(0); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string id;
        int64_t deadline_ms{0};
        int64_t bytes{0};
        bool canceled{false};
        bool drained{false};
        bool released{false};
    };

    Row* Find(const std::string& id);
    const Row* Find(const std::string& id) const;

    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_DRAIN_NIF_DRAIN_H
