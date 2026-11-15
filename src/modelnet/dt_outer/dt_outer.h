// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_OUTER_DT_OUTER_H
#define BITCOIN_MODELNET_DT_OUTER_DT_OUTER_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Empty epoch. Nothing is stored. */
inline constexpr char DT_OUTER_EPOCH[] = "EPOCH";

/** Empty optimizer state. Nothing is stored. */
inline constexpr char DT_OUTER_OPT[] = "OPT";

/** Membership below zero. Nothing is stored. */
inline constexpr char DT_OUTER_MEMBER[] = "MEMBER";

/** The journal refused this outer commit. The stored triple stays. */
inline constexpr char DT_OUTER_JOURNAL[] = "JOURNAL";

/**
 * In-memory outer checkpoint for one physical host.
 * Requirement DT-WAN-007. The last successful commit is the only stored
 * triple. No file is written and no socket is opened.
 *
 * epoch() and optimizer_state() start empty. membership_epoch() starts at 0.
 *
 * Commit stores one epoch, its optimizer state, and its membership.
 * An empty epoch is EPOCH and stores nothing. An empty optimizer state is
 * OPT and stores nothing. membership below 0 is MEMBER and stores nothing.
 * Those checks run before the journal. journal_ok false is JOURNAL and does
 * not replace epoch(), optimizer_state(), or membership_epoch().
 *
 * When the journal accepts the call, a second Commit of an epoch already
 * stored is NIFDT_REPLAY and keeps the first optimizer state and membership.
 * A later new epoch with journal_ok false is JOURNAL and leaves that
 * previous triple in place. A later new epoch with journal_ok true replaces
 * the triple.
 *
 * Wan returns false with NIFDT_NO_ROUTE. bytes_moved() stays 0.
 * permanent_leader() and diloco_complete() stay false. hosts() and
 * physical_hosts() stay 1. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. qualified() stays false.
 */
class DtOuter {
public:
    bool Commit(const std::string& epoch, const std::string& optimizer_state, int64_t membership, bool journal_ok, std::string& err);
    bool Wan(std::string& err);

    const std::string& epoch() const { return m_epoch; }
    const std::string& optimizer_state() const { return m_optimizer; }
    int64_t membership_epoch() const { return m_membership; }
    int64_t bytes_moved() const { return m_bytes_moved; }

    bool permanent_leader() const { return false; }
    bool diloco_complete() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::string m_epoch;
    std::string m_optimizer;
    int64_t m_membership{static_cast<int64_t>(0)};
    int64_t m_bytes_moved{static_cast<int64_t>(0)};
    bool m_have{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_OUTER_DT_OUTER_H
