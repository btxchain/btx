// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_REQBIND_NIF_REQBIND_H
#define BITCOIN_MODELNET_NIF_REQBIND_NIF_REQBIND_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** The first empty string field. Nothing is stored. */
inline constexpr char NIF_REQBIND_FIELD[] = "FIELD";

/** The first zero numeric field. Nothing is stored. */
inline constexpr char NIF_REQBIND_BOUND[] = "BOUND";

/**
 * In-memory bind of one native request.
 * Requirement NIF-NAT-002. Storage is the NifRequestRecord map. No file
 * is written and no socket is opened.
 *
 * Bind stores the record only when principal, receiver, realm,
 * generation, runtime_image, commitment, and attempt are all non-empty,
 * and epoch, ceiling_bytes, and lease_until_ms are all greater than 0.
 * String fields are checked in that order. The first empty string is
 * FIELD and stores nothing. Numeric fields are checked next, in that
 * order. The first zero is BOUND and stores nothing. cancelled,
 * output_ceiling, accepted_output, and economic_contract are copied with
 * the record and are not gates.
 *
 * A second Bind of an attempt already stored is NIFDT_REPLAY and keeps
 * the first record, including when the new call carries a different
 * principal. Replay is decided only after the call is otherwise complete,
 * so an empty string is still FIELD and a zero numeric is still BOUND.
 *
 * Find copies the stored record and returns true. An unknown attempt
 * returns false and leaves the output unchanged.
 *
 * Spend returns false with NIFDT_AUTOMATIC_SPEND and does not change the
 * record. launched(), gpu(), broadcast(), and qualified() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * hosts() stays 1.
 */
class NifReqBind {
public:
    bool Bind(const NifRequestRecord& record, std::string& err);
    bool Find(const std::string& attempt, NifRequestRecord& out) const;
    bool Spend(std::string& err);

    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::map<std::string, NifRequestRecord> m_by_attempt;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_REQBIND_NIF_REQBIND_H
