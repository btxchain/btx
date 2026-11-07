// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SIGHASHOK_H
#define BTX_MODELNET_SWARM_SIGHASHOK_H

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory record of whether a sighash covered its outputs.
 * txid names the transaction. covers_outputs is true only when the sighash
 * commits to the outputs. A sighash that skips outputs is not signed:
 * the txid is recorded as refused and signed_ok stays false.
 *
 * Sign order, first match wins: an empty txid is TX and stores nothing.
 * covers_outputs false records the txid as refused, signed_ok stays false,
 * and err is NOT_SIGNED. A covering sighash whose txid is already recorded
 * is REPLAY and does not set signed_ok. Otherwise the txid is recorded with
 * signed_ok true, err is cleared, and Sign returns true.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmSighashOk {
public:
    bool Sign(const std::string& txid, bool covers_outputs, std::string& err);

    /** False when txid is unknown or was recorded as refused. */
    bool signed_ok(const std::string& txid) const;

private:
    /** True only for a covering sighash. False means the txid was refused. */
    std::map<std::string, bool> m_signed_ok;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SIGHASHOK_H
