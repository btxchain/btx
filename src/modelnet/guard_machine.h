// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GUARD_MACHINE_H
#define BITCOIN_MODELNET_GUARD_MACHINE_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** One-use permit. The bearer is `secret`. Callers that publish a record keep only `commitment`. */
struct GuardPermit {
    std::string secret;
    std::string commitment;
    std::string effect;
    std::string fingerprint;
    uint64_t generation{0};
    int64_t not_after_ms{0};
    bool consumed{false};
};

/**
 * Local action table shared by btxd and btx-guardd.
 * A permit lives at most 30 seconds. A second consume is BTX035_REPLAY.
 * Pause blocks execute until resume. Logical cancel does not invent a physical stop.
 * The table holds at most kMaxPermits rows. When it is full, Prepare drops the rows past their
 * expiry; if none has expired, Prepare is BTX035_LIMIT_EXCEEDED and the table does not grow.
 */
class GuardTable {
public:
    static constexpr int64_t kPermitTtlMs = 30000;
    static constexpr size_t kMaxPermits = 1024;

    bool Prepare(const std::string& effect, const std::string& fingerprint, uint64_t generation, int64_t now_ms,
                 GuardPermit& out, std::string& err);
    bool Execute(const std::string& secret, int64_t now_ms, std::string& receipt_id, std::string& err);
    void Pause() { m_paused = true; }
    void Resume() { m_paused = false; }
    bool Paused() const { return m_paused; }
    size_t Size() const { return m_by_secret.size(); }

private:
    std::map<std::string, GuardPermit> m_by_secret;
    bool m_paused{false};
};

/**
 * One line of the btx-guardd protocol. Permit TTL and one-use rules stay in GuardTable.
 * PREPARE effect fingerprint generation -> PERMIT secret commitment not_after_ms
 * EXECUTE secret -> RECEIPT id EXECUTED STOPPED_QUIESCENT
 * PAUSE / RESUME -> OK
 */
std::string GuardHandleLine(GuardTable& table, const std::string& line, int64_t now_ms);

/** SHA-384 hex of the bearer. This is the value that may be stored or announced. */
std::string GuardCommitment(const std::string& secret);

/** 32 random bytes as lowercase hex. Empty on failure. */
std::string GuardRandomHex();

} // namespace modelnet

#endif // BITCOIN_MODELNET_GUARD_MACHINE_H
