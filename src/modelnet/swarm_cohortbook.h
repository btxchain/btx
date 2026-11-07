// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_COHORTBOOK_H
#define BTX_MODELNET_SWARM_COHORTBOOK_H

#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Cohort admission book. Time authority is the caller-supplied now_ms.
 * A lease is expired when now_ms >= until_ms, including the exact boundary.
 * now_ms == until_ms - 1 is the last instant that can admit.
 * This book does not read the wall clock, so a cached decision cannot skip
 * a fresh call. SwarmAdmitCohortMember still applies the same boundary.
 */
class SwarmCohortBook {
public:
    bool Open(int64_t epoch, std::string& err);
    /** A new lease for the same member supersedes the previous one. */
    bool Grant(const std::string& member_id, const std::string& lease_id, int64_t until_ms, std::string& err);
    bool Revoke(const std::string& lease_id, std::string& err);
    /** A lower epoch is STALE_EPOCH and does not change the book. */
    bool SetEpoch(int64_t epoch, std::string& err);
    /**
     * leader_epoch must equal the book epoch. Revoked, superseded, and expired
     * leases do not admit. A repeated admit of a still-valid lease is the same
     * membership. Checkpoint and recipe still have to match.
     */
    bool Admit(int64_t now_ms, int64_t leader_epoch, const std::string& member_id, const std::string& lease_id,
               bool checkpoint_match, bool recipe_match, std::string& err);
    int Admitted() const;
    bool Persist(const fs::path& modeldir, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);

private:
    struct Lease {
        std::string member_id;
        std::string lease_id;
        int64_t until_ms{0};
        bool revoked{false};
        bool superseded{false};
        bool admitted{false};
    };

    bool m_open{false};
    int64_t m_epoch{0};
    std::vector<Lease> m_leases;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_COHORTBOOK_H
