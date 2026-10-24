// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_COHORT_DT_COHORT_H
#define BITCOIN_MODELNET_DT_COHORT_DT_COHORT_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Same-base local-SGD outer update for two ranks on one cohort.
 * A partition does not have quorum. This is not Decoupled DiLoCo.
 */
class DtCohort {
public:
    bool Admit(const std::string& member, const std::string& base, uint64_t epoch, std::string& err);
    bool Freeze(std::string& err);
    bool OuterUpdate(const std::string& member, const std::string& base, int64_t delta, std::string& err);
    bool Commit(bool quorum, std::string& err);
    bool Partition(std::string& err);

    int64_t head() const { return m_head; }
    int head_count() const { return m_head_count; }
    bool quorum_available() const { return !m_partition; }
    bool diloco_complete() const { return false; }
    bool permanent_leader() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Member {
        std::string base;
        bool delta_set{false};
        int64_t delta{0};
    };
    std::map<std::string, Member> m_members;
    bool m_frozen{false};
    bool m_partition{false};
    int64_t m_head{0};
    int m_head_count{0};
};

} // namespace modelnet

#endif
