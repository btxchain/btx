// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_SYNC_DT_SYNC_H
#define BITCOIN_MODELNET_DT_SYNC_DT_SYNC_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty fragment id. Nothing is stored. */
inline constexpr char kDtSyncFragment[] = "FRAGMENT";

/** Empty member. Nothing is stored. */
inline constexpr char kDtSyncMember[] = "MEMBER";

/** Lag above 2. The fragment is unusable. */
inline constexpr char kDtSyncStale[] = "STALE";

/** Empty synchronizer name. The current name stays. */
inline constexpr char kDtSyncSync[] = "SYNC";

/** Fewer than two usable fragments. head() stays. */
inline constexpr char kDtSyncQuorum[] = "QUORUM";

/** Quorum is unavailable. head() stays. */
inline constexpr char kDtSyncPartition[] = "PARTITION";

/**
 * Local fragment synchronizer on one physical host.
 *
 * Admit stores one fragment id, its member, and an int64 version. An empty
 * fragment is FRAGMENT and stores nothing. An empty member is MEMBER and
 * stores nothing. A duplicate fragment id is NIFDT_REPLAY and keeps the
 * first member and version.
 *
 * NoteStale marks an admitted fragment unusable when lag is above 2 and
 * returns STALE. Lag of 2 leaves that fragment usable. An unknown fragment
 * is FRAGMENT and is not created.
 *
 * Commit averages the int64 versions of usable admitted fragments when every
 * admitted fragment is usable and at least two exist. The average is integer
 * division. Fewer than two usable fragments is QUORUM and leaves head()
 * unchanged. A commit that includes an unusable fragment is STALE and leaves
 * head() unchanged. After success head() is that integer average.
 *
 * Partition makes quorum_available() false. A later Commit is PARTITION and
 * leaves head() unchanged.
 *
 * Replace stores a new synchronizer name. An empty new name is SYNC and
 * leaves the current name. Once a name is stored, a different old name is
 * SYNC and leaves the current name. permanent_leader() stays false. There
 * is no method that sets a permanent leader.
 *
 * Wan returns false with NIFDT_NO_ROUTE and moves no bytes. bytes_moved()
 * stays 0. Scan returns false with NIFDT_NOT_SCAN. launched(), gpu(), and
 * broadcast() stay false. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * physical_hosts() is 1. diloco_complete() stays false. No socket is opened.
 */
class DtSync {
public:
    bool Admit(const std::string& fragment, const std::string& member, int64_t version, std::string& err);
    bool NoteStale(const std::string& fragment, int64_t lag, std::string& err);
    bool Replace(const std::string& old_sync, const std::string& new_sync, std::string& err);
    bool Commit(std::string& err);
    void Partition();
    bool Wan(std::string& err);
    bool Scan(std::string& err);

    int64_t head() const { return m_head; }
    bool quorum_available() const { return !m_partition; }
    bool permanent_leader() const { return false; }
    bool diloco_complete() const { return false; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

    bool admitted(const std::string& fragment) const;
    bool usable(const std::string& fragment) const;
    std::string member(const std::string& fragment) const;
    int64_t version(const std::string& fragment) const;
    std::string synchronizer() const { return m_sync; }

private:
    struct Fragment {
        std::string member;
        int64_t version{0};
        bool usable{true};
    };

    std::map<std::string, Fragment> m_fragments;
    std::string m_sync;
    bool m_partition{false};
    int64_t m_head{0};
    int64_t m_bytes_moved{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_SYNC_DT_SYNC_H
