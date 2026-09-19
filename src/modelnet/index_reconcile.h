// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_INDEX_RECONCILE_H
#define BITCOIN_MODELNET_INDEX_RECONCILE_H

#include <modelnet/metadata_gossip.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Spec E.1: metadata gossip announcement / IWANT list cap. */
constexpr size_t RECONCILE_WANT_MAX = 256;
/** Spec E.1: reconciliation recursion depth. */
constexpr int RECONCILE_RECURSION_MAX = 32;
/** Spec E.1: reconciliation in-flight responses. */
constexpr int RECONCILE_IN_FLIGHT_MAX = 3;
/** Spec E.1: full signed objects in a gossip reply. */
constexpr int RECONCILE_FULL_OBJECTS_MAX = 8;

enum class ReconcileStatus {
    EQUAL = 0,
    WANT = 1,
    DIVIDE = 2,
    REJECT = 3,
};

struct ReconcileRange {
    std::string lo;
    std::string hi;
    uint32_t count{0};
    std::string digest_hex;
};

struct ReconcileResult {
    ReconcileStatus status{ReconcileStatus::EQUAL};
    GossipMessage outbound;
    std::vector<std::string> want_ids;
    ReconcileRange left;
    ReconcileRange right;
    bool want_truncated{false};
    std::string err;
};

/**
 * Anti-entropy over catalog ID lists. Compare digests, emit a bounded want
 * list, never put secrets on the metadata mesh. Fingerprints identify
 * differences; they are not insertion authority.
 */
class IndexReconciler {
public:
    GossipDigest LocalDigest(const std::vector<std::string>& ids) const;
    bool AdmitInbound(const GossipMessage& msg, std::string& err) const;
    ReconcileResult Compare(const std::vector<std::string>& local_ids,
                            const GossipDigest& remote) const;
    ReconcileResult CompareSets(const std::vector<std::string>& local_ids,
                                const std::vector<std::string>& remote_ids) const;
    ReconcileResult CompareRange(const std::vector<std::string>& local_ids,
                                 const ReconcileRange& remote, int depth) const;
};

GossipDigest MakeCatalogDigest(const std::vector<std::string>& ids);
std::vector<std::string> SortedUniqueIds(std::vector<std::string> ids);
std::vector<std::string> BoundedWantList(const std::vector<std::string>& missing);
std::vector<std::string> MissingRemoteIds(const std::vector<std::string>& local_sorted,
                                          const std::vector<std::string>& remote_sorted,
                                          bool* truncated = nullptr);
ReconcileRange DigestIdRange(const std::vector<std::string>& sorted_ids, size_t begin, size_t end);
GossipMessage MakeWantGossip(const GossipDigest& local, const std::vector<std::string>& want);
/** Digests locate drift; they do not authorize catalog mutation. */
bool ReconcileDigestAuthorizesInsert();

} // namespace modelnet

#endif // BITCOIN_MODELNET_INDEX_RECONCILE_H
