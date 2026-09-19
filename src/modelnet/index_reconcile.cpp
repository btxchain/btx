// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/index_reconcile.h>

#include <algorithm>
#include <set>

namespace modelnet {

namespace {

uint32_t CountU32(size_t n)
{
    return n > 0xffffffffull ? 0xffffffffu : static_cast<uint32_t>(n);
}

bool FinalizeOutbound(GossipMessage& msg, std::string& err)
{
    msg.secret_bearing = false;
    if (msg.want_ids.size() > RECONCILE_WANT_MAX) {
        msg.want_ids.resize(RECONCILE_WANT_MAX);
    }
    return GossipMessageAllowed(msg, err);
}

ReconcileResult Reject(const std::string& why)
{
    ReconcileResult r;
    r.status = ReconcileStatus::REJECT;
    r.err = why;
    r.outbound.secret_bearing = false;
    return r;
}

} // namespace

std::vector<std::string> SortedUniqueIds(std::vector<std::string> ids)
{
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

GossipDigest MakeCatalogDigest(const std::vector<std::string>& ids)
{
    const auto sorted = SortedUniqueIds(ids);
    GossipDigest d;
    d.catalog_digest_hex = CatalogDigestHex(sorted);
    d.entry_count = CountU32(sorted.size());
    return d;
}

std::vector<std::string> BoundedWantList(const std::vector<std::string>& missing)
{
    if (missing.size() <= RECONCILE_WANT_MAX) return missing;
    return {missing.begin(), missing.begin() + static_cast<std::ptrdiff_t>(RECONCILE_WANT_MAX)};
}

std::vector<std::string> MissingRemoteIds(const std::vector<std::string>& local_sorted,
                                          const std::vector<std::string>& remote_sorted,
                                          bool* truncated)
{
    std::set<std::string> have(local_sorted.begin(), local_sorted.end());
    std::vector<std::string> want;
    size_t extra = 0;
    for (const auto& id : remote_sorted) {
        if (id.empty() || have.count(id)) continue;
        if (want.size() < RECONCILE_WANT_MAX) want.push_back(id);
        else ++extra;
    }
    if (truncated) *truncated = extra > 0;
    return want;
}

ReconcileRange DigestIdRange(const std::vector<std::string>& sorted_ids, size_t begin, size_t end)
{
    ReconcileRange r;
    if (begin >= end || begin >= sorted_ids.size()) return r;
    if (end > sorted_ids.size()) end = sorted_ids.size();
    r.lo = sorted_ids[begin];
    r.hi = sorted_ids[end - 1];
    r.count = CountU32(end - begin);
    const std::vector<std::string> slice(sorted_ids.begin() + static_cast<std::ptrdiff_t>(begin),
                                         sorted_ids.begin() + static_cast<std::ptrdiff_t>(end));
    r.digest_hex = CatalogDigestHex(slice);
    return r;
}

GossipMessage MakeWantGossip(const GossipDigest& local, const std::vector<std::string>& want)
{
    GossipMessage msg;
    msg.digest = local;
    msg.want_ids = BoundedWantList(want);
    msg.secret_bearing = false;
    return msg;
}

bool ReconcileDigestAuthorizesInsert()
{
    return false;
}

GossipDigest IndexReconciler::LocalDigest(const std::vector<std::string>& ids) const
{
    return MakeCatalogDigest(ids);
}

bool IndexReconciler::AdmitInbound(const GossipMessage& msg, std::string& err) const
{
    return GossipMessageAllowed(msg, err);
}

ReconcileResult IndexReconciler::Compare(const std::vector<std::string>& local_ids,
                                         const GossipDigest& remote) const
{
    const auto local = SortedUniqueIds(local_ids);
    const GossipDigest ours = MakeCatalogDigest(local);
    GossipMessage msg;
    msg.digest = ours;
    msg.secret_bearing = false;

    ReconcileResult r;
    if (ours.catalog_digest_hex == remote.catalog_digest_hex &&
        ours.entry_count == remote.entry_count) {
        r.status = ReconcileStatus::EQUAL;
        r.outbound = msg;
        std::string err;
        if (!FinalizeOutbound(r.outbound, err)) {
            r.status = ReconcileStatus::REJECT;
            r.err = err;
        }
        return r;
    }

    if (local.size() > RECONCILE_WANT_MAX) {
        r.status = ReconcileStatus::DIVIDE;
        const size_t mid = local.size() / 2;
        r.left = DigestIdRange(local, 0, mid);
        r.right = DigestIdRange(local, mid, local.size());
    } else {
        r.status = ReconcileStatus::WANT;
    }
    r.outbound = msg;
    std::string err;
    if (!FinalizeOutbound(r.outbound, err)) {
        r.status = ReconcileStatus::REJECT;
        r.err = err;
    }
    return r;
}

ReconcileResult IndexReconciler::CompareSets(const std::vector<std::string>& local_ids,
                                             const std::vector<std::string>& remote_ids) const
{
    const auto local = SortedUniqueIds(local_ids);
    const auto remote = SortedUniqueIds(remote_ids);
    const GossipDigest ours = MakeCatalogDigest(local);
    const GossipDigest theirs = MakeCatalogDigest(remote);

    bool truncated = false;
    const auto missing = MissingRemoteIds(local, remote, &truncated);
    const auto bounded = BoundedWantList(missing);

    ReconcileResult r;
    r.want_ids = bounded;
    r.want_truncated = truncated;
    r.outbound = MakeWantGossip(ours, bounded);

    if (ours.catalog_digest_hex == theirs.catalog_digest_hex &&
        ours.entry_count == theirs.entry_count) {
        r.status = ReconcileStatus::EQUAL;
        r.want_ids.clear();
        r.want_truncated = false;
        r.outbound.want_ids.clear();
    } else if (!r.outbound.want_ids.empty()) {
        r.status = ReconcileStatus::WANT;
    } else {
        r.status = ReconcileStatus::EQUAL;
    }

    std::string err;
    if (!FinalizeOutbound(r.outbound, err)) {
        r.status = ReconcileStatus::REJECT;
        r.err = err;
    }
    return r;
}

ReconcileResult IndexReconciler::CompareRange(const std::vector<std::string>& local_ids,
                                              const ReconcileRange& remote, int depth) const
{
    if (depth >= RECONCILE_RECURSION_MAX) {
        return Reject("reconciliation depth");
    }
    const auto all = SortedUniqueIds(local_ids);
    std::vector<std::string> slice;
    for (const auto& id : all) {
        if (!remote.lo.empty() && id < remote.lo) continue;
        if (!remote.hi.empty() && id > remote.hi) continue;
        slice.push_back(id);
    }
    const ReconcileRange ours = slice.empty() ? ReconcileRange{}
                                              : DigestIdRange(slice, 0, slice.size());
    GossipMessage msg;
    msg.digest.catalog_digest_hex = ours.digest_hex;
    msg.digest.entry_count = ours.count;
    msg.secret_bearing = false;

    ReconcileResult r;
    if (ours.digest_hex == remote.digest_hex && ours.count == remote.count) {
        r.status = ReconcileStatus::EQUAL;
        r.outbound = msg;
        std::string err;
        if (!FinalizeOutbound(r.outbound, err)) {
            r.status = ReconcileStatus::REJECT;
            r.err = err;
        }
        return r;
    }
    if (slice.size() > RECONCILE_WANT_MAX && depth + 1 < RECONCILE_RECURSION_MAX) {
        r.status = ReconcileStatus::DIVIDE;
        const size_t mid = slice.size() / 2;
        r.left = DigestIdRange(slice, 0, mid);
        r.right = DigestIdRange(slice, mid, slice.size());
        r.outbound = msg;
    } else {
        // No remote IDs in this message: advertise our digest only. IWANT is
        // filled by CompareSets once the peer sends an IHAVE ID list.
        r.status = ReconcileStatus::WANT;
        r.outbound = msg;
    }
    std::string err;
    if (!FinalizeOutbound(r.outbound, err)) {
        r.status = ReconcileStatus::REJECT;
        r.err = err;
    }
    return r;
}

} // namespace modelnet
