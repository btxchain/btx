// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guard.h>

#include <limits>

namespace modelnet {
namespace {

bool Multiply(int64_t left, int64_t right, int64_t& out)
{
    if (left <= 0 || right <= 0) return false;
    if (left > std::numeric_limits<int64_t>::max() / right) return false;
    out = left * right;
    return true;
}

} // namespace

bool SwarmOfferWork(const std::set<std::string>& quarantined, const std::string& digest, std::string& err)
{
    if (digest.empty() || quarantined.count(digest) != 0) {
        err = "QUARANTINE";
        return false;
    }
    err.clear();
    return true;
}

SwarmRecompute SwarmRecomputeAfter(bool mismatch, bool gap, bool expired, bool nonfinite, std::string& err)
{
    SwarmRecompute result;
    if (mismatch || gap || expired || nonfinite) {
        result.recompute = true;
        result.code = "RECOMPUTE";
        err = "RECOMPUTE";
        return result;
    }
    err.clear();
    return result;
}

bool SwarmKvBytes(int64_t layers, int64_t kv_heads, int64_t head_dim, int64_t prefix_tokens, int64_t bytes_per_element, int64_t& out, std::string& err)
{
    int64_t product = 0;
    if (!Multiply(2, layers, product) || !Multiply(product, kv_heads, product) || !Multiply(product, head_dim, product) ||
        !Multiply(product, prefix_tokens, product) || !Multiply(product, bytes_per_element, product)) {
        out = 0;
        err = "KV_GEOMETRY";
        return false;
    }
    out = product;
    err.clear();
    return true;
}

bool SwarmCacheStandsAlone(bool replaces_replay, bool replaces_admission, bool replaces_work_evidence, bool replaces_execution_grant, bool replaces_independent_evaluation, std::string& err)
{
    if (replaces_replay || replaces_admission || replaces_work_evidence || replaces_execution_grant || replaces_independent_evaluation) {
        err = "CACHE_ASSURANCE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAcceptStorageKey(const std::string& key, std::string& err)
{
    if (key.empty() || key.find('/') != std::string::npos || key.find('\\') != std::string::npos || key.find("..") != std::string::npos) {
        err = "PEER_PATH";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmManifestPieceCount(int64_t pieces, std::string& err)
{
    if (pieces <= 0 || pieces > 16384) {
        err = "MANIFEST_CAP";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmRecordMeasurement(bool supplied, bool finite, bool& measured_benchmark, std::string& err)
{
    if (!supplied || !finite) {
        measured_benchmark = false;
        err = supplied ? "MEASUREMENT" : "";
        return !supplied;
    }
    measured_benchmark = true;
    err.clear();
    return true;
}

} // namespace modelnet
