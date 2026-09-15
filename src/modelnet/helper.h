// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_HELPER_H
#define BITCOIN_MODELNET_HELPER_H

#include <modelnet/auto_storage.h>
#include <modelnet/catalog.h>
#include <modelnet/transport_pq.h>
#include <univalue.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

struct NativeRequest {
    std::string method;
    std::string path;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

struct NativeResponse {
    int status{200};
    std::string content_type{"application/json"};
    std::string body;
    std::vector<unsigned char> raw;
    bool binary{false};
    std::vector<std::pair<std::string, std::string>> headers;
    bool splice_tcp{false};
    std::string splice_host;
    uint16_t splice_port{0};
};

struct HelperConfig {
    fs::path modeldir;
    StorageMode storage_mode{StorageMode::AUTO};
    uint64_t quota_bytes{0};
    uint64_t auto_cap_bytes{0};
    uint64_t free_space_reserve_bytes{0};
    std::string bind; // host:port; empty = unix RPC only
    fs::path rpc_socket;
    fs::path tls_cert;
    fs::path tls_key;
    bool relay{false};
    bool host{false};
    bool public_host_reachable{false};
    std::string seed{"auto"};
    bool preserve_rare{false};
    bool follow_peers{true};
    bool allow_encrypted{false};
    uint64_t upload_bps{0};
    std::vector<std::string> peers;
};

bool ParseHttpRequest(const std::string& raw, NativeRequest& req, std::string& err);
std::string FormatHttpResponse(const NativeResponse& resp);

bool HandleNativeRequest(ModelCatalog& cat, const NativeRequest& req, NativeResponse& resp);

/** ISO-01: native HTTP is served only after a verified PQ1 session (HandlePq1Fd). */
bool NativeHttpRequiresVerifiedPq1();
/** Advertised /btx-model/2/ paths from capabilities.http. */
std::vector<std::string> AdvertisedNativeHttpPaths();

bool DispatchHelperRpc(ModelCatalog& cat, const UniValue& request, UniValue& result, std::string& err_code, std::string& err, std::atomic<bool>* stop = nullptr);

bool EnsureMlDsaTlsFiles(const fs::path& cert, const fs::path& key, std::string& err);
bool LoadPq1Identity(Pq1Context& pq, const fs::path& modeldir, std::string& err);

int RunModelDaemon(HelperConfig cfg, std::atomic<bool>* stop = nullptr);

bool CallUnixRpc(const fs::path& socket_path, const std::string& method, const UniValue& params, UniValue& result, std::string& err);

/** Filled by RetrieveFreeFromPeer; atomics so getmodeljob can read a running job. */
struct RetrieveProgress {
    std::atomic<uint64_t> bytes_committed{0};
    std::atomic<uint64_t> pieces_committed{0};
    std::atomic<uint32_t> file_index{0};
    std::atomic<uint32_t> piece_index{0};
    std::atomic<int> inflight{0};
    std::atomic<int> peer_retries{0};
    /** Extra-peer pieces that finished the file after the primary contact failed. */
    std::atomic<int> peer_failovers{0};
    /** Unix epoch ms; updated only when bytes_committed changes. */
    std::atomic<uint64_t> last_commit_ms{0};
};

/** Newest-first: higher created_ms wins; equal timestamps sort by job_id descending. */
inline bool RetrieveJobIsNewer(int64_t created_a, const std::string& id_a,
                               int64_t created_b, const std::string& id_b)
{
    if (created_a != created_b) return created_a > created_b;
    return id_a > id_b;
}

bool RetrieveFreeFromPeer(ModelCatalog& cat, Pq1Context& pq, const std::string& host, uint16_t port,
                           const Digest48& model_id, std::string& err, std::atomic<bool>* stop = nullptr,
                           const fs::path& pinfile = {}, RetrieveProgress* progress = nullptr,
                           const std::vector<std::string>& extra_peers = {});

} // namespace modelnet

#endif // BITCOIN_MODELNET_HELPER_H
