// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_EXECUTE_H
#define BITCOIN_MODELNET_PACKAGE_EXECUTE_H

#include <modelnet/package_acquisition.h>
#include <modelnet/transfer_session.h>

#include <string>
#include <vector>

namespace modelnet {

/** Isolated FREE_ONLY materialization. Not a live swarm fetch and not a spend. */
inline constexpr uint64_t ACQ_EXECUTE_MAX_FILE_BYTES = 8ull << 20;
inline constexpr size_t ACQ_EXECUTE_MAX_FILES = 32;

struct VerifiedLocalFile {
    std::string relative_path;
    std::string sha384_hex;
    std::string source_path;
};

struct ExecuteAcquisitionRequest {
    AcquisitionPlan plan;
    std::vector<VerifiedLocalFile> files;
    CreditBroker* credit{nullptr};
    uint64_t reserve_bytes{0};
    bool hold_lease{true};
};

struct OutputLease {
    std::string lease_id;
    std::string path;
    bool active{true};
};

bool MaterializePathAllowed(const std::string& rel_path, std::string& err);
bool Sha384Path(const std::string& path, std::string& hex, std::string& err);
bool ExclusiveNofollowWrite(const std::string& dest_path, const std::string& bytes, std::string& err_code,
                            std::string& err);

/**
 * Hash-verify local files into plan.destination. Filename presence is never
 * readiness. A mismatched cache file is discarded and replaced from source, or
 * the execute fails MODEL_BYTES_UNVERIFIED if no source remains.
 * FREE_ONLY only. Does not spend. Does not start a runtime.
 */
bool ExecuteBtxAcquisition(const ExecuteAcquisitionRequest& req, AcquisitionReceipt& out, uint64_t& reserved_bytes,
                           std::string& err_code, std::string& err);

/** GC/eviction must not delete an ACTIVE_LEASE path. */
bool TryEvictUnleasedPath(const std::string& path, const std::vector<OutputLease>& leases, std::string& err_code,
                           std::string& err);

CreditBroker& GlobalAcquisitionCredits();

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_EXECUTE_H
