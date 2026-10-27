// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifndef BITCOIN_MODELNET_LOAD01_LOAD01_H
#define BITCOIN_MODELNET_LOAD01_LOAD01_H
#include <modelnet/nifdt_contract/contract.h>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace modelnet {
/** Transport identity attests to one immutable checkpoint and request nonce.
 * Key identity is cryptographically verified; it is not proof of a distinct
 * physical host. The local coordinator must pin the expected source key. */
struct CheckpointSourceReceipt {
    std::string artifact_id;
    std::string checkpoint_sha384;
    uint64_t bytes{0};
    std::string request_nonce;
    int64_t expires_at_ms{0};
    std::vector<unsigned char> source_public_key;
    std::vector<unsigned char> signature;
};
std::vector<unsigned char> CheckpointSourceMessage(const CheckpointSourceReceipt& receipt);
struct LoadedCheckpointTensor {
    std::string dtype;
    std::vector<uint64_t> shape;
    uint64_t begin{0};
    uint64_t end{0};
};

/** ASR-ART-005. Native SafeTensors loading with SHA-384 and signed provenance.
 * Load() retains the legacy FNV integrity-only API and now accepts another
 * path; it does not grant trust or qualify deployment. LoadVerified() checks
 * ML-DSA-44, an expected peer key, nonce, expiry, SHA-384, tensor shapes and
 * exact data extents before committing resident bytes. TensorBytes and
 * LinearF32 consume those same bytes, avoiding a path-reopen race.
 * Two signed source identities are recorded only after successful loads of
 * the SAME checkpoint. None of this fabricates GPU or physical-host evidence.
 */
class Load01 {
public:
    bool Load(const std::string& source_path, const std::string& digest_hex, std::string& err);
    bool LoadVerified(const std::string& source_path, const CheckpointSourceReceipt& receipt,
                      const std::vector<unsigned char>& expected_source_key,
                      const std::string& expected_nonce, int64_t now_ms, uint64_t max_bytes,
                      std::string& err);
    std::span<const unsigned char> TensorBytes(const std::string& name) const;
    const std::map<std::string, LoadedCheckpointTensor>& tensors() const { return m_tensors; }
    /** A real bounded CPU dense layer. Output is committed only on success. */
    bool LinearF32(const std::string& weights, const std::string& bias,
                   std::span<const float> input, std::vector<float>& output, std::string& err);
    bool loaded() const { return m_loaded; }
    bool verified_resident() const { return m_verified; }
    bool consumed() const { return m_consumed; }
    size_t verified_source_count() const { return m_sources.size(); }
    const std::string& checkpoint_sha384() const { return m_checkpoint; }
    int64_t bytes_read() const { return m_bytes; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    bool passed() const { return m_verified && m_consumed && m_sources.size() >= 2; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
private:
    bool m_loaded{false};
    bool m_verified{false};
    bool m_consumed{false};
    int64_t m_bytes{0};
    std::string m_source;
    std::string m_checkpoint;
    std::string m_artifact;
    std::vector<unsigned char> m_resident;
    std::map<std::string, LoadedCheckpointTensor> m_tensors;
    std::set<std::vector<unsigned char>> m_sources;
};
} // namespace modelnet
#endif
