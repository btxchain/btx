// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H
#define BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H

#include <matmul/trusted_exact_replay_attestation.h>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace node::matmul_trusted {

/** Process-local operator trust runtime.
 *
 * The core attestation store is consensus-neutral. This adapter records the
 * explicit node role and is the sole seam used by validation, P2P, and RPC.
 * Configure once during startup, before any validation worker is created.
 */
bool Configure(matmul::trusted::StoreConfig config,
               bool trusted_mirror,
               bool serve_attestations,
               std::chrono::milliseconds wait_timeout,
               std::string& error);
/**
 * Stage startup configuration before the process signing context exists.
 *
 * AppInitParameterInteraction runs before ECC_Context is constructed, so it
 * must not derive the local signer's public key. FinalizeConfiguration must be
 * called from AppInitMain after ECC initialization and before networking or
 * validation starts.
 */
bool StageConfiguration(matmul::trusted::StoreConfig config,
                        std::optional<std::string> local_signer_wif,
                        bool trusted_mirror,
                        bool serve_attestations,
                        std::chrono::milliseconds wait_timeout,
                        std::string& error);
bool FinalizeConfiguration(std::string& error);
void Reset();
void ResetForTest();

[[nodiscard]] bool IsConfigured();
[[nodiscard]] bool IsTrustedMirror();
[[nodiscard]] bool ServesAttestations();
[[nodiscard]] bool HasLocalSigner();
[[nodiscard]] std::chrono::milliseconds WaitTimeout();
[[nodiscard]] size_t Threshold();
[[nodiscard]] std::vector<CPubKey> TrustedSigners();
[[nodiscard]] std::optional<CPubKey> LocalSigner();
[[nodiscard]] std::optional<uint256> ReplayAuthorityContext();

[[nodiscard]] matmul::trusted::AddResult Add(
    const matmul::trusted::ExactReplayAttestation& attestation,
    const uint256& expected_hash,
    int32_t expected_height);
[[nodiscard]] matmul::trusted::AddResult SignAuthoritative(
    const uint256& block_hash,
    int32_t block_height,
    matmul::trusted::ExactReplayAttestation* produced = nullptr);
/**
 * Sign a UTXO snapshot statement with the configured local attestation key.
 * Returns nullopt when unconfigured or the statement's chain/authority fields
 * do not match the local trusted-mirror configuration.
 */
[[nodiscard]] std::optional<matmul::trusted::UtxoSnapshotSignature>
SignUtxoSnapshot(const matmul::trusted::UtxoSnapshotStatement& statement);
/**
 * Verify an attested-fast-forward manifest against the configured signer set
 * and threshold. Consensus nodes (no store) always fail closed.
 */
[[nodiscard]] matmul::trusted::UtxoSnapshotVerifyResult
VerifyUtxoSnapshotManifest(
    const matmul::trusted::UtxoSnapshotManifest& manifest);
[[nodiscard]] std::optional<uint256> ChainId();
[[nodiscard]] bool HasQuorum(const uint256& block_hash, int32_t block_height);
[[nodiscard]] matmul::trusted::WaitResult WaitForQuorum(
    const uint256& block_hash,
    int32_t block_height,
    const std::function<bool()>& cancelled,
    std::vector<matmul::trusted::ExactReplayAttestation>* quorum = nullptr);
[[nodiscard]] std::vector<matmul::trusted::ExactReplayAttestation> Get(
    const uint256& block_hash, int32_t block_height);
[[nodiscard]] matmul::trusted::StoreStats Stats();

} // namespace node::matmul_trusted

#endif // BTX_NODE_MATMUL_TRUSTED_ATTESTATIONS_H
