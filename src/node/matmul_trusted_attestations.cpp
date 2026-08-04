// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/matmul_trusted_attestations.h>

#include <key_io.h>
#include <support/cleanse.h>

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace node::matmul_trusted {
namespace {

std::mutex g_mutex;
std::shared_ptr<matmul::trusted::AttestationStore> g_store;
struct StagedConfiguration {
    matmul::trusted::StoreConfig config;
    std::optional<std::string> local_signer_wif;
    bool trusted_mirror{false};
    bool serve_attestations{false};
    std::chrono::milliseconds wait_timeout{30'000};
};
std::optional<StagedConfiguration> g_staged;
bool g_trusted_mirror{false};
bool g_serve_attestations{false};
std::chrono::milliseconds g_wait_timeout{30'000};

void CleanseStagedConfigurationLocked()
{
    if (g_staged.has_value() &&
        g_staged->local_signer_wif.has_value()) {
        std::string& encoded{*g_staged->local_signer_wif};
        memory_cleanse(encoded.data(), encoded.size());
    }
    g_staged.reset();
}

std::shared_ptr<matmul::trusted::AttestationStore> Store()
{
    std::lock_guard lock{g_mutex};
    return g_store;
}

} // namespace

bool Configure(matmul::trusted::StoreConfig config,
               bool trusted_mirror,
               bool serve_attestations,
               std::chrono::milliseconds wait_timeout,
               std::string& error)
{
    if (wait_timeout < std::chrono::milliseconds{0} ||
        wait_timeout > std::chrono::minutes{10}) {
        error = "trusted attestation wait must be between 0 and 600000 ms";
        return false;
    }
    try {
        auto store{
            std::make_shared<matmul::trusted::AttestationStore>(
                std::move(config))};
        std::lock_guard lock{g_mutex};
        g_store = std::move(store);
        CleanseStagedConfigurationLocked();
        g_trusted_mirror = trusted_mirror;
        g_serve_attestations = serve_attestations;
        g_wait_timeout = wait_timeout;
        return true;
    } catch (const std::invalid_argument& e) {
        error = e.what();
        return false;
    }
}

bool StageConfiguration(matmul::trusted::StoreConfig config,
                        std::optional<std::string> local_signer_wif,
                        bool trusted_mirror,
                        bool serve_attestations,
                        std::chrono::milliseconds wait_timeout,
                        std::string& error)
{
    if (wait_timeout < std::chrono::milliseconds{0} ||
        wait_timeout > std::chrono::minutes{10}) {
        if (local_signer_wif.has_value()) {
            memory_cleanse(
                local_signer_wif->data(),
                local_signer_wif->size());
        }
        error = "trusted attestation wait must be between 0 and 600000 ms";
        return false;
    }
    std::lock_guard lock{g_mutex};
    g_store.reset();
    CleanseStagedConfigurationLocked();
    g_staged = StagedConfiguration{
        std::move(config), std::move(local_signer_wif), trusted_mirror,
        serve_attestations, wait_timeout};
    g_trusted_mirror = trusted_mirror;
    g_serve_attestations = serve_attestations;
    g_wait_timeout = wait_timeout;
    return true;
}

bool FinalizeConfiguration(std::string& error)
{
    std::optional<StagedConfiguration> staged;
    {
        std::lock_guard lock{g_mutex};
        if (!g_staged.has_value()) return true;
        staged = std::move(g_staged);
        g_staged.reset();
    }

    // Public-key derivation requires the process ECC signing context. This is
    // deliberately deferred from AppInitParameterInteraction to AppInitMain.
    if (staged->local_signer_wif.has_value()) {
        std::string& encoded{*staged->local_signer_wif};
        CKey key{DecodeSecret(encoded)};
        memory_cleanse(encoded.data(), encoded.size());
        staged->local_signer_wif.reset();
        if (!key.IsValid() || !key.IsCompressed()) {
            error = "invalid compressed WIF in MatMul attestation signer configuration";
            return false;
        }
        const CPubKey local_pubkey{key.GetPubKey()};
        if (std::find(staged->config.trusted_signers.begin(),
                      staged->config.trusted_signers.end(),
                      local_pubkey) ==
            staged->config.trusted_signers.end()) {
            staged->config.trusted_signers.push_back(local_pubkey);
        }
        staged->config.local_signer = std::move(key);
    }
    return Configure(
        std::move(staged->config), staged->trusted_mirror,
        staged->serve_attestations, staged->wait_timeout, error);
}

void Reset()
{
    std::lock_guard lock{g_mutex};
    g_store.reset();
    CleanseStagedConfigurationLocked();
    g_trusted_mirror = false;
    g_serve_attestations = false;
    g_wait_timeout = std::chrono::milliseconds{30'000};
}

void ResetForTest()
{
    Reset();
}

bool IsConfigured()
{
    return static_cast<bool>(Store());
}

bool IsTrustedMirror()
{
    std::lock_guard lock{g_mutex};
    return g_store != nullptr && g_trusted_mirror;
}

bool ServesAttestations()
{
    std::lock_guard lock{g_mutex};
    return g_store != nullptr && g_serve_attestations;
}

bool HasLocalSigner()
{
    auto store{Store()};
    return store && store->LocalSignerPubKey().has_value();
}

std::chrono::milliseconds WaitTimeout()
{
    std::lock_guard lock{g_mutex};
    return g_wait_timeout;
}

size_t Threshold()
{
    auto store{Store()};
    return store ? store->Threshold() : 0;
}

std::vector<CPubKey> TrustedSigners()
{
    auto store{Store()};
    if (!store) return {};
    return {store->TrustedSigners().begin(), store->TrustedSigners().end()};
}

std::optional<CPubKey> LocalSigner()
{
    auto store{Store()};
    return store ? store->LocalSignerPubKey() : std::nullopt;
}

std::optional<uint256> ReplayAuthorityContext()
{
    auto store{Store()};
    if (!store) return std::nullopt;
    return store->ReplayAuthorityContext();
}

matmul::trusted::AddResult Add(
    const matmul::trusted::ExactReplayAttestation& attestation,
    const uint256& expected_hash,
    int32_t expected_height)
{
    auto store{Store()};
    if (!store) return matmul::trusted::AddResult::UntrustedSigner;
    return store->Add(attestation, expected_hash, expected_height);
}

matmul::trusted::AddResult SignAuthoritative(
    const uint256& block_hash,
    int32_t block_height,
    matmul::trusted::ExactReplayAttestation* produced)
{
    auto store{Store()};
    if (!store) return matmul::trusted::AddResult::NoLocalSigner;
    return store->SignLocal(block_hash, block_height, produced);
}

bool HasQuorum(const uint256& block_hash, int32_t block_height)
{
    auto store{Store()};
    return store && store->HasQuorum(block_hash, block_height);
}

matmul::trusted::WaitResult WaitForQuorum(
    const uint256& block_hash,
    int32_t block_height,
    const std::function<bool()>& cancelled,
    std::vector<matmul::trusted::ExactReplayAttestation>* quorum)
{
    auto store{Store()};
    if (!store) return matmul::trusted::WaitResult::Timeout;
    return store->WaitForQuorum(block_hash, block_height, WaitTimeout(),
                                cancelled, quorum);
}

std::vector<matmul::trusted::ExactReplayAttestation> Get(
    const uint256& block_hash, int32_t block_height)
{
    auto store{Store()};
    return !store
        ? std::vector<matmul::trusted::ExactReplayAttestation>{}
        : store->GetAttestations(block_hash, block_height);
}

matmul::trusted::StoreStats Stats()
{
    auto store{Store()};
    return !store ? matmul::trusted::StoreStats{} : store->GetStats();
}

} // namespace node::matmul_trusted
