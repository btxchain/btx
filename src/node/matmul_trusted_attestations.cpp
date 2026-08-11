// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/matmul_trusted_attestations.h>

#include <key_io.h>
#include <logging.h>
#include <span.h>
#include <streams.h>
#include <support/cleanse.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <set>
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
    std::chrono::milliseconds wait_timeout{60'000};
};
std::optional<StagedConfiguration> g_staged;
bool g_trusted_mirror{false};
bool g_serve_attestations{false};
std::chrono::milliseconds g_wait_timeout{60'000};
//! Highest height of a configured-signer attestation observed this process.
int32_t g_highest_attested_height{-1};
//! Soft hint: max best-known height among peers that recently served MMATTEST.
int32_t g_authority_peer_tip_hint{-1};

fs::path g_persist_path;
bool g_persist_enabled{false};

std::mutex g_reverify_mutex;
double g_reverify_tokens{HistoricalReverifyBudget::BURST};
std::chrono::steady_clock::time_point g_reverify_last_refill{
    std::chrono::steady_clock::now()};
std::set<uint256> g_reverify_queued;
std::set<uint256> g_reverify_inflight;

constexpr char PERSIST_MAGIC[16] = "BTX_MMATTEST_V1";
//! Bound the on-disk rewrite so a corrupt/oversized file cannot DoS startup.
constexpr size_t PERSIST_MAX_BYTES{32 * 1024 * 1024};

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

void RefillReverifyTokensLocked(
    std::chrono::steady_clock::time_point now)
{

    const auto elapsed{now - g_reverify_last_refill};
    const double refill{
        static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                .count()) /
        static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                HistoricalReverifyBudget::REFILL)
                .count())};
    if (refill <= 0.0) return;
    g_reverify_tokens = std::min(HistoricalReverifyBudget::BURST,
                                 g_reverify_tokens + refill);
    g_reverify_last_refill = now;
}

bool FlushPersistenceLocked(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error)
{

    if (!g_persist_enabled || g_persist_path.empty() || !store) {
        return true;
    }
    const auto attestations{store->ExportAll()};
    DataStream encoded;
    encoded.write(AsBytes(Span{PERSIST_MAGIC, sizeof(PERSIST_MAGIC)}));
    encoded << static_cast<uint64_t>(attestations.size());
    for (const auto& attestation : attestations) {
        encoded << attestation;
    }
    if (encoded.size() > PERSIST_MAX_BYTES) {
        error = "attestation archive exceeds size bound";
        return false;
    }
    const fs::path tmp{g_persist_path + ".tmp"};
    if (!WriteBinaryFile(tmp, std::string(encoded.begin(), encoded.end()))) {
        error = "failed to write attestation archive temp file";
        return false;
    }
    std::error_code ec;
    fs::rename(tmp, g_persist_path, ec);
    if (ec) {
        error = strprintf("failed to publish attestation archive: %s",
                          ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool LoadPersistenceLocked(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error)
{

    if (!g_persist_enabled || g_persist_path.empty() || !store) {
        return true;
    }
    if (!fs::exists(g_persist_path)) return true;
    const auto [ok, bytes]{ReadBinaryFile(g_persist_path, PERSIST_MAX_BYTES)};
    if (!ok) {
        error = "failed to read attestation archive";
        return false;
    }
    if (bytes.size() >= PERSIST_MAX_BYTES) {
        error = "attestation archive exceeds size bound";
        return false;
    }
    if (bytes.size() < sizeof(PERSIST_MAGIC)) {
        error = "attestation archive too short";
        return false;
    }
    try {
        DataStream encoded{MakeUCharSpan(bytes)};
        char magic[sizeof(PERSIST_MAGIC)];
        encoded.read(AsWritableBytes(Span{magic, sizeof(magic)}));
        if (std::memcmp(magic, PERSIST_MAGIC, sizeof(PERSIST_MAGIC)) != 0) {
            error = "attestation archive magic mismatch";
            return false;
        }
        uint64_t count{0};
        encoded >> count;
        if (count > 16384) {
            error = "attestation archive count exceeds bound";
            return false;
        }
        std::vector<matmul::trusted::ExactReplayAttestation> loaded;
        loaded.reserve(count);
        for (uint64_t i = 0; i < count; ++i) {
            matmul::trusted::ExactReplayAttestation attestation;
            encoded >> attestation;
            loaded.push_back(std::move(attestation));
        }
        if (!encoded.empty()) {
            error = "attestation archive has trailing data";
            return false;
        }
        size_t accepted{0};
        for (const auto& attestation : loaded) {
            const auto result{store->Add(
                attestation, attestation.statement.block_hash,
                attestation.statement.block_height)};
            if (result == matmul::trusted::AddResult::Accepted ||
                result == matmul::trusted::AddResult::Duplicate) {
                ++accepted;
                if (attestation.statement.block_height >
                    g_highest_attested_height) {
                    g_highest_attested_height =
                        attestation.statement.block_height;
                }
            }
        }
        LogPrintf(
            "Loaded %zu MatMul ExactReplay attestation(s) from %s\n",
            accepted, fs::PathToString(g_persist_path));
        return true;
    } catch (const std::exception& e) {
        error = strprintf("attestation archive decode failed: %s", e.what());
        return false;
    }
}

void PersistAfterMutation(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store)
{
    std::string error;
    std::lock_guard lock{g_mutex};
    if (!FlushPersistenceLocked(store, error)) {
        LogWarning("MatMul attestation archive flush failed: %s\n", error);
    }
}

void ResetHistoricalReverifyBudgetUnlocked()
{
    g_reverify_tokens = HistoricalReverifyBudget::BURST;
    g_reverify_last_refill = std::chrono::steady_clock::now();
    g_reverify_queued.clear();
    g_reverify_inflight.clear();
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
    g_wait_timeout = std::chrono::milliseconds{60'000};
    g_highest_attested_height = -1;
    g_authority_peer_tip_hint = -1;
    g_persist_enabled = false;
    g_persist_path.clear();
}

void ResetForTest()
{
    Reset();
    {
        std::lock_guard lock{g_reverify_mutex};
        ResetHistoricalReverifyBudgetUnlocked();
    }
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
    const auto result{store->Add(attestation, expected_hash, expected_height)};
    // Accepted and Duplicate both prove a configured signer attested this
    // height; advance the local frontier high-water mark either way.
    if (result == matmul::trusted::AddResult::Accepted ||
        result == matmul::trusted::AddResult::Duplicate) {
        NoteAcceptedAttestationHeight(expected_height);
    }
    if (result == matmul::trusted::AddResult::Accepted) {
        PersistAfterMutation(store);
    }
    return result;
}

matmul::trusted::AddResult SignAuthoritative(
    const uint256& block_hash,
    int32_t block_height,
    matmul::trusted::ExactReplayAttestation* produced)
{
    auto store{Store()};
    if (!store) return matmul::trusted::AddResult::NoLocalSigner;
    const auto result{store->SignLocal(block_hash, block_height, produced)};
    if (result == matmul::trusted::AddResult::Accepted ||
        result == matmul::trusted::AddResult::Duplicate) {
        NoteAcceptedAttestationHeight(block_height);
    }
    if (result == matmul::trusted::AddResult::Accepted) {
        PersistAfterMutation(store);
    }
    return result;
}

std::optional<matmul::trusted::UtxoSnapshotSignature> SignUtxoSnapshot(
    const matmul::trusted::UtxoSnapshotStatement& statement)
{
    auto store{Store()};
    if (!store) return std::nullopt;
    return store->SignUtxoSnapshot(statement);
}

matmul::trusted::UtxoSnapshotVerifyResult VerifyUtxoSnapshotManifest(
    const matmul::trusted::UtxoSnapshotManifest& manifest)
{
    auto store{Store()};
    if (!store) {
        return matmul::trusted::UtxoSnapshotVerifyResult::ThresholdNotMet;
    }
    return matmul::trusted::VerifyUtxoSnapshotManifestSelfConsistent(
        manifest, store->ChainId(), store->ReplayAuthorityContext(),
        store->TrustedSigners(), store->Threshold());
}

std::optional<uint256> ChainId()
{
    auto store{Store()};
    if (!store) return std::nullopt;
    return store->ChainId();
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

std::optional<int32_t> HighestAttestedHeight()
{
    std::lock_guard lock{g_mutex};
    if (g_highest_attested_height < 0) return std::nullopt;
    return g_highest_attested_height;
}

std::optional<int32_t> AuthorityPeerTipHint()
{
    std::lock_guard lock{g_mutex};
    if (g_authority_peer_tip_hint < 0) return std::nullopt;
    return g_authority_peer_tip_hint;
}

std::optional<int32_t> AuthorityAttestedFrontier()
{
    std::lock_guard lock{g_mutex};
    const int32_t frontier{
        std::max(g_highest_attested_height, g_authority_peer_tip_hint)};
    if (frontier < 0) return std::nullopt;
    return frontier;
}

void NoteAcceptedAttestationHeight(int32_t height)
{
    if (height < 0) return;
    std::lock_guard lock{g_mutex};
    if (height > g_highest_attested_height) {
        g_highest_attested_height = height;
    }
}

void NoteAuthorityPeerTipHint(int32_t height)
{
    if (height < 0) return;
    std::lock_guard lock{g_mutex};
    if (height > g_authority_peer_tip_hint) {
        g_authority_peer_tip_hint = height;
    }
}

bool OpenPersistence(const fs::path& path, std::string& error)
{
    auto store{Store()};
    if (!store) {
        error = "attestation store is not configured";
        return false;
    }
    store->SetDurableRetention(true);
    std::lock_guard lock{g_mutex};
    g_persist_path = path;
    g_persist_enabled = true;
    if (!LoadPersistenceLocked(store, error)) {
        g_persist_enabled = false;
        g_persist_path.clear();
        return false;
    }
    return true;
}

void ClosePersistence()
{
    std::lock_guard lock{g_mutex};
    g_persist_enabled = false;
    g_persist_path.clear();
}

bool PersistenceEnabled()
{
    std::lock_guard lock{g_mutex};
    return g_persist_enabled;
}

bool FlushPersistence(std::string& error)
{
    auto store{Store()};
    std::lock_guard lock{g_mutex};
    return FlushPersistenceLocked(store, error);
}

HistoricalReverifyAdmit TryAdmitHistoricalReverify(
    const uint256& block_hash)
{
    std::lock_guard lock{g_reverify_mutex};
    RefillReverifyTokensLocked(std::chrono::steady_clock::now());
    if (g_reverify_queued.count(block_hash) != 0 ||
        g_reverify_inflight.count(block_hash) != 0) {
        return HistoricalReverifyAdmit::AlreadyQueued;
    }
    if (g_reverify_inflight.size() >=
        HistoricalReverifyBudget::INFLIGHT_MAX) {
        return HistoricalReverifyAdmit::InflightFull;
    }
    if (g_reverify_queued.size() >= HistoricalReverifyBudget::QUEUE_MAX) {
        return HistoricalReverifyAdmit::QueueFull;
    }
    if (g_reverify_tokens < 1.0) {
        return HistoricalReverifyAdmit::RateLimited;
    }
    g_reverify_tokens -= 1.0;
    g_reverify_queued.insert(block_hash);
    return HistoricalReverifyAdmit::Allow;
}

void NoteHistoricalReverifyStarted(const uint256& block_hash)
{
    std::lock_guard lock{g_reverify_mutex};
    g_reverify_queued.erase(block_hash);
    g_reverify_inflight.insert(block_hash);
}

void NoteHistoricalReverifyFinished(const uint256& block_hash)
{
    std::lock_guard lock{g_reverify_mutex};
    g_reverify_queued.erase(block_hash);
    g_reverify_inflight.erase(block_hash);
}

void ResetHistoricalReverifyBudgetForTest()
{
    std::lock_guard lock{g_reverify_mutex};
    ResetHistoricalReverifyBudgetUnlocked();
}

size_t HistoricalReverifyQueuedForTest()
{
    std::lock_guard lock{g_reverify_mutex};
    return g_reverify_queued.size();
}

size_t HistoricalReverifyInflightForTest()
{
    std::lock_guard lock{g_reverify_mutex};
    return g_reverify_inflight.size();
}

} // namespace node::matmul_trusted
