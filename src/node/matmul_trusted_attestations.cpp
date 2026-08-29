// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/matmul_trusted_attestations.h>

#include <chain.h>
#include <dbwrapper.h>
#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <pubkey.h>
#include <span.h>
#include <streams.h>
#include <support/cleanse.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <memory>
#include <set>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>

namespace node::matmul_trusted {
namespace {

std::mutex g_mutex;
std::shared_ptr<matmul::trusted::AttestationStore> g_store;
BlockIndexHeightLookup g_block_index_height;
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
uint256 g_authority_peer_tip_hash{};
//! Recent attested (height -> hashes). Keep every quorum hash at a height,
//! not last-writer: dual-attested siblings (live 2026-08-15) must both stay
//! visible to FindUniqueCompetingAttestedIndex after restart.
std::map<int32_t, std::set<uint256>> g_attested_by_height;
//! Pin-quorum hashes at every height, not just the 512-block FMWC hint
//! window. HasCompetingQuorum / SignAuthoritative consult this so an
//! evicted-height re-joining signer cannot mint a second twin.
std::map<int32_t, std::set<uint256>> g_quorum_hashes_by_height;
//! Height -> hash this process's local key already signed. Survives hot-cache
//! eviction; populated at durable load and on each local Sign. First hash wins.
std::map<int32_t, uint256> g_local_signed_hash_by_height;
static constexpr int32_t ATTESTED_FRONTIER_HINT_WINDOW{512};

fs::path g_persist_path;
bool g_persist_enabled{false};
bool g_open_state_dirty{false};
std::chrono::steady_clock::time_point g_open_state_last_persist{};
constexpr auto OPEN_STATE_PERSIST_DEBOUNCE{std::chrono::seconds{1}};

struct DurableAttestationKey {
    static constexpr uint8_t PREFIX{'a'};
    uint8_t prefix{PREFIX};
    uint256 authority_namespace{};
    int32_t height{-1};
    uint256 block_hash{};

    SERIALIZE_METHODS(DurableAttestationKey, obj)
    {
        READWRITE(obj.prefix, obj.authority_namespace, obj.height,
                  obj.block_hash);
    }

    friend bool operator<(const DurableAttestationKey& lhs,
                          const DurableAttestationKey& rhs)
    {
        return std::tie(lhs.authority_namespace, lhs.height, lhs.block_hash) <
               std::tie(rhs.authority_namespace, rhs.height, rhs.block_hash);
    }
};

struct DurableNamespacePrefix {
    uint8_t prefix{DurableAttestationKey::PREFIX};
    uint256 authority_namespace{};

    SERIALIZE_METHODS(DurableNamespacePrefix, obj)
    {
        READWRITE(obj.prefix, obj.authority_namespace);
    }
};

struct DurableOpenStateKey {
    static constexpr uint8_t PREFIX{'o'};
    uint8_t prefix{PREFIX};
    uint256 authority_namespace{};

    SERIALIZE_METHODS(DurableOpenStateKey, obj)
    {
        READWRITE(obj.prefix, obj.authority_namespace);
    }
};

struct DurableOpenState {
    std::vector<CPubKey> admitted{};
    std::vector<CPubKey> frozen{};

    SERIALIZE_METHODS(DurableOpenState, obj)
    {
        READWRITE(obj.admitted, obj.frozen);
    }
};

struct DurableBlocklistKey {
    static constexpr uint8_t PREFIX{'b'};
    uint8_t prefix{PREFIX};
    uint256 chain_id{};

    SERIALIZE_METHODS(DurableBlocklistKey, obj)
    {
        READWRITE(obj.prefix, obj.chain_id);
    }
};

struct DurableBlocklistState {
    std::vector<CPubKey> blocked{};

    SERIALIZE_METHODS(DurableBlocklistState, obj)
    {
        READWRITE(obj.blocked);
    }
};

// V5/RB-12 durable withdrawal tombstone (adv5): (height, hash) this node's own
// validated reorg disconnected while its local signer had voted. Seeded into
// the store's off-active-chain set at startup BEFORE attestations load, so a
// reloaded or relayed copy of our abandoned vote cannot re-form quorum.
struct DurableWithdrawnVoteKey {
    static constexpr uint8_t PREFIX{'w'};
    uint8_t prefix{PREFIX};
    uint256 authority_namespace{};
    int32_t height{-1};
    uint256 block_hash{};

    SERIALIZE_METHODS(DurableWithdrawnVoteKey, obj)
    {
        READWRITE(obj.prefix, obj.authority_namespace, obj.height,
                  obj.block_hash);
    }
};

struct DurableWithdrawnVotePrefix {
    uint8_t prefix{DurableWithdrawnVoteKey::PREFIX};
    uint256 authority_namespace{};

    SERIALIZE_METHODS(DurableWithdrawnVotePrefix, obj)
    {
        READWRITE(obj.prefix, obj.authority_namespace);
    }
};

//! Scalable authority history. The hot AttestationStore remains bounded;
//! historical quorum proofs live in LevelDB and are queried on demand.
std::unique_ptr<CDBWrapper> g_durable_db;
std::optional<uint256> g_durable_namespace;

uint256 AuthorityNamespace(
    const matmul::trusted::AttestationStore& store)
{
    HashWriter hasher;
    hasher << std::string{"BTX_MATMUL_AUTHORITY_DB_V1"}
           << store.ChainId() << store.ReplayAuthorityContext()
           << static_cast<uint64_t>(store.Threshold());
    for (const auto& signer : store.TrustedSigners()) hasher << signer;
    return hasher.GetHash();
}

std::mutex g_reverify_mutex;
double g_reverify_tokens{HistoricalReverifyBudget::BURST};
std::chrono::steady_clock::time_point g_reverify_last_refill{
    std::chrono::steady_clock::now()};
std::set<uint256> g_reverify_queued;
std::set<uint256> g_reverify_inflight;

constexpr char PERSIST_MAGIC[16] = "BTX_MMATTEST_V1";
constexpr char PERSIST_WAL_MAGIC[16] = "BTX_MMAT_WAL_V1";
//! Bound the on-disk rewrite so a corrupt/oversized file cannot DoS startup.
constexpr size_t PERSIST_MAX_BYTES{32 * 1024 * 1024};
constexpr size_t PERSIST_BATCH_MAX{256};

std::mutex g_persist_worker_mutex;
std::mutex g_persist_io_mutex;
std::condition_variable g_persist_worker_cv;
std::deque<matmul::trusted::ExactReplayAttestation> g_persist_pending;
std::thread g_persist_worker;
uint64_t g_persist_queued{0};
uint64_t g_persist_completed{0};
bool g_persist_stop{false};
std::string g_persist_worker_error;

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

bool AtomicWriteBytes(const fs::path& path, Span<const std::byte> bytes,
                      std::string& error)
{
    const fs::path tmp{path + ".tmp"};
    FILE* file{fsbridge::fopen(tmp, "wb")};
    if (!file) {
        error = "failed to open durable temp file";
        return false;
    }
    const size_t written{fwrite(bytes.data(), 1, bytes.size(), file)};
    const bool committed{written == bytes.size() && FileCommit(file)};
    const int close_result{fclose(file)};
    if (!committed || close_result != 0 || !RenameOver(tmp, path)) {
        std::error_code ec;
        fs::remove(tmp, ec);
        error = "failed to commit durable attestation file";
        return false;
    }
    DirectoryCommit(path.parent_path());
    return true;
}

bool ResetLegacyArchive(const fs::path& path, std::string& error)
{
    if (path.empty()) return true;
    DataStream encoded;
    encoded.write(AsBytes(Span{PERSIST_MAGIC, sizeof(PERSIST_MAGIC)}));
    encoded << uint64_t{0};
    return AtomicWriteBytes(path, Span{encoded.data(), encoded.size()}, error);
}

bool LoadOpenAttestorState(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store)
{
    if (!g_durable_db || !g_durable_namespace.has_value() || !store ||
        !store->OpenAttestorsEnabled()) {
        return true;
    }
    DurableOpenState state;
    const auto status{g_durable_db->TryRead(
        DurableOpenStateKey{.authority_namespace = *g_durable_namespace},
        state)};
    if (status.status == CDBWrapper::ReadStatus::Code::NOT_FOUND) return true;
    if (status.status != CDBWrapper::ReadStatus::Code::OK) return false;
    std::set<CPubKey> admitted{state.admitted.begin(), state.admitted.end()};
    std::set<CPubKey> frozen{state.frozen.begin(), state.frozen.end()};
    store->RestoreOpenAttestors(std::move(admitted), std::move(frozen));
    return true;
}

bool PersistOpenAttestorState(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error,
    bool force)
{
    if (!store || !store->OpenAttestorsEnabled()) return true;
    if (!g_durable_db || !g_durable_namespace.has_value()) return true;
    const auto now{std::chrono::steady_clock::now()};
    if (!force && g_open_state_last_persist.time_since_epoch().count() != 0 &&
        now - g_open_state_last_persist < OPEN_STATE_PERSIST_DEBOUNCE) {
        g_open_state_dirty = true;
        return true;
    }
    DurableOpenState state;
    const auto admitted{store->AdmittedOpenSigners()};
    const auto frozen{store->FrozenOpenSigners()};
    state.admitted.assign(admitted.begin(), admitted.end());
    state.frozen.assign(frozen.begin(), frozen.end());
    // Debounced writes skip fsync so a Heard flood cannot stall the WAL.
    // force=true (shutdown / Reset) still syncs.
    if (!g_durable_db->Write(
            DurableOpenStateKey{.authority_namespace = *g_durable_namespace},
            state, /*fSync=*/force)) {
        error = "failed to persist open-attestor admission state";
        g_open_state_dirty = true;
        return false;
    }
    g_open_state_dirty = false;
    g_open_state_last_persist = now;
    return true;
}

bool PersistOpenAttestorState(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error)
{
    return PersistOpenAttestorState(store, error, /*force=*/false);
}

bool LoadBlocklistState(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error)
{
    if (!g_durable_db || !store) return true;
    DurableBlocklistState state;
    const auto status{g_durable_db->TryRead(
        DurableBlocklistKey{.chain_id = store->ChainId()}, state)};
    if (status.status == CDBWrapper::ReadStatus::Code::NOT_FOUND) return true;
    if (status.status != CDBWrapper::ReadStatus::Code::OK) {
        error = "failed to read persisted attestation blocklist";
        return false;
    }
    std::set<CPubKey> blocked{state.blocked.begin(), state.blocked.end()};
    if (!store->RestoreRuntimeBlocked(std::move(blocked)) ||
        !store->PinQuorumReachable()) {
        error = "persisted attestation blocklist leaves fewer than M unblocked pin members or would block the local signer";
        return false;
    }
    return true;
}

bool PersistBlocklistState(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error)
{
    if (!store) return true;
    if (!g_durable_db) return true;
    DurableBlocklistState state;
    const auto runtime{store->RuntimeBlockedSigners()};
    state.blocked.assign(runtime.begin(), runtime.end());
    if (!g_durable_db->Write(
            DurableBlocklistKey{.chain_id = store->ChainId()},
            state, /*fSync=*/true)) {
        error = "failed to persist attestation blocklist";
        return false;
    }
    return true;
}

bool ImportAttestations(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::vector<matmul::trusted::ExactReplayAttestation> loaded,
    const fs::path& source, std::string& error)
{
    size_t accepted{0};
    size_t prior_authority{0};
    int32_t highest{-1};
    const uint256 authority_namespace{AuthorityNamespace(*store)};
    const auto local_pk{store->LocalSignerPubKey()};
    std::map<int32_t, uint256> local_signed;
    std::map<int32_t, std::set<uint256>> imported_quorum;
    std::map<DurableAttestationKey,
             std::vector<matmul::trusted::ExactReplayAttestation>> durable;
    for (size_t index{0}; index < loaded.size(); ++index) {
        const auto& attestation{loaded[index]};
        // Durable/WAL/archive records seed the signed frontier only for
        // current pin members. Open/Heard signatures are directory, not
        // authority; VerifyAttestationCrypto would mint a frontier from them.
        const auto verified{matmul::trusted::VerifyAttestation(
            attestation, store->ChainId(),
            store->ReplayAuthorityContext(),
            attestation.statement.block_hash,
            attestation.statement.block_height,
            store->TrustedSigners())};
        if (verified != matmul::trusted::VerifyResult::Valid) {
            // Flat V1 archives/WALs predate authority namespaces. Preserve
            // intentional chain/context/signer rotation by ignoring a
            // cryptographically valid record belonging to the prior
            // authority. Malformed records in either authority remain fatal.
            if (verified == matmul::trusted::VerifyResult::WrongChain ||
                verified == matmul::trusted::VerifyResult::WrongReplayAuthorityContext ||
                verified == matmul::trusted::VerifyResult::UntrustedSigner) {
                const std::set<CPubKey> self_signer{attestation.signer};
                const auto self_verified{matmul::trusted::VerifyAttestation(
                    attestation, attestation.statement.chain_id,
                    attestation.statement.replay_authority_context,
                    attestation.statement.block_hash,
                    attestation.statement.block_height, self_signer)};
                if (self_verified == matmul::trusted::VerifyResult::Valid) {
                    ++prior_authority;
                    continue;
                }
            }
            error = strprintf(
                "attestation archive record %zu from %s was rejected: %s",
                index, fs::PathToString(source),
                matmul::trusted::VerifyResultName(verified));
            return false;
        }
        const auto result{store->Add(
            attestation, attestation.statement.block_hash,
            attestation.statement.block_height)};
        if (result == matmul::trusted::AddResult::BlocklistedSigner ||
            result == matmul::trusted::AddResult::Heard ||
            result == matmul::trusted::AddResult::UntrustedSigner ||
            result == matmul::trusted::AddResult::FrozenSigner) {
            continue;
        }
        if (result != matmul::trusted::AddResult::Accepted &&
            result != matmul::trusted::AddResult::Duplicate &&
            result != matmul::trusted::AddResult::Capacity) {
            error = strprintf(
                "attestation archive record %zu from %s was rejected: %s",
                index, fs::PathToString(source),
                matmul::trusted::AddResultName(result));
            return false;
        }
        ++accepted;
        if (store->HasQuorum(attestation.statement.block_hash,
                             attestation.statement.block_height)) {
            highest = std::max(highest, attestation.statement.block_height);
            imported_quorum[attestation.statement.block_height].insert(
                attestation.statement.block_hash);
            if (local_pk.has_value()) {
                for (const auto& vote :
                     store->GetAttestations(attestation.statement.block_hash,
                                            attestation.statement.block_height)) {
                    if (vote.signer == *local_pk) {
                        local_signed.emplace(attestation.statement.block_height,
                                             attestation.statement.block_hash);
                    }
                }
            }
        }
        durable[DurableAttestationKey{
            .authority_namespace = authority_namespace,
            .height = attestation.statement.block_height,
            .block_hash = attestation.statement.block_hash}]
            .push_back(attestation);
    }
    if (!g_durable_db) {
        error = "durable attestation database is not open";
        return false;
    }
    CDBBatch batch{*g_durable_db};
    for (auto& [key, additions] : durable) {
        std::vector<matmul::trusted::ExactReplayAttestation> existing;
        const auto status{g_durable_db->TryRead(key, existing)};
        if (status.status != CDBWrapper::ReadStatus::Code::OK &&
            status.status != CDBWrapper::ReadStatus::Code::NOT_FOUND) {
            error = "failed to read durable attestation record during import";
            return false;
        }
        std::set<CPubKey> seen;
        for (const auto& item : existing) seen.insert(item.signer);
        for (auto& item : additions) {
            if (seen.insert(item.signer).second) {
                existing.push_back(std::move(item));
            }
        }
        if (existing.size() > store->MaxVotesPerBlock()) {
            error = "durable attestation record exceeds configured signer set";
            return false;
        }
        batch.Write(key, existing);
    }
    if (!durable.empty() && !g_durable_db->WriteBatch(batch, true)) {
        error = "failed to migrate durable attestation records";
        return false;
    }
    {
        std::lock_guard lock{g_mutex};
        g_highest_attested_height =
            std::max(g_highest_attested_height, highest);
        for (const auto& [height, hashes] : imported_quorum) {
            for (const auto& hash : hashes) {
                g_quorum_hashes_by_height[height].insert(hash);
            }
        }
        for (const auto& [height, hash] : local_signed) {
            g_local_signed_hash_by_height.emplace(height, hash);
        }
    }
    LogPrintf("Loaded %zu MatMul ExactReplay attestation(s) from %s\n",
              accepted, fs::PathToString(source));
    if (prior_authority != 0) {
        LogPrintf("Ignored %zu valid prior-authority MatMul attestation(s) from %s\n",
                  prior_authority, fs::PathToString(source));
    }
    return true;
}

bool LoadDurableAttestations(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    std::string& error)
{
    if (!g_durable_db) return true;
    const uint256 authority_namespace{AuthorityNamespace(*store)};
    std::unique_ptr<CDBIterator> cursor{g_durable_db->NewIterator()};
    // Seek to the one-byte namespace prefix. Seeking a fully serialized signed
    // height would incorrectly depend on LevelDB's bytewise ordering.
    cursor->Seek(DurableNamespacePrefix{
        .authority_namespace = authority_namespace});
    size_t records{0};
    int32_t highest{-1};
    const auto local_pk{store->LocalSignerPubKey()};
    std::map<int32_t, uint256> local_signed;
    std::map<int32_t, std::set<uint256>> all_quorum;
    // Verify the complete namespace, but hydrate only the newest cache-sized
    // tail. Adding every historical record to a full bounded store makes each
    // later insertion scan the entire cache for an eviction candidate.
    // Retaining the tail here keeps startup O(history * log(cache)) and the
    // subsequent hot-cache import linear in its configured capacity.
    using TailKey = std::pair<int32_t, uint256>;
    std::map<TailKey,
             std::vector<matmul::trusted::ExactReplayAttestation>> hot_tail;
    size_t hot_tail_attestations{0};
    for (; cursor->Valid(); cursor->Next()) {
        DurableAttestationKey key;
        if (!cursor->GetKey(key) ||
            key.prefix != DurableAttestationKey::PREFIX ||
            key.authority_namespace != authority_namespace) {
            break;
        }
        std::vector<matmul::trusted::ExactReplayAttestation> attestations;
        if (!cursor->GetValue(attestations) || attestations.empty() ||
            attestations.size() > store->MaxVotesPerBlock()) {
            error = "durable attestation database contains a malformed record";
            return false;
        }
        std::set<CPubKey> seen;
        std::vector<matmul::trusted::ExactReplayAttestation> pin_only;
        for (const auto& attestation : attestations) {
            if (attestation.statement.block_hash != key.block_hash ||
                attestation.statement.block_height != key.height ||
                !seen.insert(attestation.signer).second) {
                error = "durable attestation database key/value mismatch";
                return false;
            }
            const auto verified{matmul::trusted::VerifyAttestation(
                attestation, store->ChainId(),
                store->ReplayAuthorityContext(),
                key.block_hash, key.height,
                store->TrustedSigners())};
            if (verified != matmul::trusted::VerifyResult::Valid) {
                if (verified != matmul::trusted::VerifyResult::UntrustedSigner) {
                    error = strprintf(
                        "durable attestation database record rejected: %s",
                        matmul::trusted::VerifyResultName(verified));
                    return false;
                }
                continue;
            }
            pin_only.push_back(attestation);
        }
        if (pin_only.empty()) {
            continue;
        }
        const TailKey tail_key{key.height, key.block_hash};
        const bool pin_quorum{store->HasQuorumFromAttestations(
            pin_only, key.block_hash, key.height)};
        if (pin_quorum) {
            highest = std::max(highest, key.height);
            all_quorum[key.height].insert(key.block_hash);
            if (local_pk.has_value()) {
                for (const auto& attestation : pin_only) {
                    if (attestation.signer == *local_pk) {
                        local_signed.emplace(key.height, key.block_hash);
                    }
                }
            }
        }
        hot_tail_attestations += pin_only.size();
        hot_tail.emplace(tail_key, std::move(pin_only));
        while (hot_tail.size() > store->MaxBlocks() ||
               hot_tail_attestations > store->MaxAttestations()) {
            hot_tail_attestations -= hot_tail.begin()->second.size();
            hot_tail.erase(hot_tail.begin());
        }
        ++records;
    }
    for (const auto& [tail_key, attestations] : hot_tail) {
        for (const auto& attestation : attestations) {
            const auto result{store->Add(attestation, tail_key.second,
                                         tail_key.first)};
            if (result == matmul::trusted::AddResult::Heard ||
                result == matmul::trusted::AddResult::UntrustedSigner ||
                result == matmul::trusted::AddResult::FrozenSigner ||
                result == matmul::trusted::AddResult::BlocklistedSigner) {
                continue;
            }
            if (result != matmul::trusted::AddResult::Accepted &&
                result != matmul::trusted::AddResult::Duplicate) {
                error = strprintf("durable hot-cache import rejected: %s",
                                  matmul::trusted::AddResultName(result));
                return false;
            }
        }
    }
    {
        std::lock_guard lock{g_mutex};
        g_highest_attested_height =
            std::max(g_highest_attested_height, highest);
        for (const auto& [height, hashes] : all_quorum) {
            for (const auto& hash : hashes) {
                g_quorum_hashes_by_height[height].insert(hash);
            }
        }
        for (const auto& [height, hash] : local_signed) {
            g_local_signed_hash_by_height.emplace(height, hash);
        }
    }
    for (const auto& [tail_key, attestations] : hot_tail) {
        if (!store->HasQuorumFromAttestations(attestations, tail_key.second,
                                              tail_key.first)) {
            continue;
        }
        NoteAcceptedAttestationHeight(tail_key.first, tail_key.second);
    }
    LogPrintf("Verified %zu durable MatMul attestation block record(s)\n",
              records);
    return true;
}

void PersistWithdrawnLocalVote(int32_t height, const uint256& block_hash)
{
    if (height < 0 || block_hash.IsNull()) return;
    std::lock_guard io_lock{g_persist_io_mutex};
    if (!g_durable_db || !g_durable_namespace.has_value()) return;
    const bool ok{g_durable_db->Write(
        DurableWithdrawnVoteKey{.authority_namespace = *g_durable_namespace,
                                .height = height, .block_hash = block_hash},
        uint8_t{1}, /*fSync=*/true)};
    if (!ok) {
        LogPrintf("matmul: failed to persist withdrawn-local-vote tombstone "
                  "height=%d hash=%s\n", height, block_hash.ToString());
    }
}

void EraseWithdrawnLocalVote(int32_t height, const uint256& block_hash)
{
    if (height < 0 || block_hash.IsNull()) return;
    std::lock_guard io_lock{g_persist_io_mutex};
    if (!g_durable_db || !g_durable_namespace.has_value()) return;
    (void)g_durable_db->Erase(
        DurableWithdrawnVoteKey{.authority_namespace = *g_durable_namespace,
                                .height = height, .block_hash = block_hash},
        /*fSync=*/false);
}

bool LoadWithdrawnLocalVotes(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store)
{
    if (!g_durable_db) return true;
    const uint256 authority_namespace{AuthorityNamespace(*store)};
    std::unique_ptr<CDBIterator> cursor{g_durable_db->NewIterator()};
    cursor->Seek(DurableWithdrawnVotePrefix{
        .authority_namespace = authority_namespace});
    for (; cursor->Valid(); cursor->Next()) {
        DurableWithdrawnVoteKey key;
        if (!cursor->GetKey(key) ||
            key.prefix != DurableWithdrawnVoteKey::PREFIX ||
            key.authority_namespace != authority_namespace) {
            break;
        }
        store->SeedOffActiveChain(key.height, key.block_hash);
    }
    return true;
}

bool PersistDurableAttestations(
    Span<const matmul::trusted::ExactReplayAttestation> pending,
    std::string& error)
{
    if (!g_durable_db) {
        error = "durable attestation database is not open";
        return false;
    }
    if (!g_durable_namespace.has_value()) {
        error = "durable attestation authority namespace is unavailable";
        return false;
    }
    auto store{Store()};
    std::map<DurableAttestationKey,
             std::vector<matmul::trusted::ExactReplayAttestation>> grouped;
    for (const auto& attestation : pending) {
        if (!store || !store->IsAuthoritySigner(attestation.signer)) {
            continue;
        }
        grouped[DurableAttestationKey{
            .authority_namespace = *g_durable_namespace,
            .height = attestation.statement.block_height,
            .block_hash = attestation.statement.block_hash}]
            .push_back(attestation);
    }
    CDBBatch write_batch{*g_durable_db};
    for (auto& [key, additions] : grouped) {
        std::vector<matmul::trusted::ExactReplayAttestation> attestations;
        const auto status{g_durable_db->TryRead(key, attestations)};
        if (status.status != CDBWrapper::ReadStatus::Code::OK &&
            status.status != CDBWrapper::ReadStatus::Code::NOT_FOUND) {
            error = "failed to read durable attestation record";
            return false;
        }
        std::set<CPubKey> seen;
        std::vector<matmul::trusted::ExactReplayAttestation> kept;
        for (const auto& existing : attestations) {
            if (store && store->IsAuthoritySigner(existing.signer) &&
                seen.insert(existing.signer).second) {
                kept.push_back(existing);
            }
        }
        for (auto& addition : additions) {
            if (seen.insert(addition.signer).second) {
                kept.push_back(std::move(addition));
            }
        }
        if (!kept.empty()) {
            write_batch.Write(key, kept);
        }
    }
    if (!grouped.empty() && !g_durable_db->WriteBatch(write_batch, true)) {
        error = "failed to sync durable attestation batch";
        return false;
    }
    return true;
}

std::vector<matmul::trusted::ExactReplayAttestation> ReadDurableAttestations(
    const uint256& block_hash, int32_t block_height)
{
    std::lock_guard io_lock{g_persist_io_mutex};
    if (!g_durable_db || !g_durable_namespace.has_value()) return {};
    std::vector<matmul::trusted::ExactReplayAttestation> out;
    const auto status{g_durable_db->TryRead(
        DurableAttestationKey{.authority_namespace = *g_durable_namespace,
                              .height = block_height,
                              .block_hash = block_hash}, out)};
    if (status.status != CDBWrapper::ReadStatus::Code::OK) return {};
    if (auto store{Store()}) {
        std::erase_if(out, [&](const matmul::trusted::ExactReplayAttestation& a) {
            return !store->IsAuthoritySigner(a.signer);
        });
    }
    return out;
}

bool LoadPersistenceSnapshot(
    const std::shared_ptr<matmul::trusted::AttestationStore>& store,
    const fs::path& path, std::string& error)
{
    if (path.empty() || !store || !fs::exists(path)) return true;
    const auto [ok, bytes]{ReadBinaryFile(path, PERSIST_MAX_BYTES)};
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
        return ImportAttestations(store, std::move(loaded), path, error);
    } catch (const std::exception& e) {
        error = strprintf("attestation archive decode failed: %s", e.what());
        return false;
    }
}

fs::path WalPath(const fs::path& archive) { return archive + ".wal"; }

bool ResetWal(const fs::path& archive, std::string& error)
{
    DataStream encoded;
    encoded.write(AsBytes(Span{PERSIST_WAL_MAGIC, sizeof(PERSIST_WAL_MAGIC)}));
    return AtomicWriteBytes(WalPath(archive),
                            Span{encoded.data(), encoded.size()}, error);
}

bool AppendWal(const fs::path& archive,
               Span<const matmul::trusted::ExactReplayAttestation> attestations,
               std::string& error)
{
    const fs::path wal{WalPath(archive)};
    const bool new_file{!fs::exists(wal)};
    std::error_code size_ec;
    const uintmax_t prior_size{
        new_file ? 0 : fs::file_size(wal, size_ec)};
    if (size_ec || prior_size >= PERSIST_MAX_BYTES) {
        error = "attestation WAL exceeds size bound";
        return false;
    }
    DataStream records;
    for (const auto& attestation : attestations) {
        DataStream record;
        record << attestation;
        if (record.empty() || record.size() > 1U << 20) {
            error = "attestation WAL record exceeds size bound";
            return false;
        }
        records << static_cast<uint32_t>(record.size());
        records.write(Span{record.data(), record.size()});
    }
    if (records.size() > PERSIST_MAX_BYTES -
            std::min<uintmax_t>(prior_size, PERSIST_MAX_BYTES) -
            (new_file ? sizeof(PERSIST_WAL_MAGIC) : 0)) {
        error = "attestation WAL batch exceeds size bound";
        return false;
    }
    FILE* file{fsbridge::fopen(wal, new_file ? "wb" : "ab")};
    if (!file) {
        error = "failed to open attestation WAL";
        return false;
    }
    bool ok{true};
    if (new_file) {
        ok = fwrite(PERSIST_WAL_MAGIC, 1, sizeof(PERSIST_WAL_MAGIC), file) ==
             sizeof(PERSIST_WAL_MAGIC);
    }
    ok = ok && fwrite(records.data(), 1, records.size(), file) == records.size();
    ok = ok && FileCommit(file);
    const int close_result{fclose(file)};
    if (!ok || close_result != 0) {
        error = "failed to append durable attestation WAL";
        return false;
    }
    if (new_file) DirectoryCommit(wal.parent_path());
    return true;
}

bool LoadWal(const std::shared_ptr<matmul::trusted::AttestationStore>& store,
             const fs::path& archive, std::string& error)
{
    const fs::path wal{WalPath(archive)};
    if (!fs::exists(wal)) return true;
    const auto [ok, bytes]{ReadBinaryFile(wal, PERSIST_MAX_BYTES)};
    if (!ok || bytes.size() < sizeof(PERSIST_WAL_MAGIC) ||
        bytes.size() >= PERSIST_MAX_BYTES) {
        error = "failed to read bounded attestation WAL";
        return false;
    }
    try {
        DataStream encoded{MakeUCharSpan(bytes)};
        char magic[sizeof(PERSIST_WAL_MAGIC)];
        encoded.read(AsWritableBytes(Span{magic, sizeof(magic)}));
        if (std::memcmp(magic, PERSIST_WAL_MAGIC,
                        sizeof(PERSIST_WAL_MAGIC)) != 0) {
            error = "attestation WAL magic mismatch";
            return false;
        }
        std::vector<matmul::trusted::ExactReplayAttestation> loaded;
        while (!encoded.empty()) {
            uint32_t record_size{0};
            encoded >> record_size;
            if (record_size == 0 || record_size > (1U << 20) ||
                record_size > encoded.size()) {
                error = "attestation WAL record is truncated or oversized";
                return false;
            }
            std::vector<uint8_t> record(record_size);
            encoded.read(AsWritableBytes(Span{record.data(), record.size()}));
            DataStream item{Span{record.data(), record.size()}};
            matmul::trusted::ExactReplayAttestation attestation;
            item >> attestation;
            if (!item.empty()) {
                error = "attestation WAL record has trailing data";
                return false;
            }
            loaded.push_back(std::move(attestation));
            if (loaded.size() > 16384) {
                error = "attestation WAL count exceeds bound";
                return false;
            }
        }
        return ImportAttestations(store, std::move(loaded), wal, error);
    } catch (const std::exception& e) {
        error = strprintf("attestation WAL decode failed: %s", e.what());
        return false;
    }
}

void PersistAfterMutation(
    const matmul::trusted::ExactReplayAttestation& attestation)
{
    // Hold the configuration lock through queue admission. ClosePersistence
    // takes the same lock order when disabling admission and capturing its
    // drain target, so an accepted record cannot fall into the close window.
    std::lock_guard config_lock{g_mutex};
    if (!g_persist_enabled || g_persist_path.empty()) return;
    std::lock_guard worker_lock{g_persist_worker_mutex};
    g_persist_pending.push_back(attestation);
    ++g_persist_queued;
    g_persist_worker_cv.notify_all();
}

void StopPersistenceWorker();

void StartPersistenceWorker(const fs::path& path)
{
    // Apple libc++ on the macOS 15 SDK still lacks std::jthread. The worker
    // already has g_persist_stop; join the previous thread before replacing it.
    StopPersistenceWorker();
    {
        std::lock_guard lock{g_persist_worker_mutex};
        g_persist_pending.clear();
        g_persist_queued = 0;
        g_persist_completed = 0;
        g_persist_stop = false;
        g_persist_worker_error.clear();
    }
    g_persist_worker = std::thread{[path] {
        while (true) {
            std::vector<matmul::trusted::ExactReplayAttestation> batch;
            {
                std::unique_lock lock{g_persist_worker_mutex};
                g_persist_worker_cv.wait(lock, [&] {
                    return g_persist_stop || !g_persist_pending.empty();
                });
                if (g_persist_pending.empty() && g_persist_stop) {
                    return;
                }
                if (g_persist_pending.empty()) continue;
                batch.reserve(std::min(PERSIST_BATCH_MAX,
                                       g_persist_pending.size()));
                while (!g_persist_pending.empty() &&
                       batch.size() < PERSIST_BATCH_MAX) {
                    batch.push_back(std::move(g_persist_pending.front()));
                    g_persist_pending.pop_front();
                }
            }

            std::string error;
            bool ok;
            {
                std::lock_guard io_lock{g_persist_io_mutex};
                ok = AppendWal(path, batch, error);
                if (ok) ok = PersistDurableAttestations(batch, error);
                // LevelDB was sync-written, so the WAL record is now
                // redundant. Checkpoint it immediately instead of allowing a
                // long-running authority to hit the legacy 32 MiB/count
                // ceiling. Every crash cut is safe: before DB sync the WAL
                // survives; after DB sync either copy can replay idempotently.
                if (ok) ok = ResetWal(path, error);
            }
            {
                std::lock_guard lock{g_persist_worker_mutex};
                g_persist_completed += batch.size();
                if (!ok && g_persist_worker_error.empty()) {
                    g_persist_worker_error = std::move(error);
                }
            }
            g_persist_worker_cv.notify_all();
            // Never process a later record after a failed DB sync: doing so
            // could checkpoint away the only WAL copy of the failed batch.
            if (!ok) return;
        }
    }};
}

void StopPersistenceWorker()
{
    if (!g_persist_worker.joinable()) return;
    {
        std::lock_guard lock{g_persist_worker_mutex};
        g_persist_stop = true;
    }
    g_persist_worker_cv.notify_all();
    g_persist_worker.join();
}

bool WaitForPersistenceTarget(const fs::path& path, uint64_t target,
                              std::string& error)
{
    {
        std::unique_lock lock{g_persist_worker_mutex};
        g_persist_worker_cv.wait(lock, [&] {
            return g_persist_completed >= target ||
                   !g_persist_worker_error.empty();
        });
        if (!g_persist_worker_error.empty()) {
            error = g_persist_worker_error;
            return false;
        }
    }
    std::lock_guard io_lock{g_persist_io_mutex};
    // The synchronized LevelDB is authoritative. Rewriting the legacy flat
    // archive from the bounded hot cache would silently truncate history.
    return ResetWal(path, error);
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
        const bool already_pinned{
            std::find(staged->config.trusted_signers.begin(),
                      staged->config.trusted_signers.end(),
                      local_pubkey) !=
            staged->config.trusted_signers.end()};
        if (!already_pinned) {
            // Independent GPU attestors keep a pin that already meets M and
            // sign as an open key. A WIF still seeds or completes the pin
            // when it is empty or below threshold.
            if (!(staged->config.open_attestors &&
                  staged->config.trusted_signers.size() >=
                      staged->config.threshold)) {
                staged->config.trusted_signers.push_back(local_pubkey);
            }
        }
        staged->config.local_signer = std::move(key);
    }
    return Configure(
        std::move(staged->config), staged->trusted_mirror,
        staged->serve_attestations, staged->wait_timeout, error);
}

void Reset()
{
    ClosePersistence();
    std::lock_guard lock{g_mutex};
    g_store.reset();
    g_block_index_height = {};
    CleanseStagedConfigurationLocked();
    g_trusted_mirror = false;
    g_serve_attestations = false;
    g_wait_timeout = std::chrono::milliseconds{60'000};
    g_highest_attested_height = -1;
    g_authority_peer_tip_hint = -1;
    g_authority_peer_tip_hash.SetNull();
    g_attested_by_height.clear();
    g_quorum_hashes_by_height.clear();
    g_local_signed_hash_by_height.clear();
    g_persist_enabled = false;
    g_persist_path.clear();
    g_open_state_dirty = false;
    g_open_state_last_persist = {};
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

bool OpenAttestorsEnabled()
{
    auto store{Store()};
    return store && store->OpenAttestorsEnabled();
}

size_t OpenThreshold()
{
    auto store{Store()};
    return store ? store->OpenThreshold() : 0;
}

std::vector<CPubKey> AdmittedOpenSigners()
{
    auto store{Store()};
    if (!store) return {};
    const auto admitted{store->AdmittedOpenSigners()};
    return {admitted.begin(), admitted.end()};
}

std::vector<CPubKey> FrozenOpenSigners()
{
    auto store{Store()};
    if (!store) return {};
    const auto frozen{store->FrozenOpenSigners()};
    return {frozen.begin(), frozen.end()};
}

bool IsAuthoritySigner(const CPubKey& pubkey)
{
    auto store{Store()};
    return store && store->IsAuthoritySigner(pubkey);
}

bool IsBlocked(const CPubKey& pubkey)
{
    auto store{Store()};
    return store && store->IsBlocked(pubkey);
}

std::vector<CPubKey> BlockedSigners()
{
    auto store{Store()};
    if (!store) return {};
    const auto blocked{store->BlockedSigners()};
    return {blocked.begin(), blocked.end()};
}

std::vector<CPubKey> ConfigBlockedSigners()
{
    auto store{Store()};
    if (!store) return {};
    const auto blocked{store->ConfigBlockedSigners()};
    return {blocked.begin(), blocked.end()};
}

std::vector<CPubKey> RuntimeBlockedSigners()
{
    auto store{Store()};
    if (!store) return {};
    const auto blocked{store->RuntimeBlockedSigners()};
    return {blocked.begin(), blocked.end()};
}

size_t UnblockedPinMembers()
{
    auto store{Store()};
    return store ? store->UnblockedPinMembers() : 0;
}

bool PinQuorumReachable()
{
    auto store{Store()};
    return store && store->PinQuorumReachable();
}

matmul::trusted::BlocklistResult AddBlocklistedSigner(
    const CPubKey& pubkey, std::string& persist_error)
{
    persist_error.clear();
    auto store{Store()};
    if (!store) return matmul::trusted::BlocklistResult::Invalid;
    const auto result{store->AddBlocklistedSigner(pubkey)};
    if (result == matmul::trusted::BlocklistResult::Blocked) {
        std::lock_guard io_lock{g_persist_io_mutex};
        (void)PersistBlocklistState(store, persist_error);
    }
    return result;
}

std::vector<matmul::trusted::ExactReplayAttestation> HeardAttestations()
{
    auto store{Store()};
    if (!store) return {};
    return store->ExportHeard();
}

matmul::trusted::AttestationLogHead LogHead()
{
    auto store{Store()};
    return store ? store->LogHead() : matmul::trusted::AttestationLogHead{};
}

void SetBlockIndexHeightLookup(BlockIndexHeightLookup lookup)
{
    std::lock_guard lock{g_mutex};
    g_block_index_height = std::move(lookup);
}

matmul::trusted::AddResult AddRefutation(
    const matmul::trusted::ExactReplayRefutation& refutation,
    const uint256& expected_hash,
    int32_t expected_height)
{
    auto store{Store()};
    if (!store) return matmul::trusted::AddResult::UntrustedSigner;
    BlockIndexHeightLookup lookup;
    {
        std::lock_guard lock{g_mutex};
        lookup = g_block_index_height;
    }
    // Index height wins over any caller-supplied value. A lying
    // statement.block_height must not key m_refutations.
    if (lookup) {
        const auto indexed{lookup(expected_hash)};
        if (!indexed.has_value() ||
            *indexed != refutation.statement.block_height) {
            return matmul::trusted::AddResult::WrongHeight;
        }
        expected_height = *indexed;
    } else if (expected_height != refutation.statement.block_height) {
        return matmul::trusted::AddResult::WrongHeight;
    }
    return store->AddRefutation(refutation, expected_hash, expected_height);
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
    // Signed-frontier high-water is pin *quorum* only. A single stolen pin
    // vote must not inflate g_highest_attested_height / GETDATA preference.
    if ((result == matmul::trusted::AddResult::Accepted ||
         result == matmul::trusted::AddResult::Duplicate) &&
        store->IsAuthoritySigner(attestation.signer) &&
        store->HasQuorum(expected_hash, expected_height)) {
        NoteAcceptedAttestationHeight(expected_height, expected_hash);
    }
    if (result == matmul::trusted::AddResult::Accepted) {
        PersistAfterMutation(attestation);
    }
    if (store->OpenAttestorsEnabled() &&
        (result == matmul::trusted::AddResult::Accepted ||
         result == matmul::trusted::AddResult::Equivocation ||
         result == matmul::trusted::AddResult::Heard)) {
        std::string persist_error;
        std::lock_guard io_lock{g_persist_io_mutex};
        (void)PersistOpenAttestorState(store, persist_error);
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
    // Dual-quorum: never mint a second local signature at a height that
    // already has pin quorum on a different hash (live 2026-08-15:
    // 94f70747 then a9590c15 at 190354). g_quorum_hashes_by_height survives
    // the 512-block FMWC hint window and hot-cache eviction. The
    // local-signed height map also survives eviction (durable load + each
    // local Sign). Hashes this node itself disconnected do not occupy:
    // that is a local validated reorg, not a stolen-WIF jam.
    if (HasLocalSignatureAtHeight(block_hash, block_height)) {
        return matmul::trusted::AddResult::HeightOccupied;
    }
    if (HasCompetingQuorum(block_hash, block_height)) {
        return matmul::trusted::AddResult::HeightOccupied;
    }
    matmul::trusted::ExactReplayAttestation signed_attestation;
    const auto result{
        store->SignLocal(block_hash, block_height, &signed_attestation)};
    if (produced && (result == matmul::trusted::AddResult::Accepted ||
                     result == matmul::trusted::AddResult::Duplicate ||
                     result == matmul::trusted::AddResult::Heard)) {
        *produced = signed_attestation;
    }
    if (result == matmul::trusted::AddResult::Accepted ||
        result == matmul::trusted::AddResult::Duplicate) {
        const auto local_pk{store->LocalSignerPubKey()};
        if (local_pk && store->IsAuthoritySigner(*local_pk) &&
            store->HasQuorum(block_hash, block_height)) {
            NoteAcceptedAttestationHeight(block_height, block_hash);
        }
        if (block_height >= 0 && !block_hash.IsNull()) {
            std::lock_guard lock{g_mutex};
            g_local_signed_hash_by_height.emplace(block_height, block_hash);
        }
    }
    if (result == matmul::trusted::AddResult::Accepted) {
        PersistAfterMutation(signed_attestation);
    }
    return result;
}

bool NotifyActiveChainBlockDisconnected(int32_t height,
                                        const uint256& disconnected_hash)
{
    if (height < 0 || disconnected_hash.IsNull()) return false;
    auto store{Store()};
    const bool released_store{
        store && store->NotifyActiveChainBlockDisconnected(
                     height, disconnected_hash)};
    bool released_hint{false};
    {
        std::lock_guard lock{g_mutex};
        const auto it{g_local_signed_hash_by_height.find(height)};
        if (it != g_local_signed_hash_by_height.end() &&
            it->second == disconnected_hash) {
            g_local_signed_hash_by_height.erase(it);
            released_hint = true;
        }
    }
    if (released_store || released_hint) {
        // V5/RB-12 (adv5): make the withdrawal DURABLE so a reloaded or relayed
        // copy of our abandoned vote cannot re-form quorum after restart.
        PersistWithdrawnLocalVote(height, disconnected_hash);
        LogPrintf("matmul: released local mint slot at height %d after "
                  "active-chain disconnect of %s\n",
                  height, disconnected_hash.ToString());
    }
    return released_store || released_hint;
}

void NotifyActiveChainBlockConnected(int32_t height,
                                     const uint256& connected_hash)
{
    if (height < 0 || connected_hash.IsNull()) return;
    auto store{Store()};
    if (store) {
        store->NotifyActiveChainBlockConnected(height, connected_hash);
    }
    // The hash is back on the active chain: drop its withdrawal tombstone so a
    // future re-vote / reload is allowed again.
    EraseWithdrawnLocalVote(height, connected_hash);
}

size_t ClearMintedAttestations(int32_t from_height, int32_t to_height)
{
    if (from_height > to_height) return 0;
    std::set<int32_t> cleared;
    auto store{Store()};
    if (store) {
        for (const int32_t height :
             store->LocalMintedHeights(from_height, to_height)) {
            cleared.insert(height);
        }
        store->ClearLocalMintSlots(from_height, to_height);
    }
    {
        std::lock_guard lock{g_mutex};
        auto it{g_local_signed_hash_by_height.lower_bound(from_height)};
        while (it != g_local_signed_hash_by_height.end() &&
               it->first <= to_height) {
            cleared.insert(it->first);
            it = g_local_signed_hash_by_height.erase(it);
        }
    }
    if (!cleared.empty()) {
        LogPrintf("matmul: operator cleared %zu local mint slot(s) in [%d, %d]\n",
                  cleared.size(), from_height, to_height);
    }
    return cleared.size();
}

std::optional<uint256> LocalMintedHash(int32_t height)
{
    auto store{Store()};
    if (store) {
        if (auto minted{store->LocalMintedHash(height)}) return minted;
    }
    std::lock_guard lock{g_mutex};
    const auto it{g_local_signed_hash_by_height.find(height)};
    if (it == g_local_signed_hash_by_height.end() || it->second.IsNull()) {
        return std::nullopt;
    }
    return it->second;
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
    matmul::trusted::UtxoSnapshotManifest filtered{manifest};
    filtered.signatures.clear();
    const auto blocked{store->BlockedSigners()};
    for (const auto& signature : manifest.signatures) {
        if (blocked.count(signature.signer) != 0) continue;
        filtered.signatures.push_back(signature);
    }
    return matmul::trusted::VerifyUtxoSnapshotManifestSelfConsistent(
        filtered, store->ChainId(), store->ReplayAuthorityContext(),
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
    if (!store) return false;
    if (store->HasQuorum(block_hash, block_height)) return true;

    // The bounded hot cache intentionally evicts old buckets. Durable history
    // is disk-backed and queried only on a miss so restart provenance does not
    // disappear after max_blocks blocks.
    const auto historical{ReadDurableAttestations(block_hash, block_height)};
    return store->HasQuorumFromAttestations(historical, block_hash,
                                           block_height);
}

bool HasQuorumInMemory(const uint256& block_hash, int32_t block_height)
{
    auto store{Store()};
    return store && store->HasQuorum(block_hash, block_height);
}

bool HasCompetingQuorum(const uint256& block_hash, int32_t block_height)
{
    if (block_height < 0 || block_hash.IsNull()) return false;
    std::set<uint256> others;
    {
        std::lock_guard lock{g_mutex};
        const auto it{g_quorum_hashes_by_height.find(block_height)};
        if (it == g_quorum_hashes_by_height.end()) return false;
        others = it->second;
    }
    auto store{Store()};
    for (const auto& other : others) {
        if (other == block_hash || other.IsNull()) continue;
        if (store && store->IsOffActiveChain(block_height, other)) continue;
        return true;
    }
    return false;
}

bool HasLocalSignatureAtHeight(const uint256& block_hash, int32_t block_height)
{
    if (block_height < 0 || block_hash.IsNull()) return false;
    std::lock_guard lock{g_mutex};
    const auto it{g_local_signed_hash_by_height.find(block_height)};
    if (it == g_local_signed_hash_by_height.end() || it->second.IsNull()) {
        return false;
    }
    return it->second != block_hash;
}

matmul::trusted::WaitResult WaitForQuorum(
    const uint256& block_hash,
    int32_t block_height,
    const std::function<bool()>& cancelled,
    std::vector<matmul::trusted::ExactReplayAttestation>* quorum)
{
    auto store{Store()};
    if (!store) return matmul::trusted::WaitResult::Timeout;
    if (HasQuorum(block_hash, block_height)) {
        if (quorum != nullptr) *quorum = Get(block_hash, block_height);
        return matmul::trusted::WaitResult::Quorum;
    }
    return store->WaitForQuorum(block_hash, block_height, WaitTimeout(),
                                cancelled, quorum);
}

std::vector<matmul::trusted::ExactReplayAttestation> Get(
    const uint256& block_hash, int32_t block_height)
{
    auto store{Store()};
    if (!store) return {};
    auto attestations{store->GetAttestations(block_hash, block_height)};
    if (attestations.size() >= store->Threshold()) return attestations;
    auto durable{ReadDurableAttestations(block_hash, block_height)};
    return durable.size() > attestations.size() ? std::move(durable)
                                                : std::move(attestations);
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

std::optional<uint256> AuthorityPeerTipHintHash()
{
    std::lock_guard lock{g_mutex};
    if (g_authority_peer_tip_hint < 0 || g_authority_peer_tip_hash.IsNull()) {
        return std::nullopt;
    }
    return g_authority_peer_tip_hash;
}

std::vector<AttestedFrontierHint> AttestedFrontierHints()
{
    std::lock_guard lock{g_mutex};
    std::vector<AttestedFrontierHint> out;
    for (const auto& [height, hashes] : g_attested_by_height) {
        for (const auto& hash : hashes) {
            out.push_back({.hash = hash, .height = height});
        }
    }
    return out;
}

std::optional<int32_t> AuthorityAttestedFrontier()
{
    std::lock_guard lock{g_mutex};
    const int32_t frontier{
        std::max(g_highest_attested_height, g_authority_peer_tip_hint)};
    if (frontier < 0) return std::nullopt;
    return frontier;
}

void NoteAcceptedAttestationHeight(int32_t height, const uint256& hash)
{
    if (height < 0) return;
    std::lock_guard lock{g_mutex};
    if (height > g_highest_attested_height) {
        g_highest_attested_height = height;
    }
    if (!hash.IsNull()) {
        g_quorum_hashes_by_height[height].insert(hash);
        g_attested_by_height[height].insert(hash);
        const int32_t floor_height{
            g_highest_attested_height - ATTESTED_FRONTIER_HINT_WINDOW};
        while (!g_attested_by_height.empty() &&
               g_attested_by_height.begin()->first < floor_height) {
            g_attested_by_height.erase(g_attested_by_height.begin());
        }
    }
}

void NoteAuthorityPeerTipHint(int32_t height, const uint256& hash)
{
    if (height < 0) return;
    std::lock_guard lock{g_mutex};
    if (height > g_authority_peer_tip_hint) {
        g_authority_peer_tip_hint = height;
        g_authority_peer_tip_hash = hash;
    } else if (height == g_authority_peer_tip_hint && !hash.IsNull()) {
        g_authority_peer_tip_hash = hash;
    }
}

bool OpenPersistence(const fs::path& path, std::string& error)
{
    ClosePersistence();
    auto store{Store()};
    if (!store) {
        error = "attestation store is not configured";
        return false;
    }
    store->SetDurableRetention(true);
    {
        std::lock_guard io_lock{g_persist_io_mutex};
        try {
            g_durable_db = std::make_unique<CDBWrapper>(DBParams{
                .path = path + ".db",
                .cache_bytes = 8 << 20,
                .memory_only = false,
                .wipe_data = false,
                .obfuscate = false,
            });
            g_durable_namespace = AuthorityNamespace(*store);
            if (!LoadBlocklistState(store, error) ||
                !LoadOpenAttestorState(store) ||
                !LoadWithdrawnLocalVotes(store) ||
                !LoadDurableAttestations(store, error) ||
                !LoadPersistenceSnapshot(store, path, error) ||
                !LoadWal(store, path, error) ||
                !ResetLegacyArchive(path, error) ||
                !ResetWal(path, error)) {
                g_durable_db.reset();
                g_durable_namespace.reset();
                return false;
            }
        } catch (const dbwrapper_error& e) {
            error = strprintf("failed to open durable attestation database: %s",
                              e.what());
            g_durable_db.reset();
            g_durable_namespace.reset();
            return false;
        }
    }
    // Start the worker before exposing persistence to Add(). Otherwise its
    // initialization could clear a record queued in the enable/start window.
    StartPersistenceWorker(path);
    {
        std::lock_guard lock{g_mutex};
        g_persist_path = path;
        g_persist_enabled = true;
    }
    return true;
}

void ClosePersistence()
{
    fs::path path;
    bool enabled{false};
    uint64_t target{0};
    {
        std::lock_guard lock{g_mutex};
        path = g_persist_path;
        enabled = g_persist_enabled;
        // Disable queue admission while holding the same lock order used by
        // PersistAfterMutation, then capture the exact drain target.
        g_persist_enabled = false;
        g_persist_path.clear();
        if (enabled) {
            std::lock_guard worker_lock{g_persist_worker_mutex};
            target = g_persist_queued;
        }
    }
    if (enabled) {
        std::string error;
        if (!WaitForPersistenceTarget(path, target, error)) {
            LogWarning("MatMul attestation archive close flush failed: %s\n",
                       error);
        }
    }
    StopPersistenceWorker();
    {
        auto store{Store()};
        std::lock_guard io_lock{g_persist_io_mutex};
        if (g_open_state_dirty && store) {
            std::string error;
            (void)PersistOpenAttestorState(store, error, /*force=*/true);
        }
        g_durable_db.reset();
        g_durable_namespace.reset();
    }
}

bool PersistenceEnabled()
{
    std::lock_guard lock{g_mutex};
    return g_persist_enabled;
}

bool FlushPersistence(std::string& error)
{
    auto store{Store()};
    fs::path path;
    uint64_t target{0};
    {
        std::lock_guard lock{g_mutex};
        if (!g_persist_enabled || g_persist_path.empty() || !store) return true;
        path = g_persist_path;
        std::lock_guard worker_lock{g_persist_worker_mutex};
        target = g_persist_queued;
    }
    return WaitForPersistenceTarget(path, target, error);
}

HistoricalReverifyAdmit TryAdmitHistoricalReverify(
    const uint256& block_hash, bool live_gpu_busy)
{
    std::lock_guard lock{g_reverify_mutex};
    if (live_gpu_busy) {
        return HistoricalReverifyAdmit::LiveGpuBusy;
    }
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

BetterWorkTwinLocalCommitment DetectBetterWorkTwinBlockedByLocalCommitment(
    const CBlockIndex* tip,
    const CBlockIndex* best_header,
    const CBlockIndex* best_claimed_header)
{
    BetterWorkTwinLocalCommitment out;
    if (!HasLocalSigner() || !tip || !tip->phashBlock) return out;

    const CBlockIndex* competing{nullptr};
    const auto consider = [&](const CBlockIndex* idx) {
        if (!idx || idx == tip || !idx->phashBlock) return;
        if (idx->GetAncestor(tip->nHeight) == tip) return;
        if (idx->nChainWork <= tip->nChainWork) return;
        if (!competing || idx->nChainWork > competing->nChainWork) {
            competing = idx;
        }
    };
    consider(best_header);
    consider(best_claimed_header);
    if (!competing) return out;

    const CBlockIndex* const lca{LastCommonAncestor(tip, competing)};
    const CBlockIndex* local_child{nullptr};
    const CBlockIndex* twin_child{nullptr};
    int32_t fork_height{-1};
    if (!lca) {
        fork_height = tip->nHeight;
        local_child = tip;
        twin_child = competing->GetAncestor(tip->nHeight);
        if (!twin_child) twin_child = competing;
    } else {
        fork_height = lca->nHeight + 1;
        local_child = tip->GetAncestor(fork_height);
        twin_child = competing->GetAncestor(fork_height);
    }
    if (!local_child || !twin_child ||
        !local_child->phashBlock || !twin_child->phashBlock ||
        local_child == twin_child) {
        return out;
    }

    const uint256 local_hash{local_child->GetBlockHash()};
    const uint256 twin_hash{twin_child->GetBlockHash()};
    const auto minted{LocalMintedHash(fork_height)};
    const bool mint_eq_local{minted.has_value() && *minted == local_hash};
    const bool mint_ne_twin{minted.has_value() && *minted != twin_hash};
    if (!BetterWorkTwinBlockedByLocalCommitment(
            /*has_local_signer=*/true,
            /*competing_strictly_heavier=*/true,
            /*competing_extends_tip=*/false,
            mint_eq_local,
            mint_ne_twin)) {
        return out;
    }

    out.blocked = true;
    out.fork_height = fork_height;
    out.better_work_height = competing->nHeight;
    out.local_committed_hash = local_hash;
    out.better_work_twin_hash = twin_hash;
    return out;
}

} // namespace node::matmul_trusted
