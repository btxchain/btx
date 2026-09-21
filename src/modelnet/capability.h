// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CAPABILITY_H
#define BITCOIN_MODELNET_CAPABILITY_H

#include <modelnet/capability_types.h>
#include <modelnet/catalog.h>
#include <univalue.h>

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

struct CapabilityRecipe {
    UniValue json;
    Digest48 recipe_id{};
    RecipeKind kind{RecipeKind::FULL_MODEL};
    std::vector<std::string> capabilities;
    std::vector<std::string> component_ids;
    ReadinessContract readiness{ReadinessContract::FULL_REQUIRED_SET};
};

struct CapabilityLock {
    UniValue json;
    Digest48 lock_id{};
    Digest48 recipe_id{};
    Digest48 package_core_id{};
};

struct CapabilityPlan {
    UniValue json;
    std::string plan_id;
    Digest48 plan_digest{};
    Digest48 recipe_id{};
    Digest48 lock_id{};
    ReadinessTarget target{ReadinessTarget::RUNTIME_READY};
    uint64_t missing_bytes{0};
    uint64_t peak_host_bytes{0};
    int64_t ttc_lower_ms{0};
    int64_t ttc_upper_ms{0};
};

struct LocalCapabilityGrant {
    UniValue json;
    std::string grant_id;
    std::string caller;
    int64_t expires_at_ms{0};
    bool revoked{false};
    uint64_t host_bytes{0};
    uint64_t device_bytes{0};
    int max_sessions{1};
};

struct MemoryLimits {
    uint64_t host_physical_bytes{0};
    uint64_t host_pinned_bytes{0};
    uint64_t device_bytes{0};
    uint64_t speculative_bytes{0};
    bool uma{false};
};

struct LeaseRecord {
    std::string lease_id;
    Generation16 generation{};
    LeaseClass cls{LeaseClass::LOAD};
    LeaseLife life{LeaseLife::RESERVED};
    uint64_t bytes{0};
    std::string owner;
    std::string fence_backend;
    std::string operation_id;
};

struct TensorRange {
    std::string name;
    uint32_t file_index{0};
    uint64_t offset{0};
    uint64_t length{0};
    std::string dtype;
    std::vector<int64_t> shape;
    uint32_t piece_begin{0};
    uint32_t piece_end{0};
};

struct TensorRangeMap {
    UniValue json;
    Digest48 map_id{};
    Digest48 manifest_id{};
    std::vector<TensorRange> tensors;
};

struct VerifiedRangeLease {
    Digest48 manifest{};
    Generation16 generation{};
    std::vector<unsigned char> bytes;
};

struct RuntimeFingerprint {
    UniValue json;
    std::string runtime_id;
    std::string backend;
    std::string adapter_abi{RUNTIME_ADAPTER_ABI};
    bool stub{false};
};

struct ReadyReceipt {
    UniValue json;
    std::string lease_id;
    Digest48 recipe_id{};
    ReadinessTarget achieved{ReadinessTarget::VERIFIED_FILES};
    bool smoke_performed{false};
    bool smoke_passed{false};
};

struct CapabilityJob {
    std::string job_id;
    Generation16 generation{};
    std::string plan_id;
    std::string state;
    PhysicalDisposition cancel_disp{PhysicalDisposition::NOT_DISPATCHED};
    ReadyReceipt receipt;
};

bool ParseCapabilityRecipe(const UniValue& o, CapabilityRecipe& out, std::string& err_code, std::string& err);
bool RecipeGraphOk(const CapabilityRecipe& r, std::string& err_code, std::string& err);
bool RecipeDigest(const UniValue& recipe_body, Digest48& out, std::string& err);

bool ParseCapabilityLock(const UniValue& o, CapabilityLock& out, std::string& err_code, std::string& err);
bool EnsureLockedPins(const CapabilityLock& lock, const CapabilityRecipe& recipe, std::string& err_code, std::string& err);
bool ExportLockBytes(const CapabilityLock& lock, std::vector<unsigned char>& out, std::string& err);

bool ParseGrant(const UniValue& o, LocalCapabilityGrant& out, std::string& err_code, std::string& err);
bool GrantAllows(const LocalCapabilityGrant& g, const std::string& effect, int64_t now_ms, std::string& err_code,
                 std::string& err);

bool ParseMemoryLimits(const UniValue& o, MemoryLimits& out, std::string& err_code, std::string& err);

bool ResolveCapability(ModelCatalog& cat, const UniValue& query, std::vector<CapabilityPlan>& plans,
                        std::string& err_code, std::string& err);
bool PlanCapability(const CapabilityRecipe& recipe, const CapabilityLock* lock, const LocalCapabilityGrant& grant,
                    CapabilityPlan& plan, std::string& err_code, std::string& err);
int64_t CriticalPathTtcMs(const std::vector<int64_t>& stage_ms, bool overlapped);

class HostResourceBroker {
    uint64_t m_host{0};
    uint64_t m_pinned{0};
    uint64_t m_device{0};
    uint64_t m_speculative{0};
    uint64_t m_host_used{0};
    uint64_t m_pinned_used{0};
    uint64_t m_device_used{0};
    uint64_t m_speculative_used{0};
    uint64_t m_retired_awaiting{0};
    bool m_uma{false};
    int m_prefetch_jobs{0};
    std::unique_ptr<std::mutex> m_mu{std::make_unique<std::mutex>()};

public:
    HostResourceBroker() = default;
    HostResourceBroker(HostResourceBroker&&) noexcept = default;
    HostResourceBroker& operator=(HostResourceBroker&&) noexcept = default;
    HostResourceBroker(const HostResourceBroker&) = delete;
    HostResourceBroker& operator=(const HostResourceBroker&) = delete;

    bool Configure(const MemoryLimits& lim, std::string& err);
    bool Reserve(uint64_t host, uint64_t pinned, uint64_t device, bool speculative, std::string& err);
    void Release(uint64_t host, uint64_t pinned, uint64_t device, bool speculative);
    void NoteRetiredAwaiting(uint64_t bytes);
    void ClearRetired(uint64_t bytes);
    UniValue StatusJson() const;
    bool Uma() const
    {
        std::lock_guard<std::mutex> lock(*m_mu);
        return m_uma;
    }
    int PrefetchJobs() const
    {
        std::lock_guard<std::mutex> lock(*m_mu);
        return m_prefetch_jobs;
    }
    bool AdmitPrefetch(std::string& err);
    void FinishPrefetch();
};

class LeaseTable {
    std::deque<LeaseRecord> m_leases;
    std::unique_ptr<std::mutex> m_mu{std::make_unique<std::mutex>()};
    LeaseRecord* FindUnlocked(const std::string& lease_id);

public:
    LeaseTable() = default;
    LeaseTable(LeaseTable&&) noexcept = default;
    LeaseTable& operator=(LeaseTable&&) noexcept = default;
    LeaseTable(const LeaseTable&) = delete;
    LeaseTable& operator=(const LeaseTable&) = delete;

    LeaseRecord& Create(LeaseClass cls, const std::string& owner, uint64_t bytes, Generation16 gen);
    LeaseRecord* Find(const std::string& lease_id);
    bool Transition(const std::string& lease_id, LeaseLife next, std::string& err_code, std::string& err);
    PhysicalDisposition Cancel(const std::string& lease_id, bool still_inflight);
    bool ReleaseIfQuiescent(const std::string& lease_id, std::string& err);
    bool StaleCompletion(const std::string& operation_id, const Generation16& gen, std::string& err);
    UniValue Json(const std::string& lease_id) const;
};

bool DeriveTensorRangeMap(Span<const unsigned char> verified_header_and_body, uint64_t file_size,
                           uint32_t file_index, const Digest48& manifest_id, TensorRangeMap& out,
                           std::string& err_code, std::string& err);
bool ReadVerifiedRange(const Digest48& manifest, uint32_t file_index, uint64_t offset, uint64_t length,
                        const std::vector<unsigned char>& verified_file, Generation16 gen, VerifiedRangeLease& out,
                        std::string& err_code, std::string& err);
bool SparseHoleIsUnverified(uint64_t offset, uint64_t length, const std::vector<bool>& verified_bitmap,
                            uint64_t piece_size);
bool MapSignerMatchesManifest(const Digest48& map_manifest, const Digest48& expected, std::string& err_code,
                               std::string& err);
bool ReadVerifiedRangeFromPieces(const Digest48& manifest, uint64_t offset, uint64_t length,
                                 const std::vector<std::vector<unsigned char>>& pieces, uint64_t piece_size,
                                 const std::vector<bool>& verified_bitmap, Generation16 gen, VerifiedRangeLease& out,
                                 std::string& err_code, std::string& err);
bool RangeTenantBoundary(const std::string& owner, const std::string& requester, std::string& err_code, std::string& err);
bool CoalesceRangeConsumers(const std::vector<std::pair<uint64_t, uint64_t>>& requests,
                             std::vector<std::pair<uint64_t, uint64_t>>& coalesced);
bool PreferLoadOverRarity(bool consumer_needs_now, uint32_t rarity_score, uint32_t& scheduled_priority);
bool CorruptProviderFallback(bool primary_corrupt, bool secondary_verified, std::string& err_code, std::string& err);
bool CancelVerifiedRange(PhysicalDisposition inflight, PhysicalDisposition& out);
bool RequiredShardsPresent(const std::vector<uint32_t>& required, const std::vector<uint32_t>& present,
                           std::string& err_code, std::string& err);
bool AdmitTensorMapCount(size_t tensor_count, uint64_t header_bytes, std::string& err_code, std::string& err);

bool MaterializeCompleteFile(const std::vector<std::vector<unsigned char>>& pieces, const std::string& dest,
                             Generation16 gen, std::string& err_code, std::string& err);
bool StreamingEqualsFullFile(const std::vector<unsigned char>& streamed, const std::vector<unsigned char>& full);

struct RuntimeAdapterStatus {
    std::string runtime_id;
    std::string backend;
    bool present{false};
    bool stub{false};
    std::string detail;
};

std::vector<RuntimeAdapterStatus> ProbeRuntimeAdapters();
bool CpuFixtureSmoke(Span<const unsigned char> verified, Digest48& out_digest, std::string& err);
bool LoadTrustedRuntime(const std::string& runtime_id, Span<const unsigned char> verified,
                        const UniValue& typed_params, ReadyReceipt& receipt, std::string& err_code, std::string& err);
bool SleepRuntimePreserveWeights(const std::string& lease_id, UniValue& status, std::string& err_code, std::string& err);
bool WakeRuntimeRemapOnly(const std::string& lease_id, ReadyReceipt& receipt, std::string& err_code, std::string& err);
bool WakeRuntimeRebuildKv(const std::string& lease_id, ReadyReceipt& receipt, std::string& err_code, std::string& err);
bool AttachExactBaseAdapter(const Digest48& base_id, const Digest48& adapter_base_binding, std::string& err_code,
                            std::string& err);
bool ComposeLoraOrder(const std::vector<std::string>& adapter_ids, const std::vector<std::string>& scales,
                      Digest48& composition_id, std::string& err);

bool AdmitPrefetchHint(const UniValue& hint, const LocalCapabilityGrant& grant, HostResourceBroker& broker,
                        UniValue& job, std::string& err_code, std::string& err);
bool AcceptExecutableCache(const UniValue& cache, bool trusted_builder, const Digest48& model_author_sig,
                           std::string& err_code, std::string& err);

bool PrivatePrefixKey(const std::string& tenant, const UniValue& config_fingerprint, const std::string& token_prefix,
                       Digest48& out, std::string& err);
bool PrefixVisibleToTenant(const std::string& owner_tenant, const std::string& requester);

struct PeerTransferOffer {
    UniValue json;
    TransportAssurance assurance{TransportAssurance::HOST_BUFFER};
    bool nixl_present{false};
    bool gds_present{false};
};

bool ProbePeerBackends(PeerTransferOffer& out);
bool HostBufferTransfer(Span<const unsigned char> src, std::vector<unsigned char>& dest, Generation16 gen,
                        PhysicalDisposition& disp, std::string& err);
bool RetainUntilQuiescent(PhysicalDisposition d);
bool PeerMembershipAllows(const std::string& fabric_policy, const std::string& peer_id, std::string& err_code,
                           std::string& err);
bool PeerExactGeometry(const TensorRangeMap& local, const TensorRangeMap& peer, std::string& err_code, std::string& err);
bool VerifyPeerDestination(Span<const unsigned char> received, const Digest48& expected, bool compute_started,
                           std::string& err_code, std::string& err);
bool RegisterPeerMemoryNarrow(uint64_t buffer_bytes, uint64_t registered_bytes, std::string& err_code, std::string& err);
bool LatePeerCompletionAfterTimeout(const Generation16& live_gen, const Generation16& completion_gen,
                                     PhysicalDisposition& disp, std::string& err);
bool GdsCancelRetain(bool still_inflight, PhysicalDisposition& disp);
bool DirectVerifiedSourcePath(bool source_verified, bool gds_aligned, TransportAssurance& path,
                               std::string& err_code, std::string& err);
bool RejectUnverifiedOriginDirect(bool origin_verified, std::string& err_code, std::string& err);
bool AlignmentFallbackHost(bool aligned, TransportAssurance& path);
bool RejectFalseZeroCopy(bool device_pointer_recycled, bool fence_complete, std::string& err_code, std::string& err);
bool RocmMetalDirectDistinction(const std::string& backend, std::string& err_code, std::string& err);
bool DirectFastPathParity(Span<const unsigned char> direct, Span<const unsigned char> host_copy);

struct ExpertUnit {
    std::string expert_id;
    LeaseLife life{LeaseLife::RESERVED};
    uint32_t layer{0};
    uint32_t expert{0};
};

bool MoEDispatch(const std::vector<ExpertUnit>& resident, uint32_t layer, uint32_t expert, bool allow_wan,
                 std::string& err_code, std::string& err);
bool MoEAllResidentParity(Span<const unsigned char> paged, Span<const unsigned char> all_resident);
bool MoEExpertMapComplete(const std::vector<ExpertUnit>& required, const std::vector<ExpertUnit>& resident,
                           std::string& err_code, std::string& err);
bool MoEWorkingSetShift(std::vector<ExpertUnit>& working, const ExpertUnit& incoming, uint64_t device_budget_bytes,
                         uint64_t expert_bytes, std::string& err_code, std::string& err);
bool MoEEvictionRaceSafe(LeaseLife executing, bool evict_same, std::string& err_code, std::string& err);
bool MoERuntimeHook(const std::string& runtime_id, bool& hook_present, std::string& err_code, std::string& err);

struct TopologyReport {
    UniValue json;
    bool numa{false};
    bool cxl{false};
    bool macos_unified{false};
};

TopologyReport DiscoverTopology();
bool PlaceInTier(PlacementTier want, PlacementTier have, std::string& err_code, std::string& err);
bool NumaPlaceRepresentation(int node, int want_node, std::string& err_code, std::string& err);
bool PhysicalPoolUnique(const std::vector<std::string>& pool_ids, std::string& err_code, std::string& err);
bool RecoverTierLoss(PlacementTier lost, PlacementTier fallback, PlacementTier& used, std::string& err_code,
                     std::string& err);
bool PlacementCompare(int64_t local_nvme_ms, int64_t remote_tier_ms, PlacementTier& chosen);

bool JournalSwitch(const std::string& old_lock, const std::string& new_lock, const std::string& phase,
                   std::string& err);
bool CrashResumeSwitch(const std::vector<std::string>& journal, std::string& active_lock, std::string& err);

bool MigratePriorPackageState(const UniValue& old_meta, UniValue& new_meta, std::string& err_code, std::string& err);
bool RejectLegacyModelHandshake(int peer_core_version, std::string& err_code, std::string& err);

/** Ensure uses existing TransferSession/GlobalTransferCredits. No second downloader. */
bool EnsureCapability(ModelCatalog& cat, const UniValue& request, UniValue& result, std::string& err_code,
                      std::string& err);
bool GetCapabilityTtcTrace(const std::string& job_id, UniValue& out, std::string& err_code, std::string& err);
bool PlanCapabilityUpdate(const UniValue& request, UniValue& result, std::string& err_code, std::string& err);
bool AppendCapabilityEvent(const UniValue& event);
bool CompactCapabilityEvents(int64_t cursor, UniValue& out);
bool HelperDownFail(bool helper_alive, std::string& err_code, std::string& err);
bool SoftwareTrustFloor(const std::string& current_client, const std::string& rollback_client, std::string& err_code,
                         std::string& err);

/** Owner-only capability RPC. Never public HTTP. automatic_spend_atoms stays 0. */
bool IsCapabilityHelperMethod(const std::string& method);
bool DispatchCapabilityRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                            std::string& err_code, std::string& err);

HostResourceBroker& GlobalCapabilityBroker();
LeaseTable& GlobalCapabilityLeases();

bool LookupCapabilityPlan(const std::string& plan_id, CapabilityPlan& out);
void StoreCapabilityPlan(const CapabilityPlan& plan);
void StoreCapabilityJob(const CapabilityJob& job);
bool LookupCapabilityJob(const std::string& job_id, CapabilityJob& out);
void StoreCapabilityLock(const CapabilityLock& lock);
bool LookupCapabilityLock(const std::string& lock_id, CapabilityLock& out);

bool PerRankFeasible(const std::vector<uint64_t>& rank_free_bytes, uint64_t need_per_rank, std::string& err);

/** Owner-only unix daemon. Never public HTTP. */
int RunCapabilityDaemon(const fs::path& modeldir, fs::path socket, std::atomic<bool>* stop);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CAPABILITY_H
