// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Hosted Control Plane (BTX-HCP-001). Separate from consensus, wallet RPC,
// and public HTTP capability methods. automatic_spend_atoms stays 0.
// FinancialReceipt is not consensus-ready or runtime-ready.

#ifndef BITCOIN_MODELNET_HCP_H
#define BITCOIN_MODELNET_HCP_H

#include <modelnet/capability.h>
#include <modelnet/catalog.h>
#include <modelnet/hcp_types.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <atomic>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

struct HcpEnvelope {
    std::string object_type;
    UniValue body{UniValue::VOBJ};
    Digest48 body_id{};
    std::string signer_key_id;
    std::vector<unsigned char> signature;
    bool signature_present{false};
};

struct HcpConfig {
    std::string instance_id{"hcp-a"};
    std::string provider_id{"provider-demo"};
    std::string origin{"https://exchange.example"};
    std::string api_base{"https://exchange.example/btx/hcp/v1"};
    std::string audience{"https://exchange.example/btx/hcp/v1"};
    std::string mcp_audience{"https://exchange.example/mcp"};
    std::string genesis_hash{"0000000000000000000000000000000000000000000000000000000000000000"};
    // All-zero genesis is the lab/REGTEST default. It must not be treated as a
    // mainnet pin; finance/custody callers have to set a real hash.
    std::string environment{"REGTEST"};
    std::set<std::string> enabled_profiles{HCP_PROFILE_DISCOVERY, HCP_PROFILE_HANDOFF};
    bool finance_enabled{false};
    bool start_wallet{false};
    bool start_mining{false};
    bool expose_runtime_to_gateway{false};
    bool reporting_default_off{true};
    int64_t automatic_spend_atoms{HCP_AUTOMATIC_SPEND_ATOMS};
    int64_t max_body_bytes{HCP_MAX_BODY_BYTES};
    int max_page_size{HCP_MAX_PAGE};
    int64_t clock_ms{HCP_DEFAULT_CLOCK_MS};
    int64_t clock_skew_ms{120000};
    fs::path persist_dir;
    std::string replica_id{"replica-1"};
    std::string custody_backend{HCP_CUSTODY_DISABLED};
    int required_confirmations{1};
    bool walletless{true};
    bool simulation_only{false};
    bool cr11_enabled{false};
    bool cr12_enabled{false};
};

struct HcpHttpRequest {
    std::string method{"GET"};
    std::string path;
    std::string query;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct HcpHttpResponse {
    int status{200};
    std::string content_type{"application/json"};
    std::string body;
    std::map<std::string, std::string> headers;
    UniValue json{UniValue::VOBJ};
    bool CachePrivate() const;
};

bool HcpObjectTypeOk(const std::string& t);
std::string HcpDomain(const std::string& object_type);
bool ParseAtomString(const std::string& s, int64_t& out, std::string& err);
bool FormatAtomString(int64_t n, std::string& out);
bool HcpCanonicalBody(const UniValue& body, std::vector<unsigned char>& out, std::string& err);
bool HcpBodyId(const std::string& object_type, const UniValue& body, Digest48& out, std::string& err);
bool HcpAmountsOk(const UniValue& amounts, int64_t& total, std::string& err);
bool ParseHcpEnvelope(const UniValue& obj, HcpEnvelope& out, std::string& err);
UniValue EncodeHcpEnvelope(const HcpEnvelope& env);
bool HcpSign(HcpEnvelope& env, Span<const unsigned char> sk, const std::string& key_id, std::string& err);
bool HcpVerify(const HcpEnvelope& env, Span<const unsigned char> pk, std::string& err);
bool HcpRejectForbiddenFields(const UniValue& body, std::string& err);
bool HcpEnvelopeFromBytes(Span<const unsigned char> raw, HcpEnvelope& out, std::string& err);
bool HcpIsPublicReadPath(const std::string& method, const std::string& path);
//! True only for a 96-char lowercase hex SHA-384 that is not a repeated-nibble
//! placeholder (96 x 'a' / 96 x 'b' and the like). Signed extension metadata
//! must not authenticate filler strings as contract hashes.
bool HcpSha384DigestUsable(const std::string& hex);
//! Write schema_digest / operations_digest when both are usable and distinct;
//! otherwise null the fields and mark negotiation unavailable.
void HcpApplyNegotiatedDigests(UniValue& body, const std::string& schema_digest, const std::string& operations_digest);

int64_t Cr11Capacity(int64_t available, int64_t protected_atoms, int64_t remaining_authority);
bool Cr11ReportingFloorAtoms(const std::string& required_quote, const std::string& price_quote_per_coin, int exponent,
                             int64_t observed_at, int64_t now, int64_t max_age, int haircut_bps, int64_t& out,
                             std::string& err);
bool Cr11Tco(const std::string& annual_tasks, const std::string& service_per_task, int years, const std::string& upfront,
             const std::string& annual_local, bool quality_equivalent, bool inputs_known, UniValue& out,
             std::string& err);
bool Cr11ValidateDag(const UniValue& legs, std::vector<std::string>& order, std::string& err);
bool Cr11Approved(const UniValue& decisions, const std::string& entity, const std::string& plan,
                  const std::string& policy_generation, const std::string& rule,
                  const std::set<std::string>& eligible_people, int quorum, const std::string& initiator, int64_t now,
                  bool exclude_initiator, bool veto, std::string& err);

bool Crl12BrandDispatch(const std::string& s);
bool Crl12FiniteDecimal(const std::string& s, std::string& err);
bool Crl12AddDecimal(const std::string& a, const std::string& b, std::string& out, std::string& err);
bool Crl12ScaleDecimal(const std::string& a, int64_t numerator, int64_t denominator, std::string& out, std::string& err);
bool Crl12MetricEligible(const std::string& metric_kind, const std::string& mandate, const std::string& asset_kind);
bool Crl12CsvSafe(const std::string& cell, std::string& out);
std::string Crl12SchemaDigest();
std::string Crl12OperationsDigest();
std::string Cr11SchemaDigest();
std::string Cr11OperationsDigest();

HcpConfig HcpWalletlessPreset();
HcpConfig HcpFundingLabPreset();

class HcpEngine
{
public:
    static std::unique_ptr<HcpEngine> Create(const HcpConfig& cfg, std::string& err);
    ~HcpEngine();

    HcpHttpResponse Handle(const HcpHttpRequest& req);
    void SetClock(int64_t ms);
    int64_t Now() const;
    const HcpConfig& Cfg() const;

    const std::vector<unsigned char>& RootPk() const;
    const std::vector<unsigned char>& OpPk() const;
    const std::vector<unsigned char>& RootSk() const;
    const std::vector<unsigned char>& OpSk() const;
    bool SignAsProvider(HcpEnvelope& env, std::string& err);
    bool SignAsRoot(HcpEnvelope& env, std::string& err);

    UniValue PreviewProvider(const HcpEnvelope& profile);
    bool EnrollProvider(const HcpEnvelope& profile, bool operator_accept, std::string& err_code, std::string& err);
    bool RotateOperationalKey(int64_t new_sequence, std::string& err_code, std::string& err);
    bool ReplayOldKeyset(const std::string& key_id, std::string& err_code);

    std::string LabCreatePkceChallenge(const std::string& verifier);
    std::string LabAuthorize(const std::string& account, const std::string& client_id, const std::string& redirect,
                            const std::string& state, const std::string& challenge,
                            const std::vector<std::string>& scopes);
    bool LabToken(const std::string& code, const std::string& verifier, const std::string& redirect,
                  const std::string& dpop_jkt, const std::string& audience, UniValue& out, std::string& err_code);
    void LabRevokeRefresh(const std::string& refresh);
    std::string LabAccessToken() const;
    std::string LabDpop(const std::string& htm, const std::string& htu, const std::string& access_token);
    std::string LabJkt() const;
    std::string LabJktOther() const;
    void PutAccount(const std::string& account, int64_t available_atoms);
    void SetLocalGrant(const LocalCapabilityGrant& g);
    void RevokeLocalGrant();
    void SetHostedPolicy(const UniValue& policy);
    UniValue AcceptHandoff(const HcpEnvelope& env, std::string& err_code, std::string& err);
    void PutPackage(const std::string& core_id_hex, std::vector<unsigned char> bytes, const std::string& recipe_id);
    void PutOffer(const HcpEnvelope& offer);
    void SetNativeHeight(int64_t h);
    void SetNativeConfirmations(const std::string& txid, int n);
    void InjectReorg(const std::string& txid);
    void SetObserverAvailable(bool v);
    void SetIndependentVerifierAgrees(bool v);
    void SetDmaActive(bool v);
    void FenceDma();
    void SetRuntimeWarmupFail(bool v);
    void PutResidentBase(const std::string& id);
    void PutLanSource(const std::string& id, int64_t ttc_ms);
    void PutInternetSource(const std::string& id, int64_t ttc_ms);
    void SetMissingExtent(bool v);
    void SetPrivatePrompt(const std::string& prompt);
    void SetPrivateKv(const std::string& kv);
    UniValue ExportPublic(bool include_secrets);
    bool Persist();
    bool Restore();
    UniValue TrafficCapture() const;
    UniValue LogRedactionScan() const;
    void SetExecutorOwner(const std::string& replica);
    void ExpireLease();
    void SetNativeTemplateFamily(const std::string& fam);
    UniValue GoLiveManifest() const;
    void RegisterFetch(const std::string& url, int status, const std::string& location, const std::string& body);
    UniValue FetchUrl(const std::string& url, const std::string& authorization);
    void DiscloseSecret(const std::string& intent_id);
    void SetRefundHeight(int64_t h);
    int64_t NativeHeight() const;
    std::string LastSignedTxHex() const;
    std::string LastTxid() const;
    void ForceBroadcastUnknown(const std::string& intent_id);
    void CompleteConversion(const std::string& intent_id);
    void ExpireQuote(const std::string& quote_id);
    void ChangeTerms(const std::string& terms_id);
    void SeedDemoCatalog();
    UniValue SignedProviderProfile();
    UniValue ConnectorStatus() const;
    void DisconnectProvider();
    bool ProviderReachable() const;
    void SetDeviceNonce(const std::string& device_id, const std::string& nonce);
    void PairDevice(const std::string& device_id, const std::string& account);
    void RevokeDevice(const std::string& device_id);
    bool DevicePaired(const std::string& device_id) const;
    void SetReporting(bool on);
    void SetSourcePolicyNativeOnly(bool v);
    void PutSourceHintWithSecret(const std::string& url);
    void SetSchemaMigrationCrash(bool v);
    UniValue AnalyticsView() const;
    size_t IntentCount() const;
    std::string IntentState(const std::string& intent_id) const;
    std::string ReceiptState(const std::string& receipt_id) const;
    int64_t AccountAvailable(const std::string& account) const;
    int64_t AccountHeld(const std::string& account) const;
    int64_t LifetimeSpent(const std::string& policy_id) const;
    bool KnowledgeDisclosed(const std::string& intent_id) const;
    UniValue PlanLocal(const std::string& recipe_id, std::string& err_code);
    bool EnsureLocal(const std::string& recipe_id, UniValue& out, std::string& err_code);
    void SetReadiness(const std::string& device_id, const std::string& state);
    UniValue LastHandoffJob() const;
    void PutSentinel(const std::string& name, const std::string& value);
    UniValue ChildRuntimeEnv() const;
    void SetWebhookTarget(const std::string& url, std::string& err_code);
    void DeliverEventDuplicates(const std::string& event_id, int n);
    int64_t EventLogicalCount(const std::string& business_key) const;
    void RestoreCatalogueIndex();
    void CrashOutbox();
    void RecoverOutbox();
    bool OutboxDrained() const;
    void SetSubscriptionRevoked(const std::string& sub_id);
    UniValue Statements() const;
    void PutLot(const std::string& lot_id, const std::string& account, const std::string& output);
    bool AttributeOutput(const std::string& output, const std::string& account, std::string& err_code);
    void SetConfirmationsRequired(int n);
    UniValue ReceiptAuthorityLabel(const std::string& receipt_id) const;
    void SetUnknownCriticalCapability(bool v);
    UniValue SwitchProvider(const std::string& new_provider_id);
    void SetPendingUnknownOn(const std::string& provider_id, const std::string& intent_id);
    UniValue DualInstancePeerNote() const;

    int64_t Cr11CapacityOf(const std::string& account) const;
    void Cr11SetProtected(int64_t atoms);
    void Cr11SetRemainingAuthority(int64_t atoms);
    void Cr11SetPendingDeposit(int64_t atoms);
    void Cr11SetExpectedRefund(int64_t atoms);
    void Cr11SetSiblingFunds(int64_t atoms);
    void Cr11SetForecastSavings(int64_t atoms);
    void Cr11SetEncumbered(int64_t atoms);
    void Cr11SetCognitiveHoldings(int64_t atoms);
    void Cr11SetFamilyView(bool v);
    void Cr11SetRefundReplenish(bool v);
    void Cr11DisableExtension();
    void Cr11BindPerson(const std::string& actor_id, const std::string& person_id, const std::string& role);
    void Cr11ExpirePerson(const std::string& person_id);
    void Cr11SetSoftBudget(const std::string& dept, int64_t atoms);
    std::string Cr11LastChildIntent() const;
    std::string Cr11LastChildHandoff() const;
    std::string Cr11LastExecutionId() const;
    void Cr11MarkCrossCexAction(const std::string& action_id);
    void Cr11SetQuoteObservedAt(int64_t observed_at_ms);
    UniValue Cr11LastReport() const;
    int64_t Cr11LifetimeSpent() const;
    int64_t Cr11Outstanding() const;
    bool Cr11ExtensionEnabled() const;
    bool Crl12ExtensionEnabled() const;
    void Crl12SetEnabled(bool v);
    size_t Crl12PositionCount() const;
    size_t Crl12LoadSynthetic(size_t n, const std::string& account, const std::string& mandate);
    int64_t Crl12NativeAvailable(const std::string& account) const;

private:
    class Impl;
    std::unique_ptr<Impl> m;
    explicit HcpEngine(std::unique_ptr<Impl> impl);
};

bool IsHcpHelperMethod(const std::string& method);
bool DispatchHcpRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                     std::string& err_code, std::string& err);

int RunHcpDaemon(HcpConfig cfg, const std::string& bind, const fs::path& socket, std::atomic<bool>* stop);
int RunHostedCli(const std::vector<std::string>& args, std::string& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_HCP_H
