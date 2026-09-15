// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_BOUNTY_H
#define BITCOIN_MODELNET_BOUNTY_H

#include <modelnet/canonical_codec.h>
#include <modelnet/identity.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

class ModelCatalog;

constexpr int64_t BOUNTY_MAX_HEIGHT = 499999999;
constexpr int BOUNTY_PAGE_MAX = 100;
constexpr int BOUNTY_COUNCIL_MAX = 8;
constexpr int BOUNTY_LOTS_MAX = 16;
constexpr const char* BOUNTY_TRUST_LABEL = "COUNCIL_CUSTODIAL_AUTHORITY_WITH_INDIVIDUAL_REFUND_PATHS";

struct SignedEnvelope {
    UniValue body{UniValue::VOBJ};
    std::vector<unsigned char> signature;
    Digest48 record_id;
    bool verified{false};
};

bool ValidateTimeline(int64_t funding, int64_t submission, int64_t evaluation, int64_t award,
                      int64_t last_safe, int64_t refund, int confirmations, int margin, std::string& err);
bool ValidateCouncil(const UniValue& council, int threshold, std::string& err);
bool ValidateBountyTerms(const UniValue& terms, const NetworkId& network, std::string& err);
UniValue FundingView(const std::string& target, const std::string& pledged, const UniValue& confirmed);
bool EligibleBps(const std::string& principal, const std::string& frozen_total, int min_bps, std::string& err);
bool AllocateFeeReserve(const std::vector<int64_t>& reserves, int64_t fee,
                        std::vector<int64_t>& charges, std::vector<int64_t>& remaining, std::string& err);
int64_t DedupePrincipal(const std::vector<std::pair<std::string, int64_t>>& lots, std::string& err);

bool BuildSignedEnvelope(const std::string& record_type, const NetworkId& network,
                         Span<const unsigned char> pk, Span<const unsigned char> sk,
                         const UniValue& payload, const UniValue& delegation_id,
                         SignedEnvelope& out, std::string& err);
bool VerifySignedEnvelope(const SignedEnvelope& env, const NetworkId& expected_network, std::string& err);
bool EnvelopeFromJson(const UniValue& o, SignedEnvelope& env, std::string& err);
UniValue EnvelopeToJson(const SignedEnvelope& env);

class MandateBudget {
    int64_t m_total{0};
    int64_t m_per_action{0};
    int64_t m_used{0};
    bool m_revoked{false};
    std::map<std::string, std::pair<int64_t, std::string>> m_req;
    mutable std::mutex m_mu;

public:
    void Reset(int64_t total, int64_t per_action);
    bool Reserve(const std::string& key, int64_t amount, std::string& err);
    bool Reserve(const std::string& key, int64_t amount, const std::string& refund_key, std::string& err);
    void Revoke();
    bool Revoked() const;
    int64_t Used() const;
};

struct BountyChainFact {
    std::string outpoint;
    int64_t amount_atoms{0};
    int confirmations{0};
    uint32_t height{0};
    bool spent{false};
    std::string lot_id;
    std::string bounty_id;
};

class BountyChainIndex {
    std::map<std::string, BountyChainFact> m_facts;
    std::vector<std::map<std::string, BountyChainFact>> m_undo;
    uint32_t m_height{0};
    uint64_t m_epoch{1};

public:
    void Observe(const BountyChainFact& f);
    void DisconnectTip();
    void SetHeight(uint32_t h) { m_height = h; }
    uint32_t Height() const { return m_height; }
    uint64_t Epoch() const { return m_epoch; }
    const BountyChainFact* Get(const std::string& outpoint) const;
    int64_t ConfirmedAtoms(const std::string& bounty_id) const;
    UniValue Snapshot(const std::string& bounty_id) const;
    UniValue ExportRecovery(const std::string& bounty_id, const std::vector<std::string>& lot_ids) const;
    bool ImportManifest(const UniValue& manifest, std::string& err);
};

class BountyStore {
    NetworkId m_network{};
    fs::path m_dir;
    std::map<std::string, UniValue> m_drafts;
    std::map<std::string, SignedEnvelope> m_terms;
    std::map<std::string, UniValue> m_bounties;
    std::map<std::string, std::vector<SignedEnvelope>> m_noms;
    std::map<std::string, std::vector<SignedEnvelope>> m_appointments;
    std::map<std::string, SignedEnvelope> m_pledges;
    std::map<std::string, UniValue> m_rounds;
    std::map<std::string, UniValue> m_submissions;
    std::map<std::string, UniValue> m_eval_plans;
    std::map<std::string, UniValue> m_eval_jobs;
    std::map<std::string, SignedEnvelope> m_eval_reports;
    std::map<std::string, SignedEnvelope> m_challenges;
    std::map<std::string, UniValue> m_awards;
    std::map<std::string, UniValue> m_watches;
    std::map<std::string, UniValue> m_mandates;
    std::vector<UniValue> m_events;
    std::map<std::string, UniValue> m_idem;
    std::map<std::string, UniValue> m_activity;
    std::set<std::string> m_revoked_delegations;
    uint64_t m_seq{0};
    uint64_t m_epoch{1};
    mutable std::mutex m_mu;
    BountyChainIndex m_chain;
    MandateBudget m_budget;
    std::map<std::string, std::unique_ptr<MandateBudget>> m_budgets;

    UniValue Event(const std::string& kind, const std::string& bounty_id, const UniValue& payload);
    bool Idem(const std::string& method, const std::string& key, UniValue& out) const;
    void Remember(const std::string& method, const std::string& key, const UniValue& result);
    bool LoadIdentity(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, Digest48& id, std::string& err);
    bool PersistLocked(std::string& err) const;
    UniValue BountyEntryLocked(const std::string& bounty_id) const;

public:
    void Bind(const fs::path& dir, const NetworkId& network);
    NetworkId Network() const { return m_network; }
    void SetNetwork(const NetworkId& n) { m_network = n; }
    BountyChainIndex& Chain() { return m_chain; }
    MandateBudget& Budget() { return m_budget; }

    bool Dispatch(const std::string& method, const UniValue& params, UniValue& result, std::string& err_code, std::string& err);
    UniValue Capabilities() const;
    bool Load(std::string& err);
    bool Save(std::string& err) const;
};

bool IsBountyHelperMethod(const std::string& method);
bool DispatchBountyHelperRpc(ModelCatalog& cat, const std::string& method, const UniValue& params,
                             UniValue& result, std::string& err_code, std::string& err);
BountyStore& GlobalBountyStore();

/** Isolated EXACT_CHECKS runner. Other profiles are advertised only when a harness binary exists. */
bool PrepareEvaluation(const UniValue& spec, const UniValue& submission, const UniValue& resources,
                        UniValue& plan, std::string& err);
bool RunEvaluationJob(UniValue& job, std::string& err);
bool CancelEvaluationJob(UniValue& job, std::string& err);
bool EvaluationProfileReady(const std::string& profile_id);

} // namespace modelnet

#endif // BITCOIN_MODELNET_BOUNTY_H
