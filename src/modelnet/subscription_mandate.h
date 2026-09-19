// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SUBSCRIPTION_MANDATE_H
#define BITCOIN_MODELNET_SUBSCRIPTION_MANDATE_H

#include <modelnet/types.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Distinct from AgentMandate (bounty exact-terms-ID). This type does not
 * replace or widen AgentMandate. SubscriptionMandate binds one exact
 * publisher identity plus finite caps; wildcards, all-publishers, unlimited
 * amounts, and no-expiry are rejected.
 *
 * Signing is not performed here. EvaluateAndReserve returns an unsigned
 * Reservation for the wallet plane. The helper must never receive wallet keys.
 * automatic_spend_atoms remains 0; FUND_WITH_MANDATE requires an explicit
 * mandate id.
 *
 * Reorg does not magically refund spend budget: reserved/spent principal and
 * fees stay reserved. The wallet plane handles UTXO restoration separately.
 */
constexpr int64_t SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS = 0;
constexpr int SUBSCRIPTION_CONCURRENT_MAX = 32;
constexpr int SUBSCRIPTION_MANDATE_VERSION = 1;
constexpr const char* SUBSCRIPTION_REFUND_POLICY = "OWNER_CONTROLLED_ONLY";

enum class WatchAction : uint8_t {
    NOTIFY = 0,
    FREE_DOWNLOAD = 1,
    KEEP = 2,
    SEED = 3,
    PREPARE_FUNDING = 4,
    FUND_WITH_MANDATE = 5,
};

const char* WatchActionName(WatchAction a);
bool ParseWatchAction(const std::string& s, WatchAction& out);

struct WatchActionPolicy {
    WatchAction action{WatchAction::NOTIFY};
    std::string mandate_id;
};

bool ValidateWatchActionPolicy(const WatchActionPolicy& p, std::string& err);

struct SubscriptionMandate {
    int mandate_version{SUBSCRIPTION_MANDATE_VERSION};
    std::string mandate_id;
    std::string owner_identity;
    NetworkId network_id{};
    std::string publisher_id;
    std::vector<std::string> allowed_kinds;
    std::vector<std::string> allowed_actions;
    std::string collection_id;
    std::string query_filter;
    int64_t per_action_principal_limit_atoms{0};
    int64_t total_principal_limit_atoms{0};
    int64_t total_fee_limit_atoms{0};
    int64_t outstanding_exposure_limit_atoms{0};
    int64_t max_actions{0};
    int max_concurrent_reservations{0};
    int64_t expires_at_ms{0};
    std::string refund_key_policy{SUBSCRIPTION_REFUND_POLICY};
    int minimum_confirmations{1};
    std::vector<std::string> assurance_mode_restrictions;
    int64_t revocation_counter{0};
    bool revoked{false};
};

struct SubscriptionEvent {
    std::string event_id;
    std::string publisher_id;
    std::string object_kind;
    std::string object_id;
    std::string collection_id;
    std::string terms_id;
    std::string action;
    std::string mandate_id;
    std::string query_text;
    int64_t observed_at_ms{0};
    std::string nested_publisher_id;
    std::string nested_recipient;
};

struct SignedTerms {
    bool known{false};
    std::string terms_id;
    std::string publisher_id;
    std::string network_id_hex;
    std::string recipient_id;
    std::string refund_key;
    int64_t principal_atoms{0};
    int64_t fee_atoms{0};
    std::string object_kind;
    std::string collection_id;
    int confirmations{0};
    std::string assurance_mode;
    bool all_recipients{false};
    std::vector<std::string> recipients;
    std::string nested_recipient;
    std::string nested_publisher_id;
    UniValue raw{UniValue::VOBJ};
};

struct Reservation {
    std::string reservation_id;
    std::string mandate_id;
    std::string event_id;
    /** Object and terms the reservation was authorized for. Held so that a second
     *  event carrying the same event_id but a different object or terms is a
     *  conflict instead of a silent replay. Never serialized to the wallet plane. */
    std::string object_id;
    std::string terms_id;
    int64_t principal_atoms{0};
    int64_t fee_atoms{0};
    bool wallet_signed{false};
    bool broadcast{false};
    bool contains_wallet_material{false};
};

bool ValidateMandate(const SubscriptionMandate& m, std::string& err);
bool MandateFromJson(const UniValue& o, SubscriptionMandate& m, std::string& err);
UniValue MandateToJson(const SubscriptionMandate& m);
bool EventFromJson(const UniValue& o, SubscriptionEvent& ev, std::string& err);
bool TermsFromJson(const UniValue& o, SignedTerms& t, std::string& err);
UniValue ReservationToJson(const Reservation& r);

bool Evaluate(const SubscriptionEvent& event, const SignedTerms& terms,
              const SubscriptionMandate& mandate, int64_t now_ms, std::string& err);

UniValue PrepareFundingPlan(const SubscriptionEvent& event, const SignedTerms& terms);

class SubscriptionBudget {
    SubscriptionMandate m_mandate;
    int64_t m_used_principal{0};
    int64_t m_used_fees{0};
    int64_t m_outstanding{0};
    int64_t m_action_count{0};
    int m_concurrent{0};
    int64_t m_reorgs{0};
    bool m_bound{false};
    std::map<std::string, Reservation> m_by_event;
    mutable std::mutex m_mu;

public:
    bool Bind(const SubscriptionMandate& m, std::string& err);
    bool EvaluateAndReserve(const SubscriptionEvent& event, const SignedTerms& terms,
                            Reservation& out, int64_t now_ms, std::string& err);
    void Revoke();
    bool Revoked() const;
    bool Expired(int64_t now_ms) const;
    int64_t UsedPrincipal() const;
    int64_t UsedFees() const;
    /** Principal plus fees reserved and not yet settled by MarkBroadcast. */
    int64_t OutstandingExposure() const;
    int64_t ActionCount() const;
    int ConcurrentReservations() const;
    int64_t ReorgCount() const;
    /** Spent stays spent: a chain reorg never restores principal or fee budget. It
     *  does drop the idempotency entry of every already-broadcast reservation, so a
     *  replayed event is authorized afresh against the live budget rather than
     *  handed back a reservation that belonged to the orphaned chain. */
    void NoteChainReorg();
    bool MarkBroadcast(const std::string& event_id, std::string& err);
    SubscriptionMandate Mandate() const;
    UniValue StatusJson() const;
    /** WALLET_OWNER ActionPage: event → terms → reservation. Never wallet material.
     *  `cursor` is the last event_id from a previous page (exclusive). `limit` is 1..100. */
    UniValue ActivityPage(const std::string& cursor, int limit) const;
    /** Durable form of the mandate plus its spent budget and open reservations. */
    UniValue SaveStateJson() const;
    bool LoadStateJson(const UniValue& state, std::string& err);
};

bool EvaluateAndReserve(SubscriptionBudget& budget, const SubscriptionEvent& event,
                        const SignedTerms& terms, Reservation& out, int64_t now_ms,
                        std::string& err);

class SubscriptionStore {
    std::map<std::string, SubscriptionMandate> m_mandates;
    std::map<std::string, std::unique_ptr<SubscriptionBudget>> m_budgets;
    fs::path m_path;
    std::string m_node_network;
    mutable std::mutex m_mu;

    bool SaveLocked(std::string& err) const;

public:
    /** Drop every mandate, the persist binding, and the node network binding. */
    void Reset();
    /** Back the store with a file. Existing state at `path` is loaded immediately and
     *  every later mutation is written back, so spent budget and revocation survive a
     *  restart. Without a path the store stays memory-only. */
    bool SetPersistPath(const fs::path& path, std::string& err);
    bool Persisted() const;
    /** Bind the store to the network the node is actually on. Mandates for another
     *  network are then refused at creation and cannot be reserved against. */
    bool SetNodeNetwork(const std::string& network_hex, std::string& err);
    std::string NodeNetwork() const;
    bool Dispatch(const std::string& method, const UniValue& params, UniValue& result,
                  std::string& err_code, std::string& err, int64_t now_ms);
};

bool IsSubscriptionHelperMethod(const std::string& method);
bool DispatchSubscriptionRpc(const std::string& method, const UniValue& params, UniValue& result,
                             std::string& err_code, std::string& err);
SubscriptionStore& GlobalSubscriptionStore();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SUBSCRIPTION_MANDATE_H
