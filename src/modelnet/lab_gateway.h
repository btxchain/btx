// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_GATEWAY_H
#define BITCOIN_MODELNET_LAB_GATEWAY_H

#include <univalue.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace modelnet {

/** Hosted checks never hand an arbitrary method name to a general router. */
constexpr bool GeneralMethodRouterEnabled() { return false; }

/**
 * Allowlist loaded from a caller-supplied OpenAPI document.
 * HostedRouteAllowed is true only for operations that document actually lists,
 * and never for /rpc, a shell path, or a wallet method.
 */
class HostedGateway {
public:
    struct Route {
        std::string http_method;
        std::string path;
        std::string operation_id;
        bool mutation{false};
    };

    bool Load(const std::string& openapi_path, std::string& err);

    bool HostedRouteAllowed(const std::string& method, const std::string& path) const;
    bool CheckRoute(const std::string& method, const std::string& path, std::string& err) const;
    bool CheckOperationId(const std::string& operation_id, std::string& err) const;
    bool IsMutation(const std::string& operation_id) const;

    /**
     * Mutation routes require session id, realm id, resource id, idempotency key,
     * and expected state. A missing field is BTX035_SCHEMA. Unknown, shell, wallet,
     * and /rpc routes are BTX035_ROUTE. Reads do not use this scope.
     */
    bool CheckMutation(const std::string& method, const std::string& path, const std::string& session_id,
                       const std::string& realm_id, const std::string& resource_id,
                       const std::string& idempotency_key, const std::string& expected_state,
                       std::string& err) const;

    const std::vector<Route>& Routes() const { return routes_; }

private:
    std::vector<Route> routes_;
    std::unordered_map<std::string, size_t> by_route_;
    std::unordered_map<std::string, size_t> by_operation_;
};

/** A bearer token is not a mutation authority. Always BTX035_SCHEMA. */
bool MutationAuthorizedByBearer(const std::string& bearer_token, std::string& err);

/**
 * Inventory JSON keeps desired, observed, and unknown as separate arrays.
 * Omitting observed fails with BTX035_SCHEMA. The nested runtime receipt,
 * and the same fields beside it, include observed_ms and deployment_generation.
 */
bool InventoryExport(const std::vector<std::string>& desired,
                     const std::optional<std::vector<std::string>>& observed,
                     const std::vector<std::string>& unknown, int64_t observed_ms,
                     const std::string& deployment_generation, UniValue& out, std::string& err);

bool RuntimeReceipt(int64_t observed_ms, const std::string& deployment_generation, UniValue& out,
                    std::string& err);

struct AuditEvent {
    std::string event_type;
    std::string realm_id;
    std::string resource_id;
    std::string field;
    std::string value;
    std::string classification;
};

/** Stable for the same input. Does not embed a clock. */
std::string AuditEventId(const AuditEvent& event);

/** Exported value is redacted when the field is secret-classified. */
bool ExportAuditEvent(const AuditEvent& event, UniValue& out, std::string& err);

/** Private admission is never a public provider advertisement. */
bool PrivateAdmissionAdvertisesPublic();

/**
 * Passes PRIVATE_REBUILDABLE and DELEGATED_POLICY_ATTESTED through unchanged.
 * Does not rewrite them to a generic trusted claim.
 */
std::string DashboardAssurance(const std::string& mode);

/** Requires explicit_review and a non-empty public closure id, else BTX035_SCOPE_DENIED. */
bool ExportPublic(bool explicit_review, const std::string& public_closure_id, std::string& err);

/**
 * Strict gate for hostmodel, importmodel, seedmodel, demand-seed, peer-follow,
 * mirror, reveal, bundle, and package names. No legacy-id exception.
 */
bool HostPathRequiresAdmission(const std::string& path);

/** Allowed only when admitted is true and quarantined is false. Quarantine wins. */
bool AdmissionDecision(bool admitted, bool quarantined);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_GATEWAY_H
