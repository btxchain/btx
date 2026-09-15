// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_IDENTITY_H
#define BITCOIN_MODELNET_IDENTITY_H

#include <modelnet/types.h>
#include <span.h>

#include <array>
#include <string>
#include <vector>

namespace modelnet {

constexpr size_t MLDSA44_PK = 1312;
constexpr size_t MLDSA44_SK = 2560;
constexpr size_t MLDSA44_SIG = 2420;

constexpr uint32_t DELEGATE_REQUEST = 1;
constexpr uint32_t DELEGATE_SERVE = 2;
constexpr uint32_t DELEGATE_ANNOUNCE = 4;
constexpr uint32_t DELEGATE_RECEIPT = 8;
constexpr uint32_t DELEGATE_ENDPOINT = 16;
constexpr uint32_t DELEGATE_KNOWN_MASK = 31;
constexpr int64_t MAX_DELEGATION_SECONDS = 7 * DAY_SECONDS;

enum class IdentityClass : uint8_t {
    RESEARCH_PUBLISHER = 1,
    SERVICE_PROVIDER = 2,
    TRANSPORT_EPHEMERAL = 3,
    MONETARY_WALLET = 4, // never used as model identity material
    RELEASE_SECRET = 5,
};

enum class SignKind : uint8_t {
    TYPED_MODEL_RECORD = 1,
    ARBITRARY_DIGEST = 2,
};

struct ModelIdentity {
    IdentityClass cls{IdentityClass::RESEARCH_PUBLISHER};
    std::vector<unsigned char> pubkey; // 1312
    Digest48 id;
    std::string local_label;
    bool explicitly_trusted{false};
};

struct IdentityPublicExport {
    Digest48 id;
    IdentityClass cls{IdentityClass::RESEARCH_PUBLISHER};
    std::vector<unsigned char> pubkey;
    std::string local_label;
};

struct IdentitySecretBackup {
    std::vector<IdentityPublicExport> contacts;
    std::vector<std::vector<unsigned char>> model_secrets;
    bool contains_wallet_material{false};
    bool contains_tls_secrets{false};
    bool contains_release_secrets{false};
    bool contains_payment_credentials{false};
};

struct ServiceDelegation {
    Digest48 root_id;
    std::vector<unsigned char> delegate_pubkey;
    uint32_t scopes{0};
    bool all_models{true};
    std::vector<Digest48> model_scope;
    int64_t issued_at{0};
    int64_t expires_at{0};
};

bool GenerateMlDsa44(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, std::string& err);
bool SignMlDsa44(Span<const unsigned char> sk, Span<const unsigned char> msg, std::vector<unsigned char>& sig, std::string& err);
bool VerifyMlDsa44(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig);
Digest48 PublisherId(Span<const unsigned char> pubkey);
/** B0 provider_id: D384("BTX/ProviderKey/v2", U8(1) || raw ML-DSA-44 pk). */
Digest48 ProviderId(Span<const unsigned char> pubkey);
/** Research-root id: D384("BTX/ModelIdentityKey/v1.1", U8(1) || raw ML-DSA-44 pk). */
Digest48 ResearchIdentityId(Span<const unsigned char> pubkey);
inline Digest48 IdentityId(Span<const unsigned char> pubkey) { return ResearchIdentityId(pubkey); }

bool AllowModelSign(SignKind kind, IdentityClass cls);
bool ServiceKeyMayAuthorizeWalletSpend();
bool ServiceKeyMayPerformRootAction();
bool ServiceKeyMayIssueDelegation();
bool SpendingAddressIsResearchIdentity(const std::string& address);

bool ValidDelegation(const ServiceDelegation& d, int64_t now, std::string& err);
bool DelegationNamesKey(const ServiceDelegation& d, Span<const unsigned char> service_pk);

class IdentityStore {
    struct Row {
        ModelIdentity ident;
        std::vector<unsigned char> secret;
    };
    std::vector<Row> m_rows;

public:
    bool RequiresWallet() const { return false; }
    int64_t AutomaticSpendAtoms() const { return 0; }
    bool RotationCopiesReciprocity() const { return false; }
    bool Insert(ModelIdentity ident, std::vector<unsigned char> secret, std::string& err);
    bool AdoptSpendingAddress(const std::string& addr);
    size_t Size() const { return m_rows.size(); }
    std::vector<IdentityPublicExport> PublicExport() const;
    IdentitySecretBackup SecretBackup() const;
};

class DelegationTable {
    struct Row {
        ServiceDelegation d;
        Digest48 service_id;
        bool revoked{false};
    };
    std::vector<Row> m_rows;

public:
    bool InsertRootSigned(const ServiceDelegation& d, int64_t now, std::string& err);
    bool InsertServiceIssued(const ServiceDelegation& d, int64_t now, std::string& err);
    bool RevokeByRoot(const Digest48& service_id, const Digest48& root_id);
    bool HasScope(const Digest48& service_id, uint32_t cap, int64_t now) const;
    bool MayWalletSpend(const Digest48& service_id) const;
    bool MayPerformRootAction(const Digest48& service_id) const;
    bool TombstoneRetained(const Digest48& service_id) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_IDENTITY_H
