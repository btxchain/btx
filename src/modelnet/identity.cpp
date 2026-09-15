// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity.h>

#include <modelnet/crypto.h>
extern "C" {
#include <libbitcoinpqc/ml_dsa.h>
}
#include <random.h>
#include <support/cleanse.h>

#include <algorithm>
#include <utility>

namespace modelnet {

namespace {
void FillStrong(unsigned char* out, size_t n)
{
    while (n > 0) {
        const size_t chunk = std::min(n, size_t{32});
        GetStrongRandBytes(Span<unsigned char>{out, chunk});
        out += chunk;
        n -= chunk;
    }
}
} // namespace

bool GenerateMlDsa44(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, std::string& err)
{
    pk.assign(ML_DSA_44_PUBLIC_KEY_SIZE, 0);
    sk.assign(ML_DSA_44_SECRET_KEY_SIZE, 0);
    unsigned char rnd[128];
    FillStrong(rnd, sizeof(rnd));
    if (ml_dsa_44_keygen(pk.data(), sk.data(), rnd, sizeof(rnd)) != 0) {
        err = "ml-dsa-44 keygen failed";
        memory_cleanse(rnd, sizeof(rnd));
        return false;
    }
    memory_cleanse(rnd, sizeof(rnd));
    return true;
}

bool SignMlDsa44(Span<const unsigned char> sk, Span<const unsigned char> msg, std::vector<unsigned char>& sig, std::string& err)
{
    if (sk.size() != ML_DSA_44_SECRET_KEY_SIZE) {
        err = "bad secret key";
        return false;
    }
    sig.assign(ML_DSA_44_SIGNATURE_SIZE, 0);
    size_t siglen = sig.size();
    if (ml_dsa_44_sign(sig.data(), &siglen, msg.data(), msg.size(), sk.data()) != 0) {
        err = "ml-dsa-44 sign failed";
        return false;
    }
    sig.resize(siglen);
    return true;
}

bool VerifyMlDsa44(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig)
{
    if (pk.size() != ML_DSA_44_PUBLIC_KEY_SIZE) return false;
    return ml_dsa_44_verify(sig.data(), sig.size(), msg.data(), msg.size(), pk.data()) == 0;
}

Digest48 PublisherId(Span<const unsigned char> pubkey)
{
    return DomainHash("BTX/ModelPublisherId/v1.1", pubkey);
}

Digest48 ProviderId(Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> body;
    body.reserve(1 + pubkey.size());
    body.push_back(0x01);
    body.insert(body.end(), pubkey.begin(), pubkey.end());
    return DomainHash("BTX/ProviderKey/v2", body);
}

Digest48 ResearchIdentityId(Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> body;
    body.reserve(1 + pubkey.size());
    body.push_back(0x01);
    body.insert(body.end(), pubkey.begin(), pubkey.end());
    return DomainHash("BTX/ModelIdentityKey/v1.1", body);
}

bool AllowModelSign(SignKind kind, IdentityClass cls)
{
    if (kind == SignKind::ARBITRARY_DIGEST) return false;
    if (cls == IdentityClass::MONETARY_WALLET || cls == IdentityClass::RELEASE_SECRET) return false;
    return kind == SignKind::TYPED_MODEL_RECORD &&
           (cls == IdentityClass::RESEARCH_PUBLISHER || cls == IdentityClass::SERVICE_PROVIDER);
}

bool ServiceKeyMayAuthorizeWalletSpend()
{
    return false;
}

bool ServiceKeyMayPerformRootAction()
{
    return false;
}

bool ServiceKeyMayIssueDelegation()
{
    return false;
}

bool SpendingAddressIsResearchIdentity(const std::string& address)
{
    (void)address;
    return false;
}

bool DelegationNamesKey(const ServiceDelegation& d, Span<const unsigned char> service_pk)
{
    if (d.delegate_pubkey.size() != service_pk.size()) return false;
    return std::equal(d.delegate_pubkey.begin(), d.delegate_pubkey.end(), service_pk.begin());
}

bool ValidDelegation(const ServiceDelegation& d, int64_t now, std::string& err)
{
    if (d.delegate_pubkey.size() != MLDSA44_PK) {
        err = "delegate pubkey";
        return false;
    }
    if (d.scopes == 0 || (d.scopes & ~DELEGATE_KNOWN_MASK) != 0) {
        err = "delegation scope";
        return false;
    }
    if (d.all_models != d.model_scope.empty()) {
        err = "ambiguous model scope";
        return false;
    }
    if (!d.all_models) {
        auto ids = d.model_scope;
        auto uniq = ids;
        std::sort(uniq.begin(), uniq.end());
        uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
        if (ids != uniq || ids.empty()) {
            err = "model scope order";
            return false;
        }
    }
    if (d.expires_at <= d.issued_at) {
        err = "invalid expiry";
        return false;
    }
    if (d.expires_at - d.issued_at > MAX_DELEGATION_SECONDS) {
        err = "delegation too long";
        return false;
    }
    if (now >= d.expires_at) {
        err = "delegation expired";
        return false;
    }
    return true;
}

bool IdentityStore::Insert(ModelIdentity ident, std::vector<unsigned char> secret, std::string& err)
{
    if (ident.cls == IdentityClass::MONETARY_WALLET || ident.cls == IdentityClass::RELEASE_SECRET) {
        err = "monetary wallet is not a model identity";
        return false;
    }
    if (ident.cls == IdentityClass::TRANSPORT_EPHEMERAL) {
        err = "transport ephemeral is not a stored model identity";
        return false;
    }
    if (ident.pubkey.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    if (!secret.empty() && secret.size() != MLDSA44_SK) {
        err = "secret";
        return false;
    }
    if (ident.cls == IdentityClass::SERVICE_PROVIDER) ident.id = ProviderId(ident.pubkey);
    else ident.id = IdentityId(ident.pubkey);
    m_rows.push_back({std::move(ident), std::move(secret)});
    return true;
}

bool IdentityStore::AdoptSpendingAddress(const std::string& addr)
{
    (void)addr;
    return false;
}

std::vector<IdentityPublicExport> IdentityStore::PublicExport() const
{
    std::vector<IdentityPublicExport> out;
    out.reserve(m_rows.size());
    for (const auto& row : m_rows) {
        IdentityPublicExport e;
        e.id = row.ident.id;
        e.cls = row.ident.cls;
        e.pubkey = row.ident.pubkey;
        e.local_label = row.ident.local_label;
        out.push_back(std::move(e));
    }
    return out;
}

IdentitySecretBackup IdentityStore::SecretBackup() const
{
    IdentitySecretBackup bak;
    bak.contacts = PublicExport();
    bak.model_secrets.reserve(m_rows.size());
    for (const auto& row : m_rows) bak.model_secrets.push_back(row.secret);
    bak.contains_wallet_material = false;
    bak.contains_tls_secrets = false;
    bak.contains_release_secrets = false;
    bak.contains_payment_credentials = false;
    return bak;
}

bool DelegationTable::InsertRootSigned(const ServiceDelegation& d, int64_t now, std::string& err)
{
    if (!ValidDelegation(d, now, err)) return false;
    Row row;
    row.d = d;
    row.service_id = ProviderId(d.delegate_pubkey);
    row.revoked = false;
    m_rows.push_back(std::move(row));
    return true;
}

bool DelegationTable::InsertServiceIssued(const ServiceDelegation& d, int64_t now, std::string& err)
{
    (void)d;
    (void)now;
    err = "service key cannot issue a delegate";
    return false;
}

bool DelegationTable::RevokeByRoot(const Digest48& service_id, const Digest48& root_id)
{
    bool found = false;
    for (auto& row : m_rows) {
        if (row.service_id == service_id && row.d.root_id == root_id) {
            row.revoked = true;
            found = true;
        }
    }
    return found;
}

bool DelegationTable::HasScope(const Digest48& service_id, uint32_t cap, int64_t now) const
{
    if ((cap & ~DELEGATE_KNOWN_MASK) != 0) return false;
    for (const auto& row : m_rows) {
        if (row.service_id != service_id || row.revoked) continue;
        if (now >= row.d.expires_at) continue;
        if ((row.d.scopes & cap) == cap) return true;
    }
    return false;
}

bool DelegationTable::MayWalletSpend(const Digest48& service_id) const
{
    (void)service_id;
    return false;
}

bool DelegationTable::MayPerformRootAction(const Digest48& service_id) const
{
    (void)service_id;
    return false;
}

bool DelegationTable::TombstoneRetained(const Digest48& service_id) const
{
    for (const auto& row : m_rows) {
        if (row.service_id == service_id && row.revoked) return true;
    }
    return false;
}

} // namespace modelnet
