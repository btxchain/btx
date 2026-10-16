// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/pq_transport_binding.h>

#include <modelnet/crypto.h>

#include <algorithm>
#include <cctype>

namespace modelnet {
namespace {

bool FieldEmpty(const std::string& s)
{
    return s.empty();
}

bool ContainsClassicalName(const std::string& s)
{
    std::string lower;
    lower.reserve(s.size());
    for (unsigned char c : s) {
        lower.push_back(static_cast<char>(std::tolower(c)));
    }
    static const char* kNames[] = {"x25519", "secp256r1", "ecdsa", "rsa"};
    for (const char* name : kNames) {
        if (lower.find(name) != std::string::npos) return true;
    }
    return false;
}

bool LowerHex96(const std::string& s)
{
    if (s.size() != Digest48::SIZE * 2) return false;
    for (unsigned char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

Digest48 TransportBindingId(Span<const unsigned char> transport_pk)
{
    std::vector<unsigned char> body;
    body.reserve(1 + transport_pk.size());
    body.push_back(0x01);
    body.insert(body.end(), transport_pk.begin(), transport_pk.end());
    return DomainHash("BTX/035/TransportBinding/v1.1", Span<const unsigned char>{body.data(), body.size()});
}

bool SamePk(Span<const unsigned char> a, Span<const unsigned char> b)
{
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin());
}

} // namespace

bool SupportedPq1Profile(const std::string& tls_version, const std::string& group, const std::string& ciphersuite,
                         const std::string& sigalg, std::string& err)
{
    const std::string* fields[] = {&tls_version, &group, &ciphersuite, &sigalg};
    for (const std::string* field : fields) {
        if (FieldEmpty(*field) || ContainsClassicalName(*field)) {
            err = "BTX035_PROFILE";
            return false;
        }
    }
    if (tls_version != "TLSv1.3" || group != "mlkem768" || ciphersuite != "TLS_AES_256_GCM_SHA384" ||
        sigalg != "mldsa44") {
        err = "BTX035_PROFILE";
        return false;
    }
    err.clear();
    return true;
}

bool BindTransportKey(const std::string& research_root_hex, Span<const unsigned char> transport_pk_bytes,
                      TransportBindingRecord& out, std::string& err)
{
    out = TransportBindingRecord{};
    if (transport_pk_bytes.size() != MLDSA44_PK) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    Digest48 root;
    std::string hex_err;
    if (!Digest48::FromHex(research_root_hex, root, hex_err)) {
        err = "BTX035_BINDING_INVALID";
        return false;
    }
    const Digest48 transport_identity = ResearchIdentityId(transport_pk_bytes);
    out.binding_id = TransportBindingId(transport_pk_bytes);
    out.research_root_hex = research_root_hex;
    out.transport_pk.assign(transport_pk_bytes.begin(), transport_pk_bytes.end());
    out.transport_identity = transport_identity;
    err.clear();
    return true;
}

bool SubstituteTransport(const TransportBindingRecord& binding, Span<const unsigned char> other_pk, std::string& err)
{
    if (binding.transport_pk.size() != MLDSA44_PK || !SamePk(binding.transport_pk, other_pk)) {
        err = "BTX035_TRANSPORT_SUBSTITUTE";
        return false;
    }
    err.clear();
    return true;
}

bool SessionProofStore::Bind(const TransportBindingRecord& binding, std::string& err)
{
    if (binding.transport_pk.size() != MLDSA44_PK) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    Digest48 root;
    std::string hex_err;
    if (!Digest48::FromHex(binding.research_root_hex, root, hex_err)) {
        err = "BTX035_BINDING_INVALID";
        return false;
    }
    if (binding.binding_id != TransportBindingId(binding.transport_pk)) {
        err = "BTX035_BINDING_INVALID";
        return false;
    }
    if (binding.transport_identity != ResearchIdentityId(binding.transport_pk)) {
        err = "BTX035_BINDING_INVALID";
        return false;
    }
    m_roots.insert(binding.research_root_hex);
    err.clear();
    return true;
}

bool SessionProofStore::Accept(const std::string& connection_id, const std::string& nonce,
                               const std::string& research_root, int64_t now_ms, std::string& err)
{
    if (connection_id.empty() || nonce.empty()) {
        err = "BTX035_SESSION";
        return false;
    }
    const auto key = std::make_pair(connection_id, nonce);
    if (m_accepted_ms.count(key) != 0) {
        err = "BTX035_REPLAY";
        return false;
    }
    if (m_roots.count(research_root) == 0) {
        err = "BTX035_UNBOUND";
        return false;
    }
    m_accepted_ms.emplace(key, now_ms);
    err.clear();
    return true;
}

bool SessionProofStore::AcceptedMs(const std::string& connection_id, const std::string& nonce, int64_t& now_ms) const
{
    const auto it = m_accepted_ms.find(std::make_pair(connection_id, nonce));
    if (it == m_accepted_ms.end()) return false;
    now_ms = it->second;
    return true;
}

bool RecipientMatches(const std::string& stored_recipient_hex, const std::string& authenticated_kem_id_hex,
                      std::string& err)
{
    if (!LowerHex96(stored_recipient_hex) || !LowerHex96(authenticated_kem_id_hex) ||
        stored_recipient_hex != authenticated_kem_id_hex) {
        err = "BTX035_RECIPIENT";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
