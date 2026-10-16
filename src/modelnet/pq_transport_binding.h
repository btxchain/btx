// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PQ_TRANSPORT_BINDING_H
#define BITCOIN_MODELNET_PQ_TRANSPORT_BINDING_H

#include <modelnet/identity.h>
#include <span.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

/** Strict PQ transport profile. True only for TLS 1.3 / mlkem768 / AES-256-GCM-SHA384 / mldsa44. */
bool SupportedPq1Profile(const std::string& tls_version, const std::string& group,
                         const std::string& ciphersuite, const std::string& sigalg, std::string& err);

/** Stored association of a research root with one ML-DSA-44 transport public key. */
struct TransportBindingRecord {
    Digest48 binding_id;
    std::string research_root_hex;
    std::vector<unsigned char> transport_pk;
    /** ResearchIdentityId of transport_pk. Distinct domain from binding_id. */
    Digest48 transport_identity;
};

/** Bind a 1312-byte transport public key to a research-root digest.
 *  binding_id = DomainHash("BTX/035/TransportBinding/v1.1", 0x01 || transport_pk). */
bool BindTransportKey(const std::string& research_root_hex, Span<const unsigned char> transport_pk_bytes,
                      TransportBindingRecord& out, std::string& err);

/** Fail when other_pk is not the key stored on the binding. */
bool SubstituteTransport(const TransportBindingRecord& binding, Span<const unsigned char> other_pk, std::string& err);

/** Accepts a session proof once for a research root that this store has bound. */
class SessionProofStore {
    std::set<std::string> m_roots;
    std::map<std::pair<std::string, std::string>, int64_t> m_accepted_ms;

public:
    bool Bind(const TransportBindingRecord& binding, std::string& err);
    bool Accept(const std::string& connection_id, const std::string& nonce, const std::string& research_root,
                int64_t now_ms, std::string& err);
    bool AcceptedMs(const std::string& connection_id, const std::string& nonce, int64_t& now_ms) const;
};

/** True only when both recipient ids are the same 96 lowercase hex characters. */
bool RecipientMatches(const std::string& stored_recipient_hex, const std::string& authenticated_kem_id_hex,
                      std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PQ_TRANSPORT_BINDING_H
