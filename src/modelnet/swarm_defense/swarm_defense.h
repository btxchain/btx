// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFENSE_H
#define BITCOIN_MODELNET_SWARM_DEFENSE_H

#include <modelnet/swarm_defense/codes.h>
#include <modelnet/swarm_defense/limits.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local defense plane for one node.
 *
 * Mandate stores one case only when customer, case_id, asset, and
 * policy_gen are all non-empty and now_ms < until_ms. Any empty string is
 * MANDATE and stores nothing. now_ms >= until_ms, including equality, is
 * EXPIRED and stores nothing. A second mandate for the same case is REPLAY
 * and keeps the first customer, asset, and policy generation. Later calls
 * that name a case use that stored mandate. They do not take a second
 * policy generation.
 *
 * JoinFamily records family membership only. An empty peer is PEER.
 * Success sets family(peer) true and admitted(peer) false. Membership is
 * not admission.
 *
 * Admit requires a stored case and a peer already in the family. An
 * unknown case is CASE. A peer that is not in the family is NOT_ADMITTED.
 * Success sets admitted(peer) true for that case only.
 *
 * Evidence stores the exact byte vector for one stored case. An unknown
 * case is CASE. An empty evidence id or an empty vector is EVIDENCE and
 * stores nothing. A second store of the same evidence id is REPLAY and
 * keeps the original bytes and the original case. body() returns those
 * original bytes.
 *
 * Export with granted false is PRIVATE_DATA, copies nothing, and
 * bytes_moved() stays 0. Export with granted true returns true only when
 * the evidence belongs to that case, and still leaves bytes_moved() at 0.
 * This plane does not move bytes off the node. The stored body stays.
 *
 * Act always returns false with NOT_AUTHORIZED. The text is appended to a
 * tainted log as data. It is not parsed and it is not executed.
 * launched() stays false.
 *
 * Publish stores an artifact only when the case exists, the artifact id
 * is non-empty, and both sanitized and validated are true. Embargo expiry
 * alone is NOT_PUBLISHED and stores nothing. Either protection missing is
 * NOT_PUBLISHED and stores nothing. Both protections store the artifact
 * and return true even when embargo_expired is false. published() becomes
 * true only then. training_allowed() stays false. Sharing does not set
 * training consent.
 *
 * AllowTraining is a separate call. An unknown case is CASE and does not
 * set consent. Success sets training_allowed() true.
 *
 * Search returns false with NOT_VISIBLE when the evidence id is not in
 * the named case. An id that was never stored and an id stored for a
 * different case use that same code.
 *
 * launched(), gpu(), broadcast(), connected(), and windows_passed() stay
 * false. automatic_spend() returns "0". bytes_moved() returns 0. No
 * method sets launched() true.
 */
class SwarmDefense {
public:
    bool Mandate(const std::string& customer, const std::string& case_id, const std::string& asset,
                 const std::string& policy_gen, int64_t until_ms, int64_t now_ms, std::string& err);
    bool JoinFamily(const std::string& peer, std::string& err);
    bool Admit(const std::string& peer, const std::string& case_id, std::string& err);
    bool Evidence(const std::string& case_id, const std::string& evidence_id, const std::vector<unsigned char>& bytes,
                  std::string& err);
    bool Export(const std::string& case_id, const std::string& evidence_id, bool granted, std::string& err);
    bool Act(const std::string& case_id, const std::string& text, std::string& err);
    bool Publish(const std::string& case_id, const std::string& artifact_id, bool embargo_expired, bool sanitized,
                 bool validated, std::string& err);
    bool AllowTraining(const std::string& case_id, std::string& err);
    bool Search(const std::string& case_id, const std::string& evidence_id, std::string& err);

    bool family(const std::string& peer) const;
    bool admitted(const std::string& peer) const;
    bool admitted(const std::string& peer, const std::string& case_id) const;
    const std::vector<unsigned char>& body(const std::string& evidence_id) const;
    bool published() const;
    bool published(const std::string& artifact_id) const;
    bool training_allowed() const;
    bool training_allowed(const std::string& case_id) const;
    /** Byte length of model text kept as tainted data. The text is not executed. */
    std::size_t tainted_bytes() const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    bool connected() const;
    bool windows_passed() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    struct MandateRecord {
        std::string customer;
        std::string asset;
        std::string policy_gen;
        int64_t until_ms{0};
    };

    struct EvidenceRecord {
        std::string case_id;
        std::vector<unsigned char> bytes;
    };

    /** Model-produced text kept as data. tainted is always true. */
    struct TaintedNote {
        std::string text;
        bool tainted{true};
    };

    bool HasCase(const std::string& case_id) const;
    bool EvidenceInCase(const std::string& case_id, const std::string& evidence_id) const;

    std::map<std::string, MandateRecord> m_mandates;
    std::set<std::string> m_family;
    std::map<std::string, std::set<std::string>> m_admitted;
    std::map<std::string, EvidenceRecord> m_evidence;
    std::map<std::string, std::string> m_artifacts;
    std::set<std::string> m_training;
    std::vector<TaintedNote> m_tainted;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFENSE_H
