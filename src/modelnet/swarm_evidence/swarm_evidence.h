// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVIDENCE_H
#define BITCOIN_MODELNET_SWARM_EVIDENCE_H

#include <modelnet/swarm_evidence/codes.h>
#include <modelnet/swarm_evidence/limits.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local evidence records.
 *
 * Store keeps one byte vector for an id. An empty id or an empty vector
 * is EVIDENCE and stores nothing. Private bytes are stored and
 * shareable(id) is false. Public bytes are stored and shareable(id) is
 * true only for that id. A second store of an id that already holds
 * evidence or a summary is REPLAY and keeps the first record, so a later
 * public store cannot flip a private id to shareable.
 *
 * Share returns true only for a public id. An unknown id and a private id
 * both return NOT_VISIBLE. The two answers use one code. Share leaves the
 * bytes in the record. bytes_moved() stays 0.
 *
 * Summarize stores a summary linked to a source id. An empty summary id,
 * an empty summary, or an empty source id is SUMMARY and stores nothing.
 * The source id must already be a successful Store, or the result is
 * SOURCE and nothing is stored. A promise, a tainted note, or another
 * summary is not a source. Success stores the summary. summary_source(id)
 * returns that source id. A later summary for the same id is REPLAY and
 * keeps the first source id.
 *
 * Inject always returns false with NOT_AUTHORITY. The text is appended as
 * tainted data. It is not parsed and it is not executed. launched() stays
 * false.
 *
 * Promise records a replica promise and returns true. An empty id is ID
 * and is not recorded. Retrieve returns false with NOT_RETRIEVABLE and
 * does not hand bytes back. A promise is not data. Stored bytes stay in
 * the record. bytes_moved() stays 0.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend()
 * returns "0". No method spends, and no method publishes the record.
 */
class SwarmEvidence {
public:
    bool Store(const std::string& id, const std::vector<unsigned char>& bytes, bool is_private, std::string& err);
    bool shareable(const std::string& id) const;
    bool Share(const std::string& id, std::string& err);
    bool Summarize(const std::string& id, const std::string& summary, const std::string& source_id, std::string& err);
    bool Inject(const std::string& id, const std::string& text, std::string& err);
    bool Promise(const std::string& id, std::string& err);
    bool Retrieve(const std::string& id, std::string& err);

    bool stored(const std::string& id) const;
    const std::vector<unsigned char>& body(const std::string& id) const;
    std::string summary(const std::string& id) const;
    std::string summary_source(const std::string& id) const;
    bool promised(const std::string& id) const;
    /** True when this id has text kept as tainted data. */
    bool tainted(const std::string& id) const;
    /** Byte length of text kept as tainted data. The text is not executed. */
    std::size_t tainted_bytes() const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    struct EvidenceRecord {
        std::vector<unsigned char> bytes;
        bool is_private{true};
    };

    struct SummaryRecord {
        std::string summary;
        std::string source_id;
    };

    /** Model-produced text kept as data. tainted stays true. */
    struct TaintedNote {
        std::string id;
        std::string text;
        bool tainted{true};
    };

    std::map<std::string, EvidenceRecord> m_evidence;
    std::map<std::string, SummaryRecord> m_summaries;
    std::set<std::string> m_promises;
    std::vector<TaintedNote> m_tainted;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVIDENCE_H
