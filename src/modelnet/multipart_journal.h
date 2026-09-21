// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MULTIPART_JOURNAL_H
#define BITCOIN_MODELNET_MULTIPART_JOURNAL_H

#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

enum class MultipartPhase : uint8_t {
    NONE = 0,
    INITIATED = 1,
    PARTS = 2,
    COMPLETED = 3,
    ABORTED = 4,
    INIT_PLANNED = 5,
    COMPLETE_PLANNED = 6,
    OBJECT_COMMITTED = 7,
    REMOTE_OUTCOME_UNKNOWN = 8,
};

struct MultipartPart {
    uint32_t index{0};
    uint64_t offset{0};
    uint64_t length{0};
    /** Opaque completion token. Not SHA-384 identity. */
    std::string etag;
};

class MultipartJournal {
    MultipartPhase m_phase{MultipartPhase::NONE};
    std::string m_object_key;
    std::string m_upload_id;
    std::string m_source_snapshot;
    std::vector<MultipartPart> m_parts;
    uint64_t m_planned_parts{0};

public:
    bool PlanInit(const std::string& object_key, const std::string& source_snapshot, uint64_t planned_parts,
                  std::string& err);
    bool Initiate(const std::string& object_key, const std::string& upload_id, const std::string& source_snapshot,
                  uint64_t planned_parts, std::string& err);
    bool NotePart(const MultipartPart& part, std::string& err);
    bool PlanComplete(std::string& err);
    bool Complete(std::string& err);
    bool CommitObject(std::string& err);
    bool NoteRemoteUnknown(std::string& err);
    bool Abort();
    MultipartPhase Phase() const { return m_phase; }
    const std::vector<MultipartPart>& ListParts() const { return m_parts; }
    UniValue Json() const;
};

bool MultipartEtagIsCanonicalIdentity();
const char* MultipartPhaseName(MultipartPhase p);

} // namespace modelnet

#endif // BITCOIN_MODELNET_MULTIPART_JOURNAL_H
