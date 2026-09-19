// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/multipart_journal.h>

namespace modelnet {

const char* MultipartPhaseName(MultipartPhase p)
{
    switch (p) {
    case MultipartPhase::NONE: return "NONE";
    case MultipartPhase::INITIATED: return "INITIATED";
    case MultipartPhase::PARTS: return "PARTS";
    case MultipartPhase::COMPLETED: return "COMPLETED";
    case MultipartPhase::ABORTED: return "ABORTED";
    case MultipartPhase::INIT_PLANNED: return "INIT_PLANNED";
    case MultipartPhase::COMPLETE_PLANNED: return "COMPLETE_PLANNED";
    case MultipartPhase::OBJECT_COMMITTED: return "OBJECT_COMMITTED";
    case MultipartPhase::REMOTE_OUTCOME_UNKNOWN: return "REMOTE_OUTCOME_UNKNOWN";
    }
    return "NONE";
}

bool MultipartEtagIsCanonicalIdentity()
{
    return false;
}

bool MultipartJournal::PlanInit(const std::string& object_key, const std::string& source_snapshot,
                                uint64_t planned_parts, std::string& err)
{
    if (m_phase != MultipartPhase::NONE) {
        err = "phase";
        return false;
    }
    if (object_key.empty()) {
        err = "upload identity";
        return false;
    }
    if (planned_parts == 0) {
        err = "planned_parts";
        return false;
    }
    m_object_key = object_key;
    m_upload_id.clear();
    m_source_snapshot = source_snapshot;
    m_planned_parts = planned_parts;
    m_parts.clear();
    m_phase = MultipartPhase::INIT_PLANNED;
    return true;
}

bool MultipartJournal::Initiate(const std::string& object_key, const std::string& upload_id,
                                 const std::string& source_snapshot, uint64_t planned_parts, std::string& err)
{
    if (object_key.empty() || upload_id.empty()) {
        err = "upload identity";
        return false;
    }
    if (planned_parts == 0) {
        err = "planned_parts";
        return false;
    }
    if (m_phase == MultipartPhase::INIT_PLANNED) {
        if (object_key != m_object_key || source_snapshot != m_source_snapshot || planned_parts != m_planned_parts) {
            err = "plan mismatch";
            return false;
        }
    }
    m_object_key = object_key;
    m_upload_id = upload_id;
    m_source_snapshot = source_snapshot;
    m_planned_parts = planned_parts;
    m_parts.clear();
    m_phase = MultipartPhase::INITIATED;
    return true;
}

bool MultipartJournal::NotePart(const MultipartPart& part, std::string& err)
{
    if (m_phase != MultipartPhase::INITIATED && m_phase != MultipartPhase::PARTS) {
        err = "phase";
        return false;
    }
    if (part.length == 0) {
        err = "part length";
        return false;
    }
    if (m_parts.size() >= m_planned_parts) {
        err = "part overflow";
        return false;
    }
    m_parts.push_back(part);
    m_phase = MultipartPhase::PARTS;
    return true;
}

bool MultipartJournal::PlanComplete(std::string& err)
{
    if (m_phase != MultipartPhase::PARTS) {
        err = "phase";
        return false;
    }
    if (m_parts.size() != m_planned_parts) {
        err = "incomplete parts";
        return false;
    }
    m_phase = MultipartPhase::COMPLETE_PLANNED;
    return true;
}

bool MultipartJournal::Complete(std::string& err)
{
    if (m_phase != MultipartPhase::PARTS && m_phase != MultipartPhase::INITIATED &&
        m_phase != MultipartPhase::COMPLETE_PLANNED) {
        err = "phase";
        return false;
    }
    if (m_parts.size() != m_planned_parts) {
        err = "incomplete parts";
        return false;
    }
    m_phase = MultipartPhase::COMPLETED;
    return true;
}

bool MultipartJournal::CommitObject(std::string& err)
{
    if (m_phase != MultipartPhase::COMPLETED) {
        err = "phase";
        return false;
    }
    m_phase = MultipartPhase::OBJECT_COMMITTED;
    return true;
}

bool MultipartJournal::NoteRemoteUnknown(std::string& err)
{
    if (m_phase != MultipartPhase::INITIATED && m_phase != MultipartPhase::PARTS &&
        m_phase != MultipartPhase::COMPLETE_PLANNED && m_phase != MultipartPhase::COMPLETED) {
        err = "phase";
        return false;
    }
    m_phase = MultipartPhase::REMOTE_OUTCOME_UNKNOWN;
    return true;
}

bool MultipartJournal::Abort()
{
    m_phase = MultipartPhase::ABORTED;
    m_parts.clear();
    return true;
}

UniValue MultipartJournal::Json() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("phase", MultipartPhaseName(m_phase));
    o.pushKV("object_key", m_object_key);
    o.pushKV("upload_id", m_upload_id);
    o.pushKV("source_snapshot", m_source_snapshot);
    o.pushKV("planned_parts", static_cast<int>(m_planned_parts));
    o.pushKV("etag_is_canonical_identity", MultipartEtagIsCanonicalIdentity());
    UniValue parts(UniValue::VARR);
    for (const auto& p : m_parts) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("index", static_cast<int>(p.index));
        row.pushKV("offset", static_cast<int>(p.offset));
        row.pushKV("length", static_cast<int>(p.length));
        row.pushKV("etag_present", !p.etag.empty());
        parts.push_back(row);
    }
    o.pushKV("parts", parts);
    return o;
}

} // namespace modelnet
