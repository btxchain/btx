// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_remaining.h>

#include <crypto/sha384.h>
#include <util/strencodings.h>

#include <set>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

std::string Sha384(const std::string& material)
{
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(material.data()), material.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(out);
}

bool ContentId(const std::string& id)
{
    if (id.size() != 96) return false;
    for (unsigned char c : id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

} // namespace

std::string SourceContentHash(const std::string& bytes)
{
    return Sha384(bytes);
}

bool SourceIndex::Add(const RetainedSource& object, std::string& err)
{
    if (!ContentId(object.object_id) || !ContentId(object.research_record_id)) return Fail(err, "BTX035_SCHEMA");
    if (object.visibility != "PUBLIC" && object.visibility != "PRIVATE") return Fail(err, "BTX035_SCHEMA");
    if (object.tenant.empty() || object.bytes.empty()) return Fail(err, "BTX035_SCHEMA");
    for (const RetainedSource& row : m_retained) {
        if (row.object_id == object.object_id && row.tenant == object.tenant) return Fail(err, "BTX035_CONFLICT");
    }
    m_retained.push_back(object);
    m_rebuilt = false;
    err.clear();
    return true;
}

bool SourceIndex::DeleteDerived()
{
    m_public_by_hash.clear();
    m_rebuilt = false;
    return true;
}

bool SourceIndex::Rebuild(const std::string& cloud_account, std::string& err)
{
    if (!cloud_account.empty()) return Fail(err, "BTX035_SCOPE_DENIED");
    m_public_by_hash.clear();
    for (size_t i = 0; i < m_retained.size(); ++i) {
        const RetainedSource& row = m_retained[i];
        if (row.visibility != "PUBLIC") continue;
        m_public_by_hash[Sha384(row.bytes)].push_back(i);
    }
    m_rebuilt = true;
    m_cloned = false;
    err.clear();
    return true;
}

bool SourceIndex::QueryPublic(const std::string& content_hash, const std::string& tenant, std::vector<std::string>& object_ids,
                              std::string& err) const
{
    object_ids.clear();
    if (!m_rebuilt) return Fail(err, "BTX035_NOT_FOUND");
    const auto it = m_public_by_hash.find(content_hash);
    if (it == m_public_by_hash.end()) {
        err.clear();
        return true;
    }
    for (size_t index : it->second) {
        const RetainedSource& row = m_retained[index];
        if (row.visibility != "PUBLIC" || row.tenant != tenant) continue;
        object_ids.push_back(row.object_id);
    }
    err.clear();
    return true;
}

bool SourceIndex::QueryFile(const std::string& object_id, std::string& bytes, std::string& research_record_id, std::string& err) const
{
    for (const RetainedSource& row : m_retained) {
        if (row.object_id != object_id) continue;
        bytes = row.bytes;
        research_record_id = row.research_record_id;
        err.clear();
        return true;
    }
    return Fail(err, "BTX035_NOT_FOUND");
}

bool SourceIndex::QueryDiff(const std::string& before_id, const std::string& after_id, std::string& diff, std::string& err) const
{
    std::string before;
    std::string after;
    std::string ignored;
    if (!QueryFile(before_id, before, ignored, err)) return false;
    if (!QueryFile(after_id, after, ignored, err)) return false;
    diff = before == after ? "equal" : "changed";
    err.clear();
    return true;
}

bool SourceIndex::QuerySemantic(const std::string& object_id, std::string& err)
{
    std::string bytes;
    std::string record;
    if (!QueryFile(object_id, bytes, record, err)) return false;
    m_cloned = false;
    m_semantic = false;
    return Fail(err, "BTX035_PARSER_ABSENT");
}

bool WitnessLog::Record(const std::string& action_id, const std::string& intent, const std::string& decision,
                        const std::string& outcome, const std::string& rationale, std::string& err)
{
    if (action_id.empty() || intent.empty() || decision.empty() || outcome.empty()) return Fail(err, "BTX035_SCHEMA");
    if (m_rows.count(action_id)) return Fail(err, "BTX035_CONFLICT");
    Row row;
    row.intent = intent;
    row.decision = decision;
    row.outcome = outcome;
    row.rationale = rationale;
    m_rows.emplace(action_id, std::move(row));
    err.clear();
    return true;
}

bool WitnessLog::Expose(const std::string& action_id, std::string& err)
{
    const auto it = m_rows.find(action_id);
    if (it == m_rows.end()) return Fail(err, "BTX035_NOT_FOUND");
    if (!it->second.witnessed || m_checkpoint_id.empty()) return Fail(err, "BTX035_WITNESS");
    bool covered = false;
    for (const std::string& id : m_checkpoint_ids) {
        if (id == action_id) covered = true;
    }
    if (!covered) return Fail(err, "BTX035_WITNESS");
    it->second.exposed = true;
    err.clear();
    return true;
}

bool WitnessLog::Witness(const std::string& action_id, const std::string& signer_role, std::string& err)
{
    const auto it = m_rows.find(action_id);
    if (it == m_rows.end()) return Fail(err, "BTX035_NOT_FOUND");
    if (signer_role == "PUBLISHER") return Fail(err, "BTX035_AUTHORITY");
    if (signer_role != "WITNESS") return Fail(err, "BTX035_AUTHORITY");
    it->second.witnessed = true;
    err.clear();
    return true;
}

bool WitnessLog::Checkpoint(std::string& checkpoint_id, std::string& err)
{
    std::string material = "BTX/035/WitnessCheckpoint/v1.1";
    m_checkpoint_ids.clear();
    for (const auto& item : m_rows) {
        if (!item.second.witnessed) continue;
        material += "|" + item.first + "|" + item.second.outcome;
        m_checkpoint_ids.push_back(item.first);
    }
    if (m_checkpoint_ids.empty()) return Fail(err, "BTX035_WITNESS");
    m_checkpoint_id = Sha384(material);
    checkpoint_id = m_checkpoint_id;
    err.clear();
    return true;
}

bool WitnessLog::DeleteCheckpoint(std::string& err)
{
    if (m_checkpoint_id.empty()) return Fail(err, "BTX035_NOT_FOUND");
    m_checkpoint_id.clear();
    for (auto& item : m_rows) item.second.exposed = false;
    err.clear();
    return true;
}

bool WitnessLog::Exposed(const std::string& action_id) const
{
    const auto it = m_rows.find(action_id);
    return it != m_rows.end() && it->second.exposed && !m_checkpoint_id.empty();
}

std::string WitnessLog::EvidenceText(const std::string& action_id) const
{
    const auto it = m_rows.find(action_id);
    if (it == m_rows.end()) return {};
    const Row& row = it->second;
    std::string text = "intent=" + row.intent + " decision=" + row.decision + " outcome=" + row.outcome;
    if (!row.rationale.empty()) text += " rationale_not_proof=" + row.rationale;
    return text;
}

bool PackageGate::AddFile(const std::string& name, const std::string& bytes, std::string& err)
{
    if (name.empty() || name.find("..") != std::string::npos || name.find('/') != std::string::npos) {
        return Fail(err, "BTX035_PATH_UNSAFE");
    }
    if (m_files.count(name)) return Fail(err, "BTX035_CONFLICT");
    m_files.emplace(name, bytes);
    m_authenticated = false;
    err.clear();
    return true;
}

std::string PackageGate::InventoryDigest() const
{
    std::string material = "BTX/035/PackageInventory/v1.1";
    for (const auto& item : m_files) {
        material += "\n" + item.first + "\n" + Sha384(item.second);
    }
    return Sha384(material);
}

bool PackageGate::Authenticate(const std::string& owner_pin, const std::string& digest, std::string& err)
{
    if (owner_pin.size() < 16 || digest != InventoryDigest()) {
        m_authenticated = false;
        m_effect = false;
        return Fail(err, "BTX035_RELEASE_UNSIGNED");
    }
    if (HasProductionSignature() || AppointedPerson()) return Fail(err, "BTX035_AUTHORITY");
    m_owner_pin = owner_pin;
    m_authenticated = true;
    m_partial = false;
    m_effect = true;
    err.clear();
    return true;
}

bool PackageGate::AppointPersonFromPackage(const std::string& name, std::string& err)
{
    (void)name;
    return Fail(err, "BTX035_AUTHORITY");
}

bool PackageGate::InterruptAfterPersist(std::string& err)
{
    if (m_files.empty()) return Fail(err, "BTX035_NOT_FOUND");
    m_partial = true;
    m_authenticated = false;
    m_effect = false;
    err.clear();
    return true;
}

bool PackageGate::Recover(std::string& err)
{
    if (!m_partial) return Fail(err, "BTX035_NOT_FOUND");
    m_authenticated = false;
    m_effect = false;
    err.clear();
    return true;
}

bool ReleaseGate::SetCases(const std::vector<ReleaseCase>& rows, std::string& err)
{
    std::set<std::string> seen;
    for (const ReleaseCase& row : rows) {
        if (row.case_id.empty() || row.state.empty() || !seen.insert(row.case_id).second) return Fail(err, "BTX035_SCHEMA");
    }
    m_rows = rows;
    m_complete = false;
    err.clear();
    return true;
}

bool ReleaseGate::ClaimComplete(bool schema_only, std::string& err)
{
    if (schema_only) return Fail(err, "BTX035_CLAIM");
    if (!JourneysReady()) return Fail(err, "BTX035_JOURNEY");
    for (const ReleaseCase& row : m_rows) {
        if (row.mandatory && row.state != "PASS") return Fail(err, "BTX035_RELEASE");
    }
    m_complete = true;
    err.clear();
    return true;
}

bool ReleaseGate::Restore(std::string& err)
{
    for (ReleaseCase& row : m_rows) {
        if (row.state == "NOT_RUN") continue;
    }
    m_complete = false;
    err.clear();
    return true;
}

std::string ReleaseGate::StateOf(const std::string& case_id) const
{
    for (const ReleaseCase& row : m_rows) {
        if (row.case_id == case_id) return row.state;
    }
    return {};
}

bool ReleaseGate::Stop()
{
    m_stopped = true;
    m_complete = false;
    return true;
}

bool ReleaseGate::NoteJourney(const std::string& name, const std::string& binary, std::string& err)
{
    if (binary.empty() || binary.find("btx") == std::string::npos) return Fail(err, "BTX035_JOURNEY");
    if (name == "e2e") m_e2e = true;
    else if (name == "journey") m_journey = true;
    else return Fail(err, "BTX035_JOURNEY");
    m_binary = binary;
    err.clear();
    return true;
}

} // namespace modelnet
