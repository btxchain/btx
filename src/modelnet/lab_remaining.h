// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_REMAINING_H
#define BITCOIN_MODELNET_LAB_REMAINING_H

#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/** SHA-384 hex of retained object bytes. Public and private copies share this hash. */
std::string SourceContentHash(const std::string& bytes);

/** Retained source object. Visibility is PUBLIC or PRIVATE. */
struct RetainedSource {
    std::string object_id;
    std::string visibility;
    std::string tenant;
    std::string bytes;
    std::string research_record_id;
};

/**
 * RES-004. The derived index is rebuilt only from retained Git objects and
 * signed research record ids. A cloud account is rejected. A private object
 * that shares bytes with a public object does not appear in a public query.
 * A missing parser does not clone or invent a semantic result.
 */
class SourceIndex {
public:
    bool Add(const RetainedSource& object, std::string& err);
    bool DeleteDerived();
    bool Rebuild(const std::string& cloud_account, std::string& err);
    bool QueryPublic(const std::string& content_hash, const std::string& tenant, std::vector<std::string>& object_ids,
                     std::string& err) const;
    bool QueryFile(const std::string& object_id, std::string& bytes, std::string& research_record_id, std::string& err) const;
    bool QueryDiff(const std::string& before_id, const std::string& after_id, std::string& diff, std::string& err) const;
    bool QuerySemantic(const std::string& object_id, std::string& err);
    bool Rebuilt() const { return m_rebuilt; }
    bool Cloned() const { return m_cloned; }
    bool SemanticFabricated() const { return m_semantic; }
    size_t RetainedCount() const { return m_retained.size(); }

private:
    std::vector<RetainedSource> m_retained;
    std::map<std::string, std::vector<size_t>> m_public_by_hash;
    bool m_rebuilt{false};
    bool m_cloned{false};
    bool m_semantic{false};
};

/**
 * RUN-004. Success is not exposed until an external witness signs the outcome
 * or a checkpoint covers it. The publisher cannot fabricate that receipt.
 */
class WitnessLog {
public:
    bool Record(const std::string& action_id, const std::string& intent, const std::string& decision,
                const std::string& outcome, const std::string& rationale, std::string& err);
    bool Expose(const std::string& action_id, std::string& err);
    bool Witness(const std::string& action_id, const std::string& signer_role, std::string& err);
    bool Checkpoint(std::string& checkpoint_id, std::string& err);
    bool DeleteCheckpoint(std::string& err);
    bool CheckpointMissing() const { return m_checkpoint_id.empty(); }
    bool Exposed(const std::string& action_id) const;
    std::string EvidenceText(const std::string& action_id) const;

private:
    struct Row {
        std::string intent;
        std::string decision;
        std::string outcome;
        std::string rationale;
        bool witnessed{false};
        bool exposed{false};
    };
    std::map<std::string, Row> m_rows;
    std::string m_checkpoint_id;
    std::vector<std::string> m_checkpoint_ids;
};

/**
 * REV-002. This package has no production release signature and names no person
 * as release authority. Inventory bytes authenticate only after the operator
 * supplies an independent pin that matches the digest.
 */
class PackageGate {
public:
    bool HasProductionSignature() const { return false; }
    bool AppointedPerson() const { return false; }
    bool Authenticated() const { return m_authenticated; }
    bool Partial() const { return m_partial; }
    bool AddFile(const std::string& name, const std::string& bytes, std::string& err);
    std::string InventoryDigest() const;
    bool Authenticate(const std::string& owner_pin, const std::string& digest, std::string& err);
    bool AppointPersonFromPackage(const std::string& name, std::string& err);
    bool InterruptAfterPersist(std::string& err);
    bool Recover(std::string& err);

private:
    std::map<std::string, std::string> m_files;
    std::string m_owner_pin;
    bool m_authenticated{false};
    bool m_partial{false};
    bool m_effect{false};
};

struct ReleaseCase {
    std::string case_id;
    std::string state;
    bool mandatory{true};
};

/**
 * CORE-001 and DEV-003. Completion is rejected while any mandatory row is not
 * PASS. A schema-only claim is rejected. Recovery does not flip NOT_RUN to PASS.
 * Stopping the release survives restart. Journeys count only when both ran
 * through a named binary.
 */
class ReleaseGate {
public:
    bool SetCases(const std::vector<ReleaseCase>& rows, std::string& err);
    bool ClaimComplete(bool schema_only, std::string& err);
    bool Complete() const { return m_complete; }
    bool Restore(std::string& err);
    std::string StateOf(const std::string& case_id) const;
    bool Stop();
    bool RestartKeepsStopped() const { return m_stopped; }
    bool NoteJourney(const std::string& name, const std::string& binary, std::string& err);
    bool JourneysReady() const { return m_e2e && m_journey && !m_binary.empty(); }

private:
    std::vector<ReleaseCase> m_rows;
    bool m_complete{false};
    bool m_stopped{false};
    bool m_e2e{false};
    bool m_journey{false};
    std::string m_binary;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_REMAINING_H
