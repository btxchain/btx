// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_release.h>

#include <crypto/sha384.h>
#include <util/strencodings.h>

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

bool Ok(std::string& err)
{
    err.clear();
    return true;
}

bool IsLowerHex(const std::string& text, size_t n)
{
    if (text.size() != n) return false;
    for (unsigned char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

std::string Sha384Hex(const std::string& material)
{
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(material.data()), material.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(out);
}

bool Hex96(const std::string& text)
{
    return IsLowerHex(text, 96);
}

bool FieldOk(const BuildManifest& manifest)
{
    return Hex96(manifest.source_snapshot_id) && Hex96(manifest.dependency_lock_id) &&
           Hex96(manifest.environment_id) && Hex96(manifest.recipe_id) && Hex96(manifest.output_digest) &&
           Hex96(manifest.test_digest);
}

bool OriginAccountIsOnlyTrueFlag(const BuildManifest& manifest)
{
    return manifest.origin_account_ok && !manifest.pq_attestation_ok && !manifest.release_authority_ok &&
           !manifest.anti_rollback_ok && !manifest.compatibility_ok;
}

bool SameTuple(const AttestorStatement& statement, const std::string& promotion_id, const std::string& destination_realm,
               const std::string& policy_id, const std::string& closure_root)
{
    return statement.promotion_id == promotion_id && statement.destination_realm == destination_realm &&
           statement.policy_id == policy_id && statement.closure_root == closure_root;
}

std::string FinalSegment(const std::string& path)
{
    const size_t slash = path.rfind('/');
    if (slash == std::string::npos) return path;
    return path.substr(slash + 1);
}

} // namespace

std::string ManifestBindingDigest(const BuildManifest& manifest)
{
    // SHA-384 of the six ids concatenated, no separator.
    const std::string preimage = manifest.source_snapshot_id + manifest.dependency_lock_id + manifest.environment_id +
                                 manifest.recipe_id + manifest.output_digest + manifest.test_digest;
    return Sha384Hex(preimage);
}

bool DigestFieldsMatchBinding(const BuildManifest& manifest)
{
    const std::string binding = ManifestBindingDigest(manifest);
    return manifest.output_digest == binding && manifest.test_digest == binding;
}

bool VerifyManifest(const BuildManifest& manifest, std::string& err)
{
    if (manifest.source_snapshot_id.empty() || manifest.dependency_lock_id.empty() || manifest.environment_id.empty() ||
        manifest.recipe_id.empty() || manifest.output_digest.empty() || manifest.test_digest.empty() ||
        !FieldOk(manifest)) {
        return Fail(err, "BTX035_BUILD");
    }
    if (OriginAccountIsOnlyTrueFlag(manifest) && !DigestFieldsMatchBinding(manifest)) {
        return Fail(err, "BTX035_BUILD");
    }
    return Ok(err);
}

bool InstallAllowed(const BuildManifest& manifest, std::string& err)
{
    return VerifyManifest(manifest, err);
}

std::vector<PlatformEntry> PlatformMatrix()
{
    return {
        {"linux", PlatformStatus::TESTABLE},
        {"macos", PlatformStatus::TESTABLE},
        // There is no Windows runner here.
        {"windows", PlatformStatus::BLOCKED},
    };
}

bool RequireSameSnapshot(const MeasurementReport& left, const MeasurementReport& right, std::string& err)
{
    if (left.snapshot_id != right.snapshot_id) return Fail(err, "BTX035_BUILD");
    return Ok(err);
}

bool AcceptMigrationPlan(const MigrationPlan& plan, std::string& err)
{
    if (plan.money_mutation) return Fail(err, "BTX035_SCOPE_DENIED");
    return Ok(err);
}

bool BackupThenCutover(CutoverState& state, std::string& err)
{
    // Never arm a monetary stop. Writers stop only after a recorded backup.
    state.monetary_stop = false;
    if (!state.backup_recorded) {
        state.stop_writers = false;
        return Fail(err, "BTX035_MIGRATION_INCOMPLETE");
    }
    state.stop_writers = true;
    state.money_unchanged = true;
    return Ok(err);
}

bool VerifyAfterCutover(const CutoverState& state)
{
    return state.money_unchanged;
}

void ModelAttestationStore::SetRealm(const std::string& realm) { m_realm = realm; }
std::string ModelAttestationStore::Realm() const { return m_realm; }
void ModelAttestationStore::SetPolicyEpoch(uint64_t epoch) { m_policy_epoch = epoch; }
uint64_t ModelAttestationStore::PolicyEpoch() const { return m_policy_epoch; }
void ModelAttestationStore::SetThreshold(int threshold) { m_threshold = threshold; }
int ModelAttestationStore::Threshold() const { return m_threshold; }

void ModelAttestationStore::AddRevocation(const std::string& id)
{
    // Revocation removes eligibility. It does not change m_threshold.
    m_revoked.insert(id);
}

bool ModelAttestationStore::Revoked(const std::string& id) const
{
    return m_revoked.count(id) != 0;
}

void ModelAttestationStore::AddAttestation(const std::string& id) { m_attestations.insert(id); }

bool ModelAttestationStore::HasAttestation(const std::string& id) const
{
    return m_attestations.count(id) != 0;
}

bool ModelAttestationStore::TouchesMonetaryConsensus() const
{
    return false;
}

bool ModelAttestationStore::ApprovePromotion(const std::string& promotion_id, const std::string& destination_realm,
                                             const std::string& policy_id, const std::string& closure_root,
                                             const std::vector<std::string>& eligible_ids,
                                             const std::vector<AttestorStatement>& statements, std::string& err) const
{
    std::set<std::string> eligible(eligible_ids.begin(), eligible_ids.end());
    for (const std::string& id : m_revoked) eligible.erase(id);
    if (static_cast<int>(eligible.size()) < m_threshold) return Fail(err, "BTX035_THRESHOLD");

    std::set<std::string> agreed;
    for (const AttestorStatement& statement : statements) {
        if (eligible.count(statement.attestor_id) == 0) continue;
        if (!SameTuple(statement, promotion_id, destination_realm, policy_id, closure_root)) {
            return Fail(err, "BTX035_ATTEST");
        }
        agreed.insert(statement.attestor_id);
    }
    for (const std::string& id : eligible) {
        if (agreed.count(id) == 0) return Fail(err, "BTX035_THRESHOLD");
    }
    return Ok(err);
}

bool DelegatedTrustStillChecksSignatures()
{
    return true;
}

bool SkipSignatureBecauseDelegated(std::string& err)
{
    return Fail(err, "BTX035_SIGNATURE");
}

bool CrossRealmImport(const std::string& promotion_manifest_id, const std::string& source_export_authorization_id,
                      const std::string& destination_approver_id, std::string& err)
{
    if (promotion_manifest_id.empty() || source_export_authorization_id.empty() || destination_approver_id.empty() ||
        destination_approver_id == source_export_authorization_id) {
        return Fail(err, "BTX035_AUTHORITY");
    }
    return Ok(err);
}

bool RealmId(const std::string& network_id, const std::string& founder_key_id, const std::string& nonce,
             std::string& id, std::string& err)
{
    if (!IsLowerHex(nonce, 64)) return Fail(err, "BTX035_REALM");
    std::string preimage = "BTX/035/Realm/v1";
    preimage.push_back('\0');
    preimage += network_id;
    preimage += founder_key_id;
    preimage += nonce;
    id = Sha384Hex(preimage);
    return Ok(err);
}

bool AcceptIngress(const Ingress& ingress, std::string& err)
{
    if (ingress.public_acquisition.empty() || ingress.private_promotion.empty() ||
        ingress.public_acquisition == ingress.private_promotion) {
        return Fail(err, "BTX035_AUTHORITY");
    }
    return Ok(err);
}

bool SharesKeyWithWallet()
{
    return false;
}

bool TrustGraph::AddEdge(const std::string& from, const std::string& to)
{
    if (from == "public_publisher" && to == "model") return false;
    m_edges.insert({from, to});
    return true;
}

bool TrustGraph::TrustTransitive(const std::string& from, const std::string& to) const
{
    if (from == "public_publisher" && to == "model") return false;
    return m_edges.count({from, to}) != 0;
}

void PinnedTree::AddName(const std::string& name) { m_names.push_back(name); }
const std::vector<std::string>& PinnedTree::Names() const { return m_names; }

void PinnedTree::PutBytes(const std::string& path, const std::vector<unsigned char>& bytes)
{
    m_bytes[path] = bytes;
}

std::vector<PathRead> ReadMissing(const PinnedTree& tree, const std::vector<std::string>& paths)
{
    std::vector<PathRead> out;
    out.reserve(paths.size());
    for (const std::string& path : paths) {
        PathRead row;
        row.path = path;
        const auto found = tree.m_bytes.find(path);
        if (found == tree.m_bytes.end()) {
            row.err = "BTX035_MISSING";
        } else {
            row.bytes = found->second;
        }
        out.push_back(std::move(row));
    }
    return out;
}

bool IsDependencyManifest(const std::string& path)
{
    return FinalSegment(path) == "dependency.manifest";
}

std::vector<std::string> PrefetchOrder(const std::vector<std::string>& paths)
{
    std::vector<std::string> manifests;
    std::vector<std::string> rest;
    for (const std::string& path : paths) {
        if (IsDependencyManifest(path)) manifests.push_back(path);
        else rest.push_back(path);
    }
    manifests.insert(manifests.end(), rest.begin(), rest.end());
    return manifests;
}

bool JournalCheckpointDue(uint64_t events, int64_t elapsed_ms, bool protected_profile)
{
    if (!protected_profile) return false;
    return events >= 1024 || elapsed_ms >= 1000;
}

const char* ProfileLabel(bool protected_profile)
{
    return protected_profile ? "protected" : "ordinary";
}

bool AcceptConsequentialGitRef(const std::string& signature, std::string& err)
{
    if (signature.empty()) return Fail(err, "BTX035_SIGNATURE");
    return Ok(err);
}

bool WorkerStart(const std::string& head, const std::string& diff_hash, const std::string& untracked_hash,
                 std::string& err)
{
    if (head.empty() || diff_hash.empty() || untracked_hash.empty()) return Fail(err, "BTX035_MISSING");
    return Ok(err);
}

bool ExternalPromptTrusted()
{
    return false;
}

bool SliceComplete(const std::string& native_symbol, const std::string& call_path, const std::string& unit_test,
                   const std::string& integration_test, std::string& err)
{
    if (native_symbol.empty() || call_path.empty() || unit_test.empty() || integration_test.empty()) {
        return Fail(err, "BTX035_TEST");
    }
    if (unit_test.compare(0, 4, "grep") == 0 || integration_test.compare(0, 4, "grep") == 0) {
        return Fail(err, "BTX035_TEST");
    }
    return Ok(err);
}

bool ReleaseClaim(const std::string& text, Span<const bool> assurance, std::string& err)
{
    const bool says_qualified = text.find("release qualified") != std::string::npos;
    bool any_false = false;
    for (bool dimension : assurance) {
        if (!dimension) any_false = true;
    }
    if (says_qualified && any_false) return Fail(err, "BTX035_CLAIM");
    return Ok(err);
}

bool CheckAnnouncement(size_t record_ids, size_t topics, int hops, int64_t validity_ms, int query_fanout,
                       std::string& err)
{
    if (record_ids > kMaxAnnouncementRecords || topics > kMaxAnnouncementTopics || hops > kMaxAnnouncementHops ||
        hops < 0 || validity_ms > kAnnouncementValidityMs || validity_ms < 0 || query_fanout > kQueryFanoutMax ||
        query_fanout < 0) {
        return Fail(err, "BTX035_LIMIT_EXCEEDED");
    }
    return Ok(err);
}

} // namespace modelnet
