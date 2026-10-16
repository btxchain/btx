// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_release.h>
#include <test/util/setup_common.h>

#include <crypto/sha384.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_release_tests, BasicTestingSetup)

namespace {

std::string Hex96(char digit)
{
    return std::string(96, digit);
}

std::string Sha384Hex(const std::string& material)
{
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(material.data()), material.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(out);
}

modelnet::BuildManifest FilledManifest()
{
    modelnet::BuildManifest manifest;
    manifest.source_snapshot_id = Hex96('1');
    manifest.dependency_lock_id = Hex96('2');
    manifest.environment_id = Hex96('3');
    manifest.recipe_id = Hex96('4');
    manifest.output_digest = Hex96('5');
    manifest.test_digest = Hex96('6');
    return manifest;
}

modelnet::AttestorStatement Agree(const std::string& id)
{
    modelnet::AttestorStatement statement;
    statement.attestor_id = id;
    statement.promotion_id = "promo";
    statement.destination_realm = "dest";
    statement.policy_id = "policy";
    statement.closure_root = "closure";
    return statement;
}

} // namespace

BOOST_AUTO_TEST_CASE(build_001_manifest_verify_and_install)
{
    std::string err = "stale";
    modelnet::BuildManifest empty = FilledManifest();
    empty.recipe_id.clear();
    empty.pq_attestation_ok = true;
    BOOST_CHECK(!modelnet::VerifyManifest(empty, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUILD");
    BOOST_CHECK(!modelnet::InstallAllowed(empty, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUILD");

    modelnet::BuildManifest upper = FilledManifest();
    upper.output_digest[0] = 'A';
    upper.pq_attestation_ok = true;
    BOOST_CHECK(!modelnet::VerifyManifest(upper, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUILD");

    modelnet::BuildManifest origin_only = FilledManifest();
    origin_only.origin_account_ok = true;
    const std::string binding = modelnet::ManifestBindingDigest(origin_only);
    const std::string preimage = origin_only.source_snapshot_id + origin_only.dependency_lock_id +
                                 origin_only.environment_id + origin_only.recipe_id + origin_only.output_digest +
                                 origin_only.test_digest;
    BOOST_CHECK_EQUAL(binding, Sha384Hex(preimage));
    BOOST_CHECK_EQUAL(binding.size(), 96);
    BOOST_CHECK(origin_only.output_digest != binding);
    BOOST_CHECK(origin_only.test_digest != binding);
    BOOST_CHECK(!modelnet::DigestFieldsMatchBinding(origin_only));
    BOOST_CHECK(!modelnet::VerifyManifest(origin_only, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUILD");
    BOOST_CHECK(!modelnet::InstallAllowed(origin_only, err));

    modelnet::BuildManifest independent = FilledManifest();
    independent.pq_attestation_ok = true;
    BOOST_CHECK(!modelnet::DigestFieldsMatchBinding(independent));
    BOOST_CHECK(modelnet::VerifyManifest(independent, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::InstallAllowed(independent, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(build_002_platform_matrix_blocks_windows)
{
    const std::vector<modelnet::PlatformEntry> matrix = modelnet::PlatformMatrix();
    BOOST_REQUIRE_EQUAL(matrix.size(), 3);
    BOOST_CHECK_EQUAL(matrix[0].name, "linux");
    BOOST_CHECK(matrix[0].status == modelnet::PlatformStatus::TESTABLE);
    BOOST_CHECK_EQUAL(matrix[1].name, "macos");
    BOOST_CHECK(matrix[1].status == modelnet::PlatformStatus::TESTABLE);
    BOOST_CHECK_EQUAL(matrix[2].name, "windows");
    BOOST_CHECK(matrix[2].status == modelnet::PlatformStatus::BLOCKED);
    for (const modelnet::PlatformEntry& entry : matrix) {
        BOOST_CHECK(entry.status != modelnet::PlatformStatus::PASS);
    }
}

BOOST_AUTO_TEST_CASE(build_003_measurement_same_snapshot)
{
    modelnet::MeasurementReport left;
    left.snapshot_id = "snap-a";
    left.cold_ms = 10;
    left.warm_ms = 2;
    left.bytes_downloaded = 1000;
    left.rehydration = 1.5;
    left.journal_ms = 3;
    left.verify_per_s = 40.0;
    left.rebuild_ms = 8;
    left.rollout_ms = 9;

    modelnet::MeasurementReport same = left;
    same.cold_ms = 99;
    std::string err;
    BOOST_CHECK(modelnet::RequireSameSnapshot(left, same, err));
    BOOST_CHECK(err.empty());

    modelnet::MeasurementReport other = left;
    other.snapshot_id = "snap-b";
    BOOST_CHECK(!modelnet::RequireSameSnapshot(left, other, err));
    BOOST_CHECK_EQUAL(err, "BTX035_BUILD");
}

BOOST_AUTO_TEST_CASE(mig_001_plan_rejects_money_mutation)
{
    modelnet::MigrationPlan plan;
    plan.commit_id = "abc";
    plan.dirty_diff_digest = Hex96('a');
    plan.untracked_hash = Hex96('b');
    plan.binary_ids = {"btxd", "modeld"};
    plan.config_id = "cfg";
    plan.storage_root_name = "realm-root";
    plan.money_mutation = false;
    std::string err;
    BOOST_CHECK(modelnet::AcceptMigrationPlan(plan, err));
    BOOST_CHECK(err.empty());

    plan.money_mutation = true;
    BOOST_CHECK(!modelnet::AcceptMigrationPlan(plan, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
}

BOOST_AUTO_TEST_CASE(mig_002_backup_then_cutover_leaves_money_unchanged)
{
    modelnet::CutoverState state;
    state.backup_recorded = false;
    state.monetary_stop = false;
    std::string err;
    BOOST_CHECK(!modelnet::BackupThenCutover(state, err));
    BOOST_CHECK_EQUAL(err, "BTX035_MIGRATION_INCOMPLETE");
    BOOST_CHECK(!state.stop_writers);
    BOOST_CHECK(!state.monetary_stop);
    BOOST_CHECK(!modelnet::VerifyAfterCutover(state));

    state.backup_recorded = true;
    BOOST_CHECK(modelnet::BackupThenCutover(state, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(state.stop_writers);
    BOOST_CHECK(!state.monetary_stop);
    BOOST_CHECK(state.money_unchanged);
    BOOST_CHECK(modelnet::VerifyAfterCutover(state));
}

BOOST_AUTO_TEST_CASE(mdt_001_attestation_store_is_not_monetary)
{
    modelnet::ModelAttestationStore store;
    store.SetRealm("realm-1");
    store.SetPolicyEpoch(7);
    store.AddRevocation("old");
    store.AddAttestation("att-1");
    BOOST_CHECK_EQUAL(store.Realm(), "realm-1");
    BOOST_CHECK_EQUAL(store.PolicyEpoch(), uint64_t{7});
    BOOST_CHECK(store.Revoked("old"));
    BOOST_CHECK(store.HasAttestation("att-1"));
    BOOST_CHECK(!store.TouchesMonetaryConsensus());
}

BOOST_AUTO_TEST_CASE(mdt_002_promotion_keeps_threshold_after_revocation)
{
    modelnet::ModelAttestationStore store;
    store.SetThreshold(2);
    store.AddAttestation("a");
    const std::vector<std::string> eligible{"a", "b", "c"};
    std::string err;

    BOOST_CHECK(store.ApprovePromotion("promo", "dest", "policy", "closure", {"a", "b"}, {Agree("a"), Agree("b")}, err));
    BOOST_CHECK(err.empty());

    modelnet::AttestorStatement dissent = Agree("b");
    dissent.closure_root = "other";
    BOOST_CHECK(!store.ApprovePromotion("promo", "dest", "policy", "closure", {"a", "b"}, {Agree("a"), dissent}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ATTEST");

    BOOST_CHECK(!store.ApprovePromotion("promo", "dest", "policy", "closure", eligible, {Agree("a"), Agree("b")}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");

    store.AddRevocation("c");
    BOOST_CHECK_EQUAL(store.Threshold(), 2);
    modelnet::AttestorStatement revoked_dissent = Agree("c");
    revoked_dissent.policy_id = "nope";
    BOOST_CHECK(store.ApprovePromotion("promo", "dest", "policy", "closure", eligible,
                                       {Agree("a"), Agree("b"), revoked_dissent}, err));
    BOOST_CHECK(err.empty());

    store.AddRevocation("b");
    BOOST_CHECK_EQUAL(store.Threshold(), 2);
    BOOST_CHECK(!store.ApprovePromotion("promo", "dest", "policy", "closure", eligible, {Agree("a")}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_THRESHOLD");
}

BOOST_AUTO_TEST_CASE(mdt_003_delegated_trust_still_checks_signatures)
{
    BOOST_CHECK(modelnet::DelegatedTrustStillChecksSignatures());
    std::string err;
    BOOST_CHECK(!modelnet::SkipSignatureBecauseDelegated(err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE");
}

BOOST_AUTO_TEST_CASE(mdt_004_cross_realm_import_distinct_approver)
{
    std::string err;
    BOOST_CHECK(modelnet::CrossRealmImport("promo-manifest", "source-export", "dest-approver", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!modelnet::CrossRealmImport("promo-manifest", "same-approver", "same-approver", err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");

    BOOST_CHECK(!modelnet::CrossRealmImport("", "source-export", "dest-approver", err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
}

BOOST_AUTO_TEST_CASE(realm_001_id_repeats_for_same_nonce)
{
    const std::string nonce_a(64, 'a');
    const std::string nonce_b(64, 'b');
    std::string id_a;
    std::string id_again = "unset";
    std::string id_b;
    std::string err;
    BOOST_CHECK(modelnet::RealmId("net", "founder", nonce_a, id_a, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::RealmId("net", "founder", nonce_a, id_again, err));
    BOOST_CHECK_EQUAL(id_a, id_again);
    BOOST_CHECK_EQUAL(id_a.size(), 96);

    std::string preimage = "BTX/035/Realm/v1";
    preimage.push_back('\0');
    preimage += "net";
    preimage += "founder";
    preimage += nonce_a;
    BOOST_CHECK_EQUAL(id_a, Sha384Hex(preimage));

    BOOST_CHECK(modelnet::RealmId("net", "founder", nonce_b, id_b, err));
    BOOST_CHECK(id_a != id_b);

    std::string kept = "keep";
    BOOST_CHECK(!modelnet::RealmId("net", "founder", "abc", kept, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    BOOST_CHECK_EQUAL(kept, "keep");
    const std::string upper(64, 'A');
    BOOST_CHECK(!modelnet::RealmId("net", "founder", upper, kept, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REALM");
    BOOST_CHECK_EQUAL(kept, "keep");
}

BOOST_AUTO_TEST_CASE(realm_002_ingress_keys_differ_and_are_not_wallet_keys)
{
    modelnet::Ingress ingress;
    ingress.public_acquisition = "acq-key";
    ingress.private_promotion = "promo-key";
    std::string err;
    BOOST_CHECK(modelnet::AcceptIngress(ingress, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!modelnet::SharesKeyWithWallet());

    ingress.private_promotion = ingress.public_acquisition;
    BOOST_CHECK(!modelnet::AcceptIngress(ingress, err));
    BOOST_CHECK_EQUAL(err, "BTX035_AUTHORITY");
    BOOST_CHECK(!modelnet::SharesKeyWithWallet());
}

BOOST_AUTO_TEST_CASE(realm_003_trust_is_not_transitive)
{
    modelnet::TrustGraph graph;
    BOOST_CHECK(!graph.TrustTransitive("public_publisher", "model"));
    BOOST_CHECK(!graph.TrustTransitive("org", "employee_model"));

    BOOST_CHECK(!graph.AddEdge("public_publisher", "model"));
    BOOST_CHECK(!graph.TrustTransitive("public_publisher", "model"));

    BOOST_CHECK(graph.AddEdge("public_publisher", "org"));
    BOOST_CHECK(graph.AddEdge("org", "model"));
    BOOST_CHECK(!graph.TrustTransitive("public_publisher", "model"));

    BOOST_CHECK(!graph.TrustTransitive("org", "employee_model"));
    BOOST_CHECK(graph.AddEdge("org", "mid"));
    BOOST_CHECK(graph.AddEdge("mid", "employee_model"));
    BOOST_CHECK(!graph.TrustTransitive("org", "employee_model"));
    BOOST_CHECK(graph.AddEdge("org", "employee_model"));
    BOOST_CHECK(graph.TrustTransitive("org", "employee_model"));
}

BOOST_AUTO_TEST_CASE(scm_003_read_missing_blocks_only_that_path)
{
    modelnet::PinnedTree tree;
    tree.AddName("missing.txt");
    tree.AddName("sibling.txt");
    BOOST_CHECK_EQUAL(tree.Names().size(), 2);
    BOOST_CHECK_EQUAL(tree.Names()[0], "missing.txt");
    BOOST_CHECK_EQUAL(tree.Names()[1], "sibling.txt");

    const std::vector<unsigned char> body{'o', 'k'};
    tree.PutBytes("sibling.txt", body);
    const std::vector<modelnet::PathRead> rows = modelnet::ReadMissing(tree, {"missing.txt", "sibling.txt"});
    BOOST_REQUIRE_EQUAL(rows.size(), 2);
    BOOST_CHECK_EQUAL(rows[0].path, "missing.txt");
    BOOST_CHECK_EQUAL(rows[0].err, "BTX035_MISSING");
    BOOST_CHECK(rows[0].bytes.empty());
    BOOST_CHECK_EQUAL(rows[1].path, "sibling.txt");
    BOOST_CHECK(rows[1].err.empty());
    BOOST_CHECK(rows[1].bytes == body);

    const std::vector<std::string> order =
        modelnet::PrefetchOrder({"src/main.cpp", "dependency.manifest", "a/dependency.manifest", "README"});
    BOOST_REQUIRE_EQUAL(order.size(), 4);
    BOOST_CHECK_EQUAL(order[0], "dependency.manifest");
    BOOST_CHECK_EQUAL(order[1], "a/dependency.manifest");
    BOOST_CHECK_EQUAL(order[2], "src/main.cpp");
    BOOST_CHECK_EQUAL(order[3], "README");
}

BOOST_AUTO_TEST_CASE(scm_004_checkpoint_and_signed_git_ref)
{
    BOOST_CHECK(modelnet::JournalCheckpointDue(1024, 0, true));
    BOOST_CHECK(modelnet::JournalCheckpointDue(0, 1000, true));
    BOOST_CHECK(modelnet::JournalCheckpointDue(1024, 1000, true));
    BOOST_CHECK(!modelnet::JournalCheckpointDue(1023, 999, true));
    BOOST_CHECK(!modelnet::JournalCheckpointDue(1024, 1000, false));
    BOOST_CHECK(!modelnet::JournalCheckpointDue(100000, 100000, false));
    BOOST_CHECK_EQUAL(std::string(modelnet::ProfileLabel(true)), "protected");
    BOOST_CHECK(std::string(modelnet::ProfileLabel(false)) != "protected");

    std::string err;
    BOOST_CHECK(!modelnet::AcceptConsequentialGitRef("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SIGNATURE");
    BOOST_CHECK(modelnet::AcceptConsequentialGitRef("sig", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(dev_001_worker_start_records_three_hashes)
{
    std::string err;
    BOOST_CHECK(!modelnet::WorkerStart("", "diff", "untracked", err));
    BOOST_CHECK_EQUAL(err, "BTX035_MISSING");
    BOOST_CHECK(!modelnet::WorkerStart("head", "", "untracked", err));
    BOOST_CHECK_EQUAL(err, "BTX035_MISSING");
    BOOST_CHECK(!modelnet::WorkerStart("head", "diff", "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_MISSING");
    BOOST_CHECK(modelnet::WorkerStart("head", "diff", "untracked", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!modelnet::ExternalPromptTrusted());
}

BOOST_AUTO_TEST_CASE(dev_002_slice_complete_rejects_grep_tests)
{
    std::string err;
    BOOST_CHECK(modelnet::SliceComplete("modelnet::RealmId", "lab.release", "realm_unit", "realm_integration", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!modelnet::SliceComplete("modelnet::RealmId", "lab.release", "grep_only", "realm_integration", err));
    BOOST_CHECK_EQUAL(err, "BTX035_TEST");
    BOOST_CHECK(!modelnet::SliceComplete("modelnet::RealmId", "lab.release", "realm_unit", "grep-scan", err));
    BOOST_CHECK_EQUAL(err, "BTX035_TEST");
    BOOST_CHECK(!modelnet::SliceComplete("", "lab.release", "realm_unit", "realm_integration", err));
    BOOST_CHECK_EQUAL(err, "BTX035_TEST");
}

BOOST_AUTO_TEST_CASE(qa_003_release_claim_needs_every_dimension)
{
    std::string err;
    const bool incomplete[] = {true, false, true};
    BOOST_CHECK(!modelnet::ReleaseClaim("the build is release qualified", incomplete, err));
    BOOST_CHECK_EQUAL(err, "BTX035_CLAIM");

    const bool complete[] = {true, true};
    BOOST_CHECK(modelnet::ReleaseClaim("the build is release qualified", complete, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(modelnet::ReleaseClaim("still measuring", incomplete, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(net_003_announcement_caps)
{
    BOOST_CHECK_EQUAL(modelnet::kMaxAnnouncementRecords, size_t{32});
    BOOST_CHECK_EQUAL(modelnet::kMaxAnnouncementTopics, size_t{16});
    BOOST_CHECK_EQUAL(modelnet::kMaxAnnouncementHops, 4);
    BOOST_CHECK_EQUAL(modelnet::kAnnouncementValidityMs, int64_t{600000});
    BOOST_CHECK_EQUAL(modelnet::kQueryFanoutDefault, 4);
    BOOST_CHECK_EQUAL(modelnet::kQueryFanoutMax, 8);

    std::string err;
    BOOST_CHECK(modelnet::CheckAnnouncement(32, 16, 4, 600000, modelnet::kQueryFanoutDefault, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(modelnet::CheckAnnouncement(1, 1, 1, 1, 8, err));

    BOOST_CHECK(!modelnet::CheckAnnouncement(33, 16, 4, 600000, 4, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!modelnet::CheckAnnouncement(32, 17, 4, 600000, 4, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!modelnet::CheckAnnouncement(32, 16, 5, 600000, 4, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!modelnet::CheckAnnouncement(32, 16, 4, 600001, 4, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(!modelnet::CheckAnnouncement(32, 16, 4, 600000, 9, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
}

BOOST_AUTO_TEST_SUITE_END()
