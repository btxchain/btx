// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_research_gate.h>
#include <modelnet/types.h>
#include <crypto/sha384.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_research_gate_tests, BasicTestingSetup)

namespace {

std::string Id(char fill)
{
    return std::string(96, fill);
}

std::string Sha384Hex(const std::string& bytes)
{
    CSHA384 hasher;
    if (!bytes.empty()) {
        hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    }
    modelnet::Digest48 digest;
    hasher.Finalize(digest.data.data());
    return digest.Hex();
}

modelnet::LineageClaim QualifiedLineage()
{
    modelnet::LineageClaim claim;
    claim.generation_n_research_id = Id('1');
    claim.generation_n1_id = Id('2');
    claim.generation_n1_admitted = true;
    claim.producer_runtime_id = Id('3');
    claim.adopted_by_runtime_id = Id('4');
    claim.generation_n2_candidate_id = Id('5');
    claim.model_file_id = Id('6');
    return claim;
}

modelnet::TrainingProfile FilledProfile()
{
    modelnet::TrainingProfile profile;
    profile.serialization = "canonical-state";
    profile.kernel = "sgd-byte";
    profile.init = "zero-init";
    profile.data_order = "fixed-sequence";
    profile.checkpoint = "full-state";
    profile.runtime = "cpu-ref";
    return profile;
}

} // namespace

BOOST_AUTO_TEST_CASE(art_001_dependency_lock_content_id)
{
    using namespace modelnet;
    std::string err;
    std::string missing;

    DependencyLock hinted;
    hinted.Set(LockSlot::SOURCE, "", "https://example.invalid/source", true);
    BOOST_CHECK_EQUAL(hinted.OriginUrl(LockSlot::SOURCE), "https://example.invalid/source");
    BOOST_CHECK(hinted.ContentId(LockSlot::SOURCE).empty());
    BOOST_CHECK(!hinted.Resolve({LockSlot::SOURCE}, missing, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ARTIFACT");
    BOOST_CHECK_EQUAL(missing, "source");
    BOOST_CHECK(err.find("https://") == std::string::npos);

    DependencyLock upper;
    upper.Set(LockSlot::RUNTIME, std::string(96, 'A'), "https://example.invalid/runtime", true);
    BOOST_CHECK(!upper.Resolve({LockSlot::RUNTIME}, missing, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ARTIFACT");
    BOOST_CHECK_EQUAL(missing, "runtime");

    DependencyLock ordered;
    ordered.Set(LockSlot::SOURCE, Id('a'), "https://example.invalid/source", true);
    ordered.Set(LockSlot::TOKENIZER, "", "https://example.invalid/tokenizer", false);
    ordered.Set(LockSlot::DATA, "", "https://example.invalid/data", true);
    ordered.Set(LockSlot::EVALUATION, "", "", true);
    BOOST_CHECK(ordered.Resolve({LockSlot::SOURCE}, missing, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(missing.empty());
    BOOST_CHECK(!ordered.Resolve({LockSlot::TOKENIZER, LockSlot::DATA, LockSlot::EVALUATION}, missing, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ARTIFACT");
    BOOST_CHECK_EQUAL(missing, "data");

    DependencyLock closed;
    const LockSlot slots[] = {LockSlot::SOURCE, LockSlot::DATA, LockSlot::TOKENIZER, LockSlot::BASE_MODEL,
                              LockSlot::RUNTIME, LockSlot::BUILD, LockSlot::EVALUATION};
    const char fills[] = {'1', '2', '3', '4', '5', '6', '7'};
    for (size_t i = 0; i < 7; ++i) {
        closed.Set(slots[i], Id(fills[i]), "", true);
        BOOST_CHECK_EQUAL(closed.ContentId(slots[i]).size(), 96U);
    }
    closed.Set(LockSlot::SOURCE, Id('1'), "https://example.invalid/source", true);
    BOOST_CHECK(closed.Resolve({slots[0], slots[1], slots[2], slots[3], slots[4], slots[5], slots[6]}, missing, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(closed.OriginUrl(LockSlot::SOURCE), "https://example.invalid/source");
    BOOST_CHECK_EQUAL(closed.ContentId(LockSlot::SOURCE), Id('1'));
}

BOOST_AUTO_TEST_CASE(art_002_public_redistribution)
{
    using namespace modelnet;
    std::string err;
    bool public_allowed = true;

    BOOST_CHECK(!PublicRedistribution("", false, true, public_allowed, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!public_allowed);

    public_allowed = true;
    BOOST_CHECK(!PublicRedistribution("rights-1", false, true, public_allowed, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!public_allowed);

    public_allowed = true;
    BOOST_CHECK(!PublicRedistribution("", true, false, public_allowed, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!public_allowed);

    BOOST_CHECK(PublicRedistribution("rights-1", true, true, public_allowed, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(public_allowed);

    BOOST_CHECK(PublicRedistribution("rights-1", true, false, public_allowed, err));
    BOOST_CHECK(public_allowed);
}

BOOST_AUTO_TEST_CASE(art_003_pin_and_generation_fence)
{
    using namespace modelnet;
    std::string err;
    RetentionStore store;

    BOOST_CHECK(!store.Track("", 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ARTIFACT");
    BOOST_CHECK(!store.Pin("", RetentionRole::RELEASE, 1, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ARTIFACT");

    BOOST_CHECK(store.Track("old-free", 1, err));
    BOOST_CHECK(store.Track("new-free", 2, err));
    BOOST_CHECK(store.Track("old-rel", 1, err));
    BOOST_CHECK(store.Pin("old-rel", RetentionRole::RELEASE, 1, err));
    BOOST_CHECK(store.Track("old-rb", 1, err));
    BOOST_CHECK(store.Pin("old-rb", RetentionRole::ROLLBACK_TARGET, 1, err));
    BOOST_CHECK(store.Track("old-off", 1, err));
    BOOST_CHECK(store.Pin("old-off", RetentionRole::OFFLINE_BUNDLE, 1, err));
    BOOST_CHECK(store.Track("fenced", 1, err));
    BOOST_CHECK(store.Pin("fenced", RetentionRole::RELEASE, 2, err));
    BOOST_CHECK(store.Pin("pin-only", RetentionRole::OFFLINE_BUNDLE, 1, err));

    const std::vector<std::string> deleted = store.CollectGarbage(1);
    BOOST_REQUIRE_EQUAL(deleted.size(), 1U);
    BOOST_CHECK_EQUAL(deleted[0], "old-free");
    BOOST_CHECK(!store.Contains("old-free"));
    BOOST_CHECK(store.Contains("new-free"));
    BOOST_CHECK(!store.IsPinned("new-free"));
    BOOST_CHECK(store.IsPinned("old-rel"));
    BOOST_CHECK(store.IsPinned("old-rb"));
    BOOST_CHECK(store.IsPinned("old-off"));
    BOOST_CHECK(store.IsPinned("fenced"));
    BOOST_CHECK(store.IsPinned("pin-only"));

    RetentionRole role;
    BOOST_CHECK(store.PinRole("old-rel", role));
    BOOST_CHECK(role == RetentionRole::RELEASE);
    BOOST_CHECK(store.PinRole("old-rb", role));
    BOOST_CHECK(role == RetentionRole::ROLLBACK_TARGET);
    BOOST_CHECK(store.PinRole("old-off", role));
    BOOST_CHECK(role == RetentionRole::OFFLINE_BUNDLE);

    const std::vector<std::string> later = store.CollectGarbage(2);
    BOOST_REQUIRE_EQUAL(later.size(), 1U);
    BOOST_CHECK_EQUAL(later[0], "new-free");
    BOOST_CHECK(!store.Contains("new-free"));
    BOOST_CHECK(store.Contains("old-rel"));
    BOOST_CHECK(store.Contains("old-rb"));
    BOOST_CHECK(store.Contains("old-off"));
    BOOST_CHECK(store.Contains("fenced"));
    BOOST_CHECK(store.Contains("pin-only"));
}

BOOST_AUTO_TEST_CASE(ver_001_training_adapter)
{
    using namespace modelnet;
    std::string err = "stale";

    TrainingAdapter bare("");
    BOOST_CHECK(!bare.Write("a.txt", "x", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");

    TrainingAdapter adapter("/lab/out");
    BOOST_CHECK(!adapter.AddReadOnlyInput("https://example.invalid/weights", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ARTIFACT");
    BOOST_CHECK(!adapter.InputIsReadOnly("https://example.invalid/weights"));
    BOOST_CHECK(adapter.ReadOnlyInputs().empty());

    const std::string input = Id('a');
    BOOST_CHECK(adapter.AddReadOnlyInput(input, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(adapter.InputIsReadOnly(input));
    BOOST_REQUIRE_EQUAL(adapter.ReadOnlyInputs().size(), 1U);
    BOOST_CHECK_EQUAL(adapter.ReadOnlyInputs()[0], input);

    const std::string before = adapter.ResultManifestId();
    BOOST_CHECK_EQUAL(before, Sha384Hex(""));
    BOOST_CHECK_EQUAL(before.size(), 96U);
    BOOST_CHECK(!adapter.Write("/etc/passwd", "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!adapter.Write("../secret", "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!adapter.Write("sub/../../x", "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!adapter.Write("C:/Windows/a", "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!adapter.Write(input, "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!adapter.Write("nested/" + input, "nope", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK_EQUAL(adapter.ResultManifestId(), before);

    BOOST_CHECK(!adapter.Resume("", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(adapter.Status(), "NOT_RESUMABLE");
    BOOST_CHECK(!adapter.CommitCheckpoint("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK(!adapter.Resume("missing-ckpt", err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK_EQUAL(adapter.Status(), "NOT_RESUMABLE");

    const std::string first = "alpha";
    const std::string second = "beta";
    BOOST_CHECK(adapter.Write("models/a.txt", first, err));
    BOOST_CHECK_EQUAL(adapter.ResultManifestId(), Sha384Hex(first));
    BOOST_CHECK(adapter.Write("models/b.txt", second, err));
    BOOST_CHECK_EQUAL(adapter.ResultManifestId(), Sha384Hex(first + second));
    BOOST_CHECK_EQUAL(adapter.ResultManifestId().size(), 96U);

    BOOST_CHECK(adapter.CommitCheckpoint("ckpt-1", err));
    BOOST_CHECK(adapter.Resume("ckpt-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(adapter.Status(), "RESUMED");
}

BOOST_AUTO_TEST_CASE(ver_004_freeze_evaluation)
{
    using namespace modelnet;
    std::string err;
    EvaluationGate gate;

    BOOST_CHECK(!gate.Compare(Id('a'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");
    BOOST_CHECK(!gate.FreezeEvaluation("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");
    BOOST_CHECK(gate.FrozenContract().empty());

    BOOST_CHECK(gate.FreezeEvaluation(Id('a'), err));
    BOOST_CHECK_EQUAL(gate.FrozenContract(), Id('a'));
    BOOST_CHECK(gate.Compare(Id('a'), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!gate.Compare(Id('b'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");

    BOOST_CHECK(!gate.SetDevelopmentHoldout({Id('1')}, {Id('1')}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");
    BOOST_CHECK(gate.DevelopmentIds().empty());
    BOOST_CHECK(gate.SetDevelopmentHoldout({Id('1')}, {Id('2')}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!gate.SetDevelopmentHoldout({Id('1'), Id('2')}, {Id('2')}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");
    BOOST_REQUIRE_EQUAL(gate.DevelopmentIds().size(), 1U);
    BOOST_CHECK_EQUAL(gate.DevelopmentIds()[0], Id('1'));
    BOOST_REQUIRE_EQUAL(gate.HoldoutIds().size(), 1U);
    BOOST_CHECK_EQUAL(gate.HoldoutIds()[0], Id('2'));

    const std::string negative = Id('9');
    gate.AddResult(negative, true);
    gate.AddResult(Id('8'), false);
    gate.StorePositiveSummary("improved");
    BOOST_CHECK_EQUAL(gate.Summary(), "improved");
    BOOST_CHECK(gate.ResultQueryable(negative));
    BOOST_CHECK(gate.NegativeResultQueryable(negative));
    BOOST_CHECK(gate.ResultQueryable(Id('8')));
    BOOST_CHECK(!gate.NegativeResultQueryable(Id('8')));
    BOOST_CHECK(!gate.ResultQueryable(Id('7')));
}

BOOST_AUTO_TEST_CASE(rsi_001_relations_and_fork)
{
    using namespace modelnet;
    std::string err;

    BOOST_CHECK_EQUAL(RelationKindName(RelationKind::PRODUCED_BY), "PRODUCED_BY");
    BOOST_CHECK_EQUAL(RelationKindName(RelationKind::ENDORSED_BY), "ENDORSED_BY");
    BOOST_CHECK_EQUAL(RelationKindName(RelationKind::ADOPTED_BY), "ADOPTED_BY");

    BOOST_CHECK(!PublishAdoptionReceipt(RelationKind::PRODUCED_BY, SignerRole::PRODUCER, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!PublishAdoptionReceipt(RelationKind::ENDORSED_BY, SignerRole::ENDORSER, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!PublishAdoptionReceipt(RelationKind::ADOPTED_BY, SignerRole::PRODUCER, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!PublishAdoptionReceipt(RelationKind::ADOPTED_BY, SignerRole::ENDORSER, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!PublishAdoptionReceipt(RelationKind::PRODUCED_BY, SignerRole::ADOPTER, err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(PublishAdoptionReceipt(RelationKind::ADOPTED_BY, SignerRole::ADOPTER, err));
    BOOST_CHECK(err.empty());

    ResearchPrincipal key_only;
    key_only.research_key = "parent-research-key";
    const ResearchPrincipal fork_key = ForkPrincipal(key_only);
    BOOST_CHECK(fork_key.research_key.empty());
    BOOST_CHECK(fork_key.wallet.empty());
    BOOST_CHECK(!fork_key.maintainer);
    BOOST_CHECK_EQUAL(key_only.research_key, "parent-research-key");

    ResearchPrincipal wallet_only;
    wallet_only.wallet = "parent-wallet";
    const ResearchPrincipal fork_wallet = ForkPrincipal(wallet_only);
    BOOST_CHECK(fork_wallet.research_key.empty());
    BOOST_CHECK(fork_wallet.wallet.empty());
    BOOST_CHECK(!fork_wallet.maintainer);
    BOOST_CHECK_EQUAL(wallet_only.wallet, "parent-wallet");

    ResearchPrincipal maintainer_only;
    maintainer_only.maintainer = true;
    const ResearchPrincipal fork_maintainer = ForkPrincipal(maintainer_only);
    BOOST_CHECK(fork_maintainer.research_key.empty());
    BOOST_CHECK(fork_maintainer.wallet.empty());
    BOOST_CHECK(!fork_maintainer.maintainer);
    BOOST_CHECK(maintainer_only.maintainer);
}

BOOST_AUTO_TEST_CASE(rsi_002_adopt_order)
{
    using namespace modelnet;
    std::string err;

    LocalAdoption skipped("gen-n");
    BOOST_CHECK(!skipped.Adopt(true, true, false, "gen-n1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_REGRESSION");
    BOOST_CHECK_EQUAL(skipped.Active(), "gen-n");
    BOOST_CHECK(skipped.Readable("gen-n"));
    BOOST_CHECK(!skipped.Readable("gen-n1"));

    LocalAdoption no_close("gen-n");
    BOOST_CHECK(!no_close.Adopt(false, true, true, "gen-n1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK_EQUAL(no_close.Active(), "gen-n");
    BOOST_CHECK(no_close.Readable("gen-n"));

    LocalAdoption no_stage("gen-n");
    BOOST_CHECK(!no_stage.Adopt(true, false, true, "gen-n1", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK_EQUAL(no_stage.Active(), "gen-n");
    BOOST_CHECK(no_stage.Readable("gen-n"));

    LocalAdoption done("gen-n");
    BOOST_CHECK(done.Adopt(true, true, true, "gen-n1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(done.Active(), "gen-n1");
    BOOST_CHECK(done.Readable("gen-n"));
    BOOST_CHECK(done.Readable("gen-n1"));
}

BOOST_AUTO_TEST_CASE(rsi_003_qualify_lineage)
{
    using namespace modelnet;
    std::string err;

    LineageClaim model_only;
    model_only.model_file_id = Id('f');
    BOOST_CHECK(!QualifyLineage(model_only, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LINEAGE");

    LineageClaim same_runtime = QualifiedLineage();
    same_runtime.adopted_by_runtime_id = same_runtime.producer_runtime_id;
    BOOST_CHECK(!QualifyLineage(same_runtime, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LINEAGE");

    LineageClaim not_admitted = QualifiedLineage();
    not_admitted.generation_n1_admitted = false;
    BOOST_CHECK(!QualifyLineage(not_admitted, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LINEAGE");

    LineageClaim no_candidate = QualifiedLineage();
    no_candidate.generation_n2_candidate_id.clear();
    BOOST_CHECK(!QualifyLineage(no_candidate, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LINEAGE");

    LineageClaim no_research = QualifiedLineage();
    no_research.generation_n_research_id.clear();
    BOOST_CHECK(!QualifyLineage(no_research, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LINEAGE");

    BOOST_CHECK(QualifyLineage(QualifiedLineage(), err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(inc_001_incident_truth_and_quarantine)
{
    using namespace modelnet;
    std::string err;
    IncidentStore store;

    IncidentReport report;
    report.affected_ids = {Id('a'), Id('b')};
    report.severity = "HIGH";
    report.confidence = "SUSPECTED";
    report.evidence_ids = {Id('c')};
    report.scope = "local";
    report.signature_valid = true;
    report.truth = true;
    BOOST_CHECK(store.File(report, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(report.signature_valid);
    BOOST_CHECK(!report.truth);
    BOOST_CHECK(!store.IsQuarantined(Id('a')));

    IncidentReport loaded;
    BOOST_CHECK(store.Lookup(Id('a'), loaded, err));
    BOOST_CHECK(loaded.signature_valid);
    BOOST_CHECK(!loaded.truth);
    BOOST_CHECK_EQUAL(loaded.severity, "HIGH");
    BOOST_CHECK_EQUAL(loaded.confidence, "SUSPECTED");
    BOOST_CHECK_EQUAL(loaded.scope, "local");
    BOOST_REQUIRE_EQUAL(loaded.evidence_ids.size(), 1U);
    BOOST_CHECK_EQUAL(loaded.evidence_ids[0], Id('c'));
    BOOST_REQUIRE_EQUAL(loaded.affected_ids.size(), 2U);

    BOOST_CHECK(store.Quarantine(Id('a'), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(store.IsQuarantined(Id('a')));
    BOOST_CHECK(!store.IsQuarantined(Id('b')));
    BOOST_CHECK(store.Lookup(Id('a'), loaded, err));
    BOOST_CHECK(loaded.signature_valid);
    BOOST_CHECK(!loaded.truth);

    BOOST_CHECK(!store.Quarantine(Id('d'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK(!store.IsQuarantined(Id('d')));

    IncidentReport incomplete;
    incomplete.signature_valid = true;
    incomplete.truth = true;
    incomplete.severity = "HIGH";
    incomplete.confidence = "CONFIRMED";
    incomplete.scope = "local";
    BOOST_CHECK(!store.File(incomplete, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK(store.Lookup(Id('a'), loaded, err));
    BOOST_CHECK(loaded.signature_valid);
    BOOST_CHECK(!loaded.truth);
    BOOST_CHECK(!store.Lookup(Id('e'), loaded, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
}

BOOST_AUTO_TEST_CASE(inc_002_runbooks)
{
    using namespace modelnet;
    std::string err;
    const char* names[] = {
        "key_compromise",
        "leaked_data",
        "malicious_weights",
        "attestor_disagreement",
        "stale_policy",
        "corrupt_journal",
        "disconnected_wan",
        "partial_rollout",
        "unknown_effect",
        "guard_failure",
    };
    std::set<std::string> detections;
    std::set<std::string> containments;
    std::set<std::string> recoveries;
    for (const char* name : names) {
        RunbookPlan plan;
        BOOST_CHECK(Runbook(name, plan, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(!plan.detection.empty());
        BOOST_CHECK(!plan.containment.empty());
        BOOST_CHECK(!plan.recovery.empty());
        BOOST_CHECK(plan.detection != plan.containment);
        BOOST_CHECK(plan.detection != plan.recovery);
        BOOST_CHECK(plan.containment != plan.recovery);
        BOOST_CHECK(detections.insert(plan.detection).second);
        BOOST_CHECK(containments.insert(plan.containment).second);
        BOOST_CHECK(recoveries.insert(plan.recovery).second);
    }
    BOOST_CHECK_EQUAL(detections.size(), 10U);

    RunbookPlan unknown;
    unknown.detection = "stale";
    unknown.containment = "stale";
    unknown.recovery = "stale";
    BOOST_CHECK(!Runbook("not_a_runbook", unknown, err));
    BOOST_CHECK_EQUAL(err, "BTX035_NOT_FOUND");
    BOOST_CHECK(unknown.detection.empty());
    BOOST_CHECK(unknown.containment.empty());
    BOOST_CHECK(unknown.recovery.empty());
}

BOOST_AUTO_TEST_CASE(rev_005_public_strict_template)
{
    using namespace modelnet;
    std::string err;
    const StrictTemplate shipped = PublicStrictTemplate();
    BOOST_CHECK(shipped.full_replay_required);
    BOOST_CHECK(shipped.verifier_ids.empty());
    BOOST_CHECK(!shipped.pinned);

    LocalVerifierPins pins;
    BOOST_CHECK(!pins.PinVerifier("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!pins.IsPinned(""));
    BOOST_CHECK(pins.PinVerifier(Id('a'), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pins.IsPinned(Id('a')));
    BOOST_CHECK(!pins.IsPinned(Id('b')));

    const StrictTemplate after = pins.Template();
    BOOST_CHECK(after.full_replay_required);
    BOOST_CHECK(after.verifier_ids.empty());
    BOOST_CHECK(!after.pinned);
    BOOST_CHECK(!PublicStrictTemplate().pinned);
}

BOOST_AUTO_TEST_CASE(rev_009_action_registry)
{
    using namespace modelnet;
    std::string err;
    const char* allowed[] = {
        "source.snapshot",
        "git.ref_update",
        "research.run",
        "model.activate",
        "research.publish",
        "realm.promote",
        "runtime.pause",
    };
    for (const char* name : allowed) {
        BOOST_CHECK(AcceptActionIntent(name, Id('a'), err));
        BOOST_CHECK(err.empty());
    }

    const char* rejected[] = {
        "bash -c id",
        "wallet.sign",
        "",
    };
    for (const char* name : rejected) {
        BOOST_CHECK(!AcceptActionIntent(name, Id('a'), err));
        BOOST_CHECK_EQUAL(err, "BTX035_ACTION");
    }

    BOOST_CHECK(!AcceptActionIntent("research.run", Id('a').substr(0, 95), err));
    BOOST_CHECK_EQUAL(err, "BTX035_ACTION");
    BOOST_CHECK(!AcceptActionIntent("research.run", std::string(96, 'A'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_ACTION");
    BOOST_CHECK(!AcceptActionIntent("research.run", "https://example.invalid/params", err));
    BOOST_CHECK_EQUAL(err, "BTX035_ACTION");
    BOOST_CHECK(!AcceptActionIntent("source.snapshot", std::string(96, 'g'), err));
    BOOST_CHECK_EQUAL(err, "BTX035_ACTION");
}

BOOST_AUTO_TEST_CASE(rev_010_training_profile)
{
    using namespace modelnet;
    std::string err;
    BOOST_CHECK(!NamedWorkflowIsProfile("demo"));
    BOOST_CHECK(!NamedWorkflowIsProfile("EXACT_CHECKS"));
    BOOST_CHECK(!NamedWorkflowIsProfile(""));

    const TrainingProfile ok = FilledProfile();
    BOOST_CHECK(AcceptTrainingProfile(ok, err));
    BOOST_CHECK(err.empty());

    std::string TrainingProfile::* members[] = {
        &TrainingProfile::serialization,
        &TrainingProfile::kernel,
        &TrainingProfile::init,
        &TrainingProfile::data_order,
        &TrainingProfile::checkpoint,
        &TrainingProfile::runtime,
    };
    for (std::string TrainingProfile::* member : members) {
        TrainingProfile bad = ok;
        bad.*member = "";
        BOOST_CHECK(!AcceptTrainingProfile(bad, err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    }
}

BOOST_AUTO_TEST_CASE(rev_011_full_replay_modes)
{
    using namespace modelnet;
    std::string err = "stale";
    BOOST_CHECK(FullReplayRequired("PUBLIC_STRICT", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(FullReplayRequired("REALM_STRICT", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!FullReplayRequired("PRIVATE_OWNER_APPROVED", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!FullReplayRequired("private_owner_approved", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(!FullReplayRequired("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
}

BOOST_AUTO_TEST_CASE(rev_015_comparison_result)
{
    using namespace modelnet;
    std::string err;

    ComparisonResult summary_only;
    summary_only.summary_score = "0.99";
    BOOST_CHECK(!summary_only.Bind(err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");
    BOOST_CHECK(!summary_only.HasNegativeRun(Id('9')));

    ComparisonResult bad_direction;
    bad_direction.baseline = Id('1');
    bad_direction.candidate = Id('2');
    bad_direction.spec = Id('3');
    bad_direction.AddPairedRun(Id('9'), true);
    bad_direction.direction = "SIDEWAYS";
    bad_direction.trials = 4;
    bad_direction.holdout_epoch = 7;
    bad_direction.procedure = "PAIRED_SIGN_BONFERRONI_V1";
    BOOST_CHECK(!bad_direction.Bind(err));
    BOOST_CHECK_EQUAL(err, "BTX035_EVAL");

    ComparisonResult result;
    result.baseline = Id('1');
    result.candidate = Id('2');
    result.spec = Id('3');
    const std::string negative = Id('9');
    result.AddPairedRun(negative, true);
    result.AddPairedRun(Id('8'), false);
    result.direction = "HIGHER";
    result.trials = 4;
    result.holdout_epoch = 7;
    result.procedure = "PAIRED_SIGN_BONFERRONI_V1";
    BOOST_CHECK(result.Bind(err));
    BOOST_CHECK(err.empty());

    const std::size_t runs_before = result.paired_run_ids.size();
    const std::size_t negatives_before = result.negative_run_ids.size();
    result.SetSummaryScore("0.25");
    BOOST_CHECK_EQUAL(result.summary_score, "0.25");
    BOOST_CHECK_EQUAL(result.paired_run_ids.size(), runs_before);
    BOOST_CHECK_EQUAL(result.negative_run_ids.size(), negatives_before);
    BOOST_CHECK(result.HasNegativeRun(negative));
    BOOST_CHECK(std::find(result.paired_run_ids.begin(), result.paired_run_ids.end(), negative) != result.paired_run_ids.end());
    BOOST_CHECK_EQUAL(result.baseline, Id('1'));
    BOOST_CHECK_EQUAL(result.candidate, Id('2'));
    BOOST_CHECK_EQUAL(result.spec, Id('3'));
    BOOST_CHECK_EQUAL(result.direction, "HIGHER");
    BOOST_CHECK_EQUAL(result.trials, uint64_t{4});
    BOOST_CHECK_EQUAL(result.holdout_epoch, uint64_t{7});
    BOOST_CHECK_EQUAL(result.procedure, "PAIRED_SIGN_BONFERRONI_V1");
    BOOST_CHECK(result.Bind(err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
