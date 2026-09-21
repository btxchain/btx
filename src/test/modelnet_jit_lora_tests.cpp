// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01 Worker G — native LORA + UPDATE.
//   JIT-LORA-01  exact base binding
//   JIT-LORA-02  no base reload
//   JIT-LORA-03  concurrent isolation
//   JIT-LORA-04  detach while active
//   JIT-LORA-05  ordered composition
//   JIT-LORA-06  tokenizer conflict
//   JIT-LORA-07  merged representation
//   JIT-UPDATE-01  prepare alongside active
//   JIT-UPDATE-02  failed smoke
//   JIT-UPDATE-03  atomic switch
//   JIT-UPDATE-04  rollback trust floor
//   JIT-UPDATE-05  concurrent channel update
//   JIT-UPDATE-06  shared consumer release
//   JIT-UPDATE-07  idempotent switch
//
// Coordinator owns CMakeLists.txt. Do not ninja from this lane.

#include <modelnet/capability.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace modelnet {
bool ComposeRecipeAdapters(const CapabilityRecipe& recipe, Digest48& composition_id, std::string& err_code,
                            std::string& err);
bool PinResidentBase(const Digest48& base_id, Span<const unsigned char> bytes, std::string& err);
int ResidentBaseFetchCount(const Digest48& base_id);
int ResidentAdapterAttachCount(const Digest48& base_id);
bool ActivateAdapterOnResidentBase(const Digest48& base_id, const Digest48& adapter_id,
                                    const Digest48& adapter_base_binding, std::string& err_code, std::string& err);
bool BindSessionComposition(const std::string& session_id, const std::vector<std::string>& adapters,
                            const std::vector<std::string>& scales, Digest48& composition_id, std::string& err);
bool SessionCompositionId(const std::string& session_id, Digest48& out);
bool MergeAdapterRepresentation(const Digest48& base_id, const std::vector<unsigned char>& original_base,
                                const std::vector<std::string>& adapters, const std::vector<std::string>& scales,
                                Digest48& merged_id, std::vector<unsigned char>& merged_bytes, std::string& err);
PhysicalDisposition DetachAdapterLease(LeaseTable& leases, const std::string& lease_id, bool still_inflight);
void ResetCapabilityComposeState();
std::string ComposeActiveLock();
int ComposeConsumerRefs(const std::string& lock_id);
} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_lora_tests, BasicTestingSetup)

namespace {

std::string Hex96(char c)
{
    return std::string(96, c);
}

modelnet::Digest48 DigestOf(char c)
{
    modelnet::Digest48 d{};
    std::string err;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(Hex96(c), d, err));
    return d;
}

UniValue Component(const std::string& name, const std::string& kind, const std::string& digest,
                   const std::string& role, const std::string& binding = {})
{
    UniValue c(UniValue::VOBJ);
    c.pushKV("name", name);
    UniValue res(UniValue::VOBJ);
    res.pushKV("kind", kind);
    res.pushKV("digest48", digest);
    c.pushKV("resource", res);
    c.pushKV("role", role);
    c.pushKV("required", true);
    if (!binding.empty()) c.pushKV("base_binding", binding);
    return c;
}

UniValue BaseAdapterRecipe(const std::string& base, const std::string& adapter, const std::string& binding,
                            const std::string& scale = "1")
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("recipe_kind", "BASE_WITH_ADAPTERS");
    UniValue comps(UniValue::VARR);
    UniValue base_c = Component("base", "MODEL", base, "BASE");
    base_c.pushKV("tokenizer", "llama3");
    base_c.pushKV("vocab_size", "128256");
    base_c.pushKV("tokenizer_digest", Hex96('d'));
    comps.push_back(base_c);
    UniValue ad = Component("adapter", "ADAPTER", adapter, "ADAPTER", binding);
    ad.pushKV("scale", scale);
    ad.pushKV("tokenizer", "llama3");
    ad.pushKV("vocab_size", "128256");
    ad.pushKV("tokenizer_digest", Hex96('d'));
    comps.push_back(ad);
    o.pushKV("components", comps);
    o.pushKV("readiness_contract", "FULL_REQUIRED_SET");
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

bool ToActive(modelnet::LeaseTable& tbl, const std::string& lease_id)
{
    std::string code, err;
    if (!tbl.Transition(lease_id, modelnet::LeaseLife::ALLOCATED, code, err)) return false;
    if (!tbl.Transition(lease_id, modelnet::LeaseLife::POPULATING, code, err)) return false;
    if (!tbl.Transition(lease_id, modelnet::LeaseLife::VERIFIED, code, err)) return false;
    return tbl.Transition(lease_id, modelnet::LeaseLife::ACTIVE, code, err);
}

} // namespace

BOOST_AUTO_TEST_CASE(jit_lora_01_exact_base_binding)
{
    // JIT-LORA-01 — Exact base binding
    modelnet::ResetCapabilityComposeState();
    const modelnet::Digest48 base = DigestOf('a');
    const modelnet::Digest48 wrong = DigestOf('f');
    std::vector<unsigned char> base_bytes{0x11, 0x22, 0x33, 0x44};
    const std::vector<unsigned char> before = base_bytes;
    std::string err_code, err;
    BOOST_CHECK(!modelnet::AttachExactBaseAdapter(base, wrong, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "ADAPTER_BASE_MISMATCH");
    BOOST_CHECK(base_bytes == before);

    err_code.clear();
    err.clear();
    BOOST_CHECK(modelnet::AttachExactBaseAdapter(base, base, err_code, err));
    BOOST_CHECK(err_code.empty());
    BOOST_CHECK(base_bytes == before);

    modelnet::CapabilityRecipe recipe;
    UniValue bad = BaseAdapterRecipe(Hex96('a'), Hex96('b'), Hex96('f'));
    UniValue comps = bad["components"];
    UniValue base_c = comps[0];
    UniValue ad = comps[1];
    base_c.pushKV("architecture", "LlamaForCausalLM");
    base_c.pushKV("display_name", "fixture-llama");
    ad.pushKV("architecture", "LlamaForCausalLM");
    ad.pushKV("display_name", "fixture-llama");
    UniValue rebuilt(UniValue::VARR);
    rebuilt.push_back(base_c);
    rebuilt.push_back(ad);
    bad.pushKV("components", rebuilt);
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(bad, recipe, err_code, err));
    modelnet::Digest48 cid{};
    BOOST_CHECK(!modelnet::ComposeRecipeAdapters(recipe, cid, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "ADAPTER_BASE_MISMATCH");
    BOOST_CHECK(base_bytes == before);
}

BOOST_AUTO_TEST_CASE(jit_lora_02_no_base_reload)
{
    // JIT-LORA-02 — No base reload
    modelnet::ResetCapabilityComposeState();
    const modelnet::Digest48 base = DigestOf('a');
    const modelnet::Digest48 adapter = DigestOf('b');
    const std::vector<unsigned char> bytes{1, 2, 3, 4, 5};
    std::string err;
    BOOST_REQUIRE(modelnet::PinResidentBase(base, bytes, err));
    BOOST_CHECK_EQUAL(modelnet::ResidentBaseFetchCount(base), 1);
    std::string err_code;
    BOOST_REQUIRE(modelnet::ActivateAdapterOnResidentBase(base, adapter, base, err_code, err));
    BOOST_CHECK_EQUAL(modelnet::ResidentBaseFetchCount(base), 1);
    BOOST_CHECK_EQUAL(modelnet::ResidentAdapterAttachCount(base), 1);
    BOOST_REQUIRE(modelnet::ActivateAdapterOnResidentBase(base, adapter, base, err_code, err));
    BOOST_CHECK_EQUAL(modelnet::ResidentBaseFetchCount(base), 1);
    BOOST_CHECK_EQUAL(modelnet::ResidentAdapterAttachCount(base), 2);
}

BOOST_AUTO_TEST_CASE(jit_lora_03_concurrent_isolation)
{
    // JIT-LORA-03 — Concurrent isolation
    modelnet::ResetCapabilityComposeState();
    modelnet::Digest48 a{}, b{}, again{};
    std::string err;
    BOOST_REQUIRE(modelnet::BindSessionComposition("s1", {Hex96('b')}, {"1.0"}, a, err));
    BOOST_REQUIRE(modelnet::BindSessionComposition("s2", {Hex96('c')}, {"1.0"}, b, err));
    BOOST_CHECK(a != b);
    BOOST_REQUIRE(modelnet::SessionCompositionId("s1", again));
    BOOST_CHECK(again == a);
    BOOST_REQUIRE(modelnet::SessionCompositionId("s2", again));
    BOOST_CHECK(again == b);
    BOOST_CHECK(again != a);
}

BOOST_AUTO_TEST_CASE(jit_lora_04_detach_while_active)
{
    // JIT-LORA-04 — Detach while active
    modelnet::ResetCapabilityComposeState();
    modelnet::LeaseTable leases;
    modelnet::LeaseRecord& rec = leases.Create(modelnet::LeaseClass::LOAD, "lora-session", 4096,
                                                   modelnet::NewGeneration());
    const std::string lease_id = rec.lease_id;
    BOOST_REQUIRE(ToActive(leases, lease_id));
    BOOST_REQUIRE(leases.Find(lease_id));
    BOOST_CHECK_EQUAL(static_cast<int>(leases.Find(lease_id)->life), static_cast<int>(modelnet::LeaseLife::ACTIVE));

    const modelnet::PhysicalDisposition d = modelnet::DetachAdapterLease(leases, lease_id, /*still_inflight=*/true);
    BOOST_CHECK_EQUAL(modelnet::PhysicalDispositionName(d), "STILL_IN_FLIGHT");
    modelnet::LeaseRecord* still = leases.Find(lease_id);
    BOOST_REQUIRE(still);
    BOOST_CHECK_EQUAL(still->lease_id, lease_id);
    BOOST_CHECK(still->life != modelnet::LeaseLife::RELEASED);
    BOOST_CHECK(still->life == modelnet::LeaseLife::QUARANTINED || still->life == modelnet::LeaseLife::RETIRING);
    std::string err;
    BOOST_CHECK(!leases.ReleaseIfQuiescent(lease_id, err));
    UniValue j = leases.Json(lease_id);
    BOOST_CHECK_EQUAL(j["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(jit_lora_05_ordered_composition)
{
    // JIT-LORA-05 — Ordered composition
    modelnet::ResetCapabilityComposeState();
    const std::string a = Hex96('b');
    const std::string b = Hex96('c');
    modelnet::Digest48 order{}, reversed{}, scaled{}, same{};
    std::string err;
    BOOST_REQUIRE(modelnet::ComposeLoraOrder({a, b}, {"1.0", "1.0"}, order, err));
    BOOST_REQUIRE(modelnet::ComposeLoraOrder({b, a}, {"1.0", "1.0"}, reversed, err));
    BOOST_REQUIRE(modelnet::ComposeLoraOrder({a, b}, {"0.5", "1.0"}, scaled, err));
    BOOST_REQUIRE(modelnet::ComposeLoraOrder({a, b}, {"1.0", "1.0"}, same, err));
    BOOST_CHECK(order != reversed);
    BOOST_CHECK(order != scaled);
    BOOST_CHECK(reversed != scaled);
    BOOST_CHECK(order == same);
}

BOOST_AUTO_TEST_CASE(jit_lora_06_tokenizer_conflict)
{
    // JIT-LORA-06 — Tokenizer conflict
    modelnet::ResetCapabilityComposeState();
    std::string err_code, err;
    modelnet::CapabilityRecipe ok;
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(BaseAdapterRecipe(Hex96('a'), Hex96('b'), Hex96('a')), ok, err_code,
                                                   err));
    modelnet::Digest48 cid{};
    BOOST_CHECK(modelnet::ComposeRecipeAdapters(ok, cid, err_code, err));
    BOOST_CHECK(!cid.IsNull());

    UniValue bad = BaseAdapterRecipe(Hex96('a'), Hex96('b'), Hex96('a'));
    UniValue comps = bad["components"];
    UniValue adapter = comps[1];
    adapter.pushKV("tokenizer", "mistral");
    adapter.pushKV("vocab_size", "32000");
    adapter.pushKV("tokenizer_digest", Hex96('e'));
    UniValue rebuilt(UniValue::VARR);
    rebuilt.push_back(comps[0]);
    rebuilt.push_back(adapter);
    bad.pushKV("components", rebuilt);
    modelnet::CapabilityRecipe conflict;
    err_code.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(bad, conflict, err_code, err));
    BOOST_CHECK(!modelnet::ComposeRecipeAdapters(conflict, cid, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "TOKENIZER_CONFLICT");

    UniValue resize = BaseAdapterRecipe(Hex96('a'), Hex96('b'), Hex96('a'));
    UniValue comps2 = resize["components"];
    UniValue ad2 = comps2[1];
    ad2.pushKV("silent_resize", true);
    UniValue rebuilt2(UniValue::VARR);
    rebuilt2.push_back(comps2[0]);
    rebuilt2.push_back(ad2);
    resize.pushKV("components", rebuilt2);
    modelnet::CapabilityRecipe resized;
    err_code.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(resize, resized, err_code, err));
    BOOST_CHECK(!modelnet::ComposeRecipeAdapters(resized, cid, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "TOKENIZER_CONFLICT");

    UniValue self_attest = BaseAdapterRecipe(Hex96('a'), Hex96('b'), Hex96('a'));
    UniValue comps3 = self_attest["components"];
    UniValue ad3 = comps3[1];
    ad3.pushKV("tokenizer", "mistral");
    ad3.pushKV("vocab_size", "32000");
    ad3.pushKV("tokenizer_digest", Hex96('e'));
    UniValue rebuilt3(UniValue::VARR);
    rebuilt3.push_back(comps3[0]);
    rebuilt3.push_back(ad3);
    self_attest.pushKV("components", rebuilt3);
    self_attest.pushKV("validated_tokenizer_transform", true);
    self_attest.pushKV("transform_id", "package-claimed-ok");
    modelnet::CapabilityRecipe attested;
    err_code.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(self_attest, attested, err_code, err));
    BOOST_CHECK(!modelnet::ComposeRecipeAdapters(attested, cid, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "TOKENIZER_CONFLICT");
}

BOOST_AUTO_TEST_CASE(jit_lora_07_merged_representation)
{
    // JIT-LORA-07 — Merged representation
    modelnet::ResetCapabilityComposeState();
    const modelnet::Digest48 base = DigestOf('a');
    std::vector<unsigned char> original{0xca, 0xfe, 0xba, 0xbe, 0x01};
    const std::vector<unsigned char> snapshot = original;
    UniValue base_obj(UniValue::VOBJ);
    base_obj.pushKV("base", base.Hex());
    base_obj.pushKV("merged", false);
    base_obj.pushKV("automatic_spend_atoms", 0);
    UniValue merged_obj(UniValue::VOBJ);
    merged_obj.pushKV("base", base.Hex());
    UniValue ids(UniValue::VARR);
    ids.push_back(Hex96('b'));
    merged_obj.pushKV("adapters", ids);
    UniValue sc(UniValue::VARR);
    sc.push_back("1.0");
    merged_obj.pushKV("scales", sc);
    merged_obj.pushKV("merged", true);
    merged_obj.pushKV("transform", "lora-merge-v1");
    merged_obj.pushKV("automatic_spend_atoms", 0);
    modelnet::Digest48 base_rep{}, merged_rep{};
    std::string err;
    BOOST_REQUIRE(modelnet::CapabilityObjectIdJson(modelnet::REPRESENTATION_DOMAIN, base_obj, base_rep, err));
    BOOST_REQUIRE(modelnet::CapabilityObjectIdJson(modelnet::REPRESENTATION_DOMAIN, merged_obj, merged_rep, err));
    BOOST_CHECK(base_rep != merged_rep);

    modelnet::Digest48 merged_id{};
    std::vector<unsigned char> merged_bytes;
    BOOST_REQUIRE(modelnet::MergeAdapterRepresentation(base, original, {Hex96('b')}, {"1.0"}, merged_id,
                                                         merged_bytes, err));
    BOOST_CHECK(original == snapshot);
    BOOST_CHECK(merged_id != base_rep);
    BOOST_CHECK(!merged_bytes.empty());
    BOOST_CHECK(merged_bytes != original);
}

BOOST_AUTO_TEST_CASE(jit_update_01_prepare_alongside_active)
{
    // JIT-UPDATE-01 — Prepare alongside active
    modelnet::ResetCapabilityComposeState();
    std::string err;
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "prepare", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "old-lock");
    std::string active;
    BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old-lock", "PREPARE:new-lock"}, active, err));
    BOOST_CHECK_EQUAL(active, "old-lock");
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "commit", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "new-lock");
}

BOOST_AUTO_TEST_CASE(jit_update_02_failed_smoke)
{
    // JIT-UPDATE-02 — Failed smoke
    modelnet::ResetCapabilityComposeState();
    std::string err;
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "prepare", err));
    BOOST_CHECK(!modelnet::JournalSwitch("old-lock", "new-lock", "smoke-fail", err));
    BOOST_CHECK_EQUAL(err, "SMOKE_FAILED");
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "old-lock");
    BOOST_CHECK(!modelnet::JournalSwitch("old-lock", "new-lock", "commit", err));
    BOOST_CHECK_EQUAL(err, "SMOKE_FAILED");
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "old-lock");
    std::string active;
    BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old-lock", "PREPARE:new-lock", "SMOKE_FAIL:new-lock"}, active, err));
    BOOST_CHECK_EQUAL(active, "old-lock");
}

BOOST_AUTO_TEST_CASE(jit_update_03_atomic_switch)
{
    // JIT-UPDATE-03 — Atomic switch
    modelnet::ResetCapabilityComposeState();
    std::string err, active;
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "crash-before-commit", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "old-lock");
    BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old-lock", "PREPARE:new-lock", "crash-before-commit"}, active, err));
    BOOST_CHECK_EQUAL(active, "old-lock");
    BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old-lock", "PREPARE:new-lock", "INCOMPLETE"}, active, err));
    BOOST_CHECK_EQUAL(active, "old-lock");
    BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old-lock", "PREPARE:new-lock", "COMMIT:new-lock", "crash-after-commit"},
                                             active, err));
    BOOST_CHECK_EQUAL(active, "new-lock");
}

BOOST_AUTO_TEST_CASE(jit_update_04_rollback_trust_floor)
{
    // JIT-UPDATE-04 — Rollback trust floor
    modelnet::ResetCapabilityComposeState();
    std::string err;
    BOOST_REQUIRE(modelnet::JournalSwitch("gen-a|client_min=5", "gen-b|client_min=6", "commit", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "gen-b");
    BOOST_CHECK(!modelnet::JournalSwitch("gen-b|client_min=6", "gen-a|client_min=4", "rollback", err));
    BOOST_CHECK_EQUAL(err, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "gen-b");
    err.clear();
    BOOST_REQUIRE(modelnet::JournalSwitch("gen-b|client_min=6", "gen-a|client_min=6", "rollback", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "gen-a");

    modelnet::ResetCapabilityComposeState();
    err.clear();
    BOOST_REQUIRE(modelnet::JournalSwitch("gen-a|client_min=5", "gen-b|client_min=6", "commit", err));
    BOOST_CHECK(!modelnet::JournalSwitch("gen-b|client_min=6", "gen-a", "rollback", err));
    BOOST_CHECK_EQUAL(err, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "gen-b");
    err.clear();
    BOOST_CHECK(!modelnet::JournalSwitch("gen-b|client_min=6", "gen-weak|client_min=1", "commit", err));
    BOOST_CHECK_EQUAL(err, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "gen-b");
}

BOOST_AUTO_TEST_CASE(jit_update_05_concurrent_channel_update)
{
    // JIT-UPDATE-05 — Concurrent channel update
    modelnet::ResetCapabilityComposeState();
    std::string err;
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "upd-1|digest=aa", "prepare", err));
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "upd-2|digest=bb", "prepare", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "old-lock");
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "upd-1|digest=aa", "commit", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "upd-1");
    BOOST_REQUIRE(modelnet::JournalSwitch("upd-1", "upd-2|digest=bb", "commit", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "upd-2");
    std::string active;
    BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old-lock", "PREPARE:upd-1", "PREPARE:upd-2"}, active, err));
    BOOST_CHECK_EQUAL(active, "old-lock");
}

BOOST_AUTO_TEST_CASE(jit_update_06_shared_consumer_release)
{
    // JIT-UPDATE-06 — Shared consumer release
    modelnet::ResetCapabilityComposeState();
    std::string err;
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "prepare", err));
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "retain-consumer", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeConsumerRefs("old-lock"), 2);
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "commit", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "new-lock");
    BOOST_CHECK_GE(modelnet::ComposeConsumerRefs("old-lock"), 1);
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "release-consumer", err));
    BOOST_CHECK_GE(modelnet::ComposeConsumerRefs("old-lock"), 1);
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock", "release-consumer", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeConsumerRefs("old-lock"), 0);
}

BOOST_AUTO_TEST_CASE(jit_update_07_idempotent_switch)
{
    // JIT-UPDATE-07 — Idempotent switch
    modelnet::ResetCapabilityComposeState();
    std::string err;
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock|digest=aaa", "commit|idem=k1", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "new-lock");
    BOOST_REQUIRE(modelnet::JournalSwitch("old-lock", "new-lock|digest=aaa", "commit|idem=k1", err));
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "new-lock");
    BOOST_CHECK(!modelnet::JournalSwitch("old-lock", "other-lock|digest=bbb", "commit|idem=k1", err));
    BOOST_CHECK_EQUAL(err, "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(modelnet::ComposeActiveLock(), "new-lock");
}

BOOST_AUTO_TEST_SUITE_END()
