// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11 matrix id -> BOOST_AUTO_TEST_CASE
// V11-COMM-06   comm_follow_collection_quota_not_raised
// V11-COMM-07   comm_circle_no_onchain_membership
// V11-COMM-08   comm_preserve_obeys_pins_and_quota
// V11-COMM-09   comm_preserve_rare_at_most_one
// V11-COMM-09   comm_preserve_rare_jitter
// V11-COMM-10   comm_third_party_receipt_no_credit
// V11-FREE-14   free_exposure_within_ceiling
// V11-LOCAL-01  local_open_uri_preview_only
// V11-LOCAL-03  local_pickle_rejected_no_remote_inference
// V11-LOCAL-05  local_payload_storage_zero_refused
// V11-ISO-03    iso_qualify_runtime_default_not_run
// V11-ISO-04    iso_helper_missing_capabilities_listed

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/community.h>
#include <modelnet/cores.h>
#include <modelnet/firstrun.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/policy.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <modelnet/resource_uri.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_v11_remaining_tests, BasicTestingSetup)

namespace {

class EnvRestore
{
public:
    explicit EnvRestore(std::string key) : m_key(std::move(key))
    {
        if (const char* v = std::getenv(m_key.c_str())) {
            m_prev = std::string{v};
        }
    }
    ~EnvRestore()
    {
        if (m_prev) {
            setenv(m_key.c_str(), m_prev->c_str(), 1);
        } else {
            unsetenv(m_key.c_str());
        }
    }
    void Set(const char* v) { setenv(m_key.c_str(), v, 1); }
    void Unset() { unsetenv(m_key.c_str()); }

private:
    std::string m_key;
    std::optional<std::string> m_prev;
};

modelnet::Digest48 DigestTag(unsigned char a, unsigned char b = 0)
{
    modelnet::Digest48 d;
    d.data[0] = a;
    d.data[1] = b;
    return d;
}

std::vector<unsigned char> MinimalSafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

fs::path WriteSafeTensors(const fs::path& dir, const std::string& name)
{
    fs::create_directories(dir);
    const fs::path path = dir / fs::PathFromString(name);
    const auto st = MinimalSafeTensors();
    std::ofstream out(path, std::ios::binary);
    BOOST_REQUIRE(out);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    BOOST_REQUIRE(out);
    return path;
}

UniValue ParseBridgeBody(const modelnet::BrowserBridgeResponse& br)
{
    BOOST_CHECK_EQUAL(br.content_type, "application/json");
    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_REQUIRE(obj.isObject());
    return obj;
}

} // namespace

BOOST_AUTO_TEST_CASE(comm_follow_collection_quota_not_raised)
{
    BOOST_CHECK(!modelnet::CollectionFollowRaisesQuota());

    modelnet::PreservationPolicy p;
    p.storage_quota_bytes = 80ULL << 30;
    const UniValue json = modelnet::PolicyToJson(p);
    BOOST_CHECK_EQUAL(json["storage_quota_bytes"].getInt<uint64_t>(), p.storage_quota_bytes);
    BOOST_CHECK(json["preservation_propagation"].get_bool() == (p.preserve_rare && p.storage_quota_bytes > 0));

    std::vector<modelnet::Digest48> ids{DigestTag(2), DigestTag(1), DigestTag(1)};
    std::string err;
    BOOST_REQUIRE(modelnet::NormalizeCollection(ids, err));
    BOOST_CHECK_EQUAL(ids.size(), 2U);
    BOOST_CHECK_EQUAL(p.storage_quota_bytes, 80ULL << 30);
    BOOST_CHECK_EQUAL(modelnet::PolicyToJson(p)["storage_quota_bytes"].getInt<uint64_t>(), 80ULL << 30);

    const fs::path tmp = m_args.GetDataDirBase() / "v11-remaining-follow";
    const uint64_t quota = 8 << 20;
    modelnet::ModelCatalog cat{tmp, quota};
    BOOST_CHECK_EQUAL(cat.Policy().storage_quota_bytes, quota);
    BOOST_CHECK_EQUAL(cat.QuotaBytes(), quota);

    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back("collection-follow-1");
    req.pushKV("method", "subscribemodelcollection");
    req.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(cat.Policy().storage_quota_bytes, quota);
    BOOST_CHECK_EQUAL(cat.UsedBytes(), uint64_t{0});
    BOOST_CHECK_EQUAL(modelnet::PolicyToJson(cat.Policy())["storage_quota_bytes"].getInt<uint64_t>(), quota);
    BOOST_CHECK(!modelnet::CollectionFollowRaisesQuota());
    BOOST_REQUIRE(result.exists("impact"));
    BOOST_CHECK(result["impact"]["preview_only"].get_bool());
    BOOST_CHECK(!result["impact"]["quota_raised"].get_bool());
    BOOST_CHECK_EQUAL(result["impact"]["quota_bytes"].getInt<uint64_t>(), quota);
    BOOST_CHECK(result["impact"]["within_budget"].get_bool());
    BOOST_CHECK(!result["impact"]["automatic_preservation"].get_bool());

    modelnet::ModelCatalog zero{tmp / "quota0", /*quota_bytes=*/0};
    BOOST_CHECK_EQUAL(zero.QuotaBytes(), uint64_t{0});
    BOOST_CHECK_EQUAL(zero.Policy().storage_quota_bytes, uint64_t{0});
    BOOST_CHECK_EQUAL(modelnet::PolicyToJson(zero.Policy())["storage_quota_bytes"].getInt<uint64_t>(), uint64_t{0});
    modelnet::CatalogEntry imported;
    BOOST_CHECK(!zero.ImportPath(fs::PathToString(tmp / "missing.safetensors"), /*pin=*/false, imported, err));
    BOOST_CHECK(err.find("0") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(comm_circle_no_onchain_membership)
{
    BOOST_CHECK(!modelnet::CircleHasOnChainMembership());

    const fs::path tmp = m_args.GetDataDirBase() / "v11-remaining-circle";
    modelnet::ModelCatalog cat{tmp, /*quota_bytes=*/1 << 20};
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back("circle-local-1");
    req.pushKV("method", "joinmodelcircle");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_REQUIRE(result.exists("on_chain_membership"));
    BOOST_CHECK(!result["on_chain_membership"].get_bool());
    BOOST_CHECK(!modelnet::CircleHasOnChainMembership());

    UniValue leave(UniValue::VOBJ);
    UniValue leave_params(UniValue::VARR);
    leave_params.push_back("circle-local-1");
    leave.pushKV("method", "leavemodelcircle");
    leave.pushKV("params", leave_params);
    UniValue left;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, leave, left, code, err));
    BOOST_CHECK(!left["on_chain_membership"].get_bool());
}

BOOST_AUTO_TEST_CASE(comm_unsubscribe_stops_new_preservation)
{
    const fs::path tmp = m_args.GetDataDirBase() / "v11-remaining-unsub";
    modelnet::ModelCatalog cat{tmp, /*quota_bytes=*/1 << 20};
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back(std::string(96, 'a'));
    req.pushKV("method", "subscribemodelcollection");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(!result["on_chain_membership"].get_bool());

    UniValue unsub(UniValue::VOBJ);
    UniValue unsub_params(UniValue::VARR);
    unsub_params.push_back(std::string(96, 'a'));
    unsub.pushKV("method", "unsubscribemodelcollection");
    unsub.pushKV("params", unsub_params);
    UniValue left;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, unsub, left, code, err));
    BOOST_CHECK(!left["on_chain_membership"].get_bool());
    BOOST_CHECK_EQUAL(left["automatic_preservation"].get_bool(), false);

    UniValue pol(UniValue::VOBJ);
    UniValue pol_params(UniValue::VARR);
    pol_params.push_back("policy-local-1");
    pol.pushKV("method", "subscribemodelpolicy");
    pol.pushKV("params", pol_params);
    UniValue pol_result;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, pol, pol_result, code, err));
    BOOST_REQUIRE(pol_result.exists("impact"));
    BOOST_CHECK(pol_result["impact"]["preview_only"].get_bool());

    UniValue unpol(UniValue::VOBJ);
    UniValue unpol_params(UniValue::VARR);
    unpol_params.push_back("policy-local-1");
    unpol.pushKV("method", "unsubscribemodelpolicy");
    unpol.pushKV("params", unpol_params);
    UniValue unpol_result;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, unpol, unpol_result, code, err));
    BOOST_CHECK_EQUAL(unpol_result["automatic_preservation"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(getmodel_explicit_paid_quote_no_autospend)
{
    const fs::path tmp = m_args.GetDataDirBase() / "v11-remaining-explicit-paid";
    modelnet::ModelCatalog cat{tmp, /*quota_bytes=*/1 << 20};
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back(std::string(96, 'b'));
    params.push_back("EXPLICIT_PAID");
    req.pushKV("method", "getmodel");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result.exists("quote"));
    BOOST_CHECK_EQUAL(result["funding_rpc"].get_str(), "preparemodelfunding");
    BOOST_CHECK_EQUAL(result["wallet"].get_bool(), false);

    UniValue free_req(UniValue::VOBJ);
    UniValue free_params(UniValue::VARR);
    free_params.push_back(std::string(96, 'b'));
    free_params.push_back("FREE_ONLY");
    free_req.pushKV("method", "getmodel");
    free_req.pushKV("params", free_params);
    UniValue free_result;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, free_req, free_result, code, err));
    BOOST_CHECK_EQUAL(free_result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(delegate_body_refuses_unknown_scopes)
{
    const fs::path tmp = m_args.GetDataDirBase() / "v11-remaining-delegate";
    modelnet::ModelCatalog cat{tmp, /*quota_bytes=*/1 << 20};
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    UniValue body(UniValue::VOBJ);
    body.pushKV("scopes", 1 << 20);
    params.push_back(body);
    req.pushKV("method", "delegatemodelservice");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    UniValue ok_body(UniValue::VOBJ);
    ok_body.pushKV("scopes", 6);
    UniValue ok_params(UniValue::VARR);
    ok_params.push_back(ok_body);
    UniValue ok_req(UniValue::VOBJ);
    ok_req.pushKV("method", "delegatemodelservice");
    ok_req.pushKV("params", ok_params);
    UniValue ok;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, ok_req, ok, code, err));
    BOOST_CHECK(ok["recorded"].get_bool());
    BOOST_CHECK(ok["note"].get_str().find("never a money") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(comm_preserve_obeys_pins_and_quota)
{
    modelnet::PreservationPolicy off;
    off.preserve_rare = false;
    off.storage_quota_bytes = 500ULL << 30;
    BOOST_CHECK(!modelnet::MayPreserveFetch(off, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 1, 10, 200ULL << 30));

    modelnet::PreservationPolicy zero;
    zero.preserve_rare = true;
    zero.storage_quota_bytes = 0;
    BOOST_CHECK(!modelnet::MayPreserveFetch(zero, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 1, 10, 200ULL << 30));

    modelnet::PreservationPolicy ok;
    ok.preserve_rare = true;
    ok.storage_quota_bytes = 500ULL << 30;
    BOOST_CHECK(modelnet::MayPreserveFetch(ok, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 1, 10, 200ULL << 30));
    BOOST_CHECK(!modelnet::MayPreserveFetch(ok, modelnet::AdmissionLevel::BYTES_VERIFIED, true, 1, 10, 200ULL << 30));

    modelnet::EvictItem common, rare, pinned;
    common.seeded = true;
    common.observed_sources = 20;
    rare.seeded = true;
    rare.observed_sources = 1;
    pinned.pinned = true;
    pinned.observed_sources = 1;
    BOOST_CHECK(modelnet::EvictPriority(common) < modelnet::EvictPriority(rare));
    BOOST_CHECK(modelnet::EvictPriority(rare) < modelnet::EvictPriority(pinned));
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(pinned), 1000);

    std::vector<modelnet::EvictItem> items{pinned, rare, common};
    std::sort(items.begin(), items.end(), [](const modelnet::EvictItem& a, const modelnet::EvictItem& b) {
        return modelnet::EvictPriority(a) < modelnet::EvictPriority(b);
    });
    BOOST_CHECK(!items.front().pinned);
    BOOST_CHECK(items.back().pinned);
}

BOOST_AUTO_TEST_CASE(comm_preserve_rare_at_most_one)
{
    modelnet::PreservationPolicy p;
    p.preserve_rare = true;
    p.storage_quota_bytes = 500ULL << 30;

    modelnet::PreserveCandidate a, b, pick;
    a.model_id = DigestTag(1);
    a.bytes = 30;
    a.observed_sources = 1;
    a.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
    b.model_id = DigestTag(2);
    b.bytes = 90;
    b.observed_sources = 1;
    b.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;

    std::set<modelnet::Digest48> local;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, b}, local, 200ULL << 30, p, pick));
    BOOST_CHECK(pick.model_id == a.model_id);
    BOOST_CHECK(!(pick.model_id == b.model_id));

    modelnet::PreserveCandidate pick2;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, b}, local, 200ULL << 30, p, pick2));
    BOOST_CHECK(pick2.model_id == pick.model_id);

    modelnet::PreserveCandidate c = a;
    c.model_id = DigestTag(3);
    c.bytes = a.bytes;
    c.observed_sources = a.observed_sources;
    modelnet::PreserveCandidate equal_pick;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, c}, local, 200ULL << 30, p, equal_pick));
    BOOST_CHECK(equal_pick.model_id == a.model_id);
    BOOST_CHECK(!(equal_pick.model_id == c.model_id));

    local.insert(pick.model_id);
    modelnet::PreserveCandidate second;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, b}, local, 200ULL << 30, p, second));
    BOOST_CHECK(second.model_id == b.model_id);

    modelnet::EvictItem left, right;
    left.observed_sources = 8;
    left.bytes = 100;
    right.observed_sources = 8;
    right.bytes = 100;
    modelnet::EvictItem pinned_high;
    pinned_high.pinned = true;
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(left), modelnet::EvictPriority(right));
    BOOST_CHECK(modelnet::EvictPriority(left) < modelnet::EvictPriority(pinned_high));
}

BOOST_AUTO_TEST_CASE(comm_preserve_rare_jitter)
{
    modelnet::PreservationPolicy p;
    p.preserve_rare = true;
    p.storage_quota_bytes = 500ULL << 30;

    modelnet::PreserveCandidate a, b, c;
    a.model_id = DigestTag(1);
    a.bytes = 30;
    a.observed_sources = 1;
    a.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
    b = a;
    b.model_id = DigestTag(2);
    b.bytes = 90;
    c = a;
    c.model_id = DigestTag(3);
    c.bytes = a.bytes;

    std::set<modelnet::Digest48> local;
    modelnet::PreserveCandidate rare_pick;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, b}, local, 200ULL << 30, p, rare_pick, /*now=*/300));
    BOOST_CHECK(rare_pick.model_id == a.model_id);

    modelnet::PreserveCandidate pick0, pick300;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, c}, local, 200ULL << 30, p, pick0, /*now=*/0));
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, c}, local, 200ULL << 30, p, pick300, /*now=*/300));
    BOOST_CHECK(pick0.model_id == a.model_id);

    BOOST_CHECK(modelnet::PreserveRareJitterScore(a.model_id, 0) !=
                modelnet::PreserveRareJitterScore(a.model_id, 300));
    BOOST_CHECK(modelnet::PreserveRareJitterScore(c.model_id, 0) !=
                modelnet::PreserveRareJitterScore(c.model_id, 300));
    if (pick0.model_id == pick300.model_id) {
        BOOST_CHECK(modelnet::PreserveRareJitterScore(a.model_id, 0) !=
                    modelnet::PreserveRareJitterScore(a.model_id, 300));
    }
}

BOOST_AUTO_TEST_CASE(free_exposure_within_ceiling)
{
    BOOST_CHECK(modelnet::ExposureWithinCeiling(0, 0, 0));
    BOOST_CHECK(modelnet::ExposureWithinCeiling(10, 5, 15));
    BOOST_CHECK(modelnet::ExposureWithinCeiling(10, 5, 16));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(10, 6, 15));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(-1, 0, 100));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(0, -1, 100));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(0, 0, -1));
    BOOST_CHECK(modelnet::ExposureWithinCeiling(modelnet::MAX_MONEY_ATOMS, 0, modelnet::MAX_MONEY_ATOMS));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(modelnet::MAX_MONEY_ATOMS, 1, modelnet::MAX_MONEY_ATOMS));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(modelnet::MAX_MONEY_ATOMS, 1, std::numeric_limits<int64_t>::max()));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(modelnet::MAX_MONEY_ATOMS / 2 + 1, modelnet::MAX_MONEY_ATOMS / 2,
                                                modelnet::MAX_MONEY_ATOMS));
}

BOOST_AUTO_TEST_CASE(comm_third_party_receipt_no_credit)
{
    constexpr int64_t kPiece = 64 * static_cast<int64_t>(modelnet::MIB);
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("p", kPiece, 0));
    BOOST_CHECK_EQUAL(ledger.Effective("p", 0), 0);

    BOOST_CHECK(ledger.Received("p", "art", 0, 0, kPiece, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Effective("p", 0), kPiece);
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("p", kPiece, 0));
    BOOST_CHECK_EQUAL(ledger.Effective("p", 0), kPiece);
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("other", kPiece, 1));
    BOOST_CHECK_EQUAL(ledger.Effective("other", 0), 0);
}

BOOST_AUTO_TEST_CASE(local_open_uri_preview_only)
{
    // btx-open is the CLI dispatcher: DecodeResource + EnvHasPositiveStorageBudget.
    modelnet::Digest48 d = DigestTag(0xab, 0xcd);
    std::string uri, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, d, uri, err));
    modelnet::Resource r;
    BOOST_REQUIRE(modelnet::DecodeResource(uri, r, err));
    BOOST_CHECK_EQUAL(r.Uri(), uri);
    BOOST_CHECK(r.kind == modelnet::ResourceKind::MODEL);
    BOOST_CHECK(r.digest == d);

    EnvRestore env{"BTX_MODEL_STORAGE"};
    uint64_t bytes = 99;
    env.Unset();
    BOOST_CHECK(!modelnet::EnvHasPositiveStorageBudget(bytes, err));
    BOOST_CHECK_EQUAL(bytes, 0);
    env.Set("80GiB");
    BOOST_REQUIRE_MESSAGE(modelnet::EnvHasPositiveStorageBudget(bytes, err), err);
    BOOST_CHECK_EQUAL(bytes, 80ULL << 30);

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + uri.substr(6), br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
    const UniValue obj = ParseBridgeBody(br);
    BOOST_CHECK_EQUAL(obj["canonical"].get_str(), uri);
    BOOST_CHECK(obj.exists("wallet") && !obj["wallet"].get_bool());
    BOOST_CHECK(!obj.exists("inference") || !obj["inference"].get_bool());
    BOOST_CHECK(br.body.find("RUNTIME_OBSERVED") == std::string::npos);
    BOOST_CHECK(obj["kind"].get_str() == "MODEL");
}

BOOST_AUTO_TEST_CASE(local_pickle_rejected_no_remote_inference)
{
    modelnet::QualReport report;
    const unsigned char pickle[] = {0x80, 0x04, 0x95};
    BOOST_CHECK(modelnet::QualifyBytes("model.pkl", Span<const unsigned char>{pickle, sizeof(pickle)}, report) ==
                modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    BOOST_CHECK(report.result != modelnet::QualResult::RUNTIME_OBSERVED);

    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_REQUIRE(caps.exists("remote_inference"));
    BOOST_CHECK(!caps["remote_inference"].get_bool());
}

BOOST_AUTO_TEST_CASE(local_payload_storage_zero_refused)
{
    modelnet::FirstRunConsent zero;
    zero.storage_bytes = 0;
    BOOST_CHECK(!modelnet::AllowPayloadStorage(zero));

    modelnet::FirstRunConsent positive;
    positive.storage_bytes = 1;
    BOOST_CHECK(modelnet::AllowPayloadStorage(positive));
}

BOOST_AUTO_TEST_CASE(iso_qualify_runtime_default_not_run)
{
    const fs::path path = WriteSafeTensors(m_args.GetDataDirBase() / "v11-remaining-iso03", "model.safetensors");
    modelnet::QualReport report;
    modelnet::QualRuntimeOpts opts;
    const auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);
    BOOST_CHECK(!modelnet::ModelCudaQualifyKernelCompiled());
    BOOST_CHECK_EQUAL(std::string{modelnet::QualResultName(qr)}, "NOT_RUN_CUDA_ISOLATION");
}

BOOST_AUTO_TEST_CASE(iso_helper_missing_capabilities_listed)
{
    // Skip live btxd. LocalNetworkInfo (helper_ready=false) still embeds CapabilitiesObject.
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_REQUIRE(caps.exists("remote_inference"));
    BOOST_CHECK(!caps["remote_inference"].get_bool());
    BOOST_REQUIRE(caps.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(caps.exists("uri") && caps["uri"].get_bool());
    BOOST_CHECK(caps.exists("importmodel") && caps["importmodel"].get_bool());
    BOOST_CHECK(caps.exists("listmodels") && caps["listmodels"].get_bool());
    BOOST_CHECK(caps.exists("getmodel_free_only") && caps["getmodel_free_only"].get_bool());
    BOOST_CHECK(caps.exists("cuda_qualification") && caps["cuda_qualification"].get_bool());
}

BOOST_AUTO_TEST_CASE(comm_receipts_unsigned_json_rejected)
{
    const fs::path tmp = m_args.GetDataDirBase() / "v11-remaining-receipt-unsigned";
    modelnet::ModelCatalog cat{tmp, /*quota_bytes=*/1 << 20};
    modelnet::NativeRequest req;
    req.method = "POST";
    req.path = std::string(modelnet::MODEL_HTTP_ROOT) + "ext/receipts";
    req.body = "{\"verified_bytes\":1,\"provider_id\":\"00\"}";
    modelnet::NativeResponse resp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_CHECK(resp.body.find("UNSIGNED") != std::string::npos);

    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("wire", 4096, 0));
}

BOOST_AUTO_TEST_SUITE_END()
