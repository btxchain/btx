// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Regression tests for the PR 157 review findings against Cognitive Reserve
// Layer v1.2. Each case pins review-correct behavior and fails closed against
// the pre-fix engine:
//
//   * Binding GET and revoke must enforce object ownership, not only the
//     requested scope (a scoped caller must not reach another account's id).
//   * Projection GET must not leak another account's object when the optional
//     caller-supplied cursor_tenant query is omitted.
//   * Idempotency-Key handling must authenticate first, scope keys to the
//     account and operation, and return the original outcome on replay.
//   * A monetary aggregate matches valuations to eligible positions and sums
//     them. Unpriced, FX-mismatched, or never-accumulated books stay
//     UNAVAILABLE with a null value. A known zero (matched valuations that
//     sum to "0") remains COMPLETE "0".
//   * Extension schema_digest / operations_digest are SHA-384 of the published
//     schema and operations files (or negotiation is marked unavailable).
//   * Bindings start PROPOSED until owner_consent (create body or /consent).

#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <crypto/sha384.h>
#include <span.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

std::string TokenForAccount(modelnet::HcpEngine& e, const std::string& account)
{
    const std::string ver = "pkce-verifier-" + account + "-pr157";
    const std::string ch = e.LabCreatePkceChallenge(ver);
    const std::string code =
        e.LabAuthorize(account, "client-demo", "https://app.example/cb", "state-" + account, ch, cr12_test::Scopes());
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e.LabToken(code, ver, "https://app.example/cb", e.LabJkt(), "", tok, err));
    return tok["access_token"].get_str();
}

// A cross-account read/mutate must fail closed: neither the object nor a
// success envelope may come back. ENTITY_SCOPE_DENIED and NOT_FOUND are the two
// non-leaking dispositions used elsewhere in the engine.
bool DeniedCrossAccount(const modelnet::HcpHttpResponse& r, const std::string& type)
{
    if (r.status == 200) return false;
    if (cr12_test::ObjType(r) == type) return false;
    const std::string code = cr12_test::ErrCode(r);
    return code == modelnet::HCP_ERR_ENTITY_SCOPE || code == "NOT_FOUND";
}

// Filler digests are a single repeated character (the review flagged 96 x 'a'
// and 96 x 'b').
bool LooksLikeFillerDigest(const std::string& s)
{
    return !s.empty() && s.find_first_not_of(s[0]) == std::string::npos;
}

// Owning tenant stamped on the object, under any of the documented field names.
std::string OwningAccount(const UniValue& body)
{
    for (const char* k : {"account", "tenant", "owner_account", "owner"}) {
        if (body.exists(k) && body[k].isStr()) return body[k].get_str();
    }
    return {};
}

modelnet::HcpHttpRequest PostJson(modelnet::HcpEngine& e, const std::string& path, const std::string& token,
                                  const UniValue& body, const std::string& idem_key = {})
{
    auto req = hcp_test::AuthReq(e, "POST", path, token, &body);
    if (!idem_key.empty()) req.headers["idempotency-key"] = idem_key;
    return req;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_pr157_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_pr157_binding_get_cross_account_denied)
{
    auto e = cr12_test::Lab();
    const auto tok_a = cr12_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const auto tok_b = TokenForAccount(*e, "account-b");

    UniValue created_body(UniValue::VOBJ);
    created_body.pushKV("role", "DISCOVERY");
    auto created = e->Handle(PostJson(*e, "/layer/bindings", tok_a, created_body));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    const std::string id = cr12_test::Body(created)["binding_id"].get_str();
    BOOST_CHECK(!id.empty());

    auto foreign = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, tok_b));
    BOOST_CHECK_MESSAGE(DeniedCrossAccount(foreign, modelnet::HCP_TYPE_SERVICE_BINDING),
                        "account-b must not GET account-demo's binding by id");
    BOOST_CHECK(foreign.body.find("secret_ref") == std::string::npos);

    auto owner = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, tok_a));
    BOOST_REQUIRE_EQUAL(owner.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(owner)["binding_id"].get_str(), id);
}

BOOST_AUTO_TEST_CASE(cr12_pr157_binding_revoke_cross_account_denied)
{
    auto e = cr12_test::Lab();
    const auto tok_a = cr12_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const auto tok_b = TokenForAccount(*e, "account-b");

    UniValue created_body(UniValue::VOBJ);
    created_body.pushKV("role", "DISCOVERY");
    auto created = e->Handle(PostJson(*e, "/layer/bindings", tok_a, created_body));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    const std::string id = cr12_test::Body(created)["binding_id"].get_str();

    auto foreign = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings/" + id + "/revoke", tok_b));
    BOOST_CHECK_MESSAGE(DeniedCrossAccount(foreign, modelnet::HCP_TYPE_SERVICE_BINDING),
                        "account-b must not revoke account-demo's binding by id");

    auto owner = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, tok_a));
    BOOST_REQUIRE_EQUAL(owner.status, 200);
    BOOST_CHECK(cr12_test::Body(owner)["status"].get_str() != "REVOKED");
}

BOOST_AUTO_TEST_CASE(cr12_pr157_projection_get_without_cursor_tenant_no_leak)
{
    auto e = cr12_test::Lab();
    const auto tok_a = cr12_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const auto tok_b = TokenForAccount(*e, "account-b");

    UniValue pos(UniValue::VOBJ);
    pos.pushKV("observation_id", "pos-pr157-a");
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_REQUIRE_EQUAL(e->Handle(PostJson(*e, "/institutional/positions/batches", tok_a, pos)).status, 201);

    UniValue projection(UniValue::VOBJ);
    projection.pushKV("projection_id", "prj-pr157-a");
    projection.pushKV("metric_kind", "AUM");
    auto created = e->Handle(PostJson(*e, "/institutional/projections", tok_a, projection));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    BOOST_CHECK_EQUAL(OwningAccount(cr12_test::Body(created)), "account-demo");

    // Omitting cursor_tenant must not widen the read to another account.
    auto foreign = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/prj-pr157-a", tok_b));
    BOOST_CHECK_MESSAGE(DeniedCrossAccount(foreign, modelnet::HCP_TYPE_PORTFOLIO_PROJECTION),
                        "projection GET without cursor_tenant must not return another account's object");
    BOOST_CHECK(foreign.body.find("pos-pr157-a") == std::string::npos);

    auto owner = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/prj-pr157-a", tok_a));
    BOOST_REQUIRE_EQUAL(owner.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(owner)["projection_id"].get_str(), "prj-pr157-a");
}

BOOST_AUTO_TEST_CASE(cr12_pr157_idempotency_not_occupied_by_unauthenticated)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);

    UniValue unauth_body(UniValue::VOBJ);
    unauth_body.pushKV("role", "DISCOVERY");
    modelnet::HcpHttpRequest unauth;
    unauth.method = "POST";
    unauth.path = "/layer/bindings";
    unauth.headers["authorization"] = "Bearer not-a-real-token";
    unauth.headers["idempotency-key"] = "ik-pr157-unauth";
    std::vector<unsigned char> raw;
    std::string enc_err;
    BOOST_REQUIRE(modelnet::EncodePjson1(unauth_body, raw, enc_err));
    unauth.body.assign(raw.begin(), raw.end());
    BOOST_CHECK_EQUAL(e->Handle(unauth).status, 401);

    UniValue authed_body(UniValue::VOBJ);
    authed_body.pushKV("role", "CUSTODY");
    auto authed = e->Handle(PostJson(*e, "/layer/bindings", tok, authed_body, "ik-pr157-unauth"));
    BOOST_CHECK_MESSAGE(authed.status == 201,
                        "an unauthenticated request must not occupy an Idempotency-Key");
}

BOOST_AUTO_TEST_CASE(cr12_pr157_idempotency_replay_returns_original_outcome)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("role", "DISCOVERY");

    auto first = e->Handle(PostJson(*e, "/layer/bindings", tok, body, "ik-pr157-replay"));
    BOOST_REQUIRE_EQUAL(first.status, 201);
    const std::string first_id = cr12_test::Body(first)["binding_id"].get_str();

    auto replay = e->Handle(PostJson(*e, "/layer/bindings", tok, body, "ik-pr157-replay"));
    BOOST_CHECK(replay.status == 200 || replay.status == 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(replay)["binding_id"].get_str(), first_id);
}

BOOST_AUTO_TEST_CASE(cr12_pr157_idempotency_scoped_per_account)
{
    auto e = cr12_test::Lab();
    const auto tok_a = cr12_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const auto tok_b = TokenForAccount(*e, "account-b");

    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    UniValue b(UniValue::VOBJ);
    b.pushKV("role", "CUSTODY");

    auto ra = e->Handle(PostJson(*e, "/layer/bindings", tok_a, a, "ik-pr157-shared"));
    BOOST_REQUIRE_EQUAL(ra.status, 201);
    auto rb = e->Handle(PostJson(*e, "/layer/bindings", tok_b, b, "ik-pr157-shared"));
    BOOST_CHECK_MESSAGE(rb.status == 201,
                        "Idempotency-Key must be account-scoped: account-b must not collide with account-demo");
    if (rb.status == 201) {
        BOOST_CHECK(cr12_test::Body(ra)["binding_id"].get_str() != cr12_test::Body(rb)["binding_id"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(cr12_pr157_aggregate_nonzero_valuation_not_false_zero)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);

    UniValue pos(UniValue::VOBJ);
    pos.pushKV("observation_id", "pos-pr157-value");
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_REQUIRE_EQUAL(e->Handle(PostJson(*e, "/institutional/positions/batches", tok, pos)).status, 201);

    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "1234.56");
    val.pushKV("purpose", "MARKET_VALUE");
    BOOST_REQUIRE_EQUAL(e->Handle(PostJson(*e, "/institutional/valuations", tok, val)).status, 201);

    UniValue projection(UniValue::VOBJ);
    projection.pushKV("metric_kind", "AUM");
    auto r = e->Handle(PostJson(*e, "/institutional/projections", tok, projection));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    auto body = cr12_test::Body(r);
    BOOST_REQUIRE_EQUAL(body["metric_results"].size(), 1U);
    BOOST_CHECK_EQUAL(body["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(body["metric_results"][0]["status"].get_str(), "COMPLETE");
    BOOST_CHECK_EQUAL(body["metric_results"][0]["value"].get_str(), "1234.56");
    BOOST_CHECK(body["metric_results"][0]["complete"].isTrue());
    BOOST_CHECK(body["metric_results"][0]["aggregation_implemented"].isTrue());
    BOOST_CHECK_EQUAL(body["status"].get_str(), "COMPLETE");
}

BOOST_AUTO_TEST_CASE(cr12_pr157_aggregate_is_account_scoped)
{
    auto e = cr12_test::Lab();
    const auto tok_a = cr12_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const auto tok_b = TokenForAccount(*e, "account-b");

    UniValue pos(UniValue::VOBJ);
    pos.pushKV("observation_id", "pos-pr157-scope");
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_REQUIRE_EQUAL(e->Handle(PostJson(*e, "/institutional/positions/batches", tok_a, pos)).status, 201);

    UniValue projection(UniValue::VOBJ);
    projection.pushKV("metric_kind", "AUM");
    auto r = e->Handle(PostJson(*e, "/institutional/projections", tok_b, projection));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    auto body = cr12_test::Body(r);
    BOOST_CHECK_EQUAL(body["metric_results"][0]["eligible_count"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(body["position_refs"].size(), 0U);
    BOOST_CHECK(body["metric_results"][0]["status"].get_str() != "COMPLETE");
    BOOST_CHECK(body["metric_results"][0]["complete"].isFalse());
    BOOST_CHECK(body["metric_results"][0]["value"].isNull());
}

BOOST_AUTO_TEST_CASE(cr12_pr157_extension_digests_not_placeholders)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_LAYER_EXTENSION);
    auto body = cr12_test::Body(r);

    const std::string schema =
        body.exists("schema_digest") && body["schema_digest"].isStr() ? body["schema_digest"].get_str() : std::string{};
    const std::string ops = body.exists("operations_digest") && body["operations_digest"].isStr()
                                ? body["operations_digest"].get_str()
                                : std::string{};
    BOOST_CHECK_MESSAGE(schema != std::string(96, 'a'),
                        "schema_digest must be a computed digest or negotiation must be marked unavailable");
    BOOST_CHECK_MESSAGE(ops != std::string(96, 'b'),
                        "operations_digest must be a computed digest or negotiation must be marked unavailable");
    BOOST_CHECK(!LooksLikeFillerDigest(schema));
    BOOST_CHECK(!LooksLikeFillerDigest(ops));
    BOOST_CHECK(!modelnet::HcpSha384DigestUsable(std::string(96, 'a')));
    BOOST_CHECK(!modelnet::HcpSha384DigestUsable(std::string(96, 'b')));

    const bool negotiated = body.exists("negotiated") && body["negotiated"].isTrue();
    if (negotiated) {
        BOOST_CHECK(IsHex(schema));
        BOOST_CHECK(IsHex(ops));
        BOOST_CHECK_EQUAL(schema.size(), 96U);
        BOOST_CHECK_EQUAL(ops.size(), 96U);
        BOOST_CHECK(schema != ops);
        BOOST_CHECK(modelnet::HcpSha384DigestUsable(schema));
        BOOST_CHECK(modelnet::HcpSha384DigestUsable(ops));
    } else {
        BOOST_CHECK(schema.empty());
        BOOST_CHECK(ops.empty());
        BOOST_CHECK(body.exists("digests_available") && body["digests_available"].isFalse());
        BOOST_CHECK(body.exists("negotiation_unavailable_reason"));
    }

#ifdef MODELNET_CRL12_SCHEMA_PATH
    if (negotiated) {
        std::ifstream in(MODELNET_CRL12_SCHEMA_PATH, std::ios::binary);
        BOOST_REQUIRE(in.good());
        const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        unsigned char d[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
        hasher.Finalize(d);
        BOOST_CHECK_EQUAL(schema, HexStr(Span<const unsigned char>{d, sizeof(d)}));
    }
#endif
#ifdef MODELNET_CRL12_OPERATIONS_PATH
    if (negotiated) {
        std::ifstream in(MODELNET_CRL12_OPERATIONS_PATH, std::ios::binary);
        BOOST_REQUIRE(in.good());
        const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        unsigned char d[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
        hasher.Finalize(d);
        BOOST_CHECK_EQUAL(ops, HexStr(Span<const unsigned char>{d, sizeof(d)}));
    }
#endif
}

BOOST_AUTO_TEST_CASE(cr12_pr157_aggregate_empty_book_not_fake_complete_zero)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);
    UniValue projection(UniValue::VOBJ);
    projection.pushKV("metric_kind", "AUM");
    auto r = e->Handle(PostJson(*e, "/institutional/projections", tok, projection));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    auto body = cr12_test::Body(r);
    BOOST_REQUIRE_EQUAL(body["metric_results"].size(), 1U);
    BOOST_CHECK_EQUAL(body["metric_results"][0]["eligible_count"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(body["metric_results"][0]["status"].get_str(), "UNAVAILABLE");
    BOOST_CHECK(body["metric_results"][0]["complete"].isFalse());
    BOOST_CHECK(body["metric_results"][0]["value"].isNull());
    BOOST_CHECK(body["status"].get_str() != "COMPLETE");
}

BOOST_AUTO_TEST_CASE(cr12_pr157_binding_lifecycle_is_explicit)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("role", "DISCOVERY");

    auto r = e->Handle(PostJson(*e, "/layer/bindings", tok, body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    auto b = cr12_test::Body(r);
    BOOST_CHECK_MESSAGE(b.exists("lifecycle") && b["lifecycle"].isStr(),
                        "a service binding must expose an explicit lifecycle field");
    const std::string lifecycle =
        b.exists("lifecycle") && b["lifecycle"].isStr() ? b["lifecycle"].get_str() : std::string{};
    BOOST_CHECK_EQUAL(b["status"].get_str(), "PROPOSED");
    BOOST_CHECK_EQUAL(lifecycle, "PROPOSED");
    BOOST_CHECK(b.exists("consent_required") && b["consent_required"].isTrue());
    BOOST_CHECK(!(b.exists("owner_consent") && b["owner_consent"].isTrue()));

    const std::string id = b["binding_id"].get_str();
    UniValue consent(UniValue::VOBJ);
    consent.pushKV("owner_consent", true);
    auto act = e->Handle(PostJson(*e, "/layer/bindings/" + id + "/consent", tok, consent));
    BOOST_REQUIRE_EQUAL(act.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(act)["status"].get_str(), "ACTIVE");
    BOOST_CHECK_EQUAL(cr12_test::Body(act)["lifecycle"].get_str(), "CONSENTED");
    BOOST_CHECK(cr12_test::Body(act)["owner_consent"].isTrue());

    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, tok));
    BOOST_REQUIRE_EQUAL(got.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["lifecycle"].get_str(), "CONSENTED");
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["status"].get_str(), "ACTIVE");
}

BOOST_AUTO_TEST_CASE(cr12_pr157_scenario_does_not_fabricate_complete_zero)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);
    UniValue scn(UniValue::VOBJ);
    scn.pushKV("scenario_id", "scn-pr157");
    scn.pushKV("kind", "RESERVE_PRICE");
    auto r = e->Handle(PostJson(*e, "/institutional/scenarios", tok, scn));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    auto body = cr12_test::Body(r);
    BOOST_CHECK(body["status"].get_str() != "COMPLETE");
    if (body.exists("financial_change") && body["financial_change"].isObject() &&
        body["financial_change"].exists("delta") && body["financial_change"]["delta"].isStr()) {
        BOOST_CHECK(body["financial_change"]["delta"].get_str() != "0");
    }
}

BOOST_AUTO_TEST_CASE(cr12_pr157_scenario_applies_deterministic_shock)
{
    auto e = cr12_test::Lab();
    const auto tok = cr12_test::Tok(*e);
    UniValue scn(UniValue::VOBJ);
    scn.pushKV("scenario_id", "scn-pr157-shock");
    scn.pushKV("kind", "RESERVE_PRICE");
    scn.pushKV("base_atoms", "1000");
    scn.pushKV("shock_bps", -500);
    auto r = e->Handle(PostJson(*e, "/institutional/scenarios", tok, scn));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    auto body = cr12_test::Body(r);
    BOOST_CHECK_EQUAL(body["status"].get_str(), "COMPLETE");
    BOOST_REQUIRE(body.exists("financial_change") && body["financial_change"].isObject());
    BOOST_CHECK(body["financial_change"]["computed"].isTrue());
    BOOST_CHECK_EQUAL(body["financial_change"]["delta"].get_str(), "-50");
}

BOOST_AUTO_TEST_SUITE_END()
