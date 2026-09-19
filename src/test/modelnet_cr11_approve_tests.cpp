// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_approve_tests, BasicTestingSetup)

namespace {

UniValue Decision(const std::string& entity, const std::string& plan, const std::string& gen, const std::string& rule,
                  const std::string& person, const std::string& decision, int64_t sequence, int64_t expires_at)
{
    UniValue d(UniValue::VOBJ);
    d.pushKV("entity", entity);
    d.pushKV("plan", plan);
    d.pushKV("policy_generation", gen);
    d.pushKV("rule", rule);
    d.pushKV("person", person);
    d.pushKV("decision", decision);
    d.pushKV("sequence", sequence);
    d.pushKV("expires_at", expires_at);
    return d;
}

} // namespace

BOOST_AUTO_TEST_CASE(cr11_approve_01_distinct_person_quorum)
{
    UniValue decs(UniValue::VARR);
    decs.push_back(Decision("le", "p", "1", "r", "alice", "APPROVE", 1, 99));
    decs.push_back(Decision("le", "p", "1", "r", "alice", "APPROVE", 2, 99));
    std::string err;
    std::set<std::string> el{"alice", "bob"};
    BOOST_CHECK(!modelnet::Cr11Approved(decs, "le", "p", "1", "r", el, 2, "init", 1, true, true, err));

    auto e = cr11_test::Lab();
    e->Cr11BindPerson("alice-session-2", "person-a", "committee");
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr01");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr01-rule");
    post("/capital/approval-rules", &rule);
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "apr01-req");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "apr01-rule");
    req.pushKV("initiator_person_id", "person-initiator");
    post("/capital/approvals", &req);
    UniValue a1(UniValue::VOBJ);
    a1.pushKV("actor", "alice-session");
    a1.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr01-req/decisions", &a1);
    UniValue a2(UniValue::VOBJ);
    a2.pushKV("actor", "alice-session-2");
    a2.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr01-req/decisions", &a2);
    auto listed = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/apr01-req/decisions", tok));
    BOOST_REQUIRE_EQUAL(listed.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(listed)["items"].size(), 2u);
    BOOST_CHECK_EQUAL(cr11_test::Json(listed)["items"][0]["person"].get_str(), "person-a");
    BOOST_CHECK_EQUAL(cr11_test::Json(listed)["items"][1]["person"].get_str(), "person-a");

    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr01-req/decisions", &bob);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
}

BOOST_AUTO_TEST_CASE(cr11_approve_02_initiator_exclusion)
{
    UniValue decs(UniValue::VARR);
    decs.push_back(Decision("le", "p", "1", "r", "init", "APPROVE", 1, 99));
    std::string err;
    std::set<std::string> el{"init", "bob"};
    BOOST_CHECK(!modelnet::Cr11Approved(decs, "le", "p", "1", "r", el, 1, "init", 1, true, true, err));

    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr02");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr02-rule");
    post("/capital/approval-rules", &rule);
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "apr02-req");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "apr02-rule");
    req.pushKV("initiator_person_id", "person-a");
    post("/capital/approvals", &req);
    UniValue alice(UniValue::VOBJ);
    alice.pushKV("actor", "alice-session");
    alice.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr02-req/decisions", &alice);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr02-req/decisions", &bob);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    UniValue carol(UniValue::VOBJ);
    carol.pushKV("actor", "carol-session");
    carol.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr02-req/decisions", &carol);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
}

BOOST_AUTO_TEST_CASE(cr11_approve_03_changed_allocation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "chg-1");
    body.pushKV("maximum_exposure", "10");
    auto created = post("/capital/allocations", &body);
    const std::string aid = created["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr03-rule");
    post("/capital/approval-rules", &rule);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "apr03-req");
    apr.pushKV("allocation_ref", aid);
    apr.pushKV("rule_ref", "apr03-rule");
    apr.pushKV("initiator_person_id", "person-initiator");
    const std::string alloc_bid = post("/capital/approvals", &apr)["body"]["allocation_body_id"].get_str();
    UniValue alice(UniValue::VOBJ);
    alice.pushKV("actor", "alice-session");
    alice.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr03-req/decisions", &alice);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr03-req/decisions", &bob);

    body.pushKV("maximum_exposure", "11");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CONFLICT);

    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/allocations/" + aid, tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["maximum_exposure"].get_str(), "10");
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/apr03-req", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["allocation_body_id"].get_str(), alloc_bid);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["held_atoms"].get_str(), "10");
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
}

BOOST_AUTO_TEST_CASE(cr11_approve_04_changed_policy)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "pol-a");
    pol.pushKV("lifetime_cap_atoms", "1000000");
    BOOST_CHECK_EQUAL(post("/reserve/policies", &pol)["body"]["generation"].get_str(), "1");
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr04");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr04-rule");
    post("/capital/approval-rules", &rule);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "apr04-req");
    apr.pushKV("allocation_ref", aid);
    apr.pushKV("rule_ref", "apr04-rule");
    apr.pushKV("initiator_person_id", "person-initiator");
    BOOST_CHECK_EQUAL(post("/capital/approvals", &apr)["body"]["policy_generation"].get_str(), "1");
    UniValue alice(UniValue::VOBJ);
    alice.pushKV("actor", "alice-session");
    alice.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr04-req/decisions", &alice);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr04-req/decisions", &bob);

    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies/pol-a/revoke", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["status"].get_str(), "REVOKED");
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/policies/pol-a", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["status"].get_str(), "REVOKED");

    UniValue pol2(UniValue::VOBJ);
    pol2.pushKV("policy_id", "pol-b");
    pol2.pushKV("lifetime_cap_atoms", "5");
    BOOST_CHECK_EQUAL(post("/reserve/policies", &pol2)["body"]["generation"].get_str(), "2");
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/apr04-req", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["policy_generation"].get_str(), "1");
    UniValue later(UniValue::VOBJ);
    later.pushKV("request_id", "apr04-req-v2");
    later.pushKV("allocation_ref", aid);
    later.pushKV("rule_ref", "apr04-rule");
    BOOST_CHECK_EQUAL(post("/capital/approvals", &later)["body"]["policy_generation"].get_str(), "2");

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_approve_05_changed_committee)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr05");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr05-rule");
    post("/capital/approval-rules", &rule);
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "apr05-req");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "apr05-rule");
    req.pushKV("initiator_person_id", "person-initiator");
    post("/capital/approvals", &req);
    UniValue alice(UniValue::VOBJ);
    alice.pushKV("actor", "alice-session");
    alice.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr05-req/decisions", &alice);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr05-req/decisions", &bob);

    e->Cr11ExpirePerson("person-b");
    UniValue late(UniValue::VOBJ);
    late.pushKV("actor", "bob-session");
    late.pushKV("decision", "APPROVE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/apr05-req/decisions", tok, &late));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_SCOPE);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_approve_06_veto)
{
    UniValue decs(UniValue::VARR);
    decs.push_back(Decision("le", "p", "1", "r", "a", "APPROVE", 1, 99));
    decs.push_back(Decision("le", "p", "1", "r", "b", "REJECT", 1, 99));
    std::string err;
    std::set<std::string> el{"a", "b"};
    BOOST_CHECK(!modelnet::Cr11Approved(decs, "le", "p", "1", "r", el, 1, "init", 1, true, true, err));

    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr06");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr06-rule");
    post("/capital/approval-rules", &rule);
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "apr06-req");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "apr06-rule");
    req.pushKV("initiator_person_id", "person-initiator");
    post("/capital/approvals", &req);
    UniValue alice(UniValue::VOBJ);
    alice.pushKV("actor", "alice-session");
    alice.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr06-req/decisions", &alice);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "REJECT");
    post("/capital/approvals/apr06-req/decisions", &bob);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_approve_07_decision_withdrawal)
{
    UniValue decs(UniValue::VARR);
    decs.push_back(Decision("le", "p", "1", "r", "a", "APPROVE", 1, 99));
    decs.push_back(Decision("le", "p", "1", "r", "a", "REJECT", 2, 99));
    std::string err;
    std::set<std::string> el{"a"};
    BOOST_CHECK(!modelnet::Cr11Approved(decs, "le", "p", "1", "r", el, 1, "init", 1, true, true, err));

    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr07");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr07-rule");
    post("/capital/approval-rules", &rule);
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "apr07-req");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "apr07-rule");
    req.pushKV("initiator_person_id", "person-initiator");
    post("/capital/approvals", &req);
    UniValue a1(UniValue::VOBJ);
    a1.pushKV("actor", "alice-session");
    a1.pushKV("decision", "APPROVE");
    a1.pushKV("sequence", static_cast<int64_t>(1));
    post("/capital/approvals/apr07-req/decisions", &a1);
    UniValue a2(UniValue::VOBJ);
    a2.pushKV("actor", "alice-session");
    a2.pushKV("decision", "REJECT");
    a2.pushKV("sequence", static_cast<int64_t>(2));
    post("/capital/approvals/apr07-req/decisions", &a2);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr07-req/decisions", &bob);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    UniValue a3(UniValue::VOBJ);
    a3.pushKV("actor", "alice-session");
    a3.pushKV("decision", "APPROVE");
    a3.pushKV("sequence", static_cast<int64_t>(3));
    post("/capital/approvals/apr07-req/decisions", &a3);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
}

BOOST_AUTO_TEST_CASE(cr11_approve_08_decision_expiration)
{
    UniValue decs(UniValue::VARR);
    decs.push_back(Decision("le", "p", "1", "r", "a", "APPROVE", 1, 0));
    std::string err;
    std::set<std::string> el{"a"};
    BOOST_CHECK(!modelnet::Cr11Approved(decs, "le", "p", "1", "r", el, 1, "init", 10, true, true, err));
    decs = UniValue(UniValue::VARR);
    decs.push_back(Decision("le", "p", "1", "r", "a", "APPROVE", 1, 11));
    decs.push_back(Decision("le", "p", "1", "r", "b", "APPROVE", 1, 11));
    BOOST_CHECK(modelnet::Cr11Approved(decs, "le", "p", "1", "r", std::set<std::string>{"a", "b"}, 2, "init", 10, true,
                                       true, err));
}

BOOST_AUTO_TEST_CASE(cr11_approve_09_two_authorities)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr09");
    alloc.pushKV("maximum_exposure", "10");
    UniValue legs(UniValue::VARR);
    UniValue fin(UniValue::VOBJ);
    fin.pushKV("leg_id", "F1");
    fin.pushKV("kind", "FINANCIAL");
    UniValue loc(UniValue::VOBJ);
    loc.pushKV("leg_id", "L1");
    loc.pushKV("kind", "LOCAL");
    legs.push_back(fin);
    legs.push_back(loc);
    alloc.pushKV("legs", legs);
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "apr09-rule");
    post("/capital/approval-rules", &rule);
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "apr09-req");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "apr09-rule");
    req.pushKV("initiator_person_id", "person-initiator");
    post("/capital/approvals", &req);
    UniValue alice(UniValue::VOBJ);
    alice.pushKV("actor", "alice-session");
    alice.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr09-req/decisions", &alice);
    UniValue bob(UniValue::VOBJ);
    bob.pushKV("actor", "bob-session");
    bob.pushKV("decision", "APPROVE");
    post("/capital/approvals/apr09-req/decisions", &bob);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    BOOST_CHECK(!e->Cr11LastChildIntent().empty());
    BOOST_CHECK(!e->Cr11LastChildHandoff().empty());

    e->RevokeLocalGrant();
    std::string code, err;
    e->AcceptHandoff(
        hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe), code,
        err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    UniValue local;
    BOOST_CHECK(!e->EnsureLocal(hcp_test::kRecipe, local, code));
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
}

BOOST_AUTO_TEST_CASE(cr11_approve_10_role_body_mismatch)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue req(UniValue::VOBJ);
    req.pushKV("initiator_person_id", "person-initiator");
    req.pushKV("request_id", "apr10-req");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &req));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue dec(UniValue::VOBJ);
    dec.pushKV("actor", "alice-session");
    dec.pushKV("person", "person-forged");
    dec.pushKV("decision", "APPROVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/apr10-req/decisions", tok, &dec));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["person"].get_str(), "person-a");
    BOOST_CHECK(cr11_test::Json(r)["body"]["person"].get_str() != "person-forged");

    auto listed = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/apr10-req/decisions", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(listed)["items"][0]["person"].get_str(), "person-a");

    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "apr10");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
