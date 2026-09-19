// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Shared Cognitive Reserve v1.1 native fixtures. Unique BOOST cases live in per-family TUs.

#ifndef BITCOIN_TEST_MODELNET_CR11_TEST_H
#define BITCOIN_TEST_MODELNET_CR11_TEST_H

#include <test/modelnet_hcp_test.h>
#include <modelnet/package_pjson.h>

#include <set>

namespace cr11_test {

inline std::vector<std::string> Scopes()
{
    auto s = hcp_test::AllScopes();
    const char* extra[] = {"entities:admin", "capital:read", "capital:prepare", "capital:approve",
                           "capital:execute", "reserve:read", "holdings:write", "products:read",
                           "products:refer", "reports:create", "reports:read", "exports:read"};
    for (const char* x : extra) s.emplace_back(x);
    return s;
}

inline std::unique_ptr<modelnet::HcpEngine> Lab()
{
    auto e = hcp_test::Lab(true);
    BOOST_REQUIRE(e->Cr11ExtensionEnabled());
    e->Cr11BindPerson("alice-session", "person-a", "committee");
    e->Cr11BindPerson("bob-session", "person-b", "committee");
    e->Cr11BindPerson("carol-session", "person-c", "committee");
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(400);
    e->Cr11SetRemainingAuthority(250);
    return e;
}

inline std::string Tok(modelnet::HcpEngine& e, const std::vector<std::string>& scopes = {})
{
    return hcp_test::Token(e, scopes.empty() ? Scopes() : scopes);
}

inline UniValue Json(const modelnet::HcpHttpResponse& r)
{
    UniValue o;
    o.read(r.body);
    return o;
}

inline std::string ErrCode(const modelnet::HcpHttpResponse& r)
{
    const auto o = Json(r);
    if (o.exists("error") && o["error"].isObject() && o["error"].exists("code")) {
        return o["error"]["code"].get_str();
    }
    return {};
}

inline std::string ObjType(const modelnet::HcpHttpResponse& r)
{
    const auto o = Json(r);
    return o.exists("object_type") ? o["object_type"].get_str() : "";
}

} // namespace cr11_test

#endif
