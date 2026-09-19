// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Shared Cognitive Reserve Layer v1.2 native fixtures.

#ifndef BITCOIN_TEST_MODELNET_CR12_TEST_H
#define BITCOIN_TEST_MODELNET_CR12_TEST_H

#include <test/modelnet_cr11_test.h>

namespace cr12_test {

inline std::vector<std::string> Scopes()
{
    auto s = cr11_test::Scopes();
    const char* extra[] = {"layer:admin", "bindings:admin", "bindings:read", "assets:write", "assets:read",
                            "positions:write", "positions:read", "valuations:write", "valuations:read",
                            "exposures:write", "exposures:read", "metrics:admin", "metrics:read",
                            "projections:create", "projections:read", "exports:create", "exports:read",
                            "imports:write", "imports:read", "reconciliation:read", "reconciliation:write",
                            "scenarios:create", "scenarios:read", "jobs:read", "jobs:cancel"};
    for (const char* x : extra) s.emplace_back(x);
    return s;
}

inline std::vector<std::string> AnalyticsScopes()
{
    return {"catalog:read", "capital:read", "capital:prepare", "projections:read", "metrics:read",
            "assets:read", "positions:read"};
}

inline std::unique_ptr<modelnet::HcpEngine> Lab()
{
    auto e = cr11_test::Lab();
    BOOST_REQUIRE(e->Crl12ExtensionEnabled());
    return e;
}

inline std::string Tok(modelnet::HcpEngine& e, const std::vector<std::string>& scopes = {})
{
    return hcp_test::Token(e, scopes.empty() ? Scopes() : scopes);
}

using cr11_test::Json;
inline std::string ErrCode(const modelnet::HcpHttpResponse& r) { return cr11_test::ErrCode(r); }
inline std::string ObjType(const modelnet::HcpHttpResponse& r) { return cr11_test::ObjType(r); }

inline UniValue Body(const modelnet::HcpHttpResponse& r)
{
    const auto o = Json(r);
    return o.exists("body") ? o["body"] : o;
}

} // namespace cr12_test

#endif
