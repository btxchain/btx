// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/helper.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_AUTO_TEST_SUITE(modelnet_native_http_tests)

BOOST_AUTO_TEST_CASE(truncated_body_is_not_a_request)
{
    for (const std::string header : {"Content-Length", "content-length"}) {
        const std::string prefix = "POST /btx-model/2/ext/pex HTTP/1.1\r\n" + header + ": ";
        modelnet::NativeRequest req;
        std::string err;
        // On timeout or close SslReadHttp can return the bytes received so
        // far. Even valid JSON must not be dispatched before its declared end.
        BOOST_CHECK(!modelnet::ParseHttpRequest(prefix + "20\r\n\r\n{}", req, err));
        BOOST_CHECK_EQUAL(err, "truncated http");
        err.clear();
        BOOST_CHECK(!modelnet::ParseHttpRequest(prefix + "2\r\n\r\n", req, err));
        BOOST_CHECK_EQUAL(err, "truncated http");

        const std::string body = "{\"records\":[]}";
        const std::string headers = prefix + std::to_string(body.size()) + "\r\n\r\n";
        for (size_t length = 0; length < body.size(); ++length) {
            err.clear();
            BOOST_CHECK(!modelnet::ParseHttpRequest(headers + body.substr(0, length), req, err));
            BOOST_CHECK_EQUAL(err, "truncated http");
        }
    }
}

BOOST_AUTO_TEST_CASE(complete_and_empty_bodies_still_parse)
{
    for (const std::string header : {"Content-Length", "content-length"}) {
        const std::string prefix = "POST /btx-model/2/ext/pex HTTP/1.1\r\n" + header + ": ";
        modelnet::NativeRequest req;
        std::string err;
        BOOST_REQUIRE(modelnet::ParseHttpRequest(prefix + "2\r\n\r\n{}", req, err));
        BOOST_CHECK_EQUAL(req.body, "{}");
        BOOST_CHECK_EQUAL(req.method, "POST");
        BOOST_CHECK_EQUAL(req.path, "/btx-model/2/ext/pex");
        BOOST_CHECK(err.empty());
        BOOST_REQUIRE(modelnet::ParseHttpRequest(prefix + "0\r\n\r\n", req, err));
        BOOST_CHECK(req.body.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
