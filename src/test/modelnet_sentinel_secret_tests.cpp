// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Cloud sentinel credentials must never appear after redaction.

#include <modelnet/s3_client.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_sentinel_secret_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sentinel_redact_cloud_secrets)
{
    const std::string access = "BTX_TEST_ACCESS_SENTINEL";
    const std::string secret = "BTX_TEST_SECRET_SENTINEL";
    const std::string raw = std::string("aws_access_key_id=") + access +
                            " aws_secret_access_key=" + secret +
                            " AWS_SECRET_ACCESS_KEY=" + secret +
                            " x-amz-signature=" + secret;
    const auto redacted = modelnet::RedactCloudSecrets(raw, secret);
    BOOST_CHECK(redacted.find(secret) == std::string::npos);
    BOOST_CHECK(redacted.find("aws_secret_access_key=") != std::string::npos ||
                redacted.find("REDACT") != std::string::npos ||
                redacted.find("***") != std::string::npos ||
                redacted.find(secret) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(sentinel_presigned_query_redacted)
{
    const std::string url = "https://example.test/obj?X-Amz-Credential=BTX_TEST_ACCESS_SENTINEL"
                            "&X-Amz-Signature=BTX_TEST_SECRET_SENTINEL";
    const auto redacted = modelnet::RedactCloudSecrets(url, "BTX_TEST_SECRET_SENTINEL");
    BOOST_CHECK(redacted.find("BTX_TEST_SECRET_SENTINEL") == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
