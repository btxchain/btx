// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/session_gate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_session_tests, BasicTestingSetup)

namespace {

std::string Hex96(char digit)
{
    return std::string(96, digit);
}

std::vector<unsigned char> TransportPk(unsigned char fill)
{
    return std::vector<unsigned char>(modelnet::MLDSA44_PK, fill);
}

} // namespace

BOOST_AUTO_TEST_CASE(pq1_profile_or_reject_rejects_classical_names)
{
    std::string err = "stale";
    BOOST_CHECK(modelnet::Pq1ProfileOrReject("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
    BOOST_CHECK(err.empty());

    const char* classical[] = {"x25519", "X25519", "secp256r1", "ecdsa", "rsa", "ecdsa_secp256r1_sha256"};
    for (const char* name : classical) {
        BOOST_CHECK(!modelnet::Pq1ProfileOrReject("TLSv1.3", name, "TLS_AES_256_GCM_SHA384", "mldsa44", err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
        BOOST_CHECK(!modelnet::Pq1ProfileOrReject("TLSv1.3", "mlkem768", name, "mldsa44", err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
        BOOST_CHECK(!modelnet::Pq1ProfileOrReject(name, "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
        BOOST_CHECK(!modelnet::Pq1ProfileOrReject("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", name, err));
        BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    }
}

BOOST_AUTO_TEST_CASE(hostile_conf_rejects_only_a_caller_supplied_classical_token)
{
    std::string err = "X25519";
    BOOST_CHECK(!modelnet::Pq1HostileConfCannotWeaken(err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");

    err = "ECDSA+SHA256";
    BOOST_CHECK(!modelnet::Pq1HostileConfCannotWeaken(err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
}

BOOST_AUTO_TEST_CASE(accept_bound_session_rejects_classical_profile)
{
    const std::vector<unsigned char> pk = TransportPk(0x11);
    const std::string root = Hex96('a');
    std::string err;
    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.3", "x25519", "TLS_AES_256_GCM_SHA384", "mldsa44", root, pk,
                                              "conn-classical", "nonce-classical", 1000, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.2", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", root, pk,
                                              "conn-classical", "nonce-classical", 1001, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "ecdsa_secp256r1_sha256",
                                              root, pk, "conn-classical", "nonce-classical", 1002, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PROFILE");
}

BOOST_AUTO_TEST_CASE(accept_bound_session_rejects_unbound_root)
{
    std::string err;
    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", "", {},
                                              "conn-unbound", "nonce-unbound", 1100, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNBOUND");

    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", Hex96('b'),
                                              {}, "conn-unbound-pk", "nonce-unbound-pk", 1101, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNBOUND");

    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44",
                                              std::string(95, 'c'), TransportPk(0x22), "conn-unbound-hex",
                                              "nonce-unbound-hex", 1102, err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNBOUND");
}

BOOST_AUTO_TEST_CASE(accept_bound_session_rejects_replayed_nonce)
{
    const std::string root = Hex96('d');
    const std::vector<unsigned char> pk = TransportPk(0x33);
    std::string err = "stale";
    BOOST_CHECK(modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", root, pk,
                                             "conn-once", "nonce-once", 2000, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", root, pk,
                                             "conn-once", "nonce-other", 2001, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!modelnet::AcceptBoundSession("TLSv1.3", "mlkem768", "TLS_AES_256_GCM_SHA384", "mldsa44", root, pk,
                                              "conn-once", "nonce-once", 2002, err));
    BOOST_CHECK_EQUAL(err, "BTX035_REPLAY");
}

BOOST_AUTO_TEST_SUITE_END()
