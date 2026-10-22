// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Review notes on this branch (Jpp-matata, 2026-10-14): the in-process TLS
// identity must carry the X.509v3 extensions `openssl req -x509` adds.

#include <modelnet/helper.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <tinyformat.h>
#include <util/fs.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <memory>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_ainode_notes_tests, BasicTestingSetup)

namespace {

std::string Hex(const ASN1_OCTET_STRING* s)
{
    if (!s) return "";
    std::string out;
    for (int i = 0; i < ASN1_STRING_length(s); ++i) out += strprintf("%02x", ASN1_STRING_get0_data(s)[i]);
    return out;
}


} // namespace

BOOST_AUTO_TEST_CASE(tls_identity_has_the_cli_extensions)
{
    const fs::path dir = m_path_root / "tls";
    const fs::path cert = dir / "cert.pem", key = dir / "key.pem";
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureMlDsaTlsFiles(cert, key, err), err);

    FILE* f = std::fopen(fs::PathToString(cert).c_str(), "r");
    BOOST_REQUIRE(f);
    std::unique_ptr<X509, decltype(&X509_free)> x(PEM_read_X509(f, nullptr, nullptr, nullptr), X509_free);
    std::fclose(f);
    BOOST_REQUIRE(x);

    BOOST_CHECK_EQUAL(X509_get_version(x.get()), X509_VERSION_3);
    // Subject and authority key identifiers, the same key id (self-signed).
    const std::string skid = Hex(X509_get0_subject_key_id(x.get()));
    BOOST_CHECK_EQUAL(skid.size(), 40U);
    BOOST_CHECK_EQUAL(Hex(X509_get0_authority_key_id(x.get())), skid);
    // A critical basicConstraints with CA:TRUE.
    const int bc = X509_get_ext_by_NID(x.get(), NID_basic_constraints, -1);
    BOOST_REQUIRE(bc >= 0);
    BOOST_CHECK(X509_EXTENSION_get_critical(X509_get_ext(x.get(), bc)) == 1);
    BOOST_CHECK(X509_get_extension_flags(x.get()) & EXFLAG_CA);
    // Still a valid self-signature, CN=btx-modeld.
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pub(X509_get_pubkey(x.get()), EVP_PKEY_free);
    BOOST_CHECK_EQUAL(X509_verify(x.get(), pub.get()), 1);
    char cn[64] = {};
    X509_NAME_get_text_by_NID(X509_get_subject_name(x.get()), NID_commonName, cn, sizeof(cn));
    BOOST_CHECK_EQUAL(std::string(cn), "btx-modeld");
}


BOOST_AUTO_TEST_SUITE_END()
