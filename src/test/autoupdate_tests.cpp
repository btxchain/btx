// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/autoupdate.h>

#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <key.h>
#include <pqkey.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {

std::vector<unsigned char> Bytes(std::string_view text)
{
    return {text.begin(), text.end()};
}

std::string SHA256Hex(const std::vector<unsigned char>& bytes)
{
    uint256 digest;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest.begin());
    return HexStr(Span<const unsigned char>{digest.begin(), digest.size()});
}

struct FakeFetcher final : node::AutoUpdateFetcher {
    struct Reply {
        bool ok{true};
        int status{200};
        std::string final_url;
        std::vector<unsigned char> body;
        std::string error;
    };

    std::map<std::string, Reply> replies;
    std::vector<std::string> calls;

    node::AutoUpdateFetchResult Fetch(std::string_view url, size_t) override
    {
        calls.emplace_back(url);
        const auto it = replies.find(std::string{url});
        if (it == replies.end()) return {.ok = false, .error = "not found"};
        const auto& reply = it->second;
        return {
            .ok = reply.ok,
            .status = reply.status,
            .final_url = reply.final_url.empty() ? std::string{url} : reply.final_url,
            .body = reply.body,
            .error = reply.error,
        };
    }
};

struct FakeVerifier final : node::AutoUpdateSignatureVerifier {
    bool valid{true};
    int calls{0};
    std::vector<unsigned char> last_message;
    std::vector<unsigned char> last_signature;

    bool Verify(std::string_view, const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) override
    {
        ++calls;
        last_message = message;
        last_signature = signature;
        return valid;
    }
};

struct RecordingRunner final : node::AutoUpdateCommandRunner {
    int calls{0};
    node::AutoUpdateManifest last_manifest;
    std::vector<unsigned char> last_script;

    bool LaunchInstaller(const node::AutoUpdateConfig&,
                         const node::AutoUpdateManifest& manifest,
                         const std::vector<unsigned char>& script) override
    {
        ++calls;
        last_manifest = manifest;
        last_script = script;
        return true;
    }
};

node::AutoUpdateConfig TestConfig()
{
    node::AutoUpdateConfig config;
    config.enabled = true;
    config.seamless = true;
    config.dev_origin = true;
    config.manifest_url = "http://updates.test/version.txt";
    config.trusted_origin = "http://updates.test";
    config.release_pubkey = "test-pubkey";
    config.telemetry = false;
    return config;
}

std::string Manifest(std::string version,
                     std::string script_url,
                     std::string sig_url,
                     std::string script_sha256 = {})
{
    std::string hash_field;
    if (!script_sha256.empty()) {
        hash_field = strprintf(R"(,"script_sha256":"%s")", script_sha256);
    }
    return strprintf(
        R"({"version":"%s","script_url":"%s","sig_url":"%s"%s})",
        version,
        script_url,
        sig_url,
        hash_field);
}

struct Harness {
    node::AutoUpdateConfig config{TestConfig()};
    FakeFetcher fetcher;
    FakeVerifier verifier;
    RecordingRunner runner;
    std::vector<unsigned char> script{Bytes("#!/bin/sh\nexit 0\n")};
    std::string script_hash{SHA256Hex(script)};

    void AddManifest(std::string version = "99.0.0",
                     std::string script_url = "http://updates.test/install.sh",
                     std::string sig_url = "http://updates.test/version.txt.sig",
                     std::string hash = {})
    {
        if (hash.empty()) hash = script_hash;
        fetcher.replies[config.manifest_url] = {
            .final_url = config.manifest_url,
            .body = Bytes(Manifest(std::move(version), std::move(script_url), std::move(sig_url), std::move(hash))),
        };
    }

    void AddSignature(std::string sig_url = "http://updates.test/version.txt.sig")
    {
        fetcher.replies[std::move(sig_url)] = {.body = Bytes("signature")};
    }

    void AddScript(std::string script_url = "http://updates.test/install.sh")
    {
        fetcher.replies[std::move(script_url)] = {.body = script};
    }

    node::AutoUpdateCheckResult Run()
    {
        return node::CheckForAutoUpdate(config, fetcher, verifier, runner);
    }

    node::AutoUpdateCheckResult RunWith(node::AutoUpdateSignatureVerifier& verifier_in)
    {
        return node::CheckForAutoUpdate(config, fetcher, verifier_in, runner);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(autoupdate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(url_origin_matching_is_strict)
{
    BOOST_CHECK(node::AutoUpdateUrlMatchesTrustedOrigin("https://btx.dev/version.txt", "https://btx.dev", false));
    BOOST_CHECK(!node::AutoUpdateUrlMatchesTrustedOrigin("http://btx.dev/version.txt", "https://btx.dev", false));
    BOOST_CHECK(!node::AutoUpdateUrlMatchesTrustedOrigin("https://evil.example/version.txt", "https://btx.dev", false));
    BOOST_CHECK(!node::AutoUpdateUrlMatchesTrustedOrigin("https://btx.dev.evil.example/version.txt", "https://btx.dev", false));
    BOOST_CHECK(node::AutoUpdateUrlMatchesTrustedOrigin("http://127.0.0.1:8080/version.txt", "http://127.0.0.1:8080", true));
}

BOOST_AUTO_TEST_CASE(version_comparison_uses_client_version)
{
    BOOST_CHECK_EQUAL(node::CompareAutoUpdateVersion("99.0.0"), 1);
    BOOST_CHECK_EQUAL(node::CompareAutoUpdateVersion("0.32.4"), 0);
    BOOST_CHECK_EQUAL(node::CompareAutoUpdateVersion("v0.32.3"), -1);
    BOOST_CHECK_EQUAL(node::CompareAutoUpdateVersion("not-a-version"), 0);
}

BOOST_AUTO_TEST_CASE(disabled_skips_network_and_runner)
{
    Harness h;
    h.config.enabled = false;
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::DISABLED);
    BOOST_CHECK(h.fetcher.calls.empty());
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(missing_signature_is_silent_noop)
{
    Harness h;
    h.AddManifest();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::UNSIGNED_MANIFEST);
    BOOST_CHECK_EQUAL(h.verifier.calls, 0);
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(bad_signature_is_silent_noop)
{
    Harness h;
    h.AddManifest();
    h.AddSignature();
    h.AddScript();
    h.verifier.valid = false;
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::BAD_SIGNATURE);
    BOOST_CHECK_EQUAL(h.verifier.calls, 1);
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(wrong_origin_script_rejected_after_signature)
{
    Harness h;
    h.AddManifest("99.0.0", "https://evil.example/install.sh");
    h.AddSignature();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::SCRIPT_ORIGIN_REJECTED);
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(same_version_does_not_launch)
{
    Harness h;
    h.AddManifest("0.32.4");
    h.AddSignature();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::NOT_NEWER);
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(script_hash_is_required_before_launch)
{
    Harness h;
    h.AddManifest("99.0.0", "http://updates.test/install.sh", "http://updates.test/version.txt.sig", /*hash=*/"");
    h.fetcher.replies[h.config.manifest_url].body = Bytes(Manifest("99.0.0", "http://updates.test/install.sh", "http://updates.test/version.txt.sig"));
    h.AddSignature();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::SCRIPT_HASH_MISSING);
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(script_hash_mismatch_rejects)
{
    Harness h;
    h.AddManifest("99.0.0", "http://updates.test/install.sh", "http://updates.test/version.txt.sig", std::string(64, '0'));
    h.AddSignature();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::SCRIPT_HASH_MISMATCH);
    BOOST_CHECK_EQUAL(h.runner.calls, 0);
}

BOOST_AUTO_TEST_CASE(valid_signed_newer_manifest_launches)
{
    Harness h;
    h.AddManifest();
    h.AddSignature();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::LAUNCHED);
    BOOST_CHECK_EQUAL(h.verifier.calls, 1);
    BOOST_REQUIRE_EQUAL(h.runner.calls, 1);
    BOOST_CHECK_EQUAL(h.runner.last_manifest.version, "99.0.0");
    BOOST_CHECK_EQUAL(h.runner.last_manifest.script_url, "http://updates.test/install.sh");
    BOOST_CHECK(h.runner.last_script == h.script);
}

BOOST_AUTO_TEST_CASE(telemetry_query_is_appended_to_update_fetches)
{
    Harness h;
    h.config.telemetry = true;
    h.config.telemetry_client_id = "123e4567-e89b-42d3-a456-426614174000";

    const std::string sig_url = "http://updates.test/version.txt.sig?kind=manifest";
    const std::string script_url = "http://updates.test/install.sh";
    h.fetcher.replies[node::AutoUpdateTrackedUrl(h.config.manifest_url, h.config)] = {
        .body = Bytes(Manifest("99.0.0", script_url, sig_url, h.script_hash)),
    };
    h.fetcher.replies[node::AutoUpdateTrackedUrl(sig_url, h.config)] = {.body = Bytes("signature")};
    h.fetcher.replies[node::AutoUpdateTrackedUrl(script_url, h.config)] = {.body = h.script};

    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::LAUNCHED);
    BOOST_REQUIRE_EQUAL(h.fetcher.calls.size(), 3);
    for (const auto& call : h.fetcher.calls) {
        BOOST_CHECK(call.find("btx_au=1") != std::string::npos);
        BOOST_CHECK(call.find("btx_version=") != std::string::npos);
        BOOST_CHECK(call.find("btx_platform=") != std::string::npos);
        BOOST_CHECK(call.find("btx_arch=") != std::string::npos);
        BOOST_CHECK(call.find("btx_client_id=123e4567-e89b-42d3-a456-426614174000") != std::string::npos);
    }
    BOOST_CHECK(h.fetcher.calls[1].find("kind=manifest&btx_au=1") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rollout_gate_defers_when_cohort_outside_percentage)
{
    Harness h;
    h.config.rollout_cohort = 50; // apply iff cohort < rollout_percent
    const std::string body = strprintf(
        R"({"version":"99.0.0","script_url":"http://updates.test/install.sh","sig_url":"http://updates.test/version.txt.sig","script_sha256":"%s","rollout_percent":50})",
        h.script_hash);
    h.fetcher.replies[h.config.manifest_url] = {.final_url = h.config.manifest_url, .body = Bytes(body)};
    h.AddSignature();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::ROLLOUT_DEFERRED);
    BOOST_CHECK_EQUAL(h.runner.calls, 0); // installer never fetched or launched
}

BOOST_AUTO_TEST_CASE(rollout_gate_launches_when_cohort_within_percentage)
{
    Harness h;
    h.config.rollout_cohort = 50;
    const std::string body = strprintf(
        R"({"version":"99.0.0","script_url":"http://updates.test/install.sh","sig_url":"http://updates.test/version.txt.sig","script_sha256":"%s","rollout_percent":51})",
        h.script_hash);
    h.fetcher.replies[h.config.manifest_url] = {.final_url = h.config.manifest_url, .body = Bytes(body)};
    h.AddSignature();
    h.AddScript();
    const auto result = h.Run();
    BOOST_CHECK(result.status == node::AutoUpdateStatus::LAUNCHED);
    BOOST_CHECK_EQUAL(h.runner.calls, 1);
}

BOOST_AUTO_TEST_CASE(rollout_absent_field_means_full_rollout)
{
    Harness h;
    h.config.rollout_cohort = 99; // highest possible cohort
    h.AddManifest();               // no rollout_percent -> defaults to 100 -> 99 < 100 -> launches
    h.AddSignature();
    h.AddScript();
    BOOST_CHECK(h.Run().status == node::AutoUpdateStatus::LAUNCHED);
}

BOOST_AUTO_TEST_CASE(rollout_cohort_is_stable_bounded_and_overridable)
{
    node::AutoUpdateConfig c;
    c.datadir = fs::path("/var/lib/btxd-node-A");
    const int a1 = node::AutoUpdateRolloutCohort(c);
    const int a2 = node::AutoUpdateRolloutCohort(c);
    BOOST_CHECK_EQUAL(a1, a2); // stable across calls (same datadir)
    BOOST_CHECK(a1 >= 0 && a1 < 100);

    c.datadir = fs::path("/var/lib/btxd-node-B");
    const int b = node::AutoUpdateRolloutCohort(c);
    BOOST_CHECK(b >= 0 && b < 100);

    c.rollout_cohort = 250; // explicit override wins and is clamped into range
    BOOST_CHECK_EQUAL(node::AutoUpdateRolloutCohort(c), 99);
}

BOOST_AUTO_TEST_CASE(real_signature_path_accepts_supported_encodings_and_rejects_tamper)
{
    CKey signing_key;
    signing_key.MakeNewKey(/*fCompressed=*/true);

    auto run_with_signature_body = [&](std::vector<unsigned char> signature_body) {
        Harness h;
        h.config.release_pubkey = HexStr(signing_key.GetPubKey());
        h.AddManifest();
        h.AddScript();

        uint256 digest;
        const auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        CSHA256().Write(manifest_body.data(), manifest_body.size()).Finalize(digest.begin());
        std::vector<unsigned char> signature;
        BOOST_REQUIRE(signing_key.Sign(digest, signature));

        if (signature_body.empty()) signature_body = signature;
        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = std::move(signature_body)};

        auto verifier = node::MakeAutoUpdateSignatureVerifier("secp256k1");
        const auto result = h.RunWith(*verifier);
        BOOST_CHECK(result.status == node::AutoUpdateStatus::LAUNCHED);
        BOOST_CHECK_EQUAL(h.runner.calls, 1);
    };

    run_with_signature_body({});

    {
        Harness h;
        h.config.release_pubkey = HexStr(signing_key.GetPubKey());
        h.AddManifest();
        h.AddScript();

        uint256 digest;
        const auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        CSHA256().Write(manifest_body.data(), manifest_body.size()).Finalize(digest.begin());
        std::vector<unsigned char> signature;
        BOOST_REQUIRE(signing_key.Sign(digest, signature));

        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = Bytes(HexStr(signature))};
        auto verifier = node::MakeAutoUpdateSignatureVerifier("secp256k1");
        BOOST_CHECK(h.RunWith(*verifier).status == node::AutoUpdateStatus::LAUNCHED);
    }

    {
        Harness h;
        h.config.release_pubkey = HexStr(signing_key.GetPubKey());
        h.AddManifest();
        h.AddScript();

        uint256 digest;
        const auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        CSHA256().Write(manifest_body.data(), manifest_body.size()).Finalize(digest.begin());
        std::vector<unsigned char> signature;
        BOOST_REQUIRE(signing_key.Sign(digest, signature));

        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = Bytes(EncodeBase64(signature))};
        auto verifier = node::MakeAutoUpdateSignatureVerifier("secp256k1");
        BOOST_CHECK(h.RunWith(*verifier).status == node::AutoUpdateStatus::LAUNCHED);
    }

    {
        Harness h;
        h.config.release_pubkey = HexStr(signing_key.GetPubKey());
        h.AddManifest();
        h.AddScript();

        uint256 digest;
        auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        CSHA256().Write(manifest_body.data(), manifest_body.size()).Finalize(digest.begin());
        std::vector<unsigned char> signature;
        BOOST_REQUIRE(signing_key.Sign(digest, signature));
        manifest_body.push_back(' ');

        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = signature};
        auto verifier = node::MakeAutoUpdateSignatureVerifier("secp256k1");
        BOOST_CHECK(h.RunWith(*verifier).status == node::AutoUpdateStatus::BAD_SIGNATURE);
        BOOST_CHECK_EQUAL(h.runner.calls, 0);
    }
}

BOOST_AUTO_TEST_CASE(pq_ml_dsa_signature_path_launches_and_rejects_tamper)
{
    CPQKey signing_key;
    signing_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(signing_key.IsValid());
    const std::vector<unsigned char> pubkey = signing_key.GetPubKey();

    const auto sign_manifest = [&](const std::vector<unsigned char>& manifest_body) {
        uint256 digest;
        CSHA256().Write(manifest_body.data(), manifest_body.size()).Finalize(digest.begin());
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(signing_key.Sign(digest, sig, /*slhdsa_fips205=*/true));
        return sig;
    };

    // A genuine ML-DSA-44 release signature over the manifest launches the installer.
    {
        Harness h;
        h.config.release_pubkey = HexStr(pubkey);
        h.config.release_pubkey_algo = "ml-dsa-44";
        h.AddManifest();
        h.AddScript();
        const auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = sign_manifest(manifest_body)};
        auto verifier = node::MakeAutoUpdateSignatureVerifier("ml-dsa-44");
        BOOST_REQUIRE(verifier != nullptr);
        BOOST_CHECK(h.RunWith(*verifier).status == node::AutoUpdateStatus::LAUNCHED);
        BOOST_CHECK_EQUAL(h.runner.calls, 1);
    }

    // Tampering with the manifest after signing is rejected (no launch).
    {
        Harness h;
        h.config.release_pubkey = HexStr(pubkey);
        h.config.release_pubkey_algo = "ml-dsa-44";
        h.AddManifest();
        h.AddScript();
        auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        auto sig = sign_manifest(manifest_body);
        manifest_body.push_back(' ');
        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = std::move(sig)};
        auto verifier = node::MakeAutoUpdateSignatureVerifier("ml-dsa-44");
        BOOST_CHECK(h.RunWith(*verifier).status == node::AutoUpdateStatus::BAD_SIGNATURE);
        BOOST_CHECK_EQUAL(h.runner.calls, 0);
    }

    // A classical secp256k1 signature must NOT verify under the PQ scheme (and vice versa),
    // and an unknown scheme yields no verifier.
    {
        Harness h;
        h.config.release_pubkey = HexStr(pubkey);
        h.AddManifest();
        h.AddScript();
        const auto& manifest_body = h.fetcher.replies[h.config.manifest_url].body;
        h.fetcher.replies["http://updates.test/version.txt.sig"] = {.body = sign_manifest(manifest_body)};
        auto classical = node::MakeAutoUpdateSignatureVerifier("secp256k1");
        BOOST_REQUIRE(classical != nullptr);
        BOOST_CHECK(h.RunWith(*classical).status == node::AutoUpdateStatus::BAD_SIGNATURE);
    }
    BOOST_CHECK(node::MakeAutoUpdateSignatureVerifier("not-a-scheme") == nullptr);
}

// End-to-end artifact generator: when BTX_AUTOUPDATE_E2E_DIR + BTX_AUTOUPDATE_E2E_BASEURL are
// set, emit a real ML-DSA-44-signed manifest, signature, installer, and public key so a live
// btxd can be driven against an HTTP server in a shell harness. A normal `test_btx` run (no env
// vars) is a trivial no-op. This lets the PQ release-signature path be validated against the real
// PythonAutoUpdateFetcher + DetachedScriptCommandRunner, not just the in-process verifier.
BOOST_AUTO_TEST_CASE(pq_e2e_artifact_generator)
{
    const char* out_dir = std::getenv("BTX_AUTOUPDATE_E2E_DIR");
    const char* base_url = std::getenv("BTX_AUTOUPDATE_E2E_BASEURL");
    if (out_dir == nullptr || base_url == nullptr) return;

    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    // The installer asserts the node forwarded the PQ scheme + key and that btx-util (the PQ
    // verifier the real installer uses) is resolvable next to the running btxd, then drops a marker.
    const std::string install_script = R"SH(#!/bin/sh
[ "$BTX_AUTOUPDATE_PUBKEY_ALGO" = "ml-dsa-44" ] || exit 11
[ -n "$BTX_AUTOUPDATE_PUBKEY" ] || exit 12
BTXUTIL="$(dirname "$(readlink -f "/proc/$BTX_AUTOUPDATE_PID/exe" 2>/dev/null)")/btx-util"
[ -x "$BTXUTIL" ] || exit 13
touch "${BTX_AUTOUPDATE_DATADIR}/INSTALLER_RAN_PQ"
)SH";
    const std::vector<unsigned char> script_bytes(install_script.begin(), install_script.end());
    const std::string script_sha = SHA256Hex(script_bytes);

    const std::string base{base_url};
    const std::string manifest = strprintf(
        R"({"version":"99.0.0","script_url":"%s/install.sh","sig_url":"%s/version.txt.sig","script_sha256":"%s"})",
        base, base, script_sha);
    const std::vector<unsigned char> manifest_bytes(manifest.begin(), manifest.end());

    uint256 digest;
    CSHA256().Write(manifest_bytes.data(), manifest_bytes.size()).Finalize(digest.begin());
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(digest, signature, /*slhdsa_fips205=*/true));

    const std::string dir{out_dir};
    const auto write_bytes = [](const std::string& path, const unsigned char* data, size_t len) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        BOOST_REQUIRE(out.is_open());
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    };
    write_bytes(dir + "/version.txt", manifest_bytes.data(), manifest_bytes.size());
    write_bytes(dir + "/version.txt.sig", signature.data(), signature.size());
    write_bytes(dir + "/install.sh", script_bytes.data(), script_bytes.size());
    const std::string pubkey_hex = HexStr(key.GetPubKey());
    write_bytes(dir + "/pubkey.hex", reinterpret_cast<const unsigned char*>(pubkey_hex.data()), pubkey_hex.size());
}

BOOST_AUTO_TEST_SUITE_END()
