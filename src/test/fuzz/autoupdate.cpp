// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/sha256.h>
#include <node/autoupdate.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string Sha256Hex(const std::vector<unsigned char>& bytes)
{
    uint256 digest;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest.begin());
    return HexStr(Span<const unsigned char>{digest.begin(), digest.size()});
}

//! A version string: mostly well formed (so the comparison logic is reached), sometimes raw.
std::string ConsumeVersion(FuzzedDataProvider& fdp)
{
    if (fdp.ConsumeBool()) return fdp.ConsumeRandomLengthString(32);
    std::string v{fdp.PickValueInArray({"", "", " ", "v", "V"})};
    v += strprintf("%d.%d.%d", fdp.ConsumeIntegralInRange<int>(0, 1000), fdp.ConsumeIntegralInRange<int>(0, 40),
                   fdp.ConsumeIntegralInRange<int>(0, 40));
    switch (fdp.ConsumeIntegralInRange<int>(0, 6)) {
    case 0: break;
    case 1: v += strprintf("-rc%d", fdp.ConsumeIntegralInRange<int>(-1, 9)); break;
    case 2: v += strprintf("rc%d", fdp.ConsumeIntegralInRange<int>(0, 9)); break;
    case 3: v += "+" + fdp.ConsumeRandomLengthString(8); break;
    case 4: v += fdp.PickValueInArray({"-beta1", "-RC2", "rc", "-", "x"}); break;
    case 5: v += fdp.ConsumeRandomLengthString(8); break;
    case 6: v += " "; break;
    }
    return v;
}

struct FuzzedFetcher final : node::AutoUpdateFetcher {
    std::vector<node::AutoUpdateFetchResult> replies;
    std::vector<bool> keep_url;
    std::vector<std::string> final_urls;

    node::AutoUpdateFetchResult Fetch(std::string_view url, size_t max_bytes) override
    {
        const size_t i{final_urls.size()};
        if (i >= replies.size()) {
            final_urls.emplace_back(url);
            node::AutoUpdateFetchResult none;
            none.error = "no reply";
            return none;
        }
        auto reply{replies[i]};
        if (keep_url[i]) reply.final_url = std::string{url};
        if (reply.body.size() > max_bytes) reply.body.resize(max_bytes);
        final_urls.push_back(reply.final_url);
        return reply;
    }
};

struct RecordingVerifier final : node::AutoUpdateSignatureVerifier {
    std::unique_ptr<node::AutoUpdateSignatureVerifier> real; //!< null: answer `fake_answer`
    bool fake_answer{false};
    int accepted{0};
    std::vector<unsigned char> accepted_message;

    bool Verify(std::string_view pubkey_hex, const std::vector<unsigned char>& message,
                const std::vector<unsigned char>& signature) override
    {
        const bool ok{real ? real->Verify(pubkey_hex, message, signature) : fake_answer};
        if (ok) {
            ++accepted;
            accepted_message = message;
        }
        return ok;
    }
};

struct RecordingRunner final : node::AutoUpdateCommandRunner {
    bool answer{false};
    int calls{0};
    node::AutoUpdateManifest manifest;
    std::vector<unsigned char> script;

    bool LaunchInstaller(const node::AutoUpdateConfig&, const node::AutoUpdateManifest& m,
                         const std::vector<unsigned char>& s) override
    {
        ++calls;
        manifest = m;
        script = s;
        return answer; // Never executes anything.
    }
};

} // namespace

FUZZ_TARGET(autoupdate_version)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const std::string a{ConsumeVersion(fdp)}, b{ConsumeVersion(fdp)}, c{ConsumeVersion(fdp)};
    const int ab{node::CompareAutoUpdateVersionStrings(a, b)};
    const int ba{node::CompareAutoUpdateVersionStrings(b, a)};
    const int bc{node::CompareAutoUpdateVersionStrings(b, c)};
    const int ac{node::CompareAutoUpdateVersionStrings(a, c)};
    assert(ab >= -1 && ab <= 1);
    assert(node::CompareAutoUpdateVersionStrings(a, a) == 0);
    // "remote is newer" is a strict order: never newer both ways, and transitive.
    // (It is not antisymmetric on purpose: a final build never adopts a prerelease.)
    if (ab == 1) assert(ba == -1);
    if (ab == 1 && bc == 1) assert(ac == 1);
    (void)node::CompareAutoUpdateVersion(a);

    const std::string url{fdp.ConsumeRandomLengthString(128)};
    const std::string origin{fdp.ConsumeBool() ? std::string{node::DEFAULT_AUTOUPDATE_TRUSTED_ORIGIN} : fdp.ConsumeRandomLengthString(64)};
    const bool dev_origin{fdp.ConsumeBool()};
    (void)node::ParseAutoUpdateUrl(url);
    if (node::AutoUpdateUrlMatchesTrustedOrigin(url, origin, dev_origin)) {
        assert(node::ParseAutoUpdateUrl(url).has_value());
        if (!dev_origin) assert(node::ParseAutoUpdateUrl(url)->scheme == "https");
    }
}

FUZZ_TARGET(autoupdate_check)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    node::AutoUpdateConfig config;
    config.enabled = true;
    config.seamless = fdp.ConsumeBool();
    config.dev_origin = fdp.ConsumeBool();
    config.require_script_hash = fdp.ConsumeBool();
    config.telemetry = fdp.ConsumeBool();
    config.rollout_cohort = fdp.ConsumeIntegralInRange<int>(-5, 105);
    if (config.dev_origin && fdp.ConsumeBool()) {
        config.trusted_origin = "http://updates.test";
        config.manifest_url = "http://updates.test/version.txt";
    }
    // config.datadir stays empty: nothing is pinned or written to disk.
    const std::string origin{config.trusted_origin};

    // The three bodies a server (or anyone on the path) controls: manifest, signature, script.
    const std::vector<unsigned char> script{ConsumeRandomLengthByteVector(fdp, 4096)};
    std::string manifest_text;
    if (fdp.ConsumeBool()) {
        manifest_text = fdp.ConsumeRandomLengthString(1024);
    } else {
        const auto url_like = [&](std::string_view path) {
            return fdp.ConsumeBool() ? origin + std::string{path} : fdp.ConsumeRandomLengthString(64);
        };
        manifest_text = "{\"version\":\"" + ConsumeVersion(fdp) + "\",\"script_url\":\"" + url_like("/install.py") + "\"";
        if (fdp.ConsumeBool()) manifest_text += ",\"sig_url\":\"" + url_like("/version.txt.sig") + "\"";
        if (fdp.ConsumeBool()) {
            manifest_text += std::string{",\""} + fdp.PickValueInArray({"script_sha256", "install_sha256", "install_script_sha256"}) + "\":\"" +
                             (fdp.ConsumeBool() ? Sha256Hex(script) : fdp.ConsumeRandomLengthString(70)) + "\"";
        }
        if (fdp.ConsumeBool()) {
            manifest_text += strprintf(",\"%s\":%s", fdp.PickValueInArray({"rollout_percent", "rollout", "canary_percent"}),
                                       fdp.ConsumeBool() ? strprintf("%d", fdp.ConsumeIntegral<int>()) : "\"" + fdp.ConsumeRandomLengthString(8) + "\"");
        }
        manifest_text += fdp.ConsumeBool() ? "}" : fdp.ConsumeRandomLengthString(16);
    }

    FuzzedFetcher fetcher;
    for (int i = 0; i < 3; ++i) {
        node::AutoUpdateFetchResult r;
        r.ok = fdp.ConsumeIntegralInRange<int>(0, 7) != 0;
        r.status = fdp.ConsumeBool() ? 200 : fdp.ConsumeIntegralInRange<int>(0, 600);
        r.final_url = fdp.ConsumeRandomLengthString(64);
        if (i == 0) r.body.assign(manifest_text.begin(), manifest_text.end());
        if (i == 1) r.body = ConsumeRandomLengthByteVector(fdp, 8192);
        if (i == 2) r.body = script;
        fetcher.replies.push_back(std::move(r));
        fetcher.keep_url.push_back(fdp.ConsumeIntegralInRange<int>(0, 7) != 0);
    }

    RecordingVerifier verifier;
    if (fdp.ConsumeBool()) {
        // The shipped ML-DSA-44 verifier and release key, fed attacker bytes.
        verifier.real = node::MakeAutoUpdateSignatureVerifier(config.release_pubkey_algo);
    } else {
        verifier.fake_answer = fdp.ConsumeBool();
    }
    RecordingRunner runner;
    runner.answer = fdp.ConsumeBool();

    const auto result{node::CheckForAutoUpdate(config, fetcher, verifier, runner)};
    (void)node::AutoUpdateStatusString(result.status);

    // An installer is launched only for a manifest that passed every gate.
    assert(runner.calls <= 1);
    if (runner.calls == 1) {
        const auto& m{runner.manifest};
        assert(config.seamless);
        assert(verifier.accepted == 1 && verifier.accepted_message == fetcher.replies[0].body);
        assert(fetcher.final_urls.size() == 3);
        for (const auto& final_url : fetcher.final_urls) {
            assert(node::AutoUpdateUrlMatchesTrustedOrigin(final_url, config.trusted_origin, config.dev_origin));
        }
        assert(node::AutoUpdateUrlMatchesTrustedOrigin(m.script_url, config.trusted_origin, config.dev_origin));
        assert(node::AutoUpdateUrlMatchesTrustedOrigin(m.sig_url, config.trusted_origin, config.dev_origin));
        assert(runner.script == script);
        const bool hash_given{m.script_sha256.size() == 64 && IsHex(m.script_sha256)};
        assert(hash_given || !config.require_script_hash);
        if (hash_given) assert(m.script_sha256 == Sha256Hex(runner.script));
        assert(node::CompareAutoUpdateVersion(m.version) > 0);
        assert(node::AutoUpdateRolloutCohort(config) < m.rollout_percent);
    }
    if (result.status == node::AutoUpdateStatus::LAUNCHED) assert(runner.calls == 1 && runner.answer);
    if (result.status == node::AutoUpdateStatus::UPDATE_AVAILABLE) assert(verifier.accepted == 1 && !config.seamless);
}
