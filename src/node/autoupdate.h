// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_AUTOUPDATE_H
#define BITCOIN_NODE_AUTOUPDATE_H

#include <util/chaintype.h>
#include <util/fs.h>
#include <util/threadinterrupt.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

class ArgsManager;

namespace node {

static constexpr std::string_view DEFAULT_AUTOUPDATE_MANIFEST_URL{"https://btx.dev/version.txt"};
static constexpr std::string_view DEFAULT_AUTOUPDATE_TRUSTED_ORIGIN{"https://btx.dev"};
// Compiled-in release public key (post-quantum ML-DSA-44, 2624 hex chars) for the default
// scheme below, so auto-update works out of the box (default-on on mainnet, opt-out). The matching
// PRIVATE key is offline; a btx.dev/DNS/TLS compromise cannot push code without it. Operators may
// override with -autoupdatepubkey (+ -autoupdatepubkeyalgo); set it to "0"/empty to make auto-update
// inert. Rotate via a client release that bakes a new key (transition window can accept both).
// The historical classical key "03478e9d7f986823a1d77c4e2bb75f4600d3dccb5475371e45922ebfc39521420c"
// is for an optional secp256k1 first hop (-autoupdatepubkeyalgo=secp256k1).
static constexpr std::string_view DEFAULT_AUTOUPDATE_RELEASE_PUBKEY{
    "c4ed2cf3eec5fe82620d5112880eda75d9075f9d14e1de75cad107d7b719d47da6653bab0ac4dad3447c13f1c13f92bdb1004f7191cdd80b6eb338ef3b6e8dd85e9cb63200475bcb07daf774c740e8e14b4a8dbb17b16541c74dd8b5d2108cce4b1c2269c9c9174a8a5c527d8d1d12d4b736cffeb4df5a36d0f0aa2e1db583f6a2592a11046b26cfee5331fec5ef399154652b721aa53d2a24d6435b4f46b89d4bf809079517c3beecac414eeb95ce3b728ab8a941646334bcd284d30d62de7d4cd15b6ee32e5d54c32755852ad8afd43d7535bec07195cb97b17d4e7b9478da5dcee2f4c44262cdb1ae2ea3def079dde09f28f7f26c0003414bf26a0d3c7ba9e67002fe618bea888115a646c576bb384e9e0960fd6c5491752b85ac041de2911cd8d3fd6687ca9a5f5836e79bd0b31f779ac21bcae2355489448fad2e3b25e742d6934082ff6604d354bbc1b65ce3f2755859fd4f6fe3b80c50ac65ac8b3611a1f50eaff8b49b97b991de1d427ac2ba50fc176a552fd6efe88c098e409e3b02017c5afa7a038261e00b8dda193e3d5f327375257cee9d456b8575216195931033ef79566579c1ce88c395f51bd8407bb0633d5b9f612e09d0913a009aab26d6bffc0c53df5f8499f05b7a852ce8f4836c25d2387eed9f749eaefd18131fad53e859039fb49e8f2f9ab6bb8193c07161af63ba003f43ba5fad661beac383aed15988dec1d31ac6b6b30deafb2c5cad0af78351a51d716c0ed61b32bfd2fd8a4fa019a891848cd5deca79649a19d4e4df111d29fa08f3a65164ccbb49182e022d97a0acdad51e3dc24f471f4447422e7e500d9f870f86e57697d96e3e4ef26401d688ecf444d381cfd7969f6dfb3e2298d3d5e6232fa0e0b4ed88117e950fa40361888a87628d0b8b12e46b38e3cead8c5895e29b7f59c6b6d03d6a24ae06eff07a70ccd39b2258bc17554768e51cc2b134b49044ae5ccbe0a4048f13bf6e83e52d26b05672328acc468f5c031e93bb7cc25635ba93a07a03a856a843c948d8430c1ad612b3f1364102ea8c6630ee14a739738d3ee2a9e2888c928ee52bf0c92ef9619ce9f20265c038c663dfccc9fe50945def1242d1e1d601e4ff9427090b1416c40bcb2b368889807e3dd17d45516202634305ab7fd1582357ccfadb27ac50d9b6547b3690a4c5f0ba27d1f83f5066c0e15974f2b39d940d605df6cda7842e2332e9933a42f0d9b3d4014a6a74bf84e6ac1739e2e58c32c1c75dd38116f410a18d39ec6ce23f68556b3ebc7c03966a5303bee33bdbb79851a694949797b761ad3987c99da81a0e835135e3a11de8761ab66d3287ca23a7f61f20438000f9a622f4a9947959b15c3d3409835c50e34a45785807115b2dfe373f286144d65699253aa898dee05a08bdb1e207728451450ac67a3cbdc80997bf84b44ff2231fa7fce1e58398c290cb514968ca6eb171901e7ca4c0661da8a702f9574ad0c9f5317fb61e63b824719c6cc29a23cbb83bedefdd6010df4b78bc429ee962bb53146ceaccfbe1111ef8e9224bf169af5844fee40ad3ecad6887f29df4c0ab4281ed80b7397c39c549d8236655207d43eefe2425ec5cfae376ace6c26775227282a954498cb616dff090b6c577e9493c3b50d403725fa93121e0fc596e2e2abf5850189b1e42b8b8981c7ad3af4bdf18da771553fc407877ded83ddff7094ae1a473563988dee7a32edda6120cb644adb399340b51e1ca288702861e793f5b35b0c33780b129827a56728357c8fd7201d93f2c089b0372f9a0deba5e5e1a0044e6010bbccf2a2cb119a5cd6f3b39d6fd9308374aacf9ed4012fe08f7280df0cf256593"};
// Release-signature scheme for the manifest. On a post-quantum chain the update
// channel (which can ship code to every node) must itself be quantum-safe, so the
// default is the PQ ML-DSA-44 scheme rather than classical secp256k1. Supported
// values: "ml-dsa-44", "slh-dsa-128s", "secp256k1". Operators must configure a
// release public key for the chosen scheme (-autoupdatepubkey / -autoupdatepubkeyalgo).
static constexpr std::string_view DEFAULT_AUTOUPDATE_RELEASE_PUBKEY_ALGO{"ml-dsa-44"};
static constexpr int64_t DEFAULT_AUTOUPDATE_INTERVAL_SECONDS{30 * 60};
static constexpr int64_t DEFAULT_AUTOUPDATE_INITIAL_DELAY_SECONDS{30};

struct AutoUpdateUrl {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
};

struct AutoUpdateConfig {
    bool enabled{false};
    bool seamless{true};
    bool dev_origin{false};
    bool require_script_hash{true};
    std::string manifest_url{std::string{DEFAULT_AUTOUPDATE_MANIFEST_URL}};
    std::string trusted_origin{std::string{DEFAULT_AUTOUPDATE_TRUSTED_ORIGIN}};
    std::string release_pubkey{std::string{DEFAULT_AUTOUPDATE_RELEASE_PUBKEY}};
    std::string release_pubkey_algo{std::string{DEFAULT_AUTOUPDATE_RELEASE_PUBKEY_ALGO}};
    std::string python_command{"python3"};
    int64_t interval_seconds{DEFAULT_AUTOUPDATE_INTERVAL_SECONDS};
    int64_t initial_delay_seconds{DEFAULT_AUTOUPDATE_INITIAL_DELAY_SECONDS};
    int64_t daemon_pid{0};
    fs::path datadir;
    // Optional explicit rollout cohort in [0, 100). When unset the cohort is derived stably from the
    // datadir, so each node keeps the same cohort across restarts. Set it to pin a node into an
    // early canary band (e.g. 0) or a late band for testing staged rollouts.
    std::optional<int> rollout_cohort;
};

struct AutoUpdateManifest {
    std::string version;
    std::string script_url;
    std::string sig_url;
    std::string script_sha256;
    // Staged/canary rollout: the signed percentage of the fleet (0-100) eligible to apply THIS
    // release yet. A node applies the update only if its stable cohort falls under this value, so a
    // bad release reaches a fraction of nodes first. Defaults to 100 (full rollout) when the
    // manifest omits it, preserving prior behavior. Because it lives in the signed manifest body it
    // cannot be tampered with to widen a rollout.
    int rollout_percent{100};
};

struct AutoUpdateFetchResult {
    bool ok{false};
    int status{0};
    std::string final_url;
    std::vector<unsigned char> body;
    std::string error;
};

enum class AutoUpdateStatus {
    DISABLED,
    INVALID_CONFIG,
    FETCH_FAILED,
    BAD_MANIFEST,
    UNSIGNED_MANIFEST,
    BAD_SIGNATURE,
    NOT_NEWER,
    ROLLOUT_DEFERRED,
    SCRIPT_ORIGIN_REJECTED,
    SCRIPT_HASH_MISSING,
    SCRIPT_FETCH_FAILED,
    SCRIPT_HASH_MISMATCH,
    UPDATE_AVAILABLE,
    LAUNCH_FAILED,
    LAUNCHED,
};

struct AutoUpdateCheckResult {
    AutoUpdateStatus status{AutoUpdateStatus::DISABLED};
    std::string detail;
    std::string remote_version;
    std::string script_url;
};

class AutoUpdateFetcher
{
public:
    virtual ~AutoUpdateFetcher() = default;
    virtual AutoUpdateFetchResult Fetch(std::string_view url, size_t max_bytes) = 0;
};

class AutoUpdateSignatureVerifier
{
public:
    virtual ~AutoUpdateSignatureVerifier() = default;
    virtual bool Verify(std::string_view pubkey_hex,
                        const std::vector<unsigned char>& message,
                        const std::vector<unsigned char>& signature) = 0;
};

class AutoUpdateCommandRunner
{
public:
    virtual ~AutoUpdateCommandRunner() = default;
    virtual bool LaunchInstaller(const AutoUpdateConfig& config,
                                 const AutoUpdateManifest& manifest,
                                 const std::vector<unsigned char>& script) = 0;
};

class AutoUpdateManager
{
public:
    AutoUpdateManager(AutoUpdateConfig config,
                      std::unique_ptr<AutoUpdateFetcher> fetcher,
                      std::unique_ptr<AutoUpdateSignatureVerifier> verifier,
                      std::unique_ptr<AutoUpdateCommandRunner> runner);
    ~AutoUpdateManager();

    AutoUpdateManager(const AutoUpdateManager&) = delete;
    AutoUpdateManager& operator=(const AutoUpdateManager&) = delete;

    void Start();
    void Interrupt();
    void Stop();

private:
    void ThreadLoop();

    AutoUpdateConfig m_config;
    std::unique_ptr<AutoUpdateFetcher> m_fetcher;
    std::unique_ptr<AutoUpdateSignatureVerifier> m_verifier;
    std::unique_ptr<AutoUpdateCommandRunner> m_runner;
    std::thread m_thread;
    std::unique_ptr<CThreadInterrupt> m_interrupt;
};

std::optional<AutoUpdateUrl> ParseAutoUpdateUrl(std::string_view url);
bool AutoUpdateUrlMatchesTrustedOrigin(std::string_view url, std::string_view trusted_origin, bool dev_origin);
int CompareAutoUpdateVersion(std::string_view remote_version);
std::string AutoUpdateStatusString(AutoUpdateStatus status);

// This node's stable rollout cohort in [0, 100): config.rollout_cohort if set, else derived from a
// hash of the datadir so it is stable across restarts but varies across the fleet. An update with
// manifest rollout_percent P is applied only when cohort < P.
int AutoUpdateRolloutCohort(const AutoUpdateConfig& config);

AutoUpdateCheckResult CheckForAutoUpdate(const AutoUpdateConfig& config,
                                         AutoUpdateFetcher& fetcher,
                                         AutoUpdateSignatureVerifier& verifier,
                                         AutoUpdateCommandRunner& runner);

// Build a verifier for the named release-signature scheme ("ml-dsa-44",
// "slh-dsa-128s", or "secp256k1"). Returns nullptr for an unknown scheme.
std::unique_ptr<AutoUpdateSignatureVerifier> MakeAutoUpdateSignatureVerifier(
    std::string_view algo = DEFAULT_AUTOUPDATE_RELEASE_PUBKEY_ALGO);

// Expected hex-string length of a release public key for the given scheme, or
// std::nullopt if the scheme is unknown. Used for early -autoupdatepubkey validation.
std::optional<size_t> AutoUpdateReleasePubkeyHexLength(std::string_view algo);
std::unique_ptr<AutoUpdateManager> MakeAutoUpdateManager(const ArgsManager& args, ChainType chain);

} // namespace node

#endif // BITCOIN_NODE_AUTOUPDATE_H
