// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/autoupdate.h>

#include <clientversion.h>
#include <common/args.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <pqkey.h>
#include <pubkey.h>
#include <random.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/subprocess.h>
#include <util/thread.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <crt_externs.h>
#include <cstdlib>
#define BTX_ENVIRON (*_NSGetEnviron())
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#endif
#if !defined(__APPLE__)
extern "C" char** environ;
#define BTX_ENVIRON environ
#endif
#endif

namespace node {
namespace {

constexpr size_t MAX_MANIFEST_BYTES{256 * 1024};
constexpr size_t MAX_SIGNATURE_BYTES{16 * 1024};
constexpr size_t MAX_INSTALL_SCRIPT_BYTES{1024 * 1024};
constexpr int AUTOUPDATE_FETCH_TIMEOUT_SECONDS{20};
constexpr int64_t MAX_AUTOUPDATE_BACKOFF_SECONDS{6 * 60 * 60};

std::string ToLowerAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return std::tolower(ch);
    });
    return value;
}

std::string TrimAscii(std::string_view value)
{
    const auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    auto first = std::find_if(value.begin(), value.end(), not_space);
    auto last = std::find_if(value.rbegin(), value.rend(), not_space).base();
    if (first >= last) return {};
    return std::string{first, last};
}

std::string DefaultPortForScheme(std::string_view scheme)
{
    if (scheme == "https") return "443";
    if (scheme == "http") return "80";
    return {};
}

std::string NormalizedPort(std::string_view scheme, std::string_view port)
{
    return port.empty() ? DefaultPortForScheme(scheme) : std::string{port};
}

bool HostCharAllowed(char ch)
{
    return std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '.';
}

bool PortValid(std::string_view port)
{
    if (port.empty()) return true;
    uint16_t parsed{0};
    const auto [ptr, ec] = std::from_chars(port.data(), port.data() + port.size(), parsed);
    return ec == std::errc{} && ptr == port.data() + port.size() && parsed != 0;
}

std::optional<std::tuple<int, int, int>> ParseVersionTriple(std::string_view raw)
{
    std::string value = TrimAscii(raw);
    if (!value.empty() && (value.front() == 'v' || value.front() == 'V')) value.erase(value.begin());

    std::array<int, 3> parts{0, 0, 0};
    size_t pos{0};
    for (size_t i = 0; i < parts.size(); ++i) {
        if (pos >= value.size() || !std::isdigit(static_cast<unsigned char>(value[pos]))) return std::nullopt;
        int part{0};
        const char* begin = value.data() + pos;
        const char* end = value.data() + value.size();
        const auto [ptr, ec] = std::from_chars(begin, end, part);
        if (ec != std::errc{} || ptr == begin || part < 0) return std::nullopt;
        parts[i] = part;
        pos = static_cast<size_t>(ptr - value.data());
        if (i + 1 < parts.size()) {
            if (pos >= value.size() || value[pos] != '.') return std::nullopt;
            ++pos;
        }
    }

    if (pos < value.size()) {
        const char suffix = value[pos];
        if (suffix != '-' && suffix != '+' && !std::isalpha(static_cast<unsigned char>(suffix))) return std::nullopt;
    }
    return std::make_tuple(parts[0], parts[1], parts[2]);
}

std::optional<std::string> FindStringValue(const UniValue& object, std::string_view key)
{
    const UniValue& value = object.find_value(std::string{key});
    if (!value.isStr()) return std::nullopt;
    return value.get_str();
}

// Accept a manifest integer as a JSON number ("rollout_percent": 25) or a numeric string ("25").
std::optional<int> FindIntValue(const UniValue& object, std::string_view key)
{
    const UniValue& value = object.find_value(std::string{key});
    std::string text;
    if (value.isNum()) {
        text = value.getValStr();
    } else if (value.isStr()) {
        text = TrimAscii(value.get_str());
    } else {
        return std::nullopt;
    }
    if (text.empty()) return std::nullopt;
    int parsed{0};
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) return std::nullopt;
    return parsed;
}

std::optional<AutoUpdateManifest> ParseManifest(const std::vector<unsigned char>& body,
                                                std::string_view manifest_url)
{
    UniValue parsed;
    const std::string text{body.begin(), body.end()};
    if (!parsed.read(text) || !parsed.isObject()) return std::nullopt;

    AutoUpdateManifest manifest;
    auto version = FindStringValue(parsed, "version");
    auto script_url = FindStringValue(parsed, "script_url");
    if (!version || !script_url) return std::nullopt;
    manifest.version = TrimAscii(*version);
    manifest.script_url = TrimAscii(*script_url);

    if (auto sig_url = FindStringValue(parsed, "sig_url")) {
        manifest.sig_url = TrimAscii(*sig_url);
    } else {
        manifest.sig_url = std::string{manifest_url} + ".sig";
    }

    for (std::string_view key : {"script_sha256", "install_sha256", "install_script_sha256"}) {
        if (auto script_sha256 = FindStringValue(parsed, key)) {
            manifest.script_sha256 = ToLowerAscii(TrimAscii(*script_sha256));
            break;
        }
    }

    // Staged rollout percentage; accept a few key spellings. Clamp to [0, 100]; default 100.
    for (std::string_view key : {"rollout_percent", "rollout", "canary_percent"}) {
        if (auto rollout = FindIntValue(parsed, key)) {
            manifest.rollout_percent = std::clamp(*rollout, 0, 100);
            break;
        }
    }

    if (manifest.version.empty() || manifest.script_url.empty() || manifest.sig_url.empty()) {
        return std::nullopt;
    }
    return manifest;
}

std::optional<std::vector<unsigned char>> DecodeSignatureBody(const std::vector<unsigned char>& body)
{
    if (body.empty()) return std::nullopt;

    // DER signatures commonly start with ASN.1 SEQUENCE (0x30). Treat binary
    // DER as authoritative before attempting text encodings.
    if (body.front() == 0x30) return body;

    const std::string text = TrimAscii(std::string_view{reinterpret_cast<const char*>(body.data()), body.size()});
    if (text.empty()) return std::nullopt;

    if (IsHex(text) && text.size() % 2 == 0) {
        auto parsed = TryParseHex<unsigned char>(text);
        if (parsed && !parsed->empty()) return *parsed;
    }

    if (auto decoded = DecodeBase64(text)) {
        if (!decoded->empty()) return *decoded;
    }

    return std::vector<unsigned char>{text.begin(), text.end()};
}

std::string SHA256Hex(const std::vector<unsigned char>& bytes)
{
    uint256 digest;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest.begin());
    return HexStr(Span<const unsigned char>{digest.begin(), digest.size()});
}

bool LooksLikeSHA256Hex(std::string_view value)
{
    return value.size() == 64 && IsHex(value);
}

std::string SanitizeFileComponent(std::string_view value)
{
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-' || ch == '_') {
            out.push_back(ch);
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) out = "unknown";
    return out;
}

std::string UrlEncodeQueryValue(std::string_view value)
{
    static constexpr char HEX[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (const unsigned char ch : value) {
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('%');
            out.push_back(HEX[ch >> 4]);
            out.push_back(HEX[ch & 0x0f]);
        }
    }
    return out;
}

std::string LocalClientVersion()
{
    return strprintf("%d.%d.%d", CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_BUILD);
}

std::string HostPlatform()
{
#if defined(WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "darwin";
#elif defined(__linux__)
    return "linux";
#elif defined(__FreeBSD__)
    return "freebsd";
#elif defined(__DragonFly__)
    return "dragonfly";
#else
    return "unknown";
#endif
}

std::string HostArchitecture()
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

bool IsValidAutoUpdateClientId(std::string_view value)
{
    if (value.size() != 36) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(value[i]))) {
            return false;
        }
    }
    return true;
}

std::string GenerateAutoUpdateClientId()
{
    std::array<unsigned char, 16> bytes;
    GetRandBytes(Span<unsigned char>{bytes.data(), bytes.size()});
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3f) | 0x80);
    const std::string hex = HexStr(Span<const unsigned char>{bytes.data(), bytes.size()});
    return strprintf("%s-%s-%s-%s-%s",
                     hex.substr(0, 8),
                     hex.substr(8, 4),
                     hex.substr(12, 4),
                     hex.substr(16, 4),
                     hex.substr(20, 12));
}

std::string GetOrCreateAutoUpdateClientId(const fs::path& datadir)
{
    const fs::path update_dir = datadir / "autoupdate";
    const fs::path id_path = update_dir / "client-id";
    try {
        std::ifstream in{id_path};
        std::string existing;
        std::getline(in, existing);
        existing = TrimAscii(existing);
        if (IsValidAutoUpdateClientId(existing)) return ToLowerAscii(existing);
    } catch (const std::exception&) {
    }

    const std::string generated = GenerateAutoUpdateClientId();
    try {
        fs::create_directories(update_dir);
        std::ofstream out{id_path, std::ios::trunc};
        if (out.is_open()) out << generated << '\n';
    } catch (const std::exception& e) {
        LogDebug(BCLog::AUTOUPDATE, "Unable to persist auto-update client id: %s\n", e.what());
    }
    return generated;
}

class PythonAutoUpdateFetcher final : public AutoUpdateFetcher
{
public:
    explicit PythonAutoUpdateFetcher(std::string python_command) : m_python_command{std::move(python_command)} {}

    AutoUpdateFetchResult Fetch(std::string_view url, size_t max_bytes) override
    {
        namespace sp = subprocess;

        static const std::string fetch_script = R"PY(
import base64
import json
import sys
import urllib.error
import urllib.request

url = sys.argv[1]
max_bytes = int(sys.argv[2])
timeout = float(sys.argv[3])
try:
    request = urllib.request.Request(url, headers={"User-Agent": "BTX-AutoUpdate/0.32"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise RuntimeError("response too large")
        print(json.dumps({
            "ok": True,
            "status": int(response.getcode() or 0),
            "url": response.geturl(),
            "body_b64": base64.b64encode(body).decode("ascii"),
        }))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
)PY";

        AutoUpdateFetchResult result;
        try {
            sp::Popen child{
                std::vector<std::string>{
                    m_python_command,
                    "-c",
                    fetch_script,
                    std::string{url},
                    std::to_string(max_bytes),
                    std::to_string(AUTOUPDATE_FETCH_TIMEOUT_SECONDS),
                },
                sp::output{sp::PIPE},
                sp::error{sp::PIPE},
                sp::close_fds{true},
            };
            child.set_out_buf_cap(max_bytes * 2 + 4096);
            child.set_err_buf_cap(4096);
            const auto [out_res, err_res] = child.communicate();
            if (child.retcode() != 0) {
                result.error = "fetch helper failed";
                return result;
            }
            UniValue reply;
            const std::string reply_text{out_res.buf.begin(), out_res.buf.end()};
            if (!reply.read(reply_text) || !reply.isObject()) {
                result.error = "fetch helper returned malformed json";
                return result;
            }
            const UniValue& ok = reply.find_value("ok");
            if (!ok.isBool() || !ok.get_bool()) {
                if (const UniValue& error = reply.find_value("error"); error.isStr()) {
                    result.error = error.get_str();
                } else {
                    result.error = "fetch helper failed";
                }
                return result;
            }
            const UniValue& status = reply.find_value("status");
            const UniValue& final_url = reply.find_value("url");
            const UniValue& body_b64 = reply.find_value("body_b64");
            if (!status.isNum() || !final_url.isStr() || !body_b64.isStr()) {
                result.error = "fetch helper returned incomplete json";
                return result;
            }
            auto body = DecodeBase64(body_b64.get_str());
            if (!body) {
                result.error = "fetch helper returned invalid body encoding";
                return result;
            }
            result.ok = true;
            result.status = status.getInt<int>();
            result.final_url = final_url.get_str();
            result.body = std::move(*body);
            return result;
        } catch (const std::exception& e) {
            result.error = e.what();
            return result;
        }
    }

private:
    std::string m_python_command;
};

class Secp256k1AutoUpdateSignatureVerifier final : public AutoUpdateSignatureVerifier
{
public:
    bool Verify(std::string_view pubkey_hex,
                const std::vector<unsigned char>& message,
                const std::vector<unsigned char>& signature) override
    {
        const auto pubkey_bytes = TryParseHex<unsigned char>(pubkey_hex);
        if (!pubkey_bytes || pubkey_bytes->empty()) return false;
        const CPubKey pubkey{*pubkey_bytes};
        if (!pubkey.IsFullyValid()) return false;

        uint256 digest;
        CSHA256().Write(message.data(), message.size()).Finalize(digest.begin());
        return pubkey.Verify(digest, signature);
    }
};

// Post-quantum manifest-signature verifier (ML-DSA-44 / SLH-DSA-128s). The release
// signature is over SHA256(manifest_body), matching the classical path, but the key
// and signature are the configured PQ scheme so the update channel is quantum-safe.
class PQAutoUpdateSignatureVerifier final : public AutoUpdateSignatureVerifier
{
public:
    explicit PQAutoUpdateSignatureVerifier(PQAlgorithm algo) : m_algo{algo} {}

    bool Verify(std::string_view pubkey_hex,
                const std::vector<unsigned char>& message,
                const std::vector<unsigned char>& signature) override
    {
        const auto pubkey_bytes = TryParseHex<unsigned char>(pubkey_hex);
        if (!pubkey_bytes || pubkey_bytes->size() != GetPQPubKeySize(m_algo)) return false;
        if (signature.size() != GetPQSignatureSize(m_algo)) return false;

        const CPQPubKey pubkey{m_algo, *pubkey_bytes};

        uint256 digest;
        CSHA256().Write(message.data(), message.size()).Finalize(digest.begin());
        // SLH-DSA release signatures use the finalized FIPS-205 scheme (the flag is
        // a no-op for ML-DSA). This is independent of the C-002 consensus gate.
        return pubkey.Verify(digest, signature, /*slhdsa_fips205=*/true);
    }

private:
    PQAlgorithm m_algo;
};

// Map a release-signature scheme name to a PQ algorithm. std::nullopt means the name
// is not a PQ scheme (e.g. "secp256k1") or is unknown.
std::optional<PQAlgorithm> AutoUpdatePQAlgoFromName(std::string_view algo)
{
    const std::string lower = ToLowerAscii(std::string{algo});
    if (lower == "ml-dsa-44" || lower == "ml_dsa_44" || lower == "mldsa44" || lower == "ml-dsa") {
        return PQAlgorithm::ML_DSA_44;
    }
    if (lower == "slh-dsa-128s" || lower == "slh_dsa_128s" || lower == "slhdsa128s" || lower == "slh-dsa") {
        return PQAlgorithm::SLH_DSA_128S;
    }
    return std::nullopt;
}

// Directory containing the currently-running node executable, resolved portably so the installer
// can find the sibling btx-util (the PQ verifier) without relying on Linux-only /proc. Returns an
// empty string if it cannot be determined.
std::string RunningExecutableDir()
{
#ifdef WIN32
    return {};
#else
    std::string exe_path;
#if defined(__linux__)
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) exe_path.assign(buf, static_cast<size_t>(n));
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::vector<char> raw(size + 1, '\0');
    if (size > 0 && _NSGetExecutablePath(raw.data(), &size) == 0) {
        char resolved[4096];
        if (::realpath(raw.data(), resolved) != nullptr) {
            exe_path = resolved;
        } else {
            exe_path = raw.data();
        }
    }
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    char buf[4096];
    size_t len = sizeof(buf);
    if (::sysctl(mib, 4, buf, &len, nullptr, 0) == 0 && len > 0) {
        exe_path.assign(buf, len - 1);
    }
#endif
    if (exe_path.empty()) return {};
    const auto slash = exe_path.find_last_of('/');
    return slash == std::string::npos ? std::string{} : exe_path.substr(0, slash);
#endif
}

class DetachedScriptCommandRunner final : public AutoUpdateCommandRunner
{
public:
    bool LaunchInstaller(const AutoUpdateConfig& config,
                         const AutoUpdateManifest& manifest,
                         const std::vector<unsigned char>& script) override
    {
        try {
            fs::path update_dir = config.datadir / "autoupdate";
            fs::create_directories(update_dir);
            const std::string script_hash = SHA256Hex(script);
            const std::string safe_version = SanitizeFileComponent(manifest.version);
            const fs::path final_path = update_dir / fs::u8path(strprintf("install-%s-%s.sh", safe_version, script_hash.substr(0, 16)));
            const fs::path temp_path = update_dir / fs::u8path(strprintf(".install-%s-%s.tmp", safe_version, script_hash.substr(0, 16)));
            {
                std::ofstream out{temp_path, std::ios::binary | std::ios::trunc};
                if (!out.is_open()) return false;
                out.write(reinterpret_cast<const char*>(script.data()), script.size());
                if (!out.good()) return false;
            }
#ifndef WIN32
            if (chmod(fs::PathToString(temp_path).c_str(), S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
                fs::remove(temp_path);
                return false;
            }
#endif
            if (!RenameOver(temp_path, final_path)) {
                fs::remove(temp_path);
                return false;
            }

#ifndef WIN32
            return LaunchDetachedPosix(config, manifest, final_path);
#else
            LogDebug(BCLog::AUTOUPDATE, "Auto-update installer launch is not implemented on Windows\n");
            return false;
#endif
        } catch (const std::exception& e) {
            LogDebug(BCLog::AUTOUPDATE, "Auto-update failed to stage installer: %s\n", e.what());
            return false;
        }
    }

#ifndef WIN32
private:
    // Build the child's environment as owned "KEY=VALUE" strings, in the PARENT. After fork() in a
    // multithreaded process the child may call only async-signal-safe functions until exec; setenv()
    // is not (it allocates, and can deadlock if another thread held the allocator lock at fork --
    // notably on musl). So we assemble everything before fork and hand execve() an explicit envp,
    // never touching the environment in the child.
    static std::vector<std::string> BuildChildEnvStrings(const AutoUpdateConfig& config,
                                                         const AutoUpdateManifest& manifest,
                                                         const fs::path& script_path)
    {
        const std::string telemetry_query = AutoUpdateTelemetryQuery(config);
        std::vector<std::pair<std::string, std::string>> ours{
            {"BTX_AUTOUPDATE", "1"},
            {"BTX_AUTOUPDATE_MANIFEST_URL", config.manifest_url},
            {"BTX_AUTOUPDATE_REMOTE_VERSION", manifest.version},
            {"BTX_AUTOUPDATE_SCRIPT_URL", manifest.script_url},
            {"BTX_AUTOUPDATE_SCRIPT_PATH", fs::PathToString(script_path)},
            {"BTX_AUTOUPDATE_DATADIR", fs::PathToString(config.datadir)},
            {"BTX_MANIFEST_URL", config.manifest_url},
            {"BTX_TRUSTED_ORIGIN", config.trusted_origin},
            // Same release-signature scheme + key the node used, so the installer verifies the
            // manifest and signed source/commit with the SAME (post-quantum) scheme -- e.g. via
            // `btx-util verifyupdatesig` -- instead of a classical-only openssl check.
            {"BTX_AUTOUPDATE_PUBKEY_ALGO", config.release_pubkey_algo},
            {"BTX_AUTOUPDATE_PUBKEY", config.release_pubkey},
        };
        if (!telemetry_query.empty()) {
            ours.emplace_back("BTX_AUTOUPDATE_TELEMETRY_QUERY", telemetry_query);
            ours.emplace_back("BTX_AUTOUPDATE_CLIENT_VERSION", LocalClientVersion());
            ours.emplace_back("BTX_AUTOUPDATE_PLATFORM", HostPlatform());
            ours.emplace_back("BTX_AUTOUPDATE_ARCH", HostArchitecture());
            if (config.telemetry_client_id_enabled && !config.telemetry_client_id.empty()) {
                ours.emplace_back("BTX_AUTOUPDATE_CLIENT_ID", config.telemetry_client_id);
            }
        }
        // Directory of the running node binary, so the installer can find the sibling btx-util
        // verifier portably (no /proc dependency on macOS/BSD).
        if (const std::string bin_dir = RunningExecutableDir(); !bin_dir.empty()) {
            ours.emplace_back("BTX_AUTOUPDATE_BIN_DIR", bin_dir);
        }
        if (config.daemon_pid > 0) {
            ours.emplace_back("BTX_AUTOUPDATE_PID", std::to_string(config.daemon_pid));
        }

        std::vector<std::string> env;
        // Inherit the parent environment, minus any keys we are about to set (avoid duplicates;
        // getenv() would otherwise return whichever copy came first).
        for (char** e = BTX_ENVIRON; e != nullptr && *e != nullptr; ++e) {
            const std::string entry{*e};
            const std::string key = entry.substr(0, entry.find('='));
            const bool overridden = std::any_of(ours.begin(), ours.end(),
                                                [&](const auto& kv) { return kv.first == key; });
            if (!overridden) env.push_back(entry);
        }
        for (const auto& kv : ours) env.push_back(kv.first + "=" + kv.second);
        return env;
    }

    // Pointers into `strings` (NUL-terminated) for execve's envp/argv. `strings` must outlive use.
    static std::vector<char*> PointerVector(std::vector<std::string>& strings)
    {
        std::vector<char*> ptrs;
        ptrs.reserve(strings.size() + 1);
        for (auto& s : strings) ptrs.push_back(s.data());
        ptrs.push_back(nullptr);
        return ptrs;
    }

    // Resolve an executable via PATH in the PARENT (getenv/allocation are safe here), so the child
    // can execve() an absolute path instead of execvp(), which is unavailable with a custom envp on
    // non-glibc systems (no portable execvpe).
    static std::string FindExecutableInPath(std::string_view name)
    {
        const char* path = std::getenv("PATH");
        if (path == nullptr) return {};
        const std::string p{path};
        size_t start = 0;
        while (start <= p.size()) {
            const size_t colon = p.find(':', start);
            const std::string dir = p.substr(start, colon == std::string::npos ? std::string::npos : colon - start);
            if (!dir.empty()) {
                std::string candidate = dir + "/" + std::string{name};
                if (access(candidate.c_str(), X_OK) == 0) return candidate;
            }
            if (colon == std::string::npos) break;
            start = colon + 1;
        }
        return {};
    }

    static bool LaunchDetachedPosix(const AutoUpdateConfig& config,
                                    const AutoUpdateManifest& manifest,
                                    const fs::path& script_path)
    {
        // Everything the post-fork child needs is built here, before fork(), so the child only does
        // async-signal-safe work (dup2/close/execve) -- no setenv, no PATH search, no allocation.
        std::vector<std::string> env_strings = BuildChildEnvStrings(config, manifest, script_path);
        std::vector<char*> envp = PointerVector(env_strings);

        std::string script_str = fs::PathToString(script_path);
        std::string arg_bash{"bash"};
        std::string arg_sh{"sh"};
        std::string bash_path = FindExecutableInPath("bash"); // e.g. Alpine/musl: /bin/sh is ash
        std::string sh_path{"/bin/sh"};

        std::vector<char*> argv_direct{script_str.data(), nullptr};
        std::vector<char*> argv_bash{arg_bash.data(), script_str.data(), nullptr};
        std::vector<char*> argv_sh{arg_sh.data(), script_str.data(), nullptr};

        const pid_t first = fork();
        if (first < 0) return false;
        if (first == 0) {
            if (setsid() < 0) _exit(127);
            const pid_t second = fork();
            if (second < 0) _exit(127);
            if (second > 0) _exit(0);

            const int null_fd = open("/dev/null", O_RDWR);
            if (null_fd >= 0) {
                dup2(null_fd, STDIN_FILENO);
                dup2(null_fd, STDOUT_FILENO);
                dup2(null_fd, STDERR_FILENO);
                if (null_fd > STDERR_FILENO) close(null_fd);
            }
            for (int fd = STDERR_FILENO + 1; fd < 1024; ++fd) close(fd);

            // Direct exec relies on the script's shebang; prefer bash for the bash-only syntax,
            // falling back to /bin/sh. All three carry the explicit, pre-built envp.
            execve(script_str.c_str(), argv_direct.data(), envp.data());
            if (!bash_path.empty()) {
                execve(bash_path.c_str(), argv_bash.data(), envp.data());
            }
            execve(sh_path.c_str(), argv_sh.data(), envp.data());
            _exit(127);
        }

        int status{0};
        if (waitpid(first, &status, 0) != first) return false;
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
#endif
};

AutoUpdateStatus SilentStatusForVerifierFailure(bool missing_signature)
{
    return missing_signature ? AutoUpdateStatus::UNSIGNED_MANIFEST : AutoUpdateStatus::BAD_SIGNATURE;
}

} // namespace

std::optional<AutoUpdateUrl> ParseAutoUpdateUrl(std::string_view raw_url)
{
    const std::string url = TrimAscii(raw_url);
    const size_t scheme_sep = url.find("://");
    if (scheme_sep == std::string::npos || scheme_sep == 0) return std::nullopt;

    AutoUpdateUrl parsed;
    parsed.scheme = ToLowerAscii(url.substr(0, scheme_sep));
    if (parsed.scheme != "https" && parsed.scheme != "http") return std::nullopt;

    const size_t authority_begin = scheme_sep + 3;
    const size_t authority_end = url.find_first_of("/?#", authority_begin);
    const std::string authority = url.substr(authority_begin, authority_end == std::string::npos ? std::string::npos : authority_end - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos) return std::nullopt;

    std::string host;
    std::string port;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos) return std::nullopt;
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return std::nullopt;
            port = authority.substr(close + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        } else {
            host = authority;
        }
        if (host.empty() || !std::all_of(host.begin(), host.end(), HostCharAllowed)) return std::nullopt;
    }
    if (host.empty() || !PortValid(port)) return std::nullopt;

    parsed.host = ToLowerAscii(host);
    parsed.port = NormalizedPort(parsed.scheme, port);
    parsed.path = authority_end == std::string::npos ? "/" : url.substr(authority_end);
    if (parsed.path.empty()) parsed.path = "/";
    return parsed;
}

bool AutoUpdateUrlMatchesTrustedOrigin(std::string_view url, std::string_view trusted_origin, bool dev_origin)
{
    auto parsed_url = ParseAutoUpdateUrl(url);
    auto parsed_origin = ParseAutoUpdateUrl(trusted_origin);
    if (!parsed_url || !parsed_origin) return false;
    if (!dev_origin && parsed_url->scheme != "https") return false;
    return parsed_url->scheme == parsed_origin->scheme &&
           parsed_url->host == parsed_origin->host &&
           parsed_url->port == parsed_origin->port;
}

int CompareAutoUpdateVersion(std::string_view remote_version)
{
    const auto remote = ParseVersionTriple(remote_version);
    if (!remote) return 0;
    const auto local = std::make_tuple(CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_BUILD);
    if (*remote > local) return 1;
    if (*remote < local) return -1;
    return 0;
}

int AutoUpdateRolloutCohort(const AutoUpdateConfig& config)
{
    if (config.rollout_cohort) {
        return std::clamp(*config.rollout_cohort, 0, 99);
    }
    const std::string key = fs::PathToString(config.datadir);
    // No datadir to key on -> cohort 0, i.e. always within any non-zero rollout (fail-open to the
    // operator's intent rather than indefinitely deferring).
    if (key.empty()) return 0;
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(key.data()), key.size()).Finalize(digest);
    // First 4 bytes as a big-endian uint32, mapped uniformly into [0, 100).
    const uint32_t v = (uint32_t{digest[0]} << 24) | (uint32_t{digest[1]} << 16) |
                       (uint32_t{digest[2]} << 8) | uint32_t{digest[3]};
    return static_cast<int>(v % 100u);
}

std::string AutoUpdateTelemetryQuery(const AutoUpdateConfig& config)
{
    if (!config.telemetry) return {};

    std::vector<std::pair<std::string, std::string>> params{
        {"btx_au", "1"},
        {"btx_version", LocalClientVersion()},
        {"btx_platform", HostPlatform()},
        {"btx_arch", HostArchitecture()},
        {"btx_cohort", std::to_string(AutoUpdateRolloutCohort(config))},
    };
    if (config.telemetry_client_id_enabled && !config.telemetry_client_id.empty()) {
        params.emplace_back("btx_client_id", config.telemetry_client_id);
    }

    std::string query;
    for (const auto& [key, value] : params) {
        if (!query.empty()) query.push_back('&');
        query += key;
        query.push_back('=');
        query += UrlEncodeQueryValue(value);
    }
    return query;
}

std::string AutoUpdateTrackedUrl(std::string_view url, const AutoUpdateConfig& config)
{
    const std::string query = AutoUpdateTelemetryQuery(config);
    if (query.empty()) return std::string{url};

    std::string out{url};
    const size_t fragment_pos = out.find('#');
    const size_t insert_pos = fragment_pos == std::string::npos ? out.size() : fragment_pos;
    if (insert_pos > 0 && (out[insert_pos - 1] == '?' || out[insert_pos - 1] == '&')) {
        out.insert(insert_pos, query);
    } else if (out.find('?', 0) < insert_pos) {
        out.insert(insert_pos, "&" + query);
    } else {
        out.insert(insert_pos, "?" + query);
    }
    return out;
}

std::string AutoUpdateStatusString(AutoUpdateStatus status)
{
    switch (status) {
    case AutoUpdateStatus::DISABLED: return "disabled";
    case AutoUpdateStatus::INVALID_CONFIG: return "invalid-config";
    case AutoUpdateStatus::FETCH_FAILED: return "fetch-failed";
    case AutoUpdateStatus::BAD_MANIFEST: return "bad-manifest";
    case AutoUpdateStatus::UNSIGNED_MANIFEST: return "unsigned-manifest";
    case AutoUpdateStatus::BAD_SIGNATURE: return "bad-signature";
    case AutoUpdateStatus::NOT_NEWER: return "not-newer";
    case AutoUpdateStatus::ROLLOUT_DEFERRED: return "rollout-deferred";
    case AutoUpdateStatus::SCRIPT_ORIGIN_REJECTED: return "script-origin-rejected";
    case AutoUpdateStatus::SCRIPT_HASH_MISSING: return "script-hash-missing";
    case AutoUpdateStatus::SCRIPT_FETCH_FAILED: return "script-fetch-failed";
    case AutoUpdateStatus::SCRIPT_HASH_MISMATCH: return "script-hash-mismatch";
    case AutoUpdateStatus::UPDATE_AVAILABLE: return "update-available";
    case AutoUpdateStatus::LAUNCH_FAILED: return "launch-failed";
    case AutoUpdateStatus::LAUNCHED: return "launched";
    }
    assert(false);
    return "unknown";
}

bool AutoUpdateStatusIsTransient(AutoUpdateStatus status)
{
    switch (status) {
    case AutoUpdateStatus::FETCH_FAILED:
    case AutoUpdateStatus::UNSIGNED_MANIFEST:
    case AutoUpdateStatus::SCRIPT_FETCH_FAILED:
    case AutoUpdateStatus::LAUNCH_FAILED:
        return true;
    case AutoUpdateStatus::DISABLED:
    case AutoUpdateStatus::INVALID_CONFIG:
    case AutoUpdateStatus::BAD_MANIFEST:
    case AutoUpdateStatus::BAD_SIGNATURE:
    case AutoUpdateStatus::NOT_NEWER:
    case AutoUpdateStatus::ROLLOUT_DEFERRED:
    case AutoUpdateStatus::SCRIPT_ORIGIN_REJECTED:
    case AutoUpdateStatus::SCRIPT_HASH_MISSING:
    case AutoUpdateStatus::SCRIPT_HASH_MISMATCH:
    case AutoUpdateStatus::UPDATE_AVAILABLE:
    case AutoUpdateStatus::LAUNCHED:
        return false;
    }
    assert(false);
    return false;
}

AutoUpdateCheckResult CheckForAutoUpdate(const AutoUpdateConfig& config,
                                         AutoUpdateFetcher& fetcher,
                                         AutoUpdateSignatureVerifier& verifier,
                                         AutoUpdateCommandRunner& runner)
{
    AutoUpdateCheckResult result;
    if (!config.enabled) {
        result.status = AutoUpdateStatus::DISABLED;
        return result;
    }
    if (config.release_pubkey.empty()) {
        result.status = AutoUpdateStatus::INVALID_CONFIG;
        result.detail = "missing release pubkey";
        return result;
    }
    if (!AutoUpdateUrlMatchesTrustedOrigin(config.manifest_url, config.trusted_origin, config.dev_origin)) {
        result.status = AutoUpdateStatus::INVALID_CONFIG;
        result.detail = "manifest url outside trusted origin";
        return result;
    }

    const auto manifest_fetch = fetcher.Fetch(AutoUpdateTrackedUrl(config.manifest_url, config), MAX_MANIFEST_BYTES);
    if (!manifest_fetch.ok || manifest_fetch.status != 200 ||
        !AutoUpdateUrlMatchesTrustedOrigin(manifest_fetch.final_url, config.trusted_origin, config.dev_origin)) {
        result.status = AutoUpdateStatus::FETCH_FAILED;
        result.detail = manifest_fetch.error;
        return result;
    }

    const auto manifest = ParseManifest(manifest_fetch.body, config.manifest_url);
    if (!manifest) {
        result.status = AutoUpdateStatus::BAD_MANIFEST;
        return result;
    }
    result.remote_version = manifest->version;
    result.script_url = manifest->script_url;

    if (!AutoUpdateUrlMatchesTrustedOrigin(manifest->sig_url, config.trusted_origin, config.dev_origin)) {
        result.status = AutoUpdateStatus::UNSIGNED_MANIFEST;
        return result;
    }

    const auto signature_fetch = fetcher.Fetch(AutoUpdateTrackedUrl(manifest->sig_url, config), MAX_SIGNATURE_BYTES);
    if (!signature_fetch.ok || signature_fetch.status != 200 ||
        !AutoUpdateUrlMatchesTrustedOrigin(signature_fetch.final_url, config.trusted_origin, config.dev_origin)) {
        result.status = AutoUpdateStatus::UNSIGNED_MANIFEST;
        return result;
    }

    const auto signature = DecodeSignatureBody(signature_fetch.body);
    if (!signature || !verifier.Verify(config.release_pubkey, manifest_fetch.body, *signature)) {
        result.status = SilentStatusForVerifierFailure(!signature.has_value());
        return result;
    }

    if (!AutoUpdateUrlMatchesTrustedOrigin(manifest->script_url, config.trusted_origin, config.dev_origin)) {
        result.status = AutoUpdateStatus::SCRIPT_ORIGIN_REJECTED;
        return result;
    }

    if (CompareAutoUpdateVersion(manifest->version) <= 0) {
        result.status = AutoUpdateStatus::NOT_NEWER;
        return result;
    }

    // Staged/canary gate: the manifest is signed, so rollout_percent is trusted. Apply only if this
    // node's stable cohort is within the rolled-out fraction; otherwise defer (not an error) and the
    // node will re-check on the normal interval as the operator widens the rollout.
    if (const int cohort = AutoUpdateRolloutCohort(config); cohort >= manifest->rollout_percent) {
        result.status = AutoUpdateStatus::ROLLOUT_DEFERRED;
        result.detail = strprintf("cohort %d outside %d%% rollout", cohort, manifest->rollout_percent);
        return result;
    }

    if (config.require_script_hash && !LooksLikeSHA256Hex(manifest->script_sha256)) {
        result.status = AutoUpdateStatus::SCRIPT_HASH_MISSING;
        return result;
    }

    if (!config.seamless) {
        result.status = AutoUpdateStatus::UPDATE_AVAILABLE;
        return result;
    }

    const auto script_fetch = fetcher.Fetch(AutoUpdateTrackedUrl(manifest->script_url, config), MAX_INSTALL_SCRIPT_BYTES);
    if (!script_fetch.ok || script_fetch.status != 200 ||
        !AutoUpdateUrlMatchesTrustedOrigin(script_fetch.final_url, config.trusted_origin, config.dev_origin)) {
        result.status = AutoUpdateStatus::SCRIPT_FETCH_FAILED;
        result.detail = script_fetch.error;
        return result;
    }

    if (LooksLikeSHA256Hex(manifest->script_sha256) && SHA256Hex(script_fetch.body) != manifest->script_sha256) {
        result.status = AutoUpdateStatus::SCRIPT_HASH_MISMATCH;
        return result;
    }

    if (!runner.LaunchInstaller(config, *manifest, script_fetch.body)) {
        result.status = AutoUpdateStatus::LAUNCH_FAILED;
        return result;
    }

    result.status = AutoUpdateStatus::LAUNCHED;
    return result;
}

AutoUpdateManager::AutoUpdateManager(AutoUpdateConfig config,
                                     std::unique_ptr<AutoUpdateFetcher> fetcher,
                                     std::unique_ptr<AutoUpdateSignatureVerifier> verifier,
                                     std::unique_ptr<AutoUpdateCommandRunner> runner)
    : m_config{std::move(config)},
      m_fetcher{std::move(fetcher)},
      m_verifier{std::move(verifier)},
      m_runner{std::move(runner)},
      m_interrupt{std::make_unique<CThreadInterrupt>()}
{
}

AutoUpdateManager::~AutoUpdateManager()
{
    Interrupt();
    Stop();
}

void AutoUpdateManager::Start()
{
    if (m_thread.joinable()) return;
    m_interrupt->reset();
    m_thread = std::thread{&AutoUpdateManager::ThreadLoop, this};
}

void AutoUpdateManager::Interrupt()
{
    if (m_interrupt) (*m_interrupt)();
}

void AutoUpdateManager::Stop()
{
    if (m_thread.joinable()) m_thread.join();
}

void AutoUpdateManager::ThreadLoop()
{
    util::TraceThread("btx-autoupdate", [this] {
        // Add bounded random jitter to the initial delay so a fleet that boots
        // together does not stampede btx.dev / the source repo at the same instant. Keep the jitter
        // bounded separately from the steady-state poll interval so urgent releases are discovered
        // within minutes after restart instead of up to one full interval later.
        int64_t initial_delay = m_config.initial_delay_seconds;
        if (initial_delay > 0 && m_config.initial_jitter_seconds > 0) {
            initial_delay += static_cast<int64_t>(
                FastRandomContext().randrange<uint64_t>(static_cast<uint64_t>(m_config.initial_jitter_seconds)));
        }
        // CThreadInterrupt::sleep_for() returns true when the full duration elapses and false when
        // interrupted, so bail out only on interruption (i.e. when it returns false) -- otherwise the
        // thread would exit immediately after the initial delay and never run a single check.
        if (initial_delay > 0 &&
            !m_interrupt->sleep_for(std::chrono::seconds{initial_delay})) {
            return;
        }

        int64_t failure_backoff{std::max<int64_t>(1, m_config.retry_seconds)};
        while (!*m_interrupt) {
            int64_t next_delay{m_config.interval_seconds};
            const auto result = CheckForAutoUpdate(m_config, *Assert(m_fetcher), *Assert(m_verifier), *Assert(m_runner));
            if (result.status == AutoUpdateStatus::LAUNCHED) {
                LogInfo("Auto-update launched installer for BTX %s\n", result.remote_version);
                failure_backoff = std::max<int64_t>(1, m_config.retry_seconds);
            } else if (result.status == AutoUpdateStatus::UPDATE_AVAILABLE) {
                LogInfo("Auto-update found BTX %s, but seamless mode is disabled\n", result.remote_version);
                failure_backoff = std::max<int64_t>(1, m_config.retry_seconds);
            } else {
                LogDebug(BCLog::AUTOUPDATE, "Auto-update check skipped: %s%s%s\n",
                         AutoUpdateStatusString(result.status),
                         result.detail.empty() ? "" : " ",
                         result.detail);
                if (AutoUpdateStatusIsTransient(result.status)) {
                    next_delay = failure_backoff;
                    failure_backoff = std::min<int64_t>(
                        std::max<int64_t>(std::max<int64_t>(1, m_config.retry_seconds), failure_backoff * 2),
                        MAX_AUTOUPDATE_BACKOFF_SECONDS);
                } else {
                    failure_backoff = std::max<int64_t>(1, m_config.retry_seconds);
                }
            }

            if (!m_interrupt->sleep_for(std::chrono::seconds{next_delay})) return;
        }
    });
}

std::unique_ptr<AutoUpdateManager> MakeAutoUpdateManager(const ArgsManager& args, ChainType chain)
{
    AutoUpdateConfig config;
    config.enabled = args.IsArgSet("-autoupdate") ? args.GetBoolArg("-autoupdate", true) : chain == ChainType::MAIN;
    if (!config.enabled) return nullptr;

    config.seamless = args.GetBoolArg("-autoupdateseamless", true);
    config.dev_origin = args.GetBoolArg("-autoupdatedevorigin", false);
    config.require_script_hash = args.GetBoolArg("-autoupdaterequirescripthash", true);
    config.telemetry = args.GetBoolArg("-autoupdatetelemetry", true);
    config.telemetry_client_id_enabled = args.GetBoolArg("-autoupdatetelemetryclientid", false);
    config.manifest_url = args.GetArg("-autoupdatemanifesturl", std::string{DEFAULT_AUTOUPDATE_MANIFEST_URL});
    config.trusted_origin = args.GetArg("-autoupdatetrustedorigin", std::string{DEFAULT_AUTOUPDATE_TRUSTED_ORIGIN});
    config.release_pubkey = args.GetArg("-autoupdatepubkey", std::string{DEFAULT_AUTOUPDATE_RELEASE_PUBKEY});
    if (config.release_pubkey == "0") config.release_pubkey.clear();
    if (config.release_pubkey.empty()) return nullptr;
    config.release_pubkey_algo = args.GetArg("-autoupdatepubkeyalgo", std::string{DEFAULT_AUTOUPDATE_RELEASE_PUBKEY_ALGO});
    auto verifier = MakeAutoUpdateSignatureVerifier(config.release_pubkey_algo);
    if (!verifier) {
        LogPrintf("Auto-update disabled: unknown release signature scheme \"%s\" (expected ml-dsa-44, slh-dsa-128s, or secp256k1)\n",
                  config.release_pubkey_algo);
        return nullptr;
    }
    config.python_command = args.GetArg("-autoupdatepython", "python3");
    config.interval_seconds = args.GetIntArg("-autoupdateinterval", DEFAULT_AUTOUPDATE_INTERVAL_SECONDS);
    config.initial_delay_seconds = args.GetIntArg("-autoupdateinitialdelay", DEFAULT_AUTOUPDATE_INITIAL_DELAY_SECONDS);
    config.initial_jitter_seconds = args.GetIntArg("-autoupdateinitialjitter", DEFAULT_AUTOUPDATE_INITIAL_JITTER_SECONDS);
    config.retry_seconds = args.GetIntArg("-autoupdateretryinterval", DEFAULT_AUTOUPDATE_RETRY_SECONDS);
    if (args.IsArgSet("-autoupdatecohort")) {
        config.rollout_cohort = std::clamp<int>(args.GetIntArg("-autoupdatecohort", 0), 0, 99);
    }
    config.datadir = args.GetDataDirBase();
    if (config.telemetry && config.telemetry_client_id_enabled) {
        config.telemetry_client_id = GetOrCreateAutoUpdateClientId(config.datadir);
    }
#ifndef WIN32
    config.daemon_pid = getpid();
#endif

    return std::make_unique<AutoUpdateManager>(
        std::move(config),
        std::make_unique<PythonAutoUpdateFetcher>(args.GetArg("-autoupdatepython", "python3")),
        std::move(verifier),
        std::make_unique<DetachedScriptCommandRunner>());
}

std::unique_ptr<AutoUpdateSignatureVerifier> MakeAutoUpdateSignatureVerifier(std::string_view algo)
{
    if (const auto pq_algo = AutoUpdatePQAlgoFromName(algo)) {
        return std::make_unique<PQAutoUpdateSignatureVerifier>(*pq_algo);
    }
    const std::string lower = ToLowerAscii(std::string{algo});
    if (lower == "secp256k1" || lower == "ecdsa") {
        return std::make_unique<Secp256k1AutoUpdateSignatureVerifier>();
    }
    return nullptr;
}

std::optional<size_t> AutoUpdateReleasePubkeyHexLength(std::string_view algo)
{
    if (const auto pq_algo = AutoUpdatePQAlgoFromName(algo)) {
        return GetPQPubKeySize(*pq_algo) * 2;
    }
    const std::string lower = ToLowerAscii(std::string{algo});
    if (lower == "secp256k1" || lower == "ecdsa") {
        return size_t{CPubKey::COMPRESSED_SIZE} * 2;
    }
    return std::nullopt;
}

} // namespace node
