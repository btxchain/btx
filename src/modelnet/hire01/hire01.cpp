// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hire01/hire01.h>
#include <modelnet/swarm_native_io.h>
#include <modelnet/swarm_process_guard.h>
#include <modelnet/swarm_windows_sandbox.h>
#include <modelnet/identity.h>
#include <univalue.h>
#include <set>
#include <utility>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstdint>
#include <string>

namespace modelnet {

bool Hire01::QualifyModified(const std::string& model_id, bool external_controls, bool outcome_tested, std::string& err)
{
    if (model_id.empty()) {
        err = "FIELD";
        return false;
    }
    // Controls are recorded only when both checks are present.
    if (!external_controls || !outcome_tested) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    m_native_qualified = false; m_issued = false;
    m_gates.clear(); m_probes.clear(); m_release_digest.clear();
    m_model_id = model_id;
    err.clear();
    return true;
}

bool Hire01::AdvertiseWarm(const std::string& pool, int64_t slots, bool measured, std::string& err)
{
    if (pool.empty() || slots < static_cast<int64_t>(0)) {
        err = "FIELD";
        return false;
    }
    // Unmeasured capacity is not an advertisement.
    if (!measured) {
        err = "CAPACITY";
        return false;
    }
    m_slots = slots;
    m_advertised = true;
    err.clear();
    return true;
}

bool Hire01::IssueRelease(const std::string& version, bool gates_passed, std::string& err)
{
    if (version.empty()) {
        err = "FIELD";
        return false;
    }
    // This module does not issue a release, with or without gates.
    if (!gates_passed) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

int64_t Hire01::advertised_slots() const
{
    if (!m_advertised) return static_cast<int64_t>(0);
    return m_slots;
}

namespace {
const std::set<std::string> REQUIRED_DEFENSIVE_GATES{
    "external-controls", "outcome", "revocation", "rollback", "privacy", "adversarial"};
bool HexText(const std::string& value, size_t length)
{
    return value.size() == length && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
std::string BytesHex(const std::vector<unsigned char>& bytes)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string result; result.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) { result += hex[c >> 4]; result += hex[c & 15]; }
    return result;
}
bool WriteReleaseExclusive(const fs::path& path, const std::string& body, std::string& err)
{
    if (!path.is_absolute() || path.filename().empty() || !process_guard::NoSymlinkPath(path.parent_path())) {
        err = "RELEASE_PATH"; return false;
    }
#ifndef _WIN32
    std::string pattern = fs::PathToString(path.parent_path() / ".btx-defensive-release-XXXXXX");
    std::vector<char> temporary(pattern.begin(), pattern.end()); temporary.push_back('\0');
    const int fd = mkstemp(temporary.data());
    if (fd < 0) { err = "RELEASE_CREATE"; return false; }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    size_t written = 0;
    bool ok = true;
    while (written < body.size()) {
        const ssize_t n = write(fd, body.data() + written, body.size() - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        written += static_cast<size_t>(n);
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    // link() is atomic and refuses to replace a previous release or symlink.
    if (ok && link(temporary.data(), path.c_str()) != 0) ok = false;
    unlink(temporary.data());
    if (ok) {
        const int dir = open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir < 0 || fsync(dir) != 0) ok = false;
        if (dir >= 0) close(dir);
    }
    if (!ok) { err = "RELEASE_WRITE_OR_EXISTS"; return false; }
    err.clear(); return true;
#else
    return WriteWindowsReleaseExclusive(path,body,err);
#endif
}
}
bool Hire01::QualifyModifiedNative(const DefensiveReleasePolicy& policy,
                                   const std::vector<DefensiveGateProbe>& probes,
                                   int64_t now_ms, std::string& err)
{
    m_native_qualified = false; m_issued = false; m_release_digest.clear(); m_gates.clear(); m_probes.clear();
    if (!native_io::IsDigest(policy.model_id) || !native_io::IsDigest(policy.model_sha384) ||
        !native_io::IsDigest(policy.parent_model_sha384) || policy.parent_model_sha384 == policy.model_sha384 ||
        !native_io::IsDigest(policy.controls_sha384) || !native_io::IsDigest(policy.runtime_image_sha384) ||
        !native_io::IsDigest(policy.realm_id) || !HexText(policy.source_revision, 40) ||
        policy.release_public_key.size() != MLDSA44_PK || policy.expires_at_ms <= now_ms || now_ms < 0 ||
        policy.expires_at_ms - now_ms > 24LL * 3600 * 1000 || probes.size() != REQUIRED_DEFENSIVE_GATES.size()) {
        err = "DEFENSIVE_POLICY"; return false;
    }
    std::vector<unsigned char> model;
    if (!native_io::ReadVerified(fs::PathFromString(policy.model_path), policy.model_sha384,
                                policy.model_bytes, policy.max_model_bytes, model, err)) return false;
    std::set<std::string> seen;
    // Validate the full requested plan before executing even its first probe.
    for (const auto& gate : probes) {
        if (!REQUIRED_DEFENSIVE_GATES.count(gate.gate_id) || !seen.insert(gate.gate_id).second) {
            err = "DEFENSIVE_GATE_SET"; return false;
        }
        bool model_present = false, controls_present = false, runtime_present = false;
        for (const auto& file : gate.probe.files) {
            model_present |= file.sha384 == policy.model_sha384 && file.bytes == policy.model_bytes;
            controls_present |= file.sha384 == policy.controls_sha384;
            runtime_present |= file.sha384 == policy.runtime_image_sha384;
        }
        if (!model_present || !controls_present || !runtime_present) { err = "DEFENSIVE_UNBOUND_PROBE"; return false; }
    }
    std::map<std::string, NativeToolEvidence> evidence;
    for (const auto& gate : probes) {
        Cap02 runner;
        if (!runner.QualifyNative(gate.probe, err) || !runner.native_qualified()) return false;
        evidence.emplace(gate.gate_id, runner.native_evidence());
    }
    m_policy = policy; m_probes = probes; m_gates = std::move(evidence);
    m_model_id = policy.model_id; m_native_qualified = true;
    err.clear(); return true;
}
bool Hire01::IssueReleaseNative(const std::string& version, const std::string& output_path,
                                const std::vector<unsigned char>& release_secret_key,
                                int64_t now_ms, std::string& err)
{
    if (!m_native_qualified || m_issued || now_ms < 0 || now_ms >= m_policy.expires_at_ms ||
        version.empty() || version.size() > 128 ||
        !std::all_of(version.begin(), version.end(), [](unsigned char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        }) || release_secret_key.size() != MLDSA44_SK) {
        err = "DEFENSIVE_RELEASE_AUTHORITY"; return false;
    }
    // Stale or substituted files invalidate qualification before signing.
    std::vector<unsigned char> bytes;
    if (!native_io::ReadVerified(fs::PathFromString(m_policy.model_path), m_policy.model_sha384,
                                m_policy.model_bytes, m_policy.max_model_bytes, bytes, err)) {
        m_native_qualified = false; return false;
    }
    for (const auto& gate : m_probes) {
        const fs::path root = fs::PathFromString(gate.probe.root);
        for (const auto& file : gate.probe.files) {
            if (!native_io::ReadVerified(root / fs::PathFromString(file.relative_path), file.sha384,
                                        file.bytes, gate.probe.max_package_bytes, bytes, err)) {
                m_native_qualified = false; return false;
            }
        }
        if (!native_io::ReadVerified(root / fs::PathFromString(gate.probe.output_relative_path),
                                    gate.probe.expected_output_sha384, gate.probe.expected_output_bytes,
                                    16 * 1024 * 1024, bytes, err)) {
            m_native_qualified = false; return false;
        }
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("schema", "BTX/DefensiveLearningRelease/v1");
    body.pushKV("scope", "EXACT_MODEL_AND_LISTED_GATES");
    body.pushKV("version", version); body.pushKV("model_id", m_policy.model_id);
    body.pushKV("model_sha384", m_policy.model_sha384); body.pushKV("model_bytes", m_policy.model_bytes);
    body.pushKV("parent_model_sha384", m_policy.parent_model_sha384);
    body.pushKV("controls_sha384", m_policy.controls_sha384);
    body.pushKV("runtime_image_sha384", m_policy.runtime_image_sha384);
    body.pushKV("source_revision", m_policy.source_revision); body.pushKV("realm_id", m_policy.realm_id);
    body.pushKV("issued_at_ms", now_ms); body.pushKV("expires_at_ms", m_policy.expires_at_ms);
    body.pushKV("automatic_spend_atoms", "0"); body.pushKV("btx_deployment_qualified", false);
    UniValue gates(UniValue::VARR);
    for (const auto& [id, observed] : m_gates) {
        UniValue gate(UniValue::VOBJ); gate.pushKV("gate_id", id);
        gate.pushKV("package_sha384", observed.package_sha384);
        gate.pushKV("executable_sha384", observed.executable_sha384);
        gate.pushKV("output_sha384", observed.output_sha384);
        gate.pushKV("operating_system", observed.operating_system); gate.pushKV("architecture", observed.architecture);
        gate.pushKV("exit_code", observed.exit_code); gate.pushKV("elapsed_ms", observed.elapsed_ms);
        gates.push_back(gate);
    }
    body.pushKV("gates", gates);
    const std::string canonical = body.write(0, 0);
    std::vector<unsigned char> message;
    native_io::AppendField(message, "BTX/DefensiveLearningReleaseSignature/v1");
    native_io::AppendField(message, canonical);
    std::vector<unsigned char> signature;
    if (!SignMlDsa44(release_secret_key, message, signature, err) ||
        !VerifyMlDsa44(m_policy.release_public_key, message, signature)) {
        err = "DEFENSIVE_RELEASE_SIGNATURE"; return false;
    }
    UniValue document(UniValue::VOBJ); document.pushKV("release", body);
    document.pushKV("signing_public_key", BytesHex(m_policy.release_public_key));
    document.pushKV("signature", BytesHex(signature));
    const std::string encoded = document.write(0, 0) + "\n";
    if (!WriteReleaseExclusive(fs::PathFromString(output_path), encoded, err)) return false;
    m_release_digest = native_io::Digest(std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size()});
    m_issued = true; err.clear(); return true;
}
} // namespace modelnet
