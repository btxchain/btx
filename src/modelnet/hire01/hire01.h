// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifndef BITCOIN_MODELNET_HIRE01_HIRE01_H
#define BITCOIN_MODELNET_HIRE01_HIRE01_H
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/cap02/cap02.h>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {
struct DefensiveReleasePolicy {
    std::string model_id;
    std::string model_path;
    std::string model_sha384;
    uint64_t model_bytes{0};
    uint64_t max_model_bytes{1024ULL * 1024 * 1024};
    std::string parent_model_sha384;
    std::string controls_sha384;
    std::string source_revision;
    std::string runtime_image_sha384;
    std::string realm_id;
    int64_t expires_at_ms{0};
    std::vector<unsigned char> release_public_key;
};
struct DefensiveGateProbe {
    std::string gate_id;
    NativeToolProbe probe;
};
/**
 * Legacy boolean APIs only record descriptions; they cannot mint a release.
 * QualifyModifiedNative runs six actual, owner-pinned external probe programs
 * in a filesystem/network sandbox: external-controls, outcome, revocation,
 * rollback, privacy and adversarial. Each probe package must include the exact
 * model, controls and runtime image bytes. IssueReleaseNative revalidates artifacts, signs a
 * bounded release manifest with the pinned research key and writes it without
 * replacement. A signed model release is scoped to these gates and this exact
 * model; it does not qualify the full BTX deployment or authorize payments.
 */
class Hire01 {
public:
    bool QualifyModified(const std::string& model_id, bool external_controls, bool outcome_tested, std::string& err);
    bool AdvertiseWarm(const std::string& pool, int64_t slots, bool measured, std::string& err);
    bool IssueRelease(const std::string& version, bool gates_passed, std::string& err);
    bool QualifyModifiedNative(const DefensiveReleasePolicy& policy,
                              const std::vector<DefensiveGateProbe>& probes, int64_t now_ms, std::string& err);
    bool IssueReleaseNative(const std::string& version, const std::string& output_path,
                            const std::vector<unsigned char>& release_secret_key,
                            int64_t now_ms, std::string& err);
    const std::map<std::string, NativeToolEvidence>& gate_evidence() const { return m_gates; }
    const std::string& release_document_sha384() const { return m_release_digest; }
    std::string model_id() const { return m_model_id; }
    int64_t advertised_slots() const;
    bool release_issued() const { return m_issued; }
    bool passed() const { return m_native_qualified; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    bool release_qualified() const { return m_issued && m_native_qualified; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
private:
    std::string m_model_id;
    int64_t m_slots{0};
    bool m_advertised{false};
    bool m_native_qualified{false};
    bool m_issued{false};
    DefensiveReleasePolicy m_policy;
    std::vector<DefensiveGateProbe> m_probes;
    std::map<std::string, NativeToolEvidence> m_gates;
    std::string m_release_digest;
};
} // namespace modelnet
#endif
