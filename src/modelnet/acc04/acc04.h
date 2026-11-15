// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC04_ACC04_H
#define BITCOIN_MODELNET_ACC04_ACC04_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Acc04. Pass latches the in-process checks for ASR-PAY-001 through
 * ASR-PUB-004. A later Pass clears err and returns true without repeating
 * those calls.
 *
 * ASR-PAY-001 calls SwarmPayReg::Open and Reserve. The same outpoint cannot
 * fund a second pool. ASR-PAY-002 calls Claim and FailCompute and keeps the
 * claim. ASR-PAY-003 calls Terms and refuses a later atom or timeout change.
 * ASR-PAY-004 calls Settle, which stays NIFDT_UNQUALIFIED.
 * ASR-PRT-001 calls AcceptCanonicalEnvelope and StrictParseJson. A duplicate
 * key is not an envelope. ASR-PRT-002 calls LeaseTable::Cancel while work is
 * still in flight, then ReleaseIfQuiescent, which stays refused.
 * ASR-RES-001 calls HostResourceBroker::Configure and Reserve on one ceiling.
 * ASR-RES-002 calls UploadScheduler::Admit with a per-identity cap and a
 * finite slot count. ASR-SEC-001 calls SwarmTrustLabel. A self-declared
 * label does not replace the policy label. ASR-SEC-002 calls NifScope on
 * the default local policy and SendWan, which has no route.
 * ASR-REC-001 calls SwarmRecoverFault02 with a durable payment claim.
 * ASR-REC-002 calls SwarmCommandLog::Append, Commit, and Truncate. A
 * committed index cannot be removed. ASR-OBS-001 calls SwarmProbeEngine and
 * SwarmQualifyEngine. Advertised and qualified stay false. ASR-MIG-001 and
 * ASR-MIG-002 call MigrateSafe::Move. A higher assurance is refused, and
 * Fail keeps the stored body. ASR-ACC-001 stays on hosts() 1. ASR-ACC-002
 * calls SwarmProbeEngine on a missing file and Gpu. ASR-PUB-001 calls
 * SafeGitPath on a path that enters a git directory. ASR-PUB-002 calls
 * GitObjectDigest and RefJournal::AuthorizeAndStage and Publish. ASR-PUB-003
 * calls DocClaim::Claim on a qualification sentence. ASR-PUB-004 calls
 * SwarmNoteNotTrainLicense and VerifyProvenanceEvidence.
 *
 * final_acceptance() is CLOSED_IN_PROCESS, DEFINED_NEEDS_PROCESS, or
 * UNQUALIFIED for those ids, and empty for any other id. Apply stores
 * nothing and returns ID.
 * passed(), gpu_passed(), windows_passed(), release_qualified(), and
 * hardware_qualified() stay false. qualified(), advertised(), launched(),
 * gpu(), and broadcast() stay false. hosts() and physical_hosts() stay 1.
 * Hosts with n other than 1 returns HOSTS. bytes_moved() stays 0.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * The temporary log directory is removed before Pass returns.
 */
class Acc04 {
public:
    bool Pass(std::string& err);
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    const char* final_acceptance(const std::string& id) const;
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err) const;
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif
