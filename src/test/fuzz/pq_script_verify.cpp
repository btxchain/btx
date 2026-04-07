// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <vector>

void initialize_pq_script_verify()
{
    static ECC_Context ecc_context{};
}

FUZZ_TARGET(pq_script_verify, .init = initialize_pq_script_verify)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    std::vector<unsigned char> program = fuzzed_data_provider.ConsumeBytes<unsigned char>(32);
    if (program.size() < 32) program.resize(32, 0);
    const CScript script_pubkey = CScript{} << OP_2 << program;
    const std::vector<unsigned char> script_sig_bytes = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 64));
    const CScript script_sig(script_sig_bytes.begin(), script_sig_bytes.end());

    CScriptWitness witness;
    const size_t stack_items = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 8);
    witness.stack.reserve(stack_items);
    for (size_t i = 0; i < stack_items; ++i) {
        witness.stack.push_back(fuzzed_data_provider.ConsumeBytes<unsigned char>(
            fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 2048)));
    }

    ScriptError err = SCRIPT_ERR_OK;
    (void)VerifyScript(
        script_sig,
        script_pubkey,
        &witness,
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_NULLFAIL,
        BaseSignatureChecker{},
        &err);
}
