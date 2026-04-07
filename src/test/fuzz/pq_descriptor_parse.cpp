// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <key.h>
#include <script/descriptor.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/chaintype.h>

#include <string>
#include <vector>

void initialize_pq_descriptor_parse()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::MAIN);
}

FUZZ_TARGET(pq_descriptor_parse, .init = initialize_pq_descriptor_parse)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const std::string desc_str = fuzzed_data_provider.ConsumeRandomLengthString(512);

    FlatSigningProvider provider;
    std::string error;
    for (const bool require_checksum : {true, false}) {
        const auto descriptors = Parse(desc_str, provider, error, require_checksum);
        for (const auto& desc : descriptors) {
            if (!desc) continue;
            std::vector<CScript> out_scripts;
            FlatSigningProvider out_provider;
            DescriptorCache cache;
            (void)desc->Expand(0, provider, out_scripts, out_provider, &cache);
            (void)desc->ExpandFromCache(0, cache, out_scripts, out_provider);
        }
    }
}
