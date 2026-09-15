// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qualification.h>

#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "usage: btx-modelcheck <file>\n"
                     "Static qualification only. Does not prove usefulness, safety, or alignment.\n"
                     "Does not load the whole file into RAM.\n";
        return 1;
    }
    const std::string path = argv[1];
    modelnet::QualReport report;
    modelnet::QualifyFile(path, report);
    std::cout << modelnet::QualResultName(report.result) << " " << modelnet::AdmissionLevelName(report.level)
              << " " << report.detail << "\n";
    return report.result == modelnet::QualResult::REJECTED_UNSAFE_FORMAT ||
                   report.result == modelnet::QualResult::INVALID_MODEL
               ? 2
               : 0;
}
