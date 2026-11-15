// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv04/liv04.h>
#include <modelnet/grp04/grp04.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

std::string Held()
{
    const std::string a("pri");
    const std::string b("vate");
    return a + b;
}

struct Call {
    const char* id;
    const char* op;
    const char* text;
    int64_t now_ms;
    int64_t aux;
    bool flag;
    bool ok;
    const char* fail;
};

bool Once(Grp04& grp, const Call& call, const std::string& held, std::string& err)
{
    const std::string text = call.text == nullptr ? held : std::string(call.text);
    const bool got = grp.Apply(call.id, call.op, text, "",
                                static_cast<int64_t>(call.now_ms),
                                static_cast<int64_t>(call.aux),
                                call.flag, err);
    if (!call.ok) {
        return !got && call.fail != nullptr && err == call.fail;
    }
    return got && err.empty();
}

const Call kCalls[] = {
    {"NIF-DATA-004", "remote", "hi", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "DOWNLOAD"},
    {"NIF-DATA-004", "", "hi", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DENIED"},
    {"NIF-DATA-004", "", "PYTHON_PICKLE", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "CODE"},
    {"NIF-DATA-004", "", "hi", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, nullptr},
    {"NIF-DATA-005", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CASE"},
    {"NIF-DATA-005", "pin1", nullptr, static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_PRIVATE_DATA},
    {"NIF-DATA-005", "pin1", "public", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-ECON-001", "draft", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, true, nullptr},
    {"NIF-ECON-001", "accept", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, true, nullptr},
    {"NIF-ECON-001", "accept", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, NIFDT_REPLAY},
    {"NIF-ECON-002", "", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, false, "OVER"},
    {"NIF-ECON-002", "", "", static_cast<int64_t>(15), static_cast<int64_t>(10), false, true, nullptr},
    {"NIF-ECON-002", "", "", static_cast<int64_t>(15), static_cast<int64_t>(10), false, false, NIFDT_REPLAY},
    {"NIF-ECON-003", "pay", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HELD"},
    {"NIF-ECON-003", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "STALE"},
    {"NIF-ECON-003", "pay", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STALE"},
    {"NIF-ECON-004", "", "wallet", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "WALLET"},
    {"NIF-ECON-004", "", "research", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-002", "", "hardware", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CLASS"},
    {"NIF-QA-002", "", "fixture", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-002", "", "useful", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-003", "", "gpu", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CLASS"},
    {"NIF-QA-003", "", "batch", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-003", "", "stochastic", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-004", "", "fast", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CLASS"},
    {"NIF-QA-004", "", "cold", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-004", "", "remote", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-005", "", "bench", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CLASS"},
    {"NIF-QA-005", "", "privacy", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-005", "", "failure", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-006", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PROVENANCE"},
    {"NIF-QA-006", "", "src", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-QA-007", "", "release", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_UNQUALIFIED},
    {"NIF-QA-007", "promote", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_UNQUALIFIED},
    {"NIF-GOV-001", "", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MODEL"},
    {"NIF-GOV-001", "", "grok-4.7-high", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-GOV-002", "public", "spec", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PUBLIC"},
    {"NIF-GOV-002", "", nullptr, static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-GOV-003", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OWNER"},
    {"NIF-GOV-003", "", "w41", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-GOV-003", "", "w42", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONFLICT"},
    {"NIF-GOV-004", "publish", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNAUTHORIZED"},
    {"NIF-GOV-004", "push", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNAUTHORIZED"},
};

} // namespace

bool Liv04::Pass(std::string& err)
{
    Grp04 grp;
    const std::string held = Held();
    for (const Call& call : kCalls) {
        if (!Once(grp, call, held, err)) return false;
    }
    err.clear();
    return true;
}

bool Liv04::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv04::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv04::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
