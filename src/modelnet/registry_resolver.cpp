// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/registry_resolver.h>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace modelnet {
namespace {

std::string Lower(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string StripScheme(std::string loc)
{
    const auto pos = loc.find("://");
    if (pos != std::string::npos) loc = loc.substr(pos + 3);
    return loc;
}

void TrimSlashes(std::string& s)
{
    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    while (!s.empty() && s.back() == '/') s.pop_back();
}

bool SplitNsName(std::string rest, std::string& ns_name, std::string& err)
{
    TrimSlashes(rest);
    // drop host prefixes
    const std::string hosts[] = {
        "huggingface.co/", "hf.co/", "hf-mirror.com/", "www.modelscope.cn/models/", "modelscope.cn/models/",
        "www.modelscope.cn/", "modelscope.cn/", "www.wisemodel.cn/", "wisemodel.cn/",
        "openxlab.org.cn/models/", "download.openxlab.org.cn/models/", "openxlab.org.cn/",
        "modelers.cn/models/", "www.modelers.cn/models/", "modelers.cn/",
        "gitcode.com/", "www.gitcode.com/", "ai.gitee.com/", "gitee.com/", "openi.org.cn/",
        "www.openi.org.cn/",
    };
    const std::string lower = Lower(rest);
    for (const std::string& h : hosts) {
        const size_t n = h.size();
        if (lower.compare(0, n, h) == 0) {
            rest = rest.substr(n);
            break;
        }
    }
    TrimSlashes(rest);
    // strip /resolve/ /blob/ /tree/ /raw/ tails
    const auto cut_at = rest.find("/resolve/");
    const auto cut_blob = rest.find("/blob/");
    const auto cut_tree = rest.find("/tree/");
    const auto cut_raw = rest.find("/raw/");
    size_t cut = std::string::npos;
    for (size_t c : {cut_at, cut_blob, cut_tree, cut_raw}) {
        if (c != std::string::npos && (cut == std::string::npos || c < cut)) cut = c;
    }
    if (cut != std::string::npos) rest = rest.substr(0, cut);
    TrimSlashes(rest);
    if (rest.empty() || rest.find(' ') != std::string::npos) {
        err = "locator";
        return false;
    }
    ns_name = rest;
    return true;
}

} // namespace

std::vector<std::string> KnownRegistryOriginTypes()
{
    return {"huggingface", "hf-mirror", "modelscope", "wisemodel", "openxlab", "modelers",
            "gitcode",     "gitee",     "openi",      "oci",       "http"};
}

std::string RegistryUrlEncode(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size() * 3);
    static const char* hex = "0123456789ABCDEF";
    for (unsigned char c : raw) {
        const bool unres = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
                           c == '_' || c == '.' || c == '~' || c == '/';
        if (unres) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xf]);
        }
    }
    return out;
}

bool NormalizeRepoLocator(const std::string& type, const std::string& locator, std::string& ns_name, std::string& err)
{
    (void)type;
    if (locator.empty()) {
        err = "locator";
        return false;
    }
    std::string rest = locator;
    if (rest.rfind("hf://", 0) == 0) rest = rest.substr(5);
    else if (rest.rfind("ms://", 0) == 0) rest = rest.substr(5);
    else if (rest.rfind("wisemodel://", 0) == 0) rest = rest.substr(12);
    else if (rest.rfind("openxlab://", 0) == 0) rest = rest.substr(11);
    else if (rest.rfind("modelers://", 0) == 0) rest = rest.substr(11);
    else if (rest.rfind("gitcode://", 0) == 0) rest = rest.substr(10);
    else if (rest.rfind("gitee://", 0) == 0) rest = rest.substr(8);
    else if (rest.rfind("openi://", 0) == 0) rest = rest.substr(8);
    else if (rest.rfind("oci://", 0) == 0) rest = rest.substr(6);
    else if (rest.rfind("docker://", 0) == 0) rest = rest.substr(9);
    else rest = StripScheme(rest);
    return SplitNsName(rest, ns_name, err);
}

bool ResolveRegistryFileUrl(const std::string& type, const std::string& locator, const std::string& revision,
                            const std::string& filepath, ResolvedRegistryUrl& out, std::string& err)
{
    out = {};
    out.type = type;
    out.revision = revision.empty() ? "main" : revision;
    if (filepath.empty()) {
        err = "filepath";
        return false;
    }
    const std::string t = Lower(type);
    const std::string file_enc = RegistryUrlEncode(filepath);
    const std::string rev_enc = RegistryUrlEncode(out.revision);

    if (t == "http" || t == "https") {
        std::string base = locator;
        TrimSlashes(base);
        if (base.rfind("http://", 0) != 0 && base.rfind("https://", 0) != 0) {
            err = "locator";
            return false;
        }
        out.url = base + "/" + file_enc;
        const auto host_begin = out.url.find("://");
        std::string hostpart = host_begin == std::string::npos ? out.url : out.url.substr(host_begin + 3);
        const auto slash = hostpart.find('/');
        out.host = slash == std::string::npos ? hostpart : hostpart.substr(0, slash);
        return true;
    }

    std::string ns_name;
    if (!NormalizeRepoLocator(t, locator, ns_name, err)) return false;
    const std::string ns_enc = RegistryUrlEncode(ns_name);

    if (t == "huggingface" || t == "hf") {
        out.url = "https://huggingface.co/" + ns_enc + "/resolve/" + rev_enc + "/" + file_enc;
        out.host = "huggingface.co";
        out.type = "huggingface";
        return true;
    }
    if (t == "hf-mirror" || t == "hfmirror") {
        out.url = "https://hf-mirror.com/" + ns_enc + "/resolve/" + rev_enc + "/" + file_enc;
        out.host = "hf-mirror.com";
        out.type = "hf-mirror";
        return true;
    }
    if (t == "modelscope") {
        out.url = "https://www.modelscope.cn/api/v1/models/" + ns_enc + "/repo?Revision=" + rev_enc +
                  "&FilePath=" + file_enc;
        out.host = "www.modelscope.cn";
        return true;
    }
    if (t == "wisemodel") {
        out.url = "https://www.wisemodel.cn/" + ns_enc + "/resolve/" + rev_enc + "/" + file_enc;
        out.host = "www.wisemodel.cn";
        return true;
    }
    if (t == "openxlab") {
        out.url = "https://download.openxlab.org.cn/models/" + ns_enc + "/raw/" + rev_enc + "/" + file_enc;
        out.host = "download.openxlab.org.cn";
        return true;
    }
    if (t == "modelers") {
        out.url = "https://modelers.cn/" + ns_enc + "/resolve/" + rev_enc + "/" + file_enc;
        out.host = "modelers.cn";
        return true;
    }
    if (t == "gitcode") {
        out.url = "https://gitcode.com/" + ns_enc + "/raw/" + rev_enc + "/" + file_enc;
        out.host = "gitcode.com";
        return true;
    }
    if (t == "gitee") {
        out.url = "https://ai.gitee.com/" + ns_enc + "/resolve/" + rev_enc + "/" + file_enc;
        out.host = "ai.gitee.com";
        return true;
    }
    if (t == "openi") {
        out.url = "https://openi.org.cn/" + ns_enc + "/raw/" + rev_enc + "/" + file_enc;
        out.host = "openi.org.cn";
        return true;
    }
    if (t == "oci" || t == "kitops" || t == "modelpack") {
        std::string rest = locator;
        if (rest.rfind("oci://", 0) == 0) rest = rest.substr(6);
        if (rest.rfind("docker://", 0) == 0) rest = rest.substr(9);
        if (rest.rfind("https://", 0) == 0) rest = rest.substr(8);
        if (rest.rfind("http://", 0) == 0) rest = rest.substr(7);
        TrimSlashes(rest);
        std::string host = "ghcr.io";
        std::string repo = rest;
        const auto slash = rest.find('/');
        if (slash != std::string::npos) {
            const std::string maybe_host = rest.substr(0, slash);
            if (maybe_host.find('.') != std::string::npos || maybe_host == "localhost") {
                host = maybe_host;
                repo = rest.substr(slash + 1);
            }
        }
        TrimSlashes(repo);
        const bool digest = out.revision.rfind("sha256:", 0) == 0 || out.revision.rfind("sha384:", 0) == 0;
        const std::string ref = digest ? ("blobs/" + out.revision) : ("manifests/" + rev_enc);
        out.url = "https://" + host + "/v2/" + RegistryUrlEncode(repo) + "/" + ref;
        if (!filepath.empty() && filepath != "model.safetensors") {
            out.url += "?layer=" + file_enc;
        }
        out.host = host;
        out.type = "oci";
        return true;
    }
    err = "origin type";
    return false;
}

} // namespace modelnet
