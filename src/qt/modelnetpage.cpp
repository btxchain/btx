// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/modelnetpage.h>
#include <qt/forms/ui_modelnetpage.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <common/args.h>
#include <interfaces/node.h>
#include <univalue.h>

#ifdef ENABLE_MODELNET
#include <modelnet/firstrun.h>
#include <modelnet/resource_uri.h>
#endif

#include <QFileDialog>
#include <QComboBox>
#include <QHBoxLayout>
#include <QObject>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace {

QString FormatProfileLabel(const UniValue& model)
{
    if (model.exists("format") && model["format"].isStr()) {
        return QString::fromStdString(model["format"].get_str());
    }
    if (model.exists("format_profile")) {
        const int fp = model["format_profile"].getInt<int>();
        if (fp == 2) return QStringLiteral("GGUF");
        if (fp == 1) return QStringLiteral("SafeTensors");
    }
    return QStringLiteral("—");
}

QString HumanBytes(int64_t bytes)
{
    if (bytes < 0) return QStringLiteral("—");
    if (bytes < 1024) return QString::number(bytes) + QStringLiteral(" B");
    const double kb = bytes / 1024.0;
    if (kb < 1024.0) return QString::number(kb, 'f', 1) + QStringLiteral(" KiB");
    const double mb = kb / 1024.0;
    if (mb < 1024.0) return QString::number(mb, 'f', 1) + QStringLiteral(" MiB");
    const double gb = mb / 1024.0;
    return QString::number(gb, 'f', 2) + QStringLiteral(" GiB");
}

int64_t ModelByteSize(const UniValue& model)
{
    if (model.exists("size_bytes")) return model["size_bytes"].getInt<int64_t>();
    if (model.exists("bytes")) return model["bytes"].getInt<int>();
    if (model.exists("size")) return model["size"].getInt<int>();
    return -1;
}

const UniValue* NestedAvailability(const UniValue& model)
{
    if (model.exists("availability") && model["availability"].isObject()) {
        return &model["availability"];
    }
    return nullptr;
}

QString ModelDisplayName(const UniValue& model)
{
    if (model.exists("name") && model["name"].isStr()) {
        return QString::fromStdString(model["name"].get_str());
    }
    if (model.exists("label") && model["label"].isStr()) {
        return QString::fromStdString(model["label"].get_str());
    }
    if (model.exists("model") && model["model"].isObject() && model["model"]["name"].isStr()) {
        return QString::fromStdString(model["model"]["name"].get_str());
    }
    if (model.exists("display_name") && model["display_name"].isStr()) {
        return QString::fromStdString(model["display_name"].get_str());
    }
    return QStringLiteral("—");
}

QString ProvidersLine(const UniValue& model)
{
    if (const UniValue* av = NestedAvailability(model)) {
        const int total = av->exists("providers_total") ? (*av)["providers_total"].getInt<int>() : 0;
        const int complete = av->exists("providers_complete") ? (*av)["providers_complete"].getInt<int>() : 0;
        const int partial = av->exists("providers_partial") ? (*av)["providers_partial"].getInt<int>() : 0;
        return QObject::tr("providers %1 (complete %2, partial %3)").arg(total).arg(complete).arg(partial);
    }
    if (model.exists("providers_total")) {
        const int total = model["providers_total"].getInt<int>();
        const int complete = model.exists("providers_complete") ? model["providers_complete"].getInt<int>() : 0;
        const int partial = model.exists("providers_partial") ? model["providers_partial"].getInt<int>() : 0;
        return QObject::tr("providers %1 (complete %2, partial %3)").arg(total).arg(complete).arg(partial);
    }
    if (model.exists("observed_sources")) {
        return QObject::tr("observed_sources %1").arg(model["observed_sources"].getInt<int>());
    }
    return QStringLiteral("—");
}

QString AvailabilityLine(const UniValue& model)
{
    if (const UniValue* av = NestedAvailability(model)) {
        if (av->exists("class") && (*av)["class"].isStr()) {
            return QString::fromStdString((*av)["class"].get_str());
        }
        if (av->exists("reconstructable")) {
            const bool recon = (*av)["reconstructable"].get_bool();
            const bool fragile = av->exists("fragile") && (*av)["fragile"].get_bool();
            if (fragile) return QStringLiteral("fragile");
            return recon ? QStringLiteral("reconstructable") : QStringLiteral("partial");
        }
    }
    if (model.exists("availability_class") && model["availability_class"].isStr()) {
        return QString::fromStdString(model["availability_class"].get_str());
    }
    if (model.exists("availability") && model["availability"].isStr()) {
        return QString::fromStdString(model["availability"].get_str());
    }
    if (model.exists("complete")) {
        return model["complete"].get_bool() ? QStringLiteral("complete") : QStringLiteral("partial");
    }
    return QStringLiteral("—");
}

QString PublisherLine(const UniValue& model)
{
    if (model.exists("publisher") && model["publisher"].isObject()) {
        const UniValue& pub = model["publisher"];
        if (pub.exists("display_name") && pub["display_name"].isStr()) {
            const std::string dn = pub["display_name"].get_str();
            if (!dn.empty()) return QString::fromStdString(dn);
        }
        if (pub.exists("id") && pub["id"].isStr()) {
            return QString::fromStdString(pub["id"].get_str());
        }
    }
    if (model.exists("publisher") && model["publisher"].isStr()) {
        return QString::fromStdString(model["publisher"].get_str());
    }
    return QStringLiteral("—");
}

bool ModelMatchesFormatFilter(const UniValue& model, const std::string& filter)
{
    const QString fmt = FormatProfileLabel(model);
    if (filter == "GGUF") return fmt.compare(QStringLiteral("GGUF"), Qt::CaseInsensitive) == 0;
    if (filter == "SafeTensors") {
        return fmt.compare(QStringLiteral("SafeTensors"), Qt::CaseInsensitive) == 0;
    }
    return true;
}

bool ModelMatchesNeedle(const UniValue& model, const QString& needle_lower)
{
    if (needle_lower.isEmpty()) return true;
    const QString name = ModelDisplayName(model).toLower();
    if (name.contains(needle_lower)) return true;
    const QString uri = QString::fromStdString(model.write()).toLower();
    return uri.contains(needle_lower);
}

UniValue FilterModelsArray(const UniValue& models, const QString& needle_lower, const std::optional<std::string>& format_filter)
{
    UniValue out(UniValue::VARR);
    if (!models.isArray()) return out;
    for (const auto& m : models.getValues()) {
        if (format_filter && !ModelMatchesFormatFilter(m, *format_filter)) continue;
        if (!ModelMatchesNeedle(m, needle_lower)) continue;
        out.push_back(m);
    }
    return out;
}

QString UniStrField(const UniValue& obj, const char* key)
{
    if (obj.exists(key) && obj[key].isStr()) {
        return QString::fromStdString(obj[key].get_str());
    }
    return {};
}

QString FormatPercentField(const UniValue& v)
{
    if (v.isNull()) return {};
    if (v.isStr()) {
        QString s = QString::fromStdString(v.get_str()).trimmed();
        if (s.isEmpty()) return {};
        if (!s.contains(QLatin1Char('%'))) s += QLatin1Char('%');
        return s;
    }
    if (v.isNum()) {
        const double d = v.get_real();
        QString s = QString::number(d, 'f', 1);
        if (s.endsWith(QStringLiteral(".0"))) s.chop(2);
        return s + QLatin1Char('%');
    }
    return {};
}

QString FormatBytesPerSecField(const UniValue& v)
{
    if (v.isNull()) return {};
    if (v.isNum()) {
        return HumanBytes(static_cast<int64_t>(v.get_real())) + QStringLiteral("/s");
    }
    if (v.isStr()) {
        const QString s = QString::fromStdString(v.get_str()).trimmed();
        if (s.isEmpty()) return {};
        return s.contains(QLatin1Char('/')) ? s : s + QStringLiteral("/s");
    }
    return {};
}

QString TransferRateSuffix(const UniValue& obj)
{
    if (!obj.isObject()) return {};
    QStringList bits;
    if (obj.exists("percent") && !obj["percent"].isNull()) {
        const QString p = FormatPercentField(obj["percent"]);
        if (!p.isEmpty()) bits << p;
    }
    if (obj.exists("bytes_per_sec") && !obj["bytes_per_sec"].isNull()) {
        const QString r = FormatBytesPerSecField(obj["bytes_per_sec"]);
        if (!r.isEmpty()) bits << r;
    }
    return bits.join(QStringLiteral(" · "));
}

QString TransferRateSuffixFromRow(const UniValue& row)
{
    if (!row.isObject()) return {};
    QString s = TransferRateSuffix(row);
    if (!s.isEmpty()) return s;
    if (row.exists("share") && row["share"].isObject()) {
        s = TransferRateSuffix(row["share"]);
        if (!s.isEmpty()) return s;
    }
    if (row.exists("job") && row["job"].isObject()) {
        s = TransferRateSuffix(row["job"]);
        if (!s.isEmpty()) return s;
    }
    if (row.exists("transfer") && row["transfer"].isObject()) {
        s = TransferRateSuffix(row["transfer"]);
        if (!s.isEmpty()) return s;
    }
    return {};
}

QString FormatAliasesLine(const UniValue& result, const UniValue* share)
{
    QStringList names;
    auto collect = [&](const UniValue& o) {
        if (!o.isObject() || !o.exists("aliases")) return;
        const UniValue& a = o["aliases"];
        if (a.isArray()) {
            for (const auto& item : a.getValues()) {
                if (item.isStr()) {
                    const QString s = QString::fromStdString(item.get_str()).trimmed();
                    if (!s.isEmpty()) names << s;
                } else if (item.isObject() && item.exists("alias") && item["alias"].isStr()) {
                    const QString s = QString::fromStdString(item["alias"].get_str()).trimmed();
                    if (!s.isEmpty()) names << s;
                }
            }
        } else if (a.isStr()) {
            const QString s = QString::fromStdString(a.get_str()).trimmed();
            if (!s.isEmpty()) names << s;
        }
    };
    collect(result);
    if (share) collect(*share);
    names.removeDuplicates();
    if (names.isEmpty()) return {};
    return QObject::tr("aliases: %1").arg(names.join(QStringLiteral(", ")));
}

QString FormatTransfersPane(const UniValue& root)
{
    QStringList lines;
    lines << QObject::tr("Rates (percent / bytes_per_sec) appear only when the JSON includes them. This page does not auto-getmodel or spend. automatic_spend_atoms stays 0.");

    const UniValue* arr = nullptr;
    if (root.exists("transfers") && root["transfers"].isArray()) {
        arr = &root["transfers"];
    } else if (root.exists("models") && root["models"].isArray()) {
        arr = &root["models"];
    } else if (root.exists("jobs") && root["jobs"].isArray()) {
        arr = &root["jobs"];
    } else if (root.isArray()) {
        arr = &root;
    }

    if (arr) {
        for (const auto& t : arr->getValues()) {
            if (!t.isObject()) continue;
            QString name = ModelDisplayName(t);
            if (name == QStringLiteral("—")) {
                QString uri = UniStrField(t, "uri");
                if (uri.isEmpty() && t.exists("share") && t["share"].isObject()) {
                    uri = UniStrField(t["share"], "copy_text");
                    if (uri.isEmpty()) uri = UniStrField(t["share"], "uri");
                }
                if (!uri.isEmpty()) name = uri;
            }
            const QString state = UniStrField(t, "state");
            const QString rates = TransferRateSuffixFromRow(t);
            QStringList bits;
            bits << name;
            if (!state.isEmpty()) bits << state;
            if (!rates.isEmpty()) bits << rates;
            lines << bits.join(QStringLiteral(" · "));
        }
    } else {
        const QString rates = TransferRateSuffixFromRow(root);
        if (!rates.isEmpty()) lines << rates;
    }

    lines << QString();
    lines << QString::fromStdString(root.write(2));
    return lines.join(QLatin1Char('\n'));
}

QString FormatJobLine(const UniValue& job, const QString& label)
{
    if (job.isStr()) {
        const QString state = QString::fromStdString(job.get_str());
        if (state.compare(QStringLiteral("stopped"), Qt::CaseInsensitive) == 0 ||
            state.compare(QStringLiteral("idle"), Qt::CaseInsensitive) == 0) {
            return label + QStringLiteral(": ") + state;
        }
        return label + QStringLiteral(": ") + state;
    }
    if (!job.isObject()) return {};
    QString line = label + QStringLiteral(": ");
    if (job.exists("active") && job["active"].get_bool()) {
        line += QStringLiteral("active");
    } else if (job.exists("running") && job["running"].get_bool()) {
        line += QStringLiteral("running");
    } else if (job.exists("state") && job["state"].isStr()) {
        line += QString::fromStdString(job["state"].get_str());
    } else {
        line += QStringLiteral("paused");
    }
    const QString reason = UniStrField(job, "pause_reason");
    if (!reason.isEmpty()) {
        line += QStringLiteral(" (") + reason + QLatin1Char(')');
    }
    return line;
}

QString FormatResourceGovernorStatus(const UniValue& info)
{
    // Keep this formatter secret-free and profile-free. 0.34.8-dev
    // profile / optional-cloud copy belongs on dev348ProfileCloudLabel.
    QStringList lines;
    lines << QObject::tr("Resource governor");
    if (info.exists("mode") && info["mode"].isStr()) {
        lines << QObject::tr("Mode: %1").arg(QString::fromStdString(info["mode"].get_str()));
    }
    if (info.exists("enabled")) {
        lines << QObject::tr("Enabled: %1").arg(info["enabled"].get_bool() ? QStringLiteral("yes")
                                                                           : QStringLiteral("no"));
    }
    if (info.exists("system_idle_state") && info["system_idle_state"].isStr()) {
        lines << QObject::tr("System idle: %1")
                     .arg(QString::fromStdString(info["system_idle_state"].get_str()));
    }
    if (info.exists("gpu") && info["gpu"].isArray()) {
        int idx = 0;
        for (const UniValue& gpu : info["gpu"].getValues()) {
            if (!gpu.isObject()) continue;
            QString gpu_line = QObject::tr("GPU %1").arg(idx++);
            if (gpu.exists("id") && gpu["id"].isStr()) {
                gpu_line = QString::fromStdString(gpu["id"].get_str());
            }
            if (gpu.exists("mining_active") && gpu["mining_active"].get_bool()) {
                gpu_line += QStringLiteral(" mining");
                if (gpu.exists("mining_intensity")) {
                    gpu_line += QStringLiteral(" @") + QString::number(gpu["mining_intensity"].getInt<int>()) +
                                QStringLiteral("%");
                }
            } else if (gpu.exists("mining_allowed") && !gpu["mining_allowed"].get_bool()) {
                gpu_line += QStringLiteral(" mining disallowed");
            }
            const QString pause = UniStrField(gpu, "pause_reason");
            if (!pause.isEmpty()) {
                gpu_line += QStringLiteral(" — ") + pause;
            } else if (gpu.exists("thermal_state") && gpu["thermal_state"].isStr()) {
                gpu_line += QStringLiteral(" — ") + QString::fromStdString(gpu["thermal_state"].get_str());
            }
            lines << gpu_line;
        }
    }
    if (info.exists("network") && info["network"].isObject()) {
        const UniValue& net = info["network"];
        const QString pressure = UniStrField(net, "pressure_state");
        if (!pressure.isEmpty()) {
            lines << QObject::tr("Network: %1").arg(pressure);
        }
        const QString throttle = UniStrField(net, "throttle_reason");
        if (!throttle.isEmpty()) {
            lines << QObject::tr("Network throttle: %1").arg(throttle);
        }
    }
    if (info.exists("jobs") && info["jobs"].isObject()) {
        const UniValue& jobs = info["jobs"];
        if (jobs.exists("mining")) {
            const QString mining_line = FormatJobLine(jobs["mining"], QObject::tr("Mining"));
            if (!mining_line.isEmpty()) lines << mining_line;
        }
        if (jobs.exists("seeding")) {
            const QString seed_line = FormatJobLine(jobs["seeding"], QObject::tr("Seeding"));
            if (!seed_line.isEmpty()) lines << seed_line;
        }
        if (jobs.exists("preservation")) {
            const QString pres_line = FormatJobLine(jobs["preservation"], QObject::tr("Preservation"));
            if (!pres_line.isEmpty()) lines << pres_line;
        }
    }
    return lines.join(QLatin1Char('\n'));
}

#ifdef ENABLE_MODELNET
QString FormatReadyFlag(const UniValue& v)
{
    if (v.isBool()) return v.get_bool() ? QObject::tr("yes") : QObject::tr("no");
    if (v.isObject()) {
        if (v.exists("ready")) return FormatReadyFlag(v["ready"]);
        if (v.exists("ok")) return FormatReadyFlag(v["ok"]);
    }
    if (v.isStr()) {
        const QString s = QString::fromStdString(v.get_str());
        if (!s.isEmpty()) return s;
    }
    if (v.isNum()) {
        return v.getInt<int>() != 0 ? QObject::tr("yes") : QObject::tr("no");
    }
    return QString::fromStdString(v.write());
}

const UniValue* NestedObject(const UniValue& obj, const char* const* keys, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (obj.exists(keys[i]) && obj[keys[i]].isObject()) return &obj[keys[i]];
    }
    return nullptr;
}

const UniValue* MiningDoctorSection(const UniValue& info)
{
    if (info.exists("first_run") && info["first_run"].isObject()) return &info["first_run"];
    if (info.exists("mining") && info["mining"].isObject()) {
        const UniValue& m = info["mining"];
        if (m.exists("first_run") && m["first_run"].isObject()) return &m["first_run"];
        return &m;
    }
    if (info.exists("chain") && info["chain"].isObject()) {
        const UniValue& c = info["chain"];
        if (c.exists("first_run") && c["first_run"].isObject()) return &c["first_run"];
        if (c.exists("ibd") || c.exists("ready_to_mine") || c.exists("initial_block_download")) return &c;
    }
    return nullptr;
}

void CollectNextActions(const UniValue& obj, QStringList& acts)
{
    if (!obj.exists("next_actions") || !obj["next_actions"].isArray()) return;
    for (const auto& a : obj["next_actions"].getValues()) {
        QString s;
        if (a.isStr()) {
            s = QString::fromStdString(a.get_str());
        } else if (a.isObject()) {
            if (a.exists("action") && a["action"].isStr()) {
                s = QString::fromStdString(a["action"].get_str());
            } else if (a.exists("text") && a["text"].isStr()) {
                s = QString::fromStdString(a["text"].get_str());
            }
        }
        if (s.isEmpty() || acts.contains(s)) continue;
        acts << s;
    }
}

QString FormatSetupDoctor(const UniValue& info, const QString& rpc_name, QString& watch_dir_out)
{
    const char* kModelKeys[] = {
        "model", "checkmodelsetup", "models", "modelnet", "helper", "model_setup"};
    const UniValue* model = NestedObject(info, kModelKeys, sizeof(kModelKeys) / sizeof(kModelKeys[0]));
    const UniValue* mining = MiningDoctorSection(info);

    auto pick = [&](const char* key) -> const UniValue* {
        if (info.exists(key) && !info[key].isNull()) return &info[key];
        if (model && model->exists(key) && !(*model)[key].isNull()) return &(*model)[key];
        if (mining && mining->exists(key) && !(*mining)[key].isNull()) return &(*mining)[key];
        return nullptr;
    };

    QStringList lines;
    lines << QObject::tr("Setup status (%1). showmodel / unhostmodel are RPC (not auto-run). This page does not auto-getmodel or spend (automatic_spend_atoms stays 0).")
                 .arg(rpc_name);

    auto add_flag = [&](const QString& label, const char* key, const char* alt = nullptr) {
        const UniValue* v = pick(key);
        if (!v && alt) v = pick(alt);
        if (!v) return;
        lines << label.arg(FormatReadyFlag(*v));
    };

    add_flag(QObject::tr("Identity ready: %1"), "identity_ready");
    if (const UniValue* id = pick("identity_id")) {
        if (id->isStr() && !id->get_str().empty()) {
            lines << QObject::tr("Identity: %1").arg(QString::fromStdString(id->get_str()));
        }
    }
    add_flag(QObject::tr("PQ1: %1"), "pq1", "pq1_ready");
    add_flag(QObject::tr("Ready to host: %1"), "ready_to_host", "helper_ready");
    add_flag(QObject::tr("Ready to mine: %1"), "ready_to_mine");
    add_flag(QObject::tr("IBD: %1"), "ibd", "initial_block_download");

    if (const UniValue* rec = pick("recommended_action")) {
        if (rec->isStr() && !rec->get_str().empty()) {
            lines << QObject::tr("Recommended: %1").arg(QString::fromStdString(rec->get_str()));
        }
    }

    if (const UniValue* q = pick("quota")) {
        if (q->isObject()) {
            int64_t bytes = -1;
            int64_t used = -1;
            if ((*q).exists("bytes") && (*q)["bytes"].isNum()) {
                bytes = (*q)["bytes"].getInt<int64_t>();
            } else if ((*q).exists("quota_bytes") && (*q)["quota_bytes"].isNum()) {
                bytes = (*q)["quota_bytes"].getInt<int64_t>();
            }
            if ((*q).exists("used_bytes") && (*q)["used_bytes"].isNum()) {
                used = (*q)["used_bytes"].getInt<int64_t>();
            } else if ((*q).exists("used") && (*q)["used"].isNum()) {
                used = (*q)["used"].getInt<int64_t>();
            }
            if (bytes >= 0 && used >= 0) {
                lines << QObject::tr("Quota: %1 used / %2").arg(HumanBytes(used), HumanBytes(bytes));
            } else if (bytes >= 0) {
                lines << QObject::tr("Quota: %1").arg(HumanBytes(bytes));
            } else {
                lines << QObject::tr("Quota: %1").arg(QString::fromStdString(q->write()));
            }
        } else if (q->isNum()) {
            lines << QObject::tr("Quota: %1").arg(HumanBytes(q->getInt<int64_t>()));
        } else if (q->isStr() && !q->get_str().empty()) {
            lines << QObject::tr("Quota: %1").arg(QString::fromStdString(q->get_str()));
        }
    } else if (const UniValue* qb = pick("quota_bytes")) {
        if (qb->isNum()) {
            const int64_t bytes = qb->getInt<int64_t>();
            const UniValue* used = pick("used_bytes");
            if (used && used->isNum()) {
                lines << QObject::tr("Quota: %1 used / %2")
                             .arg(HumanBytes(used->getInt<int64_t>()), HumanBytes(bytes));
            } else {
                lines << QObject::tr("Quota: %1").arg(HumanBytes(bytes));
            }
        }
    }

    if (const UniValue* wd = pick("watch_dir")) {
        if (wd->isStr()) {
            watch_dir_out = QString::fromStdString(wd->get_str());
            if (!watch_dir_out.isEmpty()) {
                lines << QObject::tr("Watch dir: %1").arg(watch_dir_out);
            } else {
                lines << QObject::tr("Watch dir: not set (-modelwatch)");
            }
        }
    }
    if (const UniValue* p = pick("profile")) {
        if (p->isStr() && !p->get_str().empty()) {
            lines << QObject::tr("Operator profile: %1").arg(QString::fromStdString(p->get_str()));
        }
    }
    if (const UniValue* s = pick("cloud_layout_sentence")) {
        if (s->isStr() && !s->get_str().empty()) {
            lines << QObject::tr("%1").arg(QString::fromStdString(s->get_str()));
        }
    }
    if (const UniValue* s = pick("r2_auto_sentence")) {
        if (s->isStr() && !s->get_str().empty()) {
            lines << QObject::tr("%1").arg(QString::fromStdString(s->get_str()));
        }
    }

    QStringList acts;
    CollectNextActions(info, acts);
    if (model) CollectNextActions(*model, acts);
    if (mining) CollectNextActions(*mining, acts);
    if (!acts.isEmpty()) {
        lines << QObject::tr("Next: %1").arg(acts.join(QStringLiteral("; ")));
    }

    return lines.join(QLatin1Char('\n'));
}

bool Dev348LooksLikeSecretKey(const std::string& key)
{
    std::string k = key;
    for (char& c : k) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c == '-') c = '_';
    }
    if (k == "credential_ref" || k == "credential_refs") return false;
    return k.find("secret") != std::string::npos
        || k.find("password") != std::string::npos
        || k.find("passwd") != std::string::npos
        || k.find("private_key") != std::string::npos
        || k.find("api_key") != std::string::npos
        || k.find("session_token") != std::string::npos
        || k.find("auth_token") != std::string::npos
        || k.find("credential_value") != std::string::npos;
}

QString Dev348PickStr(const UniValue& obj, const char* const* keys, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        const char* key = keys[i];
        if (Dev348LooksLikeSecretKey(key)) continue;
        if (!obj.exists(key) || obj[key].isNull()) continue;
        if (obj[key].isStr()) {
            const std::string s = obj[key].get_str();
            if (!s.empty()) return QString::fromStdString(s);
        }
        if (obj[key].isBool()) {
            return obj[key].get_bool() ? QObject::tr("yes") : QObject::tr("no");
        }
        if (obj[key].isNum()) {
            return QString::number(obj[key].getInt<int64_t>());
        }
    }
    return {};
}

QString FormatDev348ProfileCloud(const UniValue* profile, bool profile_rpc,
                                 const UniValue* cloud, bool cloud_rpc)
{
    QStringList lines;
    lines << QObject::tr("0.34.8-dev (not a shipping tag). Operator profile and optional cloud backing.");
    lines << QObject::tr("Cloud backing is optional. Secrets are never shown here. automatic_spend_atoms stays 0.");
    if (!profile_rpc) {
        lines << QObject::tr("Profile: getmodelprofile is not on this helper (fails closed).");
    } else if (profile && profile->isObject()) {
        const char* kName[] = {"profile", "name"};
        const char* kHost[] = {"host", "modelhost"};
        const char* kSeed[] = {"seed"};
        const QString name = Dev348PickStr(*profile, kName, 2);
        const QString host = Dev348PickStr(*profile, kHost, 2);
        const QString seed = Dev348PickStr(*profile, kSeed, 1);
        QString row = QObject::tr("Profile: %1").arg(name.isEmpty() ? QObject::tr("(unset)") : name);
        if (!host.isEmpty()) row += QObject::tr(" | host=%1").arg(host);
        if (!seed.isEmpty()) row += QObject::tr(" | seed=%1").arg(seed);
        lines << row;
    } else {
        lines << QObject::tr("Profile: getmodelprofile returned no object.");
    }
    if (!cloud_rpc) {
        lines << QObject::tr("Cloud: getcloudstorageinfo is not on this helper (fails closed). Local pieces remain the swarm unit.");
    } else if (cloud && cloud->isObject()) {
        const char* kProv[] = {"provider", "cloud_provider"};
        const char* kLay[] = {"layout", "cloud_object_layout"};
        const char* kEnd[] = {"endpoint"};
        const char* kBkt[] = {"bucket"};
        const char* kCred[] = {"credential_ref"};
        const QString provider = Dev348PickStr(*cloud, kProv, 2);
        const QString layout = Dev348PickStr(*cloud, kLay, 2);
        const QString endpoint = Dev348PickStr(*cloud, kEnd, 1);
        const QString bucket = Dev348PickStr(*cloud, kBkt, 1);
        const QString cred = Dev348PickStr(*cloud, kCred, 1);
        QString row = QObject::tr("Cloud backing (optional):");
        if (!provider.isEmpty()) row += QObject::tr(" provider=%1").arg(provider);
        if (!layout.isEmpty()) row += QObject::tr(" layout=%1").arg(layout);
        if (!endpoint.isEmpty()) row += QObject::tr(" endpoint=%1").arg(endpoint);
        if (!bucket.isEmpty()) row += QObject::tr(" bucket=%1").arg(bucket);
        if (!cred.isEmpty()) row += QObject::tr(" credential_ref=%1").arg(cred);
        lines << row;
        lines << QObject::tr("R2 AUTO uses SOURCE_FILES + STREAM_FILE. Pieces stay the swarm unit.");
    } else {
        lines << QObject::tr("Cloud: getcloudstorageinfo returned no object. Cloud backing remains optional.");
    }
    return lines.join(QLatin1Char('\n'));
}

bool Dev348LooksLikeQueryOrPresign(const std::string& key, const QString& value)
{
    std::string k = key;
    for (char& c : k) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c == '-') c = '_';
    }
    if (k.find("query") != std::string::npos) return true;
    if (k.find("presign") != std::string::npos) return true;
    if (k.find("url") != std::string::npos) return true;
    if (k.find("credential") != std::string::npos) return true;
    if (k.find("secret_access") != std::string::npos) return true;
    if (k.find("access_key") != std::string::npos) return true;
    if (Dev348LooksLikeSecretKey(key)) return true;
    if (value.isEmpty()) return false;
    const QString lower = value.toLower();
    if (lower.contains(QStringLiteral("aws_secret"))) return true;
    if (lower.contains(QStringLiteral("secret_access_key"))) return true;
    if (value.contains(QStringLiteral("X-Amz-"), Qt::CaseInsensitive)) return true;
    if (lower.contains(QStringLiteral("presign"))) return true;
    if (value.contains(QLatin1Char('?')) &&
        (lower.contains(QLatin1String("http://")) || lower.contains(QLatin1String("https://")) ||
         lower.startsWith(QLatin1String("http://")) || lower.startsWith(QLatin1String("https://")))) {
        return true;
    }
    if ((lower.startsWith(QLatin1String("http://")) || lower.startsWith(QLatin1String("https://"))) &&
        value.contains(QLatin1Char('?'))) {
        return true;
    }
    return false;
}

QString Dev348SafeDisplay(const std::string& key, const QString& value)
{
    if (value.isEmpty()) return {};
    if (Dev348LooksLikeQueryOrPresign(key, value)) return {};
    return value;
}

int64_t Dev348IntField(const UniValue& obj, const char* key, int64_t def = 0)
{
    if (!obj.exists(key) || obj[key].isNull()) return def;
    if (obj[key].isNum()) return obj[key].getInt<int64_t>();
    if (obj[key].isStr()) {
        try {
            return static_cast<int64_t>(std::stoll(obj[key].get_str()));
        } catch (...) {
            return def;
        }
    }
    return def;
}

QString FormatDev348WatchAction(const QString& raw)
{
    QString action = raw.trimmed();
    if (action.isEmpty()) action = QStringLiteral("NOTIFY");
    if (action.compare(QStringLiteral("PREPARE_FUNDING"), Qt::CaseInsensitive) == 0) {
        return QStringLiteral("PREPARE_FUNDING") + QObject::tr(" (unsigned)");
    }
    return action;
}

QString FormatDev348WatchTarget(const UniValue& w)
{
    const QString kind = UniStrField(w, "kind").trimmed();
    if (kind.compare(QStringLiteral("QUERY"), Qt::CaseInsensitive) == 0) {
        return QObject::tr("QUERY (string omitted)");
    }
    auto id_for = [&](const char* field) {
        const QString raw = UniStrField(w, field);
        const QString safe = Dev348SafeDisplay(field, raw);
        if (!raw.isEmpty() && safe.isEmpty()) return QObject::tr("(redacted)");
        return safe;
    };
    if (kind.compare(QStringLiteral("PUBLISHER"), Qt::CaseInsensitive) == 0) {
        const QString id = id_for("publisher_id");
        return QObject::tr("PUBLISHER %1").arg(id.isEmpty() ? QObject::tr("(unset)") : id);
    }
    if (kind.compare(QStringLiteral("COLLECTION"), Qt::CaseInsensitive) == 0) {
        const QString id = id_for("collection_id");
        return QObject::tr("COLLECTION %1").arg(id.isEmpty() ? QObject::tr("(unset)") : id);
    }
    if (kind.compare(QStringLiteral("MODEL"), Qt::CaseInsensitive) == 0) {
        const QString id = id_for("model_id");
        return QObject::tr("MODEL %1").arg(id.isEmpty() ? QObject::tr("(unset)") : id);
    }
    const QString publisher = id_for("publisher_id");
    const QString collection = id_for("collection_id");
    const QString model = id_for("model_id");
    if (!publisher.isEmpty()) return QObject::tr("PUBLISHER %1").arg(publisher);
    if (!collection.isEmpty()) return QObject::tr("COLLECTION %1").arg(collection);
    if (!model.isEmpty()) return QObject::tr("MODEL %1").arg(model);
    if (!kind.isEmpty() && !Dev348LooksLikeQueryOrPresign("kind", kind)) {
        return kind + QObject::tr(" (query omitted)");
    }
    return QObject::tr("QUERY (string omitted)");
}

QString FormatDev348WatchId(const UniValue& w)
{
    const QString raw = UniStrField(w, "watch_id");
    const QString id = Dev348SafeDisplay("watch_id", raw);
    if (!raw.isEmpty() && id.isEmpty()) return QObject::tr("(redacted)");
    if (id.isEmpty()) return QStringLiteral("—");
    return id;
}

QString FormatDev348Watches(const UniValue* listed, bool listed_rpc)
{
    QStringList lines;
    lines << QObject::tr("0.34.8-dev (not a shipping tag). Network watches from listmodelwatches. Filesystem -modelwatch / getmodelwatchstatus is not listmodelwatches.");
    lines << QObject::tr("Filesystem drop folder is not a publisher watch. Actions: NOTIFY / FREE_DOWNLOAD / KEEP / PREPARE_FUNDING (unsigned) / FUND_WITH_MANDATE. This page does not auto-getmodel, spend, or call wallet RPCs. automatic_spend_atoms stays 0.");
    if (!listed_rpc) {
        lines << QObject::tr("listmodelwatches is not on this helper (fails closed).");
        return lines.join(QLatin1Char('\n'));
    }
    const UniValue* arr = nullptr;
    UniValue one(UniValue::VARR);
    if (listed && listed->isArray()) {
        arr = listed;
    } else if (listed && listed->isObject() && listed->exists("watches") && (*listed)["watches"].isArray()) {
        arr = &(*listed)["watches"];
    } else if (listed && listed->isObject() && listed->exists("watch_id")) {
        one.push_back(*listed);
        arr = &one;
    }
    if (!arr) {
        lines << QObject::tr("listmodelwatches returned no watch list.");
        return lines.join(QLatin1Char('\n'));
    }
    int shown = 0;
    const int cap = 24;
    for (const UniValue& w : arr->getValues()) {
        if (!w.isObject()) continue;
        const QString raw_action = UniStrField(w, "action");
        const QString safe_action = Dev348SafeDisplay("action", raw_action);
        QString action;
        if (!raw_action.isEmpty() && safe_action.isEmpty()) {
            action = QObject::tr("(redacted)");
        } else {
            action = FormatDev348WatchAction(safe_action);
        }
        lines << QObject::tr("%1 — %2 — %3")
                     .arg(FormatDev348WatchId(w), FormatDev348WatchTarget(w), action);
        if (++shown >= cap) break;
    }
    if (shown == 0) {
        lines << QObject::tr("No publisher/collection/query watches.");
    } else if (static_cast<int>(arr->size()) > shown) {
        lines << QObject::tr("… %1 more").arg(static_cast<int>(arr->size()) - shown);
    }
    return lines.join(QLatin1Char('\n'));
}

QString FormatDev348Activity(const UniValue* sequence, bool sequence_rpc,
                             const UniValue* events, bool events_rpc)
{
    QStringList lines;
    lines << QObject::tr("0.34.8-dev (not a shipping tag). Activity snippet from getmodeleventsequence + last page of getmodelevents.");
    lines << QObject::tr("Untrusted event text is not a command, path, RPC, or mandate. PREPARE_FUNDING is unsigned. automatic_spend_atoms stays 0.");
    if (!sequence_rpc && !events_rpc) {
        lines << QObject::tr("getmodeleventsequence and getmodelevents are not on this helper (fails closed).");
        return lines.join(QLatin1Char('\n'));
    }
    if (!sequence_rpc) {
        lines << QObject::tr("getmodeleventsequence is not on this helper (fails closed). Last page of getmodelevents was not selected.");
        return lines.join(QLatin1Char('\n'));
    }
    if (!events_rpc) {
        lines << QObject::tr("getmodelevents is not on this helper (fails closed).");
        return lines.join(QLatin1Char('\n'));
    }
    int64_t seq = 0;
    if (sequence && sequence->isObject()) {
        seq = Dev348IntField(*sequence, "sequence", 0);
    } else if (sequence && sequence->isNum()) {
        seq = sequence->getInt<int64_t>();
    }
    lines << QObject::tr("sequence=%1").arg(QString::number(seq));
    const UniValue* arr = nullptr;
    if (events && events->isArray()) {
        arr = events;
    } else if (events && events->isObject() && events->exists("events") && (*events)["events"].isArray()) {
        arr = &(*events)["events"];
    }
    if (!arr || arr->empty()) {
        lines << QObject::tr("No local events on the last page.");
        return lines.join(QLatin1Char('\n'));
    }
    const int snippet = 12;
    const int n = static_cast<int>(arr->size());
    const int start = n > snippet ? n - snippet : 0;
    if (start > 0) {
        lines << QObject::tr("… %1 earlier on this last page (object_id and event_type only).").arg(start);
    }
    int shown = 0;
    for (int i = start; i < n; ++i) {
        const UniValue& ev = (*arr)[i];
        if (!ev.isObject()) continue;
        // Do not render untrusted_text / provenance / query strings. object_id + event_type only.
        const QString oid_raw = UniStrField(ev, "object_id");
        const QString et_raw = UniStrField(ev, "event_type");
        QString oid = Dev348SafeDisplay("object_id", oid_raw);
        QString et = Dev348SafeDisplay("event_type", et_raw);
        if (!oid_raw.isEmpty() && oid.isEmpty()) oid = QObject::tr("(redacted)");
        if (!et_raw.isEmpty() && et.isEmpty()) et = QObject::tr("(redacted)");
        lines << QObject::tr("%1  %2")
                     .arg(oid.isEmpty() ? QStringLiteral("—") : oid)
                     .arg(et.isEmpty() ? QStringLiteral("—") : et);
        ++shown;
    }
    if (shown == 0) {
        lines << QObject::tr("No local events on the last page.");
    }
    return lines.join(QLatin1Char('\n'));
}
#endif // ENABLE_MODELNET

bool CapJsonTrue(const UniValue& o, const char* k)
{
    return o.isObject() && o.exists(k) && o[k].isTrue();
}

bool CapJsonFalse(const UniValue& o, const char* k)
{
    return o.isObject() && o.exists(k) && o[k].isFalse();
}

bool CapabilityLooksLikeWalletPath(const QString& s)
{
    const QString lower = s.toLower();
    return lower.contains(QStringLiteral("wallet.dat"))
        || lower.contains(QStringLiteral("/wallets/"))
        || lower.contains(QStringLiteral("\\wallets\\"))
        || lower.contains(QStringLiteral("walletdir"));
}

bool CapabilityLooksLikePublicHttp(const QString& s)
{
    const QString lower = s.trimmed().toLower();
    return lower.startsWith(QStringLiteral("http://")) || lower.startsWith(QStringLiteral("https://"));
}

bool CapabilityWakeRejected(const UniValue& result)
{
    if (!result.isObject()) return false;
    if (CapJsonTrue(result, "remap_only")) return true;
    if (CapJsonTrue(result, "premature_ready")) return true;
    return false;
}

bool CapabilitySmokeBlocked(const UniValue& result)
{
    if (!result.isObject()) return false;
    if (CapJsonTrue(result, "smoke_blocked") || CapJsonTrue(result, "block_warmup")) return true;
    if (CapJsonFalse(result, "smoke_passed")) return true;
    if (CapJsonFalse(result, "smoke_performed") && CapJsonTrue(result, "ready")) return true;
    if (result.exists("progress") && result["progress"].isObject()) {
        const UniValue& p = result["progress"];
        if (CapJsonTrue(p, "smoke_blocked")) return true;
        if (CapJsonFalse(p, "runtime_ready")) return true;
        if (CapJsonFalse(p, "first_useful_result") && p.exists("percent_ready") && p["percent_ready"].isNum()
            && p["percent_ready"].getInt<int>() >= 100) {
            return true;
        }
    }
    if (CapJsonFalse(result, "switch_ready")) return true;
    return false;
}

bool CapabilityWalletKey(const std::string& k)
{
    std::string low = k;
    for (char& c : low) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (low == "funded_wallet") return false;
    return low == "wallet" || low.find("wallet_path") != std::string::npos || low.find("walletdir") != std::string::npos
        || low.find("wallet_dir") != std::string::npos;
}

UniValue SanitizeCapabilityJson(const UniValue& v, bool smoke_blocked, bool wake_reject)
{
    if (v.isArray()) {
        UniValue a(UniValue::VARR);
        for (const auto& e : v.getValues()) a.push_back(SanitizeCapabilityJson(e, smoke_blocked, false));
        return a;
    }
    if (!v.isObject()) {
        if (v.isStr()) {
            const QString s = QString::fromStdString(v.get_str());
            if (CapabilityLooksLikeWalletPath(s) || CapabilityLooksLikePublicHttp(s)) {
                return UniValue("redacted");
            }
        }
        return v;
    }
    UniValue out(UniValue::VOBJ);
    for (const auto& k : v.getKeys()) {
        if (k == "automatic_spend_atoms") {
            out.pushKV(k, 0);
            continue;
        }
        if (wake_reject && (k == "ready" || k == "premature_ready" || k == "remap_only")) continue;
        if (CapabilityWalletKey(k) && !v[k].isBool()) continue;
        if (k == "progress" && v[k].isObject()) {
            UniValue p(UniValue::VOBJ);
            int percent = -1;
            for (const auto& pk : v[k].getKeys()) {
                if (pk == "percent_ready") {
                    if (v[k][pk].isNum()) percent = v[k][pk].getInt<int>();
                    continue;
                }
                if (pk == "automatic_spend_atoms") {
                    p.pushKV(pk, 0);
                    continue;
                }
                p.pushKV(pk, SanitizeCapabilityJson(v[k][pk], smoke_blocked, false));
            }
            if (smoke_blocked) {
                if (percent < 0 || percent >= 100) percent = 70;
                p.pushKV("percent_ready", percent);
                p.pushKV("runtime_ready", false);
                p.pushKV("first_useful_result", false);
            } else if (percent >= 0) {
                p.pushKV("percent_ready", percent);
            }
            out.pushKV("progress", p);
            continue;
        }
        out.pushKV(k, SanitizeCapabilityJson(v[k], smoke_blocked, false));
    }
    if (wake_reject) {
        out.pushKV("remap_only", true);
        out.pushKV("ready", false);
        out.pushKV("premature_ready", true);
    }
    if (!out.exists("automatic_spend_atoms")) out.pushKV("automatic_spend_atoms", 0);
    return out;
}

QString FormatCapabilityOutput(const std::string& method, const UniValue& result, bool wake)
{
    QStringList lines;
    lines << QObject::tr("%1 (owner-local; never public HTTP; automatic_spend_atoms=0)")
                 .arg(QString::fromStdString(method));
    const bool wake_reject = wake && CapabilityWakeRejected(result);
    const bool smoke_blocked = CapabilitySmokeBlocked(result);
    if (wake_reject) {
        lines << QObject::tr("remap_only is not readiness. Discarded KV/workspace must be rebuilt. Not success (PREMATURE_READY).");
    }
    if (smoke_blocked) {
        lines << QObject::tr("Progress: smoke blocked or not passed — not 100% ready. Canonical bytes, tensors, transforms, runtime, and first result are separate.");
    }
    lines << QString::fromStdString(SanitizeCapabilityJson(result, smoke_blocked, wake_reject).write(2));
    return lines.join(QLatin1Char('\n'));
}

UniValue CapabilityZeroGrant()
{
    UniValue grant(UniValue::VOBJ);
    grant.pushKV("caller", "local");
    grant.pushKV("automatic_spend_atoms", 0);
    return grant;
}

UniValue CapabilityRpcParams(const UniValue& obj)
{
    UniValue params(UniValue::VARR);
    params.push_back(obj);
    return params;
}

QString WatchFolderHintText(const QString& watch_dir)
{
    QString configured = watch_dir;
    if (configured.isEmpty()) {
        configured = QString::fromStdString(gArgs.GetArg("-modelwatch", ""));
    }
    if (configured.isEmpty()) {
        return QObject::tr("Watch folder: not set. Start btxd with -modelwatch=<dir> to auto-host new GGUF or SafeTensors files (scanmodelwatch). This is a filesystem drop folder, not a publisher watch. This page does not auto-getmodel or spend. automatic_spend_atoms stays 0.");
    }
    return QObject::tr("Watch folder: %1 (-modelwatch). New GGUF/SafeTensors are auto-hosted; scanmodelwatch is idempotent. This is a filesystem drop folder, not a publisher watch. This page does not auto-getmodel or spend. automatic_spend_atoms stays 0.")
        .arg(configured);
}

} // namespace

ModelNetPage::ModelNetPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ModelNetPage)
{
    ui->setupUi(this);

    ui->sortCombo->addItem(tr("Relevance"), QStringLiteral("RELEVANCE"));
    ui->sortCombo->addItem(tr("Availability"), QStringLiteral("AVAILABILITY"));
    ui->sortCombo->addItem(tr("Newest"), QStringLiteral("NEWEST"));
    ui->sortCombo->addItem(tr("Nearly funded"), QStringLiteral("NEARLY_FUNDED"));
    ui->sortCombo->addItem(tr("Most funding needed"), QStringLiteral("MOST_FUNDING_NEEDED"));
    ui->sortCombo->addItem(tr("Recently unlocked"), QStringLiteral("RECENTLY_UNLOCKED"));
    ui->sortCombo->addItem(tr("Size (desc)"), QStringLiteral("SIZE_DESC"));
    ui->sortCombo->addItem(tr("Providers"), QStringLiteral("PROVIDERS"));

    ui->formatCombo->addItem(tr("Any"), QString());
    ui->formatCombo->addItem(QStringLiteral("GGUF"), QStringLiteral("GGUF"));
    ui->formatCombo->addItem(tr("SafeTensors"), QStringLiteral("SafeTensors"));

    connect(ui->refreshButton, &QPushButton::clicked, this, &ModelNetPage::refresh);
    connect(ui->copyUriButton, &QPushButton::clicked, this, &ModelNetPage::copyOpenedUri);
    connect(ui->searchButton, &QPushButton::clicked, this, &ModelNetPage::runModelSearch);
    connect(ui->searchLineEdit, &QLineEdit::returnPressed, this, &ModelNetPage::runModelSearch);
    connect(ui->searchLineEdit, &QLineEdit::textChanged, this, &ModelNetPage::onSearchTextChanged);
    connect(ui->publishButton, &QPushButton::clicked, this, &ModelNetPage::onPublishSearchRecord);
    connect(ui->importButton, &QPushButton::clicked, this, &ModelNetPage::onImportModel);
    connect(ui->importBrowseButton, &QPushButton::clicked, this, &ModelNetPage::onImportBrowse);
    connect(ui->importCopyUriButton, &QPushButton::clicked, this, &ModelNetPage::copyImportShareUri);
    connect(ui->capabilityEnsureButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityEnsure);
    connect(ui->capabilityPrefetchButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityPrefetch);
    connect(ui->capabilitySleepButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilitySleep);
    connect(ui->capabilityReleaseButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityRelease);
    connect(ui->capabilityWakeButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityWake);
    connect(ui->capabilityUpdateButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityUpdate);
    connect(ui->capabilitySwitchButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilitySwitch);
    connect(ui->capabilityEventsButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityEvents);
    connect(ui->capabilityTtcButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityTtc);
    connect(ui->capabilityRuntimeCapsButton, &QPushButton::clicked, this, &ModelNetPage::onCapabilityRuntimeCaps);
    connect(ui->modelsScopeTabWidget, &QTabWidget::currentChanged, this, [this](int) {
        ui->searchCoverageLabel->setText(
            tr("Scope changed — run Search to refresh results (coverage always incomplete)."));
    });

    auto* feed_timer = new QTimer(this);
    connect(feed_timer, &QTimer::timeout, this, &ModelNetPage::pollFeedSequence);
    feed_timer->start(4000);

    ui->uriDisplayLabel->installEventFilter(this);
    ui->uriRowWidget->setVisible(false);
    ui->importShareRowWidget->setVisible(false);
    ui->importAliasHintLabel->setVisible(false);
    refresh();
}

ModelNetPage::~ModelNetPage()
{
    delete ui;
}

void ModelNetPage::setClientModel(ClientModel *model)
{
    m_client_model = model;
    refresh();
}

void ModelNetPage::showOpenedUri(const QString& uri)
{
    refresh();
#ifdef ENABLE_MODELNET
    m_full_uri = QString::fromStdString(modelnet::CopyUri(uri.toStdString()));
    const std::string display = modelnet::ShortDisplayUri(m_full_uri.toStdString());
    ui->uriDisplayLabel->setText(QString::fromStdString(display));
    ui->uriRowWidget->setVisible(!m_full_uri.isEmpty());
    const QString note = tr("Opened resource URI (not a payment, not a spend):\n%1\nCopy uses the full URI, not the short display.\n\n")
                              .arg(QString::fromStdString(display));
#else
    m_full_uri = uri;
    ui->uriDisplayLabel->setText(uri);
    ui->uriRowWidget->setVisible(!uri.isEmpty());
    const QString note = tr("Opened resource URI (not a payment, not a spend):\n%1\n\n").arg(uri);
#endif
    ui->modelsOutput->setPlainText(note + ui->modelsOutput->toPlainText());
}

void ModelNetPage::copyOpenedUri()
{
    if (m_full_uri.isEmpty()) return;
    GUIUtil::setClipboard(m_full_uri);
}

void ModelNetPage::copyImportShareUri()
{
    if (m_import_share_uri.isEmpty()) return;
    GUIUtil::setClipboard(m_import_share_uri);
}

bool ModelNetPage::eventFilter(QObject* obj, QEvent* ev)
{
    if (obj == ui->uriDisplayLabel && ev->type() == QEvent::KeyPress) {
        const auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->matches(QKeySequence::Copy)) {
            copyOpenedUri();
            return true;
        }
    }
    return QWidget::eventFilter(obj, ev);
}

QString ModelNetPage::callRpc(const std::string& method, const UniValue& params) const
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        return tr("Node RPC is not connected. Use btx-cli %1 on the restricted local model endpoint.")
            .arg(QString::fromStdString(method));
    }
    try {
        const UniValue result = m_client_model->node().executeRpc(method, params, /*uri=*/"");
        return QString::fromStdString(result.write(2));
    } catch (const UniValue& e) {
        return QString::fromStdString(e.write(2)) + QLatin1Char('\n') +
               tr("If the node cannot reach btx-modeld, the same method is available via btx-cli %1.")
                   .arg(QString::fromStdString(method));
    } catch (const std::exception& e) {
        return QString::fromStdString(e.what()) + QLatin1Char('\n') +
               tr("Use btx-cli %1 against the restricted local model endpoint.")
                   .arg(QString::fromStdString(method));
    }
#else
    (void)params;
    return tr("Model network support was not compiled into this GUI. Use btx-cli %1.")
        .arg(QString::fromStdString(method));
#endif
}

std::optional<UniValue> ModelNetPage::tryRpc(const std::string& method, const UniValue& params) const
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) return std::nullopt;
    try {
        return m_client_model->node().executeRpc(method, params, /*uri=*/"");
    } catch (...) {
        return std::nullopt;
    }
#else
    (void)method;
    (void)params;
    return std::nullopt;
#endif
}

void ModelNetPage::refreshConsent()
{
#ifdef ENABLE_MODELNET
    std::string err;
    modelnet::FirstRunConsent consent;
    const fs::path path = modelnet::FirstRunConsentPath(gArgs.GetDataDirNet());
    const bool loaded = modelnet::LoadFirstRunConsent(path, consent, err);
    uint64_t env_bytes = 0;
    std::string env_err;
    const bool env_budget = modelnet::EnvHasPositiveStorageBudget(env_bytes, env_err);
    const bool payload_ok = (loaded && modelnet::AllowPayloadStorage(consent)) || env_budget;
    QString text;
    if (loaded) {
        text = tr("Consent file: %1\nStorage: %2 bytes | seed=%3 | preserve_rare=%4 | governor_auto=%5 | mining_idle=%6 | consented_unix=%7")
                   .arg(GUIUtil::PathToQString(path),
                        QString::number(consent.storage_bytes),
                        QString::fromUtf8(modelnet::SeedModeName(consent.seed)),
                        consent.preserve_rare ? QStringLiteral("true") : QStringLiteral("false"),
                        consent.resource_governor_auto ? QStringLiteral("true") : QStringLiteral("false"),
                        consent.mining_idle ? QStringLiteral("true") : QStringLiteral("false"),
                        QString::number(consent.consented_unix));
    } else {
        text = tr("No first-run consent file (%1). Payload storage stays 0 until a finite budget is allocated.")
                   .arg(QString::fromStdString(err));
    }
    if (env_budget) {
        text += QLatin1Char('\n') + tr("BTX_MODEL_STORAGE env budget: %1 bytes.").arg(env_bytes);
    }
    text += QLatin1Char('\n') +
            (payload_ok ? tr("Payload storage: allowed (positive budget). Automatic spend remains 0.")
                        : tr("Payload storage: refused (storage_bytes == 0). No auto-fetch."));
    ui->consentLabel->setText(text);
#else
    ui->consentLabel->setText(tr("Model network was not compiled into this GUI."));
#endif
}

void ModelNetPage::refreshResourceGovernorStatus()
{
#ifdef ENABLE_MODELNET
    QString text;
    if (!m_client_model) {
        text = tr("Resource governor: connect the wallet to btxd to read live status. "
                  "When RPC is available, this panel uses getresourcegovernorinfo (same name as btx-cli).");
    } else {
        const auto info = tryRpc("getresourcegovernorinfo", UniValue(UniValue::VARR));
        if (info) {
            text = FormatResourceGovernorStatus(*info);
        } else {
            text = tr("Resource governor: getresourcegovernorinfo is not available on this node yet. "
                      "Upgrade btxd or query btx-cli getresourcegovernorinfo when the RPC is enabled.");
        }
    }
    ui->resourceGovernorStatusLabel->setText(text);
#else
    ui->resourceGovernorStatusLabel->setVisible(false);
#endif
}

void ModelNetPage::refreshSetupStatus()
{
#ifdef ENABLE_MODELNET
    QString rpc_used;
    std::optional<UniValue> info;
    if (m_client_model) {
        info = tryRpc("getsetupstatus", UniValue(UniValue::VARR));
        if (info) {
            rpc_used = QStringLiteral("getsetupstatus");
        } else {
            info = tryRpc("checkmodelsetup", UniValue(UniValue::VARR));
            if (info) {
                rpc_used = QStringLiteral("checkmodelsetup");
            } else {
                info = tryRpc("getmodelnetworkinfo", UniValue(UniValue::VARR));
                if (info) rpc_used = QStringLiteral("getmodelnetworkinfo");
            }
        }
    }
    QString watch_dir;
    if (!m_client_model) {
        ui->doctorStatusLabel->setText(
            tr("Setup status: connect the wallet to btxd to run getsetupstatus "
               "(fallback: checkmodelsetup / getmodelnetworkinfo). "
               "showmodel / unhostmodel are RPC. This page does not auto-getmodel or spend. automatic_spend_atoms stays 0."));
    } else if (!info) {
        ui->doctorStatusLabel->setText(
            tr("Setup status: getsetupstatus, checkmodelsetup, and getmodelnetworkinfo are unavailable. "
               "Use btx-cli getsetupstatus. showmodel / unhostmodel are RPC. This page does not auto-getmodel or spend. automatic_spend_atoms stays 0."));
    } else {
        ui->doctorStatusLabel->setText(FormatSetupDoctor(*info, rpc_used, watch_dir));
    }
    ui->watchFolderHintLabel->setText(WatchFolderHintText(watch_dir));
#else
    ui->doctorStatusLabel->setText(tr("Model network was not compiled into this GUI."));
    ui->watchFolderHintLabel->setText(WatchFolderHintText(QString()));
#endif
}

void ModelNetPage::refreshDev348ProfileCloud()
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        ui->dev348ProfileCloudLabel->setText(
            tr("0.34.8-dev (not a shipping tag). Operator profile and optional cloud backing.\n"
               "Cloud backing is optional. Secrets are never shown. automatic_spend_atoms stays 0.\n"
               "Connect to btxd to query getmodelprofile / getcloudstorageinfo. Missing methods fail closed."));
        return;
    }
    const auto profile = tryRpc("getmodelprofile", UniValue(UniValue::VARR));
    const auto cloud = tryRpc("getcloudstorageinfo", UniValue(UniValue::VARR));
    ui->dev348ProfileCloudLabel->setText(
        FormatDev348ProfileCloud(profile ? &*profile : nullptr, bool(profile),
                                 cloud ? &*cloud : nullptr, bool(cloud)));
#else
    ui->dev348ProfileCloudLabel->setText(
        tr("0.34.8-dev profile/cloud panel: model network was not compiled into this GUI. "
           "Cloud backing is optional. Secrets are never shown."));
#endif
}

void ModelNetPage::refreshDev348WatchesActivity()
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        ui->dev348WatchesLabel->setText(
            tr("0.34.8-dev (not a shipping tag). Network watches from listmodelwatches. Filesystem -modelwatch / getmodelwatchstatus is not listmodelwatches.\n"
               "Filesystem drop folder is not a publisher watch. PREPARE_FUNDING is unsigned. automatic_spend_atoms stays 0.\n"
               "Connect to btxd to query listmodelwatches. Missing methods fail closed."));
        ui->dev348ActivityLabel->setText(
            tr("0.34.8-dev (not a shipping tag). Activity snippet from getmodeleventsequence + last page of getmodelevents.\n"
               "Untrusted event text is not a command, path, RPC, or mandate. automatic_spend_atoms stays 0.\n"
               "Connect to btxd. Missing methods fail closed."));
        return;
    }
    const auto listed = tryRpc("listmodelwatches", UniValue(UniValue::VARR));
    ui->dev348WatchesLabel->setText(FormatDev348Watches(listed ? &*listed : nullptr, bool(listed)));

    const auto sequence = tryRpc("getmodeleventsequence", UniValue(UniValue::VARR));
    // Bounded getmodelevents only. Never waitformodelevent / wait_s / timeout_ms (must not hang
    // if the helper lacks the method). Never wallet RPCs. Never auto-getmodel.
    UniValue req(UniValue::VOBJ);
    const int64_t page_max = 100;
    req.pushKV("limit", page_max);
    if (sequence) {
        int64_t seq = 0;
        if (sequence->isObject()) {
            seq = Dev348IntField(*sequence, "sequence", 0);
        } else if (sequence->isNum()) {
            seq = sequence->getInt<int64_t>();
        }
        const int64_t cursor = seq > page_max ? seq - page_max : 0;
        req.pushKV("cursor", cursor);
    }
    UniValue params(UniValue::VARR);
    params.push_back(req);
    const auto events = tryRpc("getmodelevents", params);
    ui->dev348ActivityLabel->setText(
        FormatDev348Activity(sequence ? &*sequence : nullptr, bool(sequence),
                             events ? &*events : nullptr, bool(events)));
#else
    ui->dev348WatchesLabel->setText(
        tr("0.34.8-dev watches panel: model network was not compiled into this GUI. "
           "Filesystem -modelwatch / getmodelwatchstatus is not listmodelwatches. Secrets are never shown. automatic_spend_atoms stays 0."));
    ui->dev348ActivityLabel->setText(
        tr("0.34.8-dev activity panel: model network was not compiled into this GUI. "
           "Untrusted event text is not a command, path, RPC, or mandate. automatic_spend_atoms stays 0."));
#endif
}

void ModelNetPage::refreshLocalCatalogCache()
{
    m_have_local_cache = false;
    m_cached_listmodels = UniValue(UniValue::VARR);
    const auto parsed = tryRpc("listmodels", UniValue(UniValue::VARR));
    if (!parsed || !parsed->exists("models") || !(*parsed)["models"].isArray()) return;
    m_cached_listmodels = (*parsed)["models"];
    m_have_local_cache = true;
}

int ModelNetPage::modelsScopeTabIndex() const
{
    return ui->modelsScopeTabWidget->currentIndex();
}

UniValue ModelNetPage::buildSearchQueryObject(const std::optional<std::string>& scope,
                                              const std::optional<std::string>& sort_override) const
{
    UniValue query(UniValue::VOBJ);
    query.pushKV("text", ui->searchLineEdit->text().trimmed().toStdString());
    query.pushKV("limit", 25);
    if (scope) {
        query.pushKV("scope", *scope);
    }
    const std::string sort = sort_override ? *sort_override : currentSortKey();
    query.pushKV("sort", sort);
    if (const auto fmt = currentFormatFilter()) {
        UniValue filters(UniValue::VOBJ);
        filters.pushKV("format", *fmt);
        query.pushKV("filters", filters);
    }
    return query;
}

std::string ModelNetPage::currentSortKey() const
{
    return ui->sortCombo->currentData().toString().toStdString();
}

std::optional<std::string> ModelNetPage::currentFormatFilter() const
{
    const QString data = ui->formatCombo->currentData().toString();
    if (data.isEmpty()) return std::nullopt;
    return data.toStdString();
}

QString ModelNetPage::modelFullUri(const UniValue& model) const
{
    std::string raw;
    if (model.exists("uri") && model["uri"].isStr()) raw = model["uri"].get_str();
    else if (model.exists("model_uri") && model["model_uri"].isStr()) raw = model["model_uri"].get_str();
#ifdef ENABLE_MODELNET
    if (!raw.empty()) {
        const std::string full = modelnet::CopyUri(raw);
        if (!full.empty()) return QString::fromStdString(full);
    }
#else
    if (!raw.empty()) return QString::fromStdString(raw);
#endif
    if (model.exists("model_id") && model["model_id"].isStr()) {
        return QStringLiteral("btx://") + QString::fromStdString(model["model_id"].get_str());
    }
    return QString();
}

void ModelNetPage::clearResultsList()
{
    ui->resultsList->clear();
}

void ModelNetPage::updateCoverageLabel(int result_count, const UniValue* meta)
{
    int connected_peers = 0;
    int index_peers = 0;
    bool local_only = false;
    if (meta) {
        if (meta->exists("coverage") && (*meta)["coverage"].isObject()) {
            const UniValue& cov = (*meta)["coverage"];
            if (cov.exists("connected_peers_queried")) {
                connected_peers = cov["connected_peers_queried"].getInt<int>();
            }
            if (cov.exists("index_peers_queried")) {
                index_peers = cov["index_peers_queried"].getInt<int>();
            }
            if (cov.exists("local") && cov["local"].get_bool()) {
                local_only = true;
            }
        } else if (meta->exists("coverage") && (*meta)["coverage"].isStr()) {
            local_only = (*meta)["coverage"].get_str() == "local-only preview";
        }
    }
    QString text = tr("%1 results found from current network view").arg(result_count);
    if (local_only) {
        text = tr("%1 local matches (preview only; not a network search)").arg(result_count);
    } else if (connected_peers > 0 || index_peers > 0) {
        text += tr(" — %1 connected peer(s) queried").arg(connected_peers);
        if (index_peers > 0) {
            text += tr(", %1 index peer(s)").arg(index_peers);
        }
    }
    text += tr(". Partial view only; not a complete global directory.");
    ui->searchCoverageLabel->setText(text);
}

void ModelNetPage::renderModelCards(const UniValue& models, const UniValue* meta)
{
    clearResultsList();
    if (!models.isArray()) {
        updateCoverageLabel(0, meta);
        return;
    }

    const int n = static_cast<int>(models.getValues().size());
    updateCoverageLabel(n, meta);

    for (const auto& m : models.getValues()) {
        const QString full_uri = modelFullUri(m);
#ifdef ENABLE_MODELNET
        const QString uri_display = full_uri.isEmpty()
            ? QStringLiteral("—")
            : QString::fromStdString(modelnet::ShortDisplayUri(full_uri.toStdString()));
#else
        const QString uri_display = full_uri.isEmpty() ? QStringLiteral("—") : full_uri;
#endif

        auto* item = new QListWidgetItem();
        item->setData(Qt::UserRole, full_uri);
        ui->resultsList->addItem(item);

        auto* card = new QWidget();
        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(6, 4, 6, 4);

        auto* title = new QLabel(
            QStringLiteral("<b>%1</b> · %2 · %3")
                .arg(ModelDisplayName(m).toHtmlEscaped(),
                     FormatProfileLabel(m).toHtmlEscaped(),
                     HumanBytes(ModelByteSize(m)).toHtmlEscaped()));
        title->setWordWrap(true);
        layout->addWidget(title);

        auto* meta_line = new QLabel(
            QStringLiteral("%1 · availability: %2 · publisher: %3")
                .arg(ProvidersLine(m).toHtmlEscaped(),
                     AvailabilityLine(m).toHtmlEscaped(),
                     PublisherLine(m).toHtmlEscaped()));
        meta_line->setWordWrap(true);
        layout->addWidget(meta_line);

        QString life = QStringLiteral("PUBLIC");
        if (m.exists("lifecycle_state") && m["lifecycle_state"].isStr()) {
            life = QString::fromStdString(m["lifecycle_state"].get_str());
        } else if (m.exists("lifecycle") && m["lifecycle"].isObject() && m["lifecycle"]["state"].isStr()) {
            life = QString::fromStdString(m["lifecycle"]["state"].get_str());
        } else if (m.exists("result_type") && m["result_type"].isStr()) {
            life = QString::fromStdString(m["result_type"].get_str());
        }
        QString fund_line;
        const UniValue* rel = nullptr;
        if (m.exists("release") && m["release"].isObject()) rel = &m["release"];
        else if (m.exists("economy") && m["economy"].isObject() && m["economy"]["release"].isObject()) {
            rel = &m["economy"]["release"];
        }
        if (rel && (*rel).exists("target_atoms") && (*rel)["target_atoms"].getInt<int64_t>() > 0) {
            const int64_t target = (*rel)["target_atoms"].getInt<int64_t>();
            const int64_t confirmed = (*rel).exists("confirmed_funded_atoms") ? (*rel)["confirmed_funded_atoms"].getInt<int64_t>() : 0;
            const int64_t remaining = (*rel).exists("remaining_atoms") ? (*rel)["remaining_atoms"].getInt<int64_t>() : 0;
            QString pct = QStringLiteral("—");
            if ((*rel).exists("funded_percent")) {
                pct = QString::number((*rel)["funded_percent"].get_real(), 'f', 1) + QStringLiteral("%");
            }
            const bool known = !(*rel).exists("value_known") || (*rel)["value_known"].get_bool();
            fund_line = known
                ? tr("Release campaign · %1 confirmed / %2 target · %3 remaining · %4")
                      .arg(confirmed).arg(target).arg(remaining).arg(pct)
                : tr("Release campaign · pledged %1 · confirmed funding unknown")
                      .arg((*rel).exists("pledged_atoms") ? (*rel)["pledged_atoms"].getInt<int64_t>() : 0);
        }
        auto* life_line = new QLabel(tr("Lifecycle: %1%2")
                                         .arg(life.toHtmlEscaped(),
                                              fund_line.isEmpty() ? QString() : QStringLiteral(" · ") + fund_line.toHtmlEscaped()));
        life_line->setWordWrap(true);
        layout->addWidget(life_line);

        auto* uri_line = new QLabel(tr("URI: %1").arg(uri_display.toHtmlEscaped()));
        uri_line->setWordWrap(true);
        uri_line->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(uri_line);

        auto* btn_row = new QHBoxLayout();
        auto* download_btn = new QPushButton(tr("Download"));
        download_btn->setProperty("modelUri", full_uri);
        connect(download_btn, &QPushButton::clicked, this, &ModelNetPage::onResultDownload);
        btn_row->addWidget(download_btn);

        auto* copy_btn = new QPushButton(tr("Copy btx://"));
        copy_btn->setProperty("modelUri", full_uri);
        connect(copy_btn, &QPushButton::clicked, this, &ModelNetPage::onResultCopyUri);
        btn_row->addWidget(copy_btn);

        auto* details_btn = new QPushButton(tr("Details"));
        details_btn->setProperty("modelUri", full_uri);
        connect(details_btn, &QPushButton::clicked, this, &ModelNetPage::onResultDetails);
        btn_row->addWidget(details_btn);

        bool fundable = false;
        QString release_id;
        if (m.exists("fundable_now") && m["fundable_now"].isTrue()) fundable = true;
        if (m.exists("actions") && m["actions"].isArray()) {
            for (const auto& a : m["actions"].getValues()) {
                if (a.isStr() && a.get_str() == "FUND_RELEASE") fundable = true;
            }
        }
        if (m.exists("release") && m["release"].isObject()) {
            const UniValue& rel = m["release"];
            if (rel.exists("release_id") && rel["release_id"].isStr()) release_id = QString::fromStdString(rel["release_id"].get_str());
            else if (rel.exists("id") && rel["id"].isStr()) release_id = QString::fromStdString(rel["id"].get_str());
        }
        if (fundable) {
            auto* fund_btn = new QPushButton(tr("Fund Release"));
            fund_btn->setProperty("releaseId", release_id);
            connect(fund_btn, &QPushButton::clicked, this, &ModelNetPage::onResultFund);
            btn_row->addWidget(fund_btn);
        }
        const bool bounty = (m.exists("object_kind") && m["object_kind"].isStr() && m["object_kind"].get_str() == "BOUNTY") ||
                            (m.exists("bounty_id") && m["bounty_id"].isStr());
        if (bounty) {
            auto* fund_b = new QPushButton(tr("Fund Bounty"));
            connect(fund_b, &QPushButton::clicked, this, &ModelNetPage::onResultFundBounty);
            btn_row->addWidget(fund_b);
            auto* award_btn = new QPushButton(tr("Award"));
            connect(award_btn, &QPushButton::clicked, this, &ModelNetPage::onResultAward);
            btn_row->addWidget(award_btn);
            auto* refund_btn = new QPushButton(tr("Refund"));
            connect(refund_btn, &QPushButton::clicked, this, &ModelNetPage::onResultRefund);
            btn_row->addWidget(refund_btn);
        }
        bool cacheable = false;
        if (m.exists("ciphertext_cacheable") && m["ciphertext_cacheable"].isTrue()) cacheable = true;
        if (m.exists("actions") && m["actions"].isArray()) {
            for (const auto& a : m["actions"].getValues()) {
                if (a.isStr() && a.get_str() == "CACHE_ENCRYPTED") cacheable = true;
            }
        }
        if (cacheable) {
            auto* cache_btn = new QPushButton(tr("Cache Encrypted"));
            cache_btn->setProperty("releaseId", release_id);
            cache_btn->setProperty("modelUri", full_uri);
            connect(cache_btn, &QPushButton::clicked, this, &ModelNetPage::onResultCache);
            btn_row->addWidget(cache_btn);
        }
        btn_row->addStretch();
        layout->addLayout(btn_row);

        item->setSizeHint(card->sizeHint());
        ui->resultsList->setItemWidget(item, card);
    }
}

void ModelNetPage::renderSearchResponse(const UniValue& result)
{
    UniValue models(UniValue::VARR);
    if (result.exists("results") && result["results"].isArray()) {
        models = result["results"];
    } else if (result.exists("models") && result["models"].isArray()) {
        models = result["models"];
    } else if (result.exists("publishers") && result["publishers"].isArray()) {
        models = result["publishers"];
    } else if (result.exists("collections") && result["collections"].isArray()) {
        models = result["collections"];
    } else if (result.exists("items") && result["items"].isArray()) {
        for (const auto& it : result["items"].getValues()) {
            if (it.isObject() && it.exists("entry") && it["entry"].isObject()) models.push_back(it["entry"]);
            else if (it.isObject()) models.push_back(it);
        }
    }
    const auto fmt = currentFormatFilter();
    const QString needle = ui->searchLineEdit->text().trimmed().toLower();
    if (fmt || !needle.isEmpty()) {
        models = FilterModelsArray(models, needle, fmt);
    }
    if (result.exists("results_returned")) {
        m_last_results_returned = result["results_returned"].getInt<int>();
    } else {
        m_last_results_returned = static_cast<int>(models.isArray() ? models.getValues().size() : 0);
    }
    renderModelCards(models, &result);

    if (result.exists("query_id") && result["query_id"].isStr()) {
        pollSearchStatus(result["query_id"].get_str(), 0);
    }
}

void ModelNetPage::pollSearchStatus(const std::string& query_id, int attempt)
{
    if (attempt >= 12 || query_id.empty() || m_last_search_method.empty()) return;
    UniValue params(UniValue::VARR);
    params.push_back(query_id);
    const auto status = tryRpc("getsearchstatus", params);
    if (!status) return;

    const std::string state = status->exists("state") ? (*status)["state"].get_str() : std::string{};
    const int returned = status->exists("results_returned") ? (*status)["results_returned"].getInt<int>() : 0;
    const bool more_results = returned > m_last_results_returned;

    if (more_results) {
        const auto refreshed = tryRpc(m_last_search_method, m_last_search_params);
        if (refreshed) {
            renderSearchResponse(*refreshed);
        }
    }

    if (state == "RUNNING") {
        QTimer::singleShot(600, this, [this, query_id, attempt]() { pollSearchStatus(query_id, attempt + 1); });
    }
}

void ModelNetPage::renderLocalTypeahead(const QString& needle)
{
    if (!m_have_local_cache) {
        ui->searchCoverageLabel->setText(tr("Local preview (≤2 chars) — no local catalog cached yet."));
        clearResultsList();
        return;
    }
    const QString lower = needle.trimmed().toLower();
    const UniValue filtered = FilterModelsArray(m_cached_listmodels, lower, currentFormatFilter());
    UniValue meta(UniValue::VOBJ);
    UniValue cov(UniValue::VOBJ);
    cov.pushKV("local", true);
    cov.pushKV("complete", false);
    meta.pushKV("coverage", cov);
    renderModelCards(filtered, &meta);
}

void ModelNetPage::onSearchTextChanged(const QString& text)
{
    const int len = text.trimmed().size();
    if (len == 0) {
        clearResultsList();
        ui->searchCoverageLabel->setText(
            tr("Search to discover models. Coverage is always incomplete until you run Search."));
        return;
    }
    if (len <= 2) {
        renderLocalTypeahead(text);
    }
}

void ModelNetPage::runModelSearch()
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        ui->modelsOutput->setPlainText(
            tr("Node RPC is not connected. Connect the wallet to a node, or use btx-cli searchmodels."));
        return;
    }

    std::string method = "searchmodels";
    std::optional<std::string> scope;
    std::optional<std::string> sort_override;
    switch (modelsScopeTabIndex()) {
    case 1:
        method = "getmodelfeed";
        sort_override = "NEARLY_FUNDED";
        break;
    case 2:
        method = "browsemodels";
        sort_override = "AVAILABILITY";
        break;
    case 3:
        method = "getmodelfeed";
        sort_override = "RARE";
        break;
    case 4:
        method = "getrecentlyunlockedmodels";
        break;
    case 5:
        scope = "LOCAL";
        break;
    case 6:
        method = "getrecentreleases";
        break;
    case 7:
        method = "searchpublishers";
        break;
    case 8:
        method = "searchcollections";
        break;
    case 9:
        method = "searchbounties";
        scope = "NETWORK";
        break;
    case 0:
    default:
        if (ui->searchLineEdit->text().trimmed().isEmpty()) {
            method = "getmodelfeed";
        } else {
            scope = "NETWORK";
        }
        break;
    }

    UniValue query = buildSearchQueryObject(scope, sort_override);
    if (method == "getmodelfeed") {
        query.pushKV("mode", sort_override ? *sort_override : "NEWEST");
        query.pushKV("scope", "NETWORK");
    }
    UniValue params(UniValue::VARR);
    params.push_back(query);

    m_last_search_method = method;
    m_last_search_params = params;
    m_last_results_returned = 0;

    ui->modelsOutput->setPlainText(QString::fromStdString(method) + QStringLiteral(" …"));
    const auto result = tryRpc(method, params);
    if (!result) {
        ui->modelsOutput->setPlainText(callRpc(method, params));
        ui->searchCoverageLabel->setText(tr("Search failed — see detail pane."));
        return;
    }

    renderSearchResponse(*result);
    ui->modelsOutput->setPlainText(
        tr("%1 (read-only; no auto-fetch)\n").arg(QString::fromStdString(method)) +
        QString::fromStdString(result->write(2)));
#else
    ui->modelsOutput->setPlainText(tr("Model network support was not compiled into this GUI."));
#endif
}

void ModelNetPage::onResultDownload()
{
    const auto* btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    const QString uri = btn->property("modelUri").toString();
    showModelPlan(uri);
}

void ModelNetPage::onResultCopyUri()
{
    const auto* btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    const QString uri = btn->property("modelUri").toString();
    if (uri.isEmpty()) return;
#ifdef ENABLE_MODELNET
    GUIUtil::setClipboard(QString::fromStdString(modelnet::CopyUri(uri.toStdString())));
#else
    GUIUtil::setClipboard(uri);
#endif
}

void ModelNetPage::showModelPlan(const QString& full_uri)
{
    if (full_uri.isEmpty()) {
        ui->modelsOutput->setPlainText(tr("No btx:// URI for this result."));
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(full_uri.toStdString());
    ui->modelsOutput->setPlainText(
        tr("getmodel (plan only — does not spend or fetch until you approve elsewhere)\n") +
        callRpc("getmodel", params));
}

void ModelNetPage::onResultDetails()
{
    const auto* btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    showModelDetails(btn->property("modelUri").toString());
}

void ModelNetPage::onResultFund()
{
    const auto* btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    showFundPlan(btn->property("releaseId").toString());
}

void ModelNetPage::onResultFundBounty()
{
    UniValue params(UniValue::VARR);
    params.push_back(UniValue(UniValue::VOBJ));
    const auto reply = QMessageBox::question(
        this,
        tr("Confirm bounty inspection"),
        tr("preparebountyfunding / inspectbountytransaction will be shown. This page will not broadcast. There is no automatic spend."),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (reply != QMessageBox::Yes) {
        ui->modelsOutput->setPlainText(tr("Bounty funding cancelled. No transaction was created or broadcast."));
        return;
    }
    ui->modelsOutput->setPlainText(
        tr("preparebountyfunding / inspectbountytransaction (no automatic spend)\n") +
        callRpc("getbountycapabilities") + QLatin1Char('\n') +
        callRpc("searchbounties", params));
}

void ModelNetPage::onResultAward()
{
    UniValue params(UniValue::VARR);
    params.push_back(UniValue(UniValue::VOBJ));
    ui->modelsOutput->setPlainText(
        tr("inspectbountyaward (policy approval is not a transaction signature)\n") +
        callRpc("getbountycapabilities"));
}

void ModelNetPage::onResultRefund()
{
    UniValue params(UniValue::VARR);
    params.push_back(UniValue(UniValue::VOBJ));
    ui->modelsOutput->setPlainText(
        tr("preparebountyrefund — council/helper may be offline\n") +
        callRpc("getbountycapabilities"));
}

void ModelNetPage::onResultCache()
{
    const auto* btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    QString id = btn->property("releaseId").toString();
    if (id.isEmpty()) id = btn->property("modelUri").toString();
    showCachePlan(id);
}

void ModelNetPage::showFundPlan(const QString& release_id)
{
    if (release_id.isEmpty()) {
        ui->modelsOutput->setPlainText(tr("No release id on this card."));
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(release_id.toStdString());
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("automatic_spend_atoms", 0);
    params.push_back(opts);
    const auto result = tryRpc("preparefundmodelrelease", params);
    if (!result) {
        ui->modelsOutput->setPlainText(
            tr("preparefundmodelrelease failed.\n") + callRpc("preparefundmodelrelease", params));
        return;
    }
    auto field = [&](const char* k) -> QString {
        if (!result->exists(k)) return QStringLiteral("—");
        const UniValue& v = (*result)[k];
        if (v.isNum()) return QString::number(v.getInt<int64_t>());
        if (v.isStr()) return QString::fromStdString(v.get_str());
        if (v.isBool()) return v.get_bool() ? QStringLiteral("true") : QStringLiteral("false");
        return QString::fromStdString(v.write());
    };
    QStringList lines;
    lines << tr("Unsigned funding plan — this page never spends (automatic_spend_atoms=0).");
    lines << tr("Confirm in the wallet after reviewing every field below.");
    lines << QString();
    lines << tr("Release identity: %1").arg(release_id);
    lines << tr("Amount (atoms): %1").arg(field("amount_atoms"));
    lines << tr("Fee (atoms): %1").arg(field("fee_atoms"));
    lines << tr("Fee cap (atoms): %1").arg(field("fee_cap_atoms"));
    lines << tr("SHA-256 hashlock: %1").arg(field("key_hash"));
    lines << tr("Hashlock algorithm: %1").arg(field("hashlock_algorithm").isEmpty() ? field("htlc") : field("hashlock_algorithm"));
    lines << tr("Refund height: %1").arg(field("refund_height"));
    lines << tr("Descriptor: %1").arg(field("descriptor"));
    lines << tr("Next: signmodelfunding, then submitmodelfunding.");
    lines << QString();
    lines << QString::fromStdString(result->write(2));
    const auto reply = QMessageBox::question(
        this,
        tr("Confirm funding inspection"),
        tr("Amount (atoms): %1\nFee (atoms): %2\nSHA-256 hashlock: %3\nRefund height: %4\nRelease identity: %5\n\nThis page will not broadcast. There is no automatic spend.")
            .arg(field("amount_atoms"), field("fee_atoms"), field("key_hash"), field("refund_height"), release_id),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (reply != QMessageBox::Yes) {
        ui->modelsOutput->setPlainText(tr("Funding cancelled. No transaction was created or broadcast."));
        return;
    }
    ui->modelsOutput->setPlainText(lines.join(QLatin1Char('\n')));
}

void ModelNetPage::showCachePlan(const QString& release_id)
{
    if (release_id.isEmpty()) {
        ui->modelsOutput->setPlainText(tr("No release id on this card."));
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(release_id.toStdString());
    ui->modelsOutput->setPlainText(
        tr("cacheencryptedmodel (ciphertext only; never auto-download from a feed card; plaintext stays sealed)\n") +
        callRpc("cacheencryptedmodel", params));
}

void ModelNetPage::pollFeedSequence()
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) return;
    const auto st = tryRpc("getmodelfeedsequence", UniValue(UniValue::VARR));
    if (!st) return;
    int64_t seq = 0;
    if (st->exists("feed_sequence") && (*st)["feed_sequence"].isNum()) {
        seq = (*st)["feed_sequence"].getInt<int64_t>();
    }
    if (seq <= 0 || seq == m_feed_sequence) return;
    const bool first = m_feed_sequence == 0;
    m_feed_sequence = seq;
    if (first) return;
    if (m_last_search_method == "getmodelfeed" || m_last_search_method == "getrecentreleases" ||
        m_last_search_method == "getrecentlyunlockedmodels" || m_last_search_method.empty()) {
        UniValue q(UniValue::VOBJ);
        q.pushKV("scope", "NETWORK");
        q.pushKV("mode", "NEWEST");
        q.pushKV("limit", 25);
        UniValue params(UniValue::VARR);
        params.push_back(q);
        if (const auto feed = tryRpc("getmodelfeed", params)) {
            renderSearchResponse(*feed);
            ui->searchCoverageLabel->setText(
                tr("Feed sequence %1 — live (no restart). Coverage remains incomplete.")
                    .arg(QString::number(seq)));
        }
    }
#else
    (void)0;
#endif
}

void ModelNetPage::pollCampaign(const QString& id, int attempt)
{
    if (attempt >= 20 || id.isEmpty()) return;
    UniValue params(UniValue::VARR);
    params.push_back(id.toStdString());
    const auto status = tryRpc("getmodelreleaseeconomics", params);
    if (status) {
        ui->modelsOutput->setPlainText(
            tr("getmodelreleaseeconomics (live; no restart)\n") + QString::fromStdString(status->write(2)));
    }
    QTimer::singleShot(1500, this, [this, id, attempt]() { pollCampaign(id, attempt + 1); });
}

void ModelNetPage::showModelDetails(const QString& full_uri)
{
    if (full_uri.isEmpty()) {
        ui->modelsOutput->setPlainText(tr("No btx:// URI for this result."));
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(full_uri.toStdString());
    ui->modelsOutput->setPlainText(
        tr("getmodeleconomyentry + getmodeldirectoryentry (read-only)\n") +
        callRpc("getmodeleconomyentry", params) + QLatin1Char('\n') +
        callRpc("getmodeldirectoryentry", params));
    pollCampaign(full_uri, 0);
}

void ModelNetPage::onPublishSearchRecord()
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        ui->publishOutput->setPlainText(
            tr("Node RPC is not connected. Connect the wallet, or use btx-cli publishmodelsearchrecord."));
        return;
    }
    const QString id = ui->publishModelIdEdit->text().trimmed();
    const QString name = ui->publishDisplayNameEdit->text().trimmed();
    if (id.isEmpty() || name.isEmpty()) {
        ui->publishOutput->setPlainText(tr("Model id and display name are required."));
        return;
    }
    UniValue meta(UniValue::VOBJ);
    meta.pushKV("display_name", name.toStdString());
    meta.pushKV("canonical_name", name.toStdString());
    const QString family = ui->publishFamilyEdit->text().trimmed();
    const QString format = ui->publishFormatEdit->text().trimmed();
    const QString tags = ui->publishTagsEdit->text().trimmed();
    const QString desc = ui->publishDescriptionEdit->text().trimmed();
    if (!family.isEmpty()) meta.pushKV("family", family.toStdString());
    if (!format.isEmpty()) meta.pushKV("format", format.toStdString());
    if (!desc.isEmpty()) meta.pushKV("short_description", desc.toStdString());
    if (!tags.isEmpty()) {
        UniValue arr(UniValue::VARR);
        for (const QString& t : tags.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
            arr.push_back(t.trimmed().toStdString());
        }
        meta.pushKV("tags", arr);
    }
    UniValue params(UniValue::VARR);
    params.push_back(id.toStdString());
    params.push_back(meta);
    const auto result = tryRpc("publishmodelsearchrecord", params);
    if (!result) {
        ui->publishOutput->setPlainText(callRpc("publishmodelsearchrecord", params));
        return;
    }
    ui->publishOutput->setPlainText(
        tr("publishmodelsearchrecord (metadata only; automatic_spend_atoms=0)\n") +
        QString::fromStdString(result->write(2)));
#else
    ui->publishOutput->setPlainText(tr("Model network support was not compiled into this GUI."));
#endif
}

void ModelNetPage::onImportBrowse()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Import model file"), QString(),
        tr("Models and share cards (*.gguf *.safetensors *.btx *.btxlink);;All files (*)"));
    if (!path.isEmpty()) ui->importPathEdit->setText(path);
}

void ModelNetPage::showImportShare(const UniValue& result)
{
    m_import_share_uri.clear();
    const UniValue* share = nullptr;
    if (result.exists("share") && result["share"].isObject()) {
        share = &result["share"];
    }

    QString copy_text;
    if (share && share->exists("copy_text") && (*share)["copy_text"].isStr()) {
        copy_text = QString::fromStdString((*share)["copy_text"].get_str());
    } else if (result.exists("copy_text") && result["copy_text"].isStr()) {
        copy_text = QString::fromStdString(result["copy_text"].get_str());
    }

    QString uri;
    if (share && share->exists("uri") && (*share)["uri"].isStr()) {
        uri = QString::fromStdString((*share)["uri"].get_str());
    } else if (result.exists("uri") && result["uri"].isStr()) {
        uri = QString::fromStdString(result["uri"].get_str());
    }
#ifdef ENABLE_MODELNET
    if (!uri.isEmpty()) {
        const std::string full = modelnet::CopyUri(uri.toStdString());
        if (!full.empty()) uri = QString::fromStdString(full);
    }
#endif

    auto fill_if_empty = [](QLineEdit* edit, const UniValue& obj, const char* key) {
        if (!edit->text().trimmed().isEmpty()) return;
        if (obj.exists(key) && obj[key].isStr()) {
            edit->setText(QString::fromStdString(obj[key].get_str()));
        }
    };
    if (share) {
        fill_if_empty(ui->publishFamilyEdit, *share, "family");
        fill_if_empty(ui->publishFormatEdit, *share, "format");
    }

    m_import_share_uri = uri;
    if (copy_text.isEmpty() && !uri.isEmpty()) {
        copy_text = uri;
    }

    QString rates = TransferRateSuffixFromRow(result);
    if (rates.isEmpty() && share) rates = TransferRateSuffix(*share);
    if (rates.isEmpty() && result.exists("transfers") && result["transfers"].isArray()) {
        for (const auto& t : result["transfers"].getValues()) {
            rates = TransferRateSuffixFromRow(t);
            if (!rates.isEmpty()) break;
        }
    }

    QString line = copy_text;
    if (!rates.isEmpty()) {
        if (!line.isEmpty()) line += QStringLiteral(" · ");
        line += rates;
    }

    const bool show = !copy_text.isEmpty() || !uri.isEmpty() || !rates.isEmpty();
    ui->importShareRowWidget->setVisible(show);
    ui->importShareLabel->setText(line);
    ui->importCopyUriButton->setVisible(!uri.isEmpty());
    ui->importCopyUriButton->setEnabled(!uri.isEmpty());

    QString hint = tr("After copy_text, optionally setmodelalias <id> <name> so showmodel and getmodel can use an Ollama-style alias. unhostmodel unpins and unseeds in one call. This page does not auto-getmodel or spend. automatic_spend_atoms stays 0.");
    const QString aliases = FormatAliasesLine(result, share);
    if (!aliases.isEmpty()) {
        hint = aliases + QLatin1Char('\n') + hint;
    }
    ui->importAliasHintLabel->setText(hint);
    ui->importAliasHintLabel->setVisible(show);
}

void ModelNetPage::onImportModel()
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        ui->publishOutput->setPlainText(
            tr("Node RPC is not connected. Connect the wallet, or use btx-cli importmodel."));
        return;
    }
    QString path = ui->importPathEdit->text().trimmed();
    if (path.isEmpty()) {
        onImportBrowse();
        path = ui->importPathEdit->text().trimmed();
    }
    if (path.isEmpty()) {
        ui->publishOutput->setPlainText(tr("Choose a local GGUF or SafeTensors path to import."));
        return;
    }
    const bool looks_share =
        path.contains(QStringLiteral("btx://"), Qt::CaseInsensitive) ||
        path.endsWith(QStringLiteral(".btx"), Qt::CaseInsensitive) ||
        path.endsWith(QStringLiteral(".btxlink"), Qt::CaseInsensitive);
    if (looks_share) {
        UniValue share_params(UniValue::VARR);
        share_params.push_back(path.toStdString());
        const auto preview = tryRpc("openmodelshare", share_params);
        if (!preview) {
            showImportShare(UniValue(UniValue::VOBJ));
            ui->publishOutput->setPlainText(
                tr("openmodelshare (preview only; never retrieves or spends)\n") +
                callRpc("openmodelshare", share_params));
            return;
        }
        showImportShare(*preview);
        ui->publishOutput->setPlainText(
            tr("openmodelshare (preview only; automatic_spend_atoms=0; this page does not auto-getmodel)\n") +
            QString::fromStdString(preview->write(2)));
        return;
    }
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("pin", true);
    opts.pushKV("publish", true);
    UniValue params(UniValue::VARR);
    params.push_back(path.toStdString());
    params.push_back(opts);
    const auto result = tryRpc("importmodel", params);
    if (!result) {
        showImportShare(UniValue(UniValue::VOBJ));
        ui->publishOutput->setPlainText(callRpc("importmodel", params));
        return;
    }
    if (result->exists("model_id") && (*result)["model_id"].isStr()) {
        ui->publishModelIdEdit->setText(QString::fromStdString((*result)["model_id"].get_str()));
    }
    if (result->exists("format") && (*result)["format"].isStr() &&
        ui->publishFormatEdit->text().trimmed().isEmpty()) {
        ui->publishFormatEdit->setText(QString::fromStdString((*result)["format"].get_str()));
    }
    if (result->exists("family") && (*result)["family"].isStr() &&
        ui->publishFamilyEdit->text().trimmed().isEmpty()) {
        ui->publishFamilyEdit->setText(QString::fromStdString((*result)["family"].get_str()));
    }
    showImportShare(*result);
    QString out = tr("importmodel (pin+publish; automatic_spend_atoms=0)\n");
    const QString copy_text = ui->importShareLabel->text();
    if (!copy_text.isEmpty()) {
        out += copy_text + QLatin1Char('\n');
    }
    if (ui->importAliasHintLabel->isVisible() && !ui->importAliasHintLabel->text().isEmpty()) {
        out += ui->importAliasHintLabel->text() + QLatin1Char('\n');
    }
    out += QString::fromStdString(result->write(2));
    ui->publishOutput->setPlainText(out);
#else
    ui->publishOutput->setPlainText(tr("Model network support was not compiled into this GUI."));
#endif
}

void ModelNetPage::refreshTransfersAndShares()
{
    const QString rpc_note = tr("\n\nRPC: %1 (same name as CLI). This page never calls getmodel/importmodel automatically.");

    QString downloads;
    if (const auto xfer = tryRpc("getmodeltransfers", UniValue(UniValue::VARR))) {
        downloads = tr("getmodeltransfers\n") + FormatTransfersPane(*xfer);
    } else {
        downloads = tr("getmodeltransfers unavailable on this node.\n") +
                    callRpc("getmodeltransfers");
    }
    downloads += QLatin1Char('\n') + tr("getmodeljob") + QLatin1Char('\n');
    if (const auto job = tryRpc("getmodeljob", UniValue(UniValue::VARR))) {
        const QString job_rates = TransferRateSuffixFromRow(*job);
        if (!job_rates.isEmpty()) {
            downloads += tr("getmodeljob rates: %1").arg(job_rates) + QLatin1Char('\n');
        }
        downloads += QString::fromStdString(job->write(2));
    } else {
        downloads += callRpc("getmodeljob");
    }
    ui->downloadsOutput->setPlainText(downloads + rpc_note.arg(QStringLiteral("getmodeltransfers, getmodeljob")));

    QString shared = tr("Seeded/shared inventory is the same listmodels RPC. Demand-seed is -modelseed=auto after a positive budget; this page does not advertise new models by itself.");
    if (const auto listed = tryRpc("listmodels", UniValue(UniValue::VARR))) {
        shared += QLatin1String("\n\n") + tr("listmodels") + QLatin1Char('\n') + FormatTransfersPane(*listed);
    } else {
        shared += QLatin1String("\n\n") + callRpc("listmodels");
    }
    ui->sharedOutput->setPlainText(shared + rpc_note.arg(QStringLiteral("listmodels, getmodeltransfers")));
}

void ModelNetPage::refreshCapabilities()
{
    const auto caps = tryRpc("getbtxruntimecapabilities", UniValue(UniValue::VARR));
    if (!caps) {
        ui->capabilityStatusLabel->setText(
            tr("Capabilities: helper down or RPC unavailable (HELPER_DOWN). Monetary node continues. automatic_spend_atoms stays 0."));
        return;
    }
    QString line = tr("Capabilities — Available now / Preparing. Public HTTP is 405. GUI BUILD_GUI=OFF on this compile tree is DEFERRED_WITH_EVIDENCE for live widgets; this tab is the registered front door.");
    if (caps->exists("gui") && (*caps)["gui"].isStr()) {
        line += QLatin1Char(' ') + QString::fromStdString((*caps)["gui"].get_str());
    }
    ui->capabilityStatusLabel->setText(line);
    if (ui->capabilityOutput->toPlainText().isEmpty()) {
        ui->capabilityOutput->setPlainText(FormatCapabilityOutput("getbtxruntimecapabilities", *caps, false));
    }
}

void ModelNetPage::onCapabilityEnsure()
{
    UniValue recipe(UniValue::VOBJ);
    recipe.pushKV("recipe_kind", "FULL_MODEL");
    UniValue comps(UniValue::VARR);
    UniValue c(UniValue::VOBJ);
    c.pushKV("name", "base");
    UniValue res(UniValue::VOBJ);
    res.pushKV("kind", "MODEL");
    res.pushKV("digest48", std::string(96, 'a'));
    c.pushKV("resource", res);
    c.pushKV("role", "BASE");
    c.pushKV("required", true);
    comps.push_back(c);
    recipe.pushKV("components", comps);
    UniValue grant(UniValue::VOBJ);
    grant.pushKV("caller", "local");
    grant.pushKV("host_bytes", 8388608);
    grant.pushKV("automatic_spend_atoms", 0);
    UniValue plan_req(UniValue::VOBJ);
    plan_req.pushKV("recipe", recipe);
    plan_req.pushKV("grant", grant);
    UniValue params(UniValue::VARR);
    params.push_back(plan_req);
    const auto plan = tryRpc("planbtxcapability", params);
    if (!plan) {
        ui->capabilityOutput->setPlainText(tr("planbtxcapability failed (not runtime-ready). automatic_spend_atoms=0"));
        return;
    }
    UniValue ens(UniValue::VOBJ);
    if (plan->exists("plan_id") && (*plan)["plan_id"].isStr()) ens.pushKV("plan_id", (*plan)["plan_id"].get_str());
    ens.pushKV("grant", grant);
    UniValue ens_params(UniValue::VARR);
    ens_params.push_back(ens);
    const auto got = tryRpc("ensurebtxcapability", ens_params);
    if (!got) {
        ui->capabilityOutput->setPlainText(
            tr("ensurebtxcapability failed (not runtime-ready). automatic_spend_atoms=0\n") +
            FormatCapabilityOutput("planbtxcapability", *plan, false));
        return;
    }
    showCapabilityReply("ensurebtxcapability", got, tr("ensurebtxcapability failed. automatic_spend_atoms stays 0."));
    if (got->exists("lease_id") && (*got)["lease_id"].isStr()) {
        ui->capabilityLeaseEdit->setText(QString::fromStdString((*got)["lease_id"].get_str()));
    }
}

void ModelNetPage::showCapabilityReply(const std::string& method, const std::optional<UniValue>& got,
                                      const QString& fail, bool wake)
{
    if (!got) {
        ui->capabilityOutput->setPlainText(fail);
        return;
    }
    ui->capabilityOutput->setPlainText(FormatCapabilityOutput(method, *got, wake));
}

void ModelNetPage::onCapabilityPrefetch()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("grant", CapabilityZeroGrant());
    o.pushKV("kind", "DEMAND");
    o.pushKV("automatic_spend_atoms", 0);
    const auto got = tryRpc("prefetchbtxcapability", CapabilityRpcParams(o));
    showCapabilityReply("prefetchbtxcapability", got, tr("prefetchbtxcapability failed. automatic_spend_atoms stays 0."));
}

void ModelNetPage::onCapabilitySleep()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("lease_id", ui->capabilityLeaseEdit->text().trimmed().toStdString());
    o.pushKV("automatic_spend_atoms", 0);
    const auto got = tryRpc("sleepbtxcapability", CapabilityRpcParams(o));
    showCapabilityReply("sleepbtxcapability", got,
                         tr("sleepbtxcapability failed; remap-only is not ready. automatic_spend_atoms stays 0."));
}

void ModelNetPage::onCapabilityRelease()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("lease_id", ui->capabilityLeaseEdit->text().trimmed().toStdString());
    o.pushKV("automatic_spend_atoms", 0);
    const auto got = tryRpc("releasebtxcapability", CapabilityRpcParams(o));
    showCapabilityReply("releasebtxcapability", got, tr("releasebtxcapability failed. automatic_spend_atoms stays 0."));
}

void ModelNetPage::onCapabilityWake()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("lease_id", ui->capabilityLeaseEdit->text().trimmed().toStdString());
    o.pushKV("remap_only", false);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("grant", CapabilityZeroGrant());
    const auto got = tryRpc("wakebtxcapability", CapabilityRpcParams(o));
    if (got && CapabilityWakeRejected(*got)) {
        showCapabilityReply("wakebtxcapability", got,
                            tr("wakebtxcapability: remap_only is not readiness. automatic_spend_atoms stays 0."),
                            /*wake=*/true);
        return;
    }
    showCapabilityReply("wakebtxcapability", got,
                         tr("wakebtxcapability failed. remap_only is not readiness. automatic_spend_atoms stays 0."),
                         /*wake=*/true);
    if (got && got->exists("lease_id") && (*got)["lease_id"].isStr()) {
        ui->capabilityLeaseEdit->setText(QString::fromStdString((*got)["lease_id"].get_str()));
    }
}

void ModelNetPage::onCapabilityUpdate()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("preview", true);
    o.pushKV("automatic_spend_atoms", 0);
    // Never send smoke_passed=true from this page. Smoke blocked is not 100% ready.
    o.pushKV("smoke_passed", false);
    const std::string lock = ui->capabilityLeaseEdit->text().trimmed().toStdString();
    if (!lock.empty()) o.pushKV("lock_id", lock);
    o.pushKV("grant", CapabilityZeroGrant());
    const auto got = tryRpc("planbtxcapabilityupdate", CapabilityRpcParams(o));
    showCapabilityReply("planbtxcapabilityupdate", got,
                         tr("planbtxcapabilityupdate failed. Old generation remains. automatic_spend_atoms stays 0."));
    if (got && got->exists("proposed_lock") && (*got)["proposed_lock"].isStr()) {
        const QString proposed = QString::fromStdString((*got)["proposed_lock"].get_str());
        if (!CapabilityLooksLikeWalletPath(proposed)) {
            ui->capabilityNewLockEdit->setText(proposed);
        }
    }
}

void ModelNetPage::onCapabilitySwitch()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("old_lock", ui->capabilityLeaseEdit->text().trimmed().toStdString());
    const QString neu = ui->capabilityNewLockEdit->text().trimmed();
    if (!neu.isEmpty()) o.pushKV("new_lock", neu.toStdString());
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("grant", CapabilityZeroGrant());
    const auto got = tryRpc("switchbtxcapability", CapabilityRpcParams(o));
    showCapabilityReply("switchbtxcapability", got,
                         tr("switchbtxcapability failed. automatic_spend_atoms stays 0."));
}

void ModelNetPage::onCapabilityEvents()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("cursor", 0);
    o.pushKV("automatic_spend_atoms", 0);
    const auto got = tryRpc("getbtxcapabilityevents", CapabilityRpcParams(o));
    showCapabilityReply("getbtxcapabilityevents", got,
                         tr("getbtxcapabilityevents failed. automatic_spend_atoms stays 0."));
}

void ModelNetPage::onCapabilityTtc()
{
    UniValue o(UniValue::VOBJ);
    const QString id = ui->capabilityLeaseEdit->text().trimmed();
    if (!id.isEmpty()) o.pushKV("job_id", id.toStdString());
    o.pushKV("automatic_spend_atoms", 0);
    const auto got = tryRpc("getbtxttctrace", CapabilityRpcParams(o));
    showCapabilityReply("getbtxttctrace", got,
                         tr("getbtxttctrace failed (job_id required). automatic_spend_atoms stays 0. Smoke blocked is not 100% ready."));
}

void ModelNetPage::onCapabilityRuntimeCaps()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("automatic_spend_atoms", 0);
    const auto got = tryRpc("getbtxruntimecapabilities", CapabilityRpcParams(o));
    showCapabilityReply("getbtxruntimecapabilities", got,
                         tr("getbtxruntimecapabilities failed (HELPER_DOWN). automatic_spend_atoms stays 0. Public HTTP is 405."));
}

void ModelNetPage::refresh()
{
    refreshResourceGovernorStatus();
    refreshSetupStatus();
    refreshDev348ProfileCloud();
    refreshDev348WatchesActivity();
    refreshConsent();
    refreshLocalCatalogCache();
    refreshCapabilities();

    const QString rpc_note = tr("\n\nRPC: %1 (same name as CLI). This page never calls getmodel/importmodel automatically.");
    if (ui->resultsList->count() == 0 && m_client_model) {
        UniValue q(UniValue::VOBJ);
        q.pushKV("scope", "NETWORK");
        q.pushKV("mode", "NEWEST");
        q.pushKV("limit", 25);
        UniValue params(UniValue::VARR);
        params.push_back(q);
        if (const auto feed = tryRpc("getmodelfeed", params)) {
            renderSearchResponse(*feed);
            ui->modelsOutput->setPlainText(
                tr("getmodelfeed NEWEST (decentralized current view; not a global chronology)\n") +
                QString::fromStdString(feed->write(2)));
        } else {
            ui->modelsOutput->setPlainText(
                tr("getmodelnetworkinfo") + QLatin1Char('\n') + callRpc("getmodelnetworkinfo") +
                rpc_note.arg(QStringLiteral("searchmodels, getmodelfeed, getmodeleconomyentry")));
        }
    }
    refreshTransfersAndShares();
    ui->collectionsOutput->setPlainText(
        tr("searchcollections — signed immutable membership snapshots. This GUI does not auto-subscribe or auto-fetch.\n") +
        callRpc("searchcollections") +
        rpc_note.arg(QStringLiteral("searchcollections, getcollection, subscribemodelcollection")));
    ui->identityOutput->setPlainText(
        tr("searchpublishers (local/network-sample identities; not a global directory)\n") +
        callRpc("searchpublishers") +
        QLatin1String("\n\n") +
        tr("Research identities are not spending keys and not the wallet.\n\nlistmodelidentities\n") +
        callRpc("listmodelidentities") +
        rpc_note.arg(QStringLiteral("searchpublishers, getpublisher, listmodelidentities, createmodelidentity")));
    ui->preservationOutput->setPlainText(
        tr("getmodelpolicy") + QLatin1Char('\n') + callRpc("getmodelpolicy") +
        rpc_note.arg(QStringLiteral("getmodelpolicy")));
    ui->peersOutput->setPlainText(
        tr("getmodelpeers") + QLatin1Char('\n') + callRpc("getmodelpeers") +
        rpc_note.arg(QStringLiteral("getmodelpeers")));
}
