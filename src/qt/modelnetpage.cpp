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
#include <QTimer>
#include <QVBoxLayout>

#include <stdexcept>

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
    connect(ui->modelsScopeTabWidget, &QTabWidget::currentChanged, this, [this](int) {
        ui->searchCoverageLabel->setText(
            tr("Scope changed — run Search to refresh results (coverage always incomplete)."));
    });

    auto* feed_timer = new QTimer(this);
    connect(feed_timer, &QTimer::timeout, this, &ModelNetPage::pollFeedSequence);
    feed_timer->start(4000);

    ui->uriDisplayLabel->installEventFilter(this);
    ui->uriRowWidget->setVisible(false);
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

void ModelNetPage::refresh()
{
    refreshResourceGovernorStatus();
    refreshConsent();
    refreshLocalCatalogCache();

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
    ui->downloadsOutput->setPlainText(
        tr("getmodeljob") + QLatin1Char('\n') + callRpc("getmodeljob") +
        rpc_note.arg(QStringLiteral("getmodeljob")));
    ui->sharedOutput->setPlainText(
        tr("Seeded/shared inventory is the same listmodels RPC. Demand-seed is -modelseed=auto after a positive budget; this page does not advertise new models by itself.") +
        QLatin1String("\n\n") + callRpc("listmodels") +
        rpc_note.arg(QStringLiteral("listmodels")));
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
