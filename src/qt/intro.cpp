// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <qt/intro.h>
#include <qt/forms/ui_intro.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>

#include <common/args.h>
#include <interfaces/node.h>
#include <util/fs_helpers.h>
#include <validation.h>

#include <QCheckBox>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSettings>
#include <QStandardPaths>

#include <algorithm>
#include <cmath>
#include <limits>

/* Check free space asynchronously to prevent hanging the UI thread.

   Up to one request to check a path is in flight to this thread; when the check()
   function runs, the current path is requested from the associated Intro object.
   The reply is sent back through a signal.

   This ensures that no queue of checking requests is built up while the user is
   still entering the path, and that always the most recently entered path is checked as
   soon as the thread becomes available.
*/
class FreespaceChecker : public QObject
{
    Q_OBJECT

public:
    explicit FreespaceChecker(Intro *intro);

    enum Status {
        ST_OK,
        ST_ERROR
    };

public Q_SLOTS:
    void check();

Q_SIGNALS:
    void reply(int status, const QString &message, quint64 available);

private:
    Intro *intro;
};

#include <qt/intro.moc>

FreespaceChecker::FreespaceChecker(Intro *_intro)
{
    this->intro = _intro;
}

void FreespaceChecker::check()
{
    QString dataDirStr = intro->getPathToCheck();
    fs::path dataDir = GUIUtil::QStringToPath(dataDirStr);
    uint64_t freeBytesAvailable = 0;
    int replyStatus = ST_OK;
    QString replyMessage = tr("A new data directory will be created.");

    /* Find first parent that exists, so that fs::space does not fail */
    fs::path parentDir = dataDir;
    fs::path parentDirOld = fs::path();
    while(parentDir.has_parent_path() && !fs::exists(parentDir))
    {
        parentDir = parentDir.parent_path();

        /* Check if we make any progress, break if not to prevent an infinite loop here */
        if (parentDirOld == parentDir)
            break;

        parentDirOld = parentDir;
    }

    try {
        freeBytesAvailable = fs::space(parentDir).available;
        if(fs::exists(dataDir))
        {
            if(fs::is_directory(dataDir))
            {
                QString separator = "<code>" + QDir::toNativeSeparators("/") + tr("name") + "</code>";
                replyStatus = ST_OK;
                replyMessage = tr("Directory already exists. Add %1 if you intend to create a new directory here.").arg(separator);
            } else {
                replyStatus = ST_ERROR;
                replyMessage = tr("Path already exists, and is not a directory.");
            }
        }
    } catch (const fs::filesystem_error&)
    {
        /* Parent directory does not exist or is not accessible */
        replyStatus = ST_ERROR;
        replyMessage = tr("Cannot create data directory here.");
    }
    Q_EMIT reply(replyStatus, replyMessage, freeBytesAvailable);
}

namespace {
//! Return pruning size that will be used if automatic pruning is enabled.
int GetPruneTargetMiB()
{
    int64_t prune_target_mib = gArgs.GetIntArg("-prune", 0);
    // >1 means automatic pruning is enabled by config, 1 means manual pruning, 0 means no pruning.
    return prune_target_mib > 1 ? prune_target_mib : DEFAULT_PRUNE_TARGET_MiB;
}
} // namespace

Intro::Intro(QWidget *parent, int64_t blockchain_size_gb, int64_t chain_state_size_gb) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::Intro),
    m_blockchain_size_gb(blockchain_size_gb),
    m_chain_state_size_gb(chain_state_size_gb),
    m_prune_target_mib{GetPruneTargetMiB()}
{
    ui->setupUi(this);
    ui->welcomeLabel->setText(ui->welcomeLabel->text().arg(CLIENT_NAME));
    ui->storageLabel->setText(ui->storageLabel->text().arg(CLIENT_NAME));

    ui->lblExplanation1->setText(ui->lblExplanation1->text()
        .arg(CLIENT_NAME)
        .arg(m_blockchain_size_gb)
        .arg(2009)
        .arg(tr("Bitcoin"))
    );
    ui->lblExplanation2->setText(ui->lblExplanation2->text().arg(CLIENT_NAME));

    const int min_prune_target_MiB = (MIN_DISK_SPACE_FOR_BLOCK_FILES + MiB_BYTES - 1) / MiB_BYTES;
    ui->pruneMiB->setRange(min_prune_target_MiB, std::numeric_limits<int>::max());
    if (gArgs.IsArgSet("-prune")) {
        m_prune_checkbox_is_default = false;
        switch (gArgs.GetIntArg("-prune", 0)) {
        case 0:
            ui->prune->setChecked(false);
            break;
        case 1:
            ui->prune->setTristate();
            ui->prune->setCheckState(Qt::PartiallyChecked);
            break;
        default:
            ui->prune->setChecked(true);
        }
    }
    ui->pruneMiB->setValue(m_prune_target_mib);
    ui->pruneMiB->setToolTip(ui->prune->toolTip());
    ui->lblPruneSuffix->setToolTip(ui->prune->toolTip());
    UpdatePruneLabels(ui->prune->checkState() == Qt::Checked);

    ui->modelStorageSpin->setRange(0, 1048576);
    ui->modelStorageSpin->setValue(500);
    ui->modelStorageUnit->setCurrentIndex(1); // GiB
    ui->modelNetParticipate->setChecked(true);
    ui->modelStorageAuto->setChecked(true);
    ui->modelDemandSeed->setChecked(true);
    ui->modelResourceGovernor->setChecked(true);
    ui->modelMiningIdle->setChecked(false);
    ui->modelPreserveRare->setChecked(false);
    ui->lblResourceMode->setText(tr("Resource mode: Automatic"));
    ui->installOsHandler->setChecked(true);
    ui->installOsHandlerSystem->setChecked(false);
#if defined(Q_OS_LINUX)
    ui->installOsHandlerSystem->setEnabled(ui->installOsHandler->isChecked());
    connect(ui->installOsHandler, &QCheckBox::toggled, this, [this](bool on) {
        ui->installOsHandlerSystem->setEnabled(on);
        if (!on) ui->installOsHandlerSystem->setChecked(false);
    });
    connect(ui->modelResourceGovernor, &QCheckBox::toggled, this, [this](bool on) {
        ui->lblResourceMode->setText(on ? tr("Resource mode: Automatic") : tr("Resource mode: Off"));
    });
#else
    ui->installOsHandler->setVisible(false);
    ui->installOsHandlerSystem->setVisible(false);
    ui->installOsHandler->setChecked(false);
#endif

#if (QT_VERSION >= QT_VERSION_CHECK(6, 7, 0))
    connect(ui->prune, &QCheckBox::checkStateChanged, [this](const Qt::CheckState prune_state) {
#else
    connect(ui->prune, &QCheckBox::stateChanged, [this](const int prune_state) {
#endif
        m_prune_checkbox_is_default = false;
        UpdatePruneLabels(prune_state == Qt::Checked);
        UpdateFreeSpaceLabel();
    });
    connect(ui->pruneMiB, qOverload<int>(&QSpinBox::valueChanged), [this](int prune_MiB) {
        m_prune_target_mib = prune_MiB;
        UpdatePruneLabels(ui->prune->checkState() == Qt::Checked);
        UpdateFreeSpaceLabel();
    });

    bool have_user_assumevalid = false;
    if (gArgs.IsArgSet("-assumevalid")) {
        const auto user_assumevalid = gArgs.GetArg("-assumevalid", /* ignored default; determines return type */ "");
        const auto block_hash{uint256::FromUserHex(user_assumevalid)};
        if (block_hash && !block_hash->IsNull()) {
            // -assumevalid=blockhash: initialise with the user-specified value, enabled
            ui->assumevalid->setChecked(true);
            ui->assumevalidBlock->setText(QString::fromStdString(user_assumevalid));
            have_user_assumevalid = true;
        } else {
            // -assumevalid=0: default checkbox to off, and initialise with chainparams later
            ui->assumevalid->setChecked(false);
        }
    }
    if (!have_user_assumevalid) {
        const auto chainparams = CreateChainParams(gArgs, gArgs.GetChainType());
        const uint256 default_assumevalid = chainparams ? chainparams->GetConsensus().defaultAssumeValid : uint256();
        if (default_assumevalid.IsNull()) {
            // no chainparams assumevalid (nor user-provided), so hide the options entirely
            ui->groupAssumeValid->setVisible(false);
        } else {
            // assumevalid from chainparams only (normal case): disable editing of blockhash
            ui->assumevalidBlock->setText(QString::fromStdString(default_assumevalid.GetHex()));
            ui->assumevalidBlock->setReadOnly(true);
        }
    }
    {
        // TO-DO: Ideally, we would include actual margins here (instead of extra digits), but this seems non-trivial
        const int text_width = ui->assumevalidBlock->fontMetrics().horizontalAdvance(QStringLiteral("4")) * (64 + 4);
        ui->assumevalidBlock->setFixedWidth(text_width);
    }

    startThread();
}

Intro::~Intro()
{
    delete ui;
    /* Ensure thread is finished before it is deleted */
    thread->quit();
    thread->wait();
}

QString Intro::getDataDirectory()
{
    return ui->dataDirectory->text();
}

void Intro::setDataDirectory(const QString &dataDir)
{
    ui->dataDirectory->setText(dataDir);
    if(dataDir == GUIUtil::getDefaultDataDirectory())
    {
        ui->dataDirDefault->setChecked(true);
        ui->dataDirectory->setEnabled(false);
        ui->ellipsisButton->setEnabled(false);
    } else {
        ui->dataDirCustom->setChecked(true);
        ui->dataDirectory->setEnabled(true);
        ui->ellipsisButton->setEnabled(true);
    }
}

int64_t Intro::getPruneMiB() const
{
    switch (ui->prune->checkState()) {
    case Qt::Checked:
        return m_prune_target_mib;
    case Qt::PartiallyChecked:
        return 1;
    case Qt::Unchecked: default:
        return 0;
    }
}

QString Intro::getAssumeValid() const
{
    if (!ui->assumevalid->isChecked()) {
        return QStringLiteral("0");
    }
    return ui->assumevalidBlock->text();
}

uint64_t Intro::getModelStorageBytes() const
{
    const uint64_t n = static_cast<uint64_t>(std::max(0, ui->modelStorageSpin->value()));
    uint64_t mul = 1024ULL * 1024ULL * 1024ULL;
    switch (ui->modelStorageUnit->currentIndex()) {
    case 0: mul = 1024ULL * 1024ULL; break;
    case 1: mul = 1024ULL * 1024ULL * 1024ULL; break;
    case 2: mul = 1024ULL * 1024ULL * 1024ULL * 1024ULL; break;
    default: break;
    }
    if (n != 0 && n > std::numeric_limits<uint64_t>::max() / mul) {
        return std::numeric_limits<uint64_t>::max();
    }
    return n * mul;
}

QString Intro::getModelStorageArg() const
{
    if (ui->modelStorageAuto->isChecked()) return QStringLiteral("auto");
    const int n = std::max(0, ui->modelStorageSpin->value());
    if (n == 0) return QStringLiteral("0");
    static const char* units[] = {"MiB", "GiB", "TiB"};
    const int idx = std::clamp(ui->modelStorageUnit->currentIndex(), 0, 2);
    return QString::number(n) + QLatin1String(units[idx]);
}

bool Intro::getModelNetParticipateChecked() const
{
    return ui->modelNetParticipate->isChecked();
}

bool Intro::getModelStorageAutoChecked() const
{
    return ui->modelStorageAuto->isChecked();
}

bool Intro::getDemandSeedChecked() const
{
    return ui->modelDemandSeed->isChecked();
}

bool Intro::getSpareResourcesChecked() const
{
    return ui->modelResourceGovernor->isChecked();
}

bool Intro::getMiningIdleChecked() const
{
    return ui->modelMiningIdle->isChecked();
}

bool Intro::getPreserveRareChecked() const
{
    return ui->modelPreserveRare->isChecked();
}

bool Intro::getInstallOsHandlerChecked() const
{
    return ui->installOsHandler->isChecked();
}

bool Intro::getInstallOsHandlerSystemChecked() const
{
    return ui->installOsHandler->isChecked() && ui->installOsHandlerSystem->isChecked();
}

#if defined(Q_OS_LINUX)
namespace {
QString FindBtxOpenBinary()
{
    const QByteArray env = qgetenv("BTX_OPEN");
    if (!env.isEmpty()) {
        return QString::fromLocal8Bit(env);
    }
    const QString sibling = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("btx-open"));
    if (QFileInfo(sibling).isExecutable()) {
        return sibling;
    }
    return QStandardPaths::findExecutable(QStringLiteral("btx-open"));
}

QString FindInstallOsHandlerScript()
{
    const QByteArray env = qgetenv("BTX_INSTALL_OS_HANDLER");
    if (!env.isEmpty()) {
        return QString::fromLocal8Bit(env);
    }
    QDir dir(QCoreApplication::applicationDirPath());
    for (int i = 0; i < 8; ++i) {
        const QString cand = dir.filePath(QStringLiteral("contrib/modelnet/install-os-handler.sh"));
        if (QFileInfo::exists(cand)) {
            return cand;
        }
        const QString beside = dir.filePath(QStringLiteral("install-os-handler.sh"));
        if (QFileInfo::exists(beside)) {
            return beside;
        }
        if (!dir.cdUp()) {
            break;
        }
    }
    return {};
}
} // namespace
#endif // Q_OS_LINUX

bool Intro::installOsHandler() const
{
#if !defined(Q_OS_LINUX)
    return true;
#else
    const QString script = FindInstallOsHandlerScript();
    if (script.isEmpty()) {
        qWarning() << "install-os-handler.sh not found";
        return false;
    }
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QString btx_open = FindBtxOpenBinary();
    if (!btx_open.isEmpty() && QFileInfo(btx_open).isAbsolute()) {
        env.insert(QStringLiteral("BTX_OPEN"), btx_open);
    }
    QStringList args;
    if (getInstallOsHandlerSystemChecked()) {
        env.insert(QStringLiteral("INSTALL_SYSTEM"), QStringLiteral("1"));
        args << QStringLiteral("--system");
    } else {
        env.insert(QStringLiteral("INSTALL_SYSTEM"), QStringLiteral("0"));
    }
    QProcess proc;
    proc.setProgram(script);
    proc.setArguments(args);
    proc.setProcessEnvironment(env);
    proc.setProcessChannelMode(QProcess::MergedChannels);
    proc.start();
    if (!proc.waitForStarted()) {
        qWarning() << "install-os-handler.sh failed to start:" << script;
        return false;
    }
    // Block until pkexec/sudo/xdg-mime returns. Never QProcess::kill() (SIGKILL);
    // QProcess's destructor SIGKILLs a still-running child, so wait it out.
    if (!proc.waitForFinished(-1)) {
        proc.terminate();
        (void)proc.waitForFinished(-1);
        qWarning() << "install-os-handler.sh did not finish";
        return false;
    }
    const QByteArray out = proc.readAll();
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
        qWarning() << "install-os-handler.sh failed:" << proc.exitCode() << out;
        return false;
    }
    return true;
#endif
}

bool Intro::showIfNeeded(std::unique_ptr<Intro>& intro)
{
    intro.reset();

    QSettings settings;
    /* If data directory provided on command line, no need to look at settings
       or show a picking dialog */
    if(!gArgs.GetArg("-datadir", "").empty())
        return true;
    /* 1) Default data directory for operating system */
    QString dataDir = GUIUtil::getDefaultDataDirectory();
    /* 2) Allow QSettings to override default dir */
    dataDir = settings.value("strDataDir", dataDir).toString();

    if(!fs::exists(GUIUtil::QStringToPath(dataDir)) || gArgs.GetBoolArg("-choosedatadir", DEFAULT_CHOOSE_DATADIR) || settings.value("fReset", false).toBool() || gArgs.GetBoolArg("-resetguisettings", false))
    {
        /* Use selectParams here to guarantee Params() can be used by node interface */
        try {
            SelectParams(gArgs.GetChainType());
        } catch (const std::exception&) {
            return false;
        }

        /* If current default data directory does not exist, let the user choose one */
        intro = std::make_unique<Intro>(nullptr, Params().AssumedBlockchainSize(), Params().AssumedChainStateSize());
        intro->setDataDirectory(dataDir);
        intro->setWindowIcon(QIcon(QStringLiteral(":icons/bitcoin")));

        while(true)
        {
            if(!intro->exec())
            {
                /* Cancel clicked */
                return false;
            }
            dataDir = intro->getDataDirectory();
            try {
                if (TryCreateDirectories(GUIUtil::QStringToPath(dataDir))) {
                    // If a new data directory has been created, make wallets subdirectory too
                    TryCreateDirectories(GUIUtil::QStringToPath(dataDir) / "wallets");
                }
                break;
            } catch (const fs::filesystem_error&) {
                QMessageBox::critical(nullptr, CLIENT_NAME,
                    tr("Error: Specified data directory \"%1\" cannot be created.").arg(dataDir));
                /* fall through, back to choosing screen */
            }
        }

        settings.setValue("strDataDir", dataDir);
        settings.setValue("fReset", false);
    }
    /* Only override -datadir if different from the default, to make it possible to
     * override -datadir in the bitcoin.conf file in the default data directory
     * (to be consistent with bitcoind behavior)
     */
    if(dataDir != GUIUtil::getDefaultDataDirectory()) {
        gArgs.SoftSetArg("-datadir", fs::PathToString(GUIUtil::QStringToPath(dataDir))); // use OS locale for path setting
    }
    return true;
}

void Intro::setStatus(int status, const QString &message, quint64 bytesAvailable)
{
    switch(status)
    {
    case FreespaceChecker::ST_OK:
        ui->errorMessage->setText(message);
        ui->errorMessage->setStyleSheet("");
        break;
    case FreespaceChecker::ST_ERROR:
        ui->errorMessage->setText(tr("Error") + ": " + message);
        ui->errorMessage->setStyleSheet("QLabel { color: #800000 }");
        break;
    }
    /* Indicate number of bytes available */
    if(status == FreespaceChecker::ST_ERROR)
    {
        ui->freeSpace->setText("");
    } else {
        m_bytes_available = bytesAvailable;
        if (ui->prune->isEnabled() && m_prune_checkbox_is_default) {
            ui->prune->setChecked(m_bytes_available < (m_blockchain_size_gb + m_chain_state_size_gb + 10) * GB_BYTES);
        }
        UpdateFreeSpaceLabel();
    }
    /* Don't allow confirm in ERROR state */
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(status != FreespaceChecker::ST_ERROR);
}

void Intro::UpdateFreeSpaceLabel()
{
    QString freeString = tr("%n GB of space available", "", m_bytes_available / GB_BYTES);
    if (m_bytes_available < m_required_space_gb * GB_BYTES) {
        freeString += " " + tr("(of %n GB needed)", "", m_required_space_gb);
        ui->freeSpace->setStyleSheet("QLabel { color: #800000 }");
    } else if (m_bytes_available / GB_BYTES - m_required_space_gb < 10) {
        freeString += " " + tr("(%n GB needed)", "", m_required_space_gb);
        ui->freeSpace->setStyleSheet("QLabel { color: #999900 }");
    } else {
        ui->freeSpace->setStyleSheet("");
    }
    ui->freeSpace->setText(freeString + ".");
}

void Intro::on_dataDirectory_textChanged(const QString &dataDirStr)
{
    /* Disable OK button until check result comes in */
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    checkPath(dataDirStr);
}

void Intro::on_ellipsisButton_clicked()
{
    QString dir = QDir::toNativeSeparators(QFileDialog::getExistingDirectory(nullptr, tr("Choose data directory"), ui->dataDirectory->text()));
    if(!dir.isEmpty())
        ui->dataDirectory->setText(dir);
}

void Intro::on_dataDirDefault_clicked()
{
    setDataDirectory(GUIUtil::getDefaultDataDirectory());
}

void Intro::on_dataDirCustom_clicked()
{
    ui->dataDirectory->setEnabled(true);
    ui->ellipsisButton->setEnabled(true);
}

void Intro::startThread()
{
    thread = new QThread(this);
    FreespaceChecker *executor = new FreespaceChecker(this);
    executor->moveToThread(thread);

    connect(executor, &FreespaceChecker::reply, this, &Intro::setStatus);
    connect(this, &Intro::requestCheck, executor, &FreespaceChecker::check);
    /*  make sure executor object is deleted in its own thread */
    connect(thread, &QThread::finished, executor, &QObject::deleteLater);

    thread->start();
}

void Intro::checkPath(const QString &dataDir)
{
    mutex.lock();
    pathToCheck = dataDir;
    if(!signalled)
    {
        signalled = true;
        Q_EMIT requestCheck();
    }
    mutex.unlock();
}

QString Intro::getPathToCheck()
{
    QString retval;
    mutex.lock();
    retval = pathToCheck;
    signalled = false; /* new request can be queued now */
    mutex.unlock();
    return retval;
}

void Intro::UpdatePruneLabels(bool prune_checked)
{
    m_required_space_gb = m_blockchain_size_gb + m_chain_state_size_gb;
    QString storageRequiresMsg = tr("At least %1 GB of data will be stored in this directory, and it will grow over time.");
    const int64_t prune_target_gb = (m_prune_target_mib * MiB_BYTES + GB_BYTES - 1) / GB_BYTES;
    if (prune_checked && prune_target_gb <= m_blockchain_size_gb) {
        m_required_space_gb = prune_target_gb + m_chain_state_size_gb;
        storageRequiresMsg = tr("Approximately %1 GB of data will be stored in this directory.");
    }
    ui->pruneMiB->setEnabled(prune_checked);
    static constexpr uint64_t nPowTargetSpacing = 10 * 60;  // from chainparams, which we don't have at this stage
    static constexpr uint32_t expected_block_data_size = 2250000;  // includes undo data
    const uint64_t expected_backup_days = m_prune_target_mib * MiB_BYTES / (uint64_t(expected_block_data_size) * 86400 / nPowTargetSpacing);
    ui->lblPruneSuffix->setText(
        //: Explanatory text on the capability of the current prune target.
        tr("(sufficient to restore backups %n day(s) old)", "", expected_backup_days));
    ui->sizeWarningLabel->setText(
        tr("%1 will download and store a copy of the Bitcoin block chain.").arg(CLIENT_NAME) + " " +
        storageRequiresMsg.arg(m_required_space_gb) + " " +
        tr("The wallet will also be stored in this directory.")
    );
    this->adjustSize();
}
