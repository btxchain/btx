// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/openuridialog.h>
#include <qt/forms/ui_openuridialog.h>

#include <qt/guiutil.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsrecipient.h>

#include <QAbstractButton>
#include <QLineEdit>
#include <QUrl>

OpenURIDialog::OpenURIDialog(const PlatformStyle* platformStyle, QWidget* parent) : QDialog(parent, GUIUtil::dialog_flags),
                                                                                    ui(new Ui::OpenURIDialog),
                                                                                    m_platform_style(platformStyle)
{
    ui->setupUi(this);
    ui->pasteButton->setIcon(m_platform_style->SingleColorIcon(":/icons/editpaste"));
    QObject::connect(ui->pasteButton, &QAbstractButton::clicked, ui->uriEdit, &QLineEdit::paste);

    GUIUtil::handleCloseWindowShortcut(this);
}

OpenURIDialog::~OpenURIDialog()
{
    delete ui;
}

QString OpenURIDialog::getURI()
{
    return ui->uriEdit->text().trimmed();
}

void OpenURIDialog::accept()
{
    SendCoinsRecipient rcp;
    const QString uri = getURI();
    // Model identity first: btx://… must not be treated as BIP21 payment.
    if (uri.startsWith(QStringLiteral("btx://"), Qt::CaseInsensitive) ||
        uri.endsWith(QStringLiteral(".btx"), Qt::CaseInsensitive) ||
        uri.endsWith(QStringLiteral(".btxlink"), Qt::CaseInsensitive)) {
        QDialog::accept();
        return;
    }
    if (uri.startsWith(QStringLiteral("bitcoin:"), Qt::CaseInsensitive)) {
        ui->uriEdit->setValid(false);
        return;
    }
    if (GUIUtil::parseBitcoinURI(uri, &rcp)) {
        QDialog::accept();
        return;
    }
    ui->uriEdit->setValid(false);
}

void OpenURIDialog::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        ui->pasteButton->setIcon(m_platform_style->SingleColorIcon(":/icons/editpaste"));
    }

    QDialog::changeEvent(e);
}
