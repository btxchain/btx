// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    // Dummy BTX payment path (invalid checksum).
    const QString addr("btxrt1p8l5y0c82fsranluweyq7jxm2ve6f8fcmktyy73s34dt8n95r5fjswd2rxa");

    uri.setUrl(QString("btx:%1?req-dontexist=").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("btx:%1?dontexist=").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("btx:%1?label=Example Address").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.label == QString("Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("btx:%1?amount=0.001").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("btx:%1?amount=1.001").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("btx:%1?amount=100&label=Example").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Example"));

    uri.setUrl(QString("btx:%1?amount=x100x4").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.amount == 16777216LL);

    uri.setUrl(QString("btx:%1?amount=100x2").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.amount == 10000LL);

    uri.setUrl(QString("btx:%1?message=Example Address").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI(QString("btx:%1?message=Example Address").arg(addr), &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("btx:%1?req-message=Example Address").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    // Commas in amounts are not allowed.
    uri.setUrl(QString("btx:%1?amount=1,000&label=Example").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("btx:%1?amount=x1,0000&label=Example").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("btx:%1?amount=1,000.0&label=Example").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // There are two amount specifications. The last value wins.
    uri.setUrl(QString("btx:%1?amount=100&amount=200&label=Example").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.amount == 20000000000LL);
    QVERIFY(rv.label == QString("Example"));

    // The first amount value is correct. However, the second amount value is not valid. Hence, the URI is not valid.
    uri.setUrl(QString("btx:%1?amount=100&amount=1,000&label=Example").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Test label containing a question mark ('?').
    uri.setUrl(QString("btx:%1?amount=100&label=?").arg(addr));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("?"));

    // Escape sequences are not supported.
    uri.setUrl(QString("btx:") + addr + QString("?amount=100&label=%3F"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == addr);
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("%3F"));

    // COORDINATOR LOCK: leftover Bitcoin URIs must fail. Do not flip these to QVERIFY(parse).
    uri.setUrl(QString("bitcoin:%1?amount=0.001").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QString("bitcoin:%1?label=Legacy").arg(addr), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QString("BITCOIN:%1?amount=1").arg(addr), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QString("bitcoin://%1").arg(addr), &rv));
    uri.setUrl(QString("bitcoin://%1?label=Example").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
    SendCoinsRecipient formatted;
    formatted.address = addr;
    formatted.amount = 100000;
    const QString payment_uri = GUIUtil::formatBitcoinURI(formatted);
    QVERIFY(payment_uri.startsWith(QStringLiteral("btx:")));
    QVERIFY(!payment_uri.contains(QStringLiteral("bitcoin:"), Qt::CaseInsensitive));

    // V11-URI-13: btx:// is a model resource, never a payment URI.
    const QString model_uri(
        "btx://pqc0whmrlv2emtc8eknxja6l6ffdj5mta0nj9msfsdkrz6qg0de448gm0a3kcctd92p9ekje2c97wd5glyrdl");
    QVERIFY(!GUIUtil::parseBitcoinURI(model_uri, &rv));
    uri.setUrl(model_uri);
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
    uri.setUrl(QString("btx://%1").arg(addr));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QString("btx://%1?amount=0.001").arg(addr), &rv));
}
