// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_QT_SWAPNETDIALOG_H
#define BTX_QT_SWAPNETDIALOG_H
#include <QDialog>
#include <QList>
#include <functional>
#include <univalue.h>
namespace interfaces {class Node;}
class QComboBox;class QLabel;class QLineEdit;class QPushButton;class QTableWidget;class QTextEdit;class QThread;class QTimer;
class SwapNetDialog final : public QDialog {
    interfaces::Node& m_node;
    QComboBox *m_sell{},*m_buy{};
    QLineEdit *m_wallet{},*m_amount{},*m_fee{};
    QLabel* m_status{};
    QTableWidget* m_quotes{};
    QTextEdit* m_details{};
    QTimer* m_poll{};
    QList<QThread*> m_threads;
    bool m_busy{false};
    std::string m_request,m_swap;
    UniValue m_quote_rows{UniValue::VARR};
    using Reply=std::function<void(const UniValue&)>;
    void Call(const std::string& method,const UniValue& body,Reply callback);
    void Refresh();void RequestQuotes();void Poll();void Preview();void SetMode(const std::string& mode);
    std::string SelectedAsset(QComboBox*) const;
    static int Decimals(const std::string& asset);
    static std::string ToAtoms(const QString&,int);
    static QString FromAtoms(const std::string&,int);
public:
    explicit SwapNetDialog(interfaces::Node& node,QWidget* parent=nullptr);
    ~SwapNetDialog() override;
};
#endif
