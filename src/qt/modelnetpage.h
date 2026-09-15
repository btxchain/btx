// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_MODELNETPAGE_H
#define BITCOIN_QT_MODELNETPAGE_H

#include <QEvent>
#include <QWidget>

#include <univalue.h>

#include <optional>
#include <cstdint>
#include <string>

class ClientModel;

namespace Ui {
    class ModelNetPage;
}

/** Models-first desktop page: Models, Downloads, Shared Models, Collections,
 *  Preservation, Peers, Identity. Same RPC names as btx-cli. Does not spend,
 *  auto-fetch, or start inference. */
class ModelNetPage : public QWidget
{
    Q_OBJECT

public:
    explicit ModelNetPage(QWidget *parent = nullptr);
    ~ModelNetPage();

    void setClientModel(ClientModel *model);
    void showOpenedUri(const QString& uri);

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override;

public Q_SLOTS:
    void refresh();
    void copyOpenedUri();

private Q_SLOTS:
    void runModelSearch();
    void onSearchTextChanged(const QString& text);
    void onResultDownload();
    void onResultCopyUri();
    void onResultDetails();
    void onResultFund();
    void onResultFundBounty();
    void onResultAward();
    void onResultRefund();
    void onResultCache();
    void onPublishSearchRecord();

private:
    Ui::ModelNetPage *ui;
    ClientModel* m_client_model{nullptr};

    QString callRpc(const std::string& method, const UniValue& params = UniValue(UniValue::VARR)) const;
    std::optional<UniValue> tryRpc(const std::string& method, const UniValue& params) const;
    void refreshConsent();
    void refreshResourceGovernorStatus();
    void refreshLocalCatalogCache();
    void clearResultsList();
    void renderSearchResponse(const UniValue& result);
    void renderModelCards(const UniValue& models, const UniValue* meta);
    void renderLocalTypeahead(const QString& needle);
    void updateCoverageLabel(int result_count, const UniValue* meta);
    std::string currentSortKey() const;
    std::optional<std::string> currentFormatFilter() const;
    QString modelFullUri(const UniValue& model) const;
    void pollSearchStatus(const std::string& query_id, int attempt);
    void showModelPlan(const QString& full_uri);
    void showModelDetails(const QString& full_uri);
    void showFundPlan(const QString& release_id);
    void showCachePlan(const QString& release_id);
    void pollCampaign(const QString& id, int attempt);
    void pollFeedSequence();
    UniValue buildSearchQueryObject(const std::optional<std::string>& scope,
                                    const std::optional<std::string>& sort_override) const;
    int modelsScopeTabIndex() const;

    QString m_full_uri;
    UniValue m_cached_listmodels{UniValue::VARR};
    bool m_have_local_cache{false};
    UniValue m_last_search_params{UniValue::VNULL};
    std::string m_last_search_method;
    int m_last_results_returned{0};
    int64_t m_feed_sequence{0};
};

#endif // BITCOIN_QT_MODELNETPAGE_H
