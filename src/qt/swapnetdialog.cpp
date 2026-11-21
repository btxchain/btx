// Copyright (c) 2026 The BTX developers. MIT license.
#include <qt/swapnetdialog.h>
#include <interfaces/node.h>
#include <consensus/amount.h>
#include <QComboBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTextEdit>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <memory>
#include <optional>
#include <stdexcept>
static_assert(COIN==100000000,"Review BTX display precision before building this panel");
namespace {
QString Q(const std::string& s){return QString::fromStdString(s);}
std::string S(const QString& s){return s.toStdString();}
UniValue Obj(){return UniValue(UniValue::VOBJ);}
struct RpcResult {std::optional<UniValue> value;QString error;};
}
SwapNetDialog::SwapNetDialog(interfaces::Node& node,QWidget* parent):QDialog(parent),m_node(node){
 setWindowTitle(tr("Swap BTX — noncustodial exchange"));resize(900,700);
 auto* layout=new QVBoxLayout(this);
 auto* intro=new QLabel(tr("Compare exact quotes, then authorize one trade. Your node—not this window—continues funded settlement and recovery."),this);intro->setWordWrap(true);layout->addWidget(intro);
 auto* form=new QFormLayout;
 m_wallet=new QLineEdit(this);m_wallet->setPlaceholderText(tr("Loaded wallet name; leave empty only when exactly one is loaded"));form->addRow(tr("BTX wallet"),m_wallet);
 m_sell=new QComboBox(this);m_buy=new QComboBox(this);form->addRow(tr("Pay asset"),m_sell);form->addRow(tr("Receive asset"),m_buy);
 m_amount=new QLineEdit(this);m_amount->setPlaceholderText(tr("Exact decimal amount in the pay asset"));form->addRow(tr("Amount"),m_amount);
 m_fee=new QLineEdit(this);m_fee->setPlaceholderText(tr("Your maximum total outgoing-chain fee, not an estimate"));form->addRow(tr("Maximum network fee"),m_fee);layout->addLayout(form);
 auto* buttons=new QHBoxLayout;
 auto* refresh=new QPushButton(tr("Refresh readiness"),this);auto* enable=new QPushButton(tr("Enable new trades"),this);
 auto* quotes=new QPushButton(tr("Get quotes"),this);auto* preview=new QPushButton(tr("Preview selected quote"),this);auto* pause=new QPushButton(tr("Pause new trades"),this);
 for(auto* b:{refresh,enable,quotes,preview,pause})buttons->addWidget(b);layout->addLayout(buttons);
 m_quotes=new QTableWidget(0,4,this);m_quotes->setHorizontalHeaderLabels({tr("Provider identity"),tr("Minimum receive"),tr("Execution policy"),tr("Quote ID")});
 m_quotes->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);m_quotes->setSelectionBehavior(QAbstractItemView::SelectRows);m_quotes->setSelectionMode(QAbstractItemView::SingleSelection);m_quotes->setEditTriggers(QAbstractItemView::NoEditTriggers);layout->addWidget(m_quotes);
 m_status=new QLabel(tr("Checking local readiness…"),this);m_status->setWordWrap(true);layout->addWidget(m_status);
 m_details=new QTextEdit(this);m_details->setReadOnly(true);layout->addWidget(m_details);
 connect(refresh,&QPushButton::clicked,this,[this]{Refresh();});connect(enable,&QPushButton::clicked,this,[this]{
  if(QMessageBox::question(this,tr("Enable trading?"),tr("This permits new trade requests. It does not grant spending authority. Each confirmation creates a separately bounded authorization."))==QMessageBox::Yes)SetMode("trade");});
 connect(quotes,&QPushButton::clicked,this,[this]{RequestQuotes();});connect(preview,&QPushButton::clicked,this,[this]{Preview();});
 connect(pause,&QPushButton::clicked,this,[this]{SetMode("recovery");});
 m_poll=new QTimer(this);m_poll->setInterval(2000);connect(m_poll,&QTimer::timeout,this,[this]{Poll();});Refresh();
}
SwapNetDialog::~SwapNetDialog(){if(m_poll)m_poll->stop();for(auto* t:m_threads){t->requestInterruption();t->wait();}}
void SwapNetDialog::Call(const std::string& method,const UniValue& body,Reply callback){
 if(m_busy)return;m_busy=true;m_status->setText(tr("Reading the local node…"));
 UniValue params(UniValue::VARR);params.push_back(body);
 const auto wallet=m_wallet->text();const std::string uri=wallet.isEmpty()?"":"/wallet/"+QUrl::toPercentEncoding(wallet).toStdString();
 auto result=std::make_shared<RpcResult>();auto* node=&m_node;
 auto* thread=QThread::create([node,method,params,uri,result]{try{result->value=node->executeRpc(method,params,uri);}catch(const UniValue& e){result->error=Q(e.write());}catch(const std::exception& e){result->error=QString::fromUtf8(e.what());}catch(...){result->error=QStringLiteral("Local RPC failed; inspect the node before retrying a trade.");}});
 m_threads.push_back(thread);
 connect(thread,&QThread::finished,this,[this,thread,result,callback=std::move(callback)]{
  m_threads.removeOne(thread);thread->deleteLater();m_busy=false;
  if(!result->value){m_status->setText(result->error);m_details->setPlainText(result->error);return;}
  try{callback(*result->value);}catch(const std::exception& e){m_status->setText(QString::fromUtf8(e.what()));}
 });thread->start();
}
std::string SwapNetDialog::SelectedAsset(QComboBox* box)const{return S(box->currentData().toString());}
int SwapNetDialog::Decimals(const std::string& asset){return asset.rfind("evm:",0)==0?18:8;}
std::string SwapNetDialog::ToAtoms(const QString& input,int decimals){
 QString text=input.trimmed();if(text.isEmpty()||text.size()>80)throw std::invalid_argument("Enter a positive exact decimal amount");
 const auto parts=text.split('.');if(parts.size()>2||parts[0].isEmpty())throw std::invalid_argument("Invalid decimal amount");
 for(const auto& part:parts)for(QChar c:part)if(c<'0'||c>'9')throw std::invalid_argument("Use decimal digits only; no exponent or sign");
 const QString fraction=parts.size()==2?parts[1]:QString{};if(fraction.size()>decimals)throw std::invalid_argument("Too many fractional digits");
 QString result=parts[0]+fraction.leftJustified(decimals,'0');while(result.size()>1&&result[0]=='0')result.remove(0,1);
 if(result=="0"||result.size()>78)throw std::invalid_argument("Amount is zero or outside supported range");return S(result);
}
QString SwapNetDialog::FromAtoms(const std::string& value,int decimals){
 QString n=Q(value);if(n.size()<=decimals)n=n.rightJustified(decimals+1,'0');n.insert(n.size()-decimals,'.');
 while(n.endsWith('0'))n.chop(1);if(n.endsWith('.'))n.chop(1);return n;
}
void SwapNetDialog::Refresh(){Call("getswaponboarding",Obj(),[this](const UniValue& r){
 m_details->setPlainText(Q(r.write(2)));m_status->setText(tr("Discovery does not imply funds, verification readiness, or a fair price."));
 const QString sell=m_sell->currentData().toString(),buy=m_buy->currentData().toString();m_sell->clear();m_buy->clear();
 for(const auto& a:r["assets"].getValues()){
  const auto id=a["asset"].get_str();const auto family=a["family"].get_str();QString label=Q(family).toUpper()+" — "+Q(id.substr(0,24))+QStringLiteral("…");
  m_sell->addItem(label,Q(id));m_buy->addItem(label,Q(id));
 }
 if(m_sell->findData(sell)>=0)m_sell->setCurrentIndex(m_sell->findData(sell));
 if(m_buy->findData(buy)>=0)m_buy->setCurrentIndex(m_buy->findData(buy));else if(m_buy->count()>1)m_buy->setCurrentIndex(1);
 });}
void SwapNetDialog::SetMode(const std::string& mode){auto p=Obj();p.pushKV("mode",mode);Call("setswapmode",p,[this](const UniValue& r){m_details->setPlainText(Q(r.write(2)));m_status->setText(tr("Mode saved. Existing funded obligations continue recovery."));});}
void SwapNetDialog::RequestQuotes(){try{
 const auto sell=SelectedAsset(m_sell),buy=SelectedAsset(m_buy);if(sell.empty()||buy.empty()||sell==buy)throw std::invalid_argument("Select two configured assets");
 auto p=Obj();p.pushKV("sell_asset",sell);p.pushKV("buy_asset",buy);p.pushKV("sell_atoms",ToAtoms(m_amount->text(),Decimals(sell)));
 Call("requestswapquote",p,[this](const UniValue& r){m_request=r["request_id"].get_str();m_swap.clear();m_quote_rows=UniValue(UniValue::VARR);m_quotes->setRowCount(0);m_status->setText(tr("Request sent. No balance has been reserved or spent."));m_poll->start();});
 }catch(const std::exception& e){m_status->setText(QString::fromUtf8(e.what()));}}
void SwapNetDialog::Poll(){
 if(m_busy)return;
 if(!m_swap.empty()){auto p=Obj();p.pushKV("swap_id",m_swap);Call("getswap",p,[this](const UniValue& r){m_details->setPlainText(Q(r.write(2)));m_status->setText(tr("This is local execution status; inspect both chains for independent verification."));});return;}
 if(m_request.empty())return;auto p=Obj();p.pushKV("request_id",m_request);Call("getswapquotes",p,[this](const UniValue& r){
 m_quote_rows=r["quotes"];m_quotes->setRowCount(static_cast<int>(m_quote_rows.size()));
 for(unsigned i=0;i<m_quote_rows.size();++i){const auto& q=m_quote_rows[i];
  m_quotes->setItem(i,0,new QTableWidgetItem(Q(q["provider"].get_str())));
  m_quotes->setItem(i,1,new QTableWidgetItem(FromAtoms(q["minimum_receive_atoms"].get_str(),Decimals(q["buy_asset"].get_str()))));
  const bool allowed=q.exists("execution_policy")&&q["execution_policy"]["allowed"].get_bool();
  m_quotes->setItem(i,2,new QTableWidgetItem(allowed?tr("Within local policy"):tr("Policy blocked / inspect")));
  m_quotes->setItem(i,3,new QTableWidgetItem(Q(q["id"].get_str())));
 }
 m_status->setText(tr("%1 executable-size quote(s). Identities do not prove independent owners.").arg(m_quote_rows.size()));
 });}
void SwapNetDialog::Preview(){try{
 const int row=m_quotes->currentRow();if(row<0||static_cast<unsigned>(row)>=m_quote_rows.size())throw std::invalid_argument("Select a quote first");
 const auto& q=m_quote_rows[row];auto p=Obj();p.pushKV("quote_id",q["id"].get_str());p.pushKV("max_local_fee_atoms",ToAtoms(m_fee->text(),Decimals(q["sell_asset"].get_str())));
 m_poll->stop();Call("previewswapquote",p,[this](const UniValue& r){
 m_details->setPlainText(Q(r.write(2)));
 if(!r["decision"]["allowed"].get_bool()){m_status->setText(tr("The selected quote is outside your execution policy. No spending was authorized."));return;}
 const QString text=tr("Confirm this exact quote and fee cap?\n\nThis creates one bounded owner mandate. Settlement may take multiple chain confirmations. If the maker does not fund, your refund may require waiting for the contract deadline. Keep the node and chain verifiers available.\n\nMinimum receive: %1 atomic units of %2\nMaximum outgoing fee: %3 atomic units of %4\n\nThe detailed terms are displayed below.")
   .arg(Q(r["minimum_receive"]["atoms"].get_str()),Q(r["minimum_receive"]["asset"].get_str()),Q(r["outgoing_fee_cap"]["atoms"].get_str()),Q(r["outgoing_fee_cap"]["asset"].get_str()));
 if(QMessageBox::question(this,tr("Authorize one swap"),text)!=QMessageBox::Yes)return;
 auto confirm=Obj();confirm.pushKV("preview_id",r["preview_id"].get_str());confirm.pushKV("consent",true);confirm.pushKV("create_single_trade_mandate",true);
 Call("confirmswapquote",confirm,[this](const UniValue& result){m_details->setPlainText(Q(result.write(2)));if(result.exists("swap_id"))m_swap=result["swap_id"].get_str();else if(result.exists("id"))m_swap=result["id"].get_str();m_status->setText(tr("Trade submitted. Closing this window does not cancel or stop node recovery."));m_poll->start();});
 });
 }catch(const std::exception& e){m_status->setText(QString::fromUtf8(e.what()));}}
