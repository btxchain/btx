from pathlib import Path
import json
R=Path(__file__).resolve().parents[1]
sources=[
('M01','Worldwide AI spending forecast, September 2026','Gartner','https://www.gartner.com/en/newsroom/press-releases/2026-09-16-gartner-forecasts-worldwide-ai-spending-to-grow-49-point-5-percent-in-2026','2026-09-16','Forecast: 2026 total $2,670,460m; infrastructure $1,484,397m; 2027 total $3,637,292m. Search retrieval supplied primary-source text; direct open returned a cache miss. Figures are forecast market context, not BTX-addressable revenues.'),
('M02','The cost of compute: a $7 trillion race to scale data centers','McKinsey','https://www.mckinsey.com/industries/technology-media-and-telecommunications/our-insights/the-cost-of-compute-a-7-trillion-dollar-race-to-scale-data-centers','2025-04-28','$5.2tn AI-related and $1.5tn traditional data-center capital expenditure through 2030 in the central scenario. Cumulative investment, not annual spending; do not add to M01.'),
('M03','2025 AI Index Report','Stanford HAI','https://hai.stanford.edu/ai-index/2025-ai-index-report','2025','Documents falling costs at fixed capability levels; the report discusses a greater than 280-fold fall in GPT-3.5-level inference cost between November 2022 and October 2024. Historical observation, not a BTX benchmark or 2030 forecast.'),
('M04','Instinct MI400 series product specifications','AMD','https://www.amd.com/en/products/accelerators/instinct/mi400.html','accessed 2026-09-17','MI455X page lists up to 432 GB HBM4, 23.3 TB/s peak theoretical memory bandwidth and 3.6 TB/s scale-up bandwidth. Vendor specifications; no end-to-end application speedup inferred.'),
('M05','Vera Rubin ramps into full production','NVIDIA','https://nvidianews.nvidia.com/news/vera-rubin-full-production-agentic-ai-factory','2026-05-31','Vendor announcement reports 10x agent throughput at scale versus its previous platform. Used only as directional evidence of integrated hardware progress.'),
('M06','Second-quarter 2026 earnings announcement','Coinbase','https://investor.coinbase.com/news/news-details/2026/Coinbase-Q2-Earnings-Everything-Exchange-Drives-3rd-Consecutive-Quarter-of-Record-Crypto-Trading-Volume-Market-Share-Revenue-Diversification-and-Resilience/default.aspx','2026-08','Public institutional digital-asset venue analogue. Company report: subscription/services $555m and 48% of net revenue. Case A uses a hypothetical business, not a claim of BTX integration.'),
('M07','AI Agent Skills Hub expansion','Binance','https://www.binance.com/en/support/announcement/detail/c582a7a577904965af5d140b015e9a2c','2026-04-02','13 additional skills spanning trading, payments and institutional functions. Case B borrows the business model of modular agent access, not any proprietary API implementation.'),
('M08','Capital Connect institutional programme','Binance','https://www.binance.com/en/support/announcement/detail/35509d42de1645c097371c651936f78e','2026-04-09','Describes institutional investors, professional trading teams and portfolio accounts. No endorsement or available BTX custody is implied.'),
('M09','2025 full-year financial highlights','Kraken / Payward','https://blog.kraken.com/news/kraken-2025-financials','2026-02-03','2025 company disclosure: $48.2bn assets on platform, 5.7m funded accounts, $2.2bn adjusted revenue; 47% trading and 53% asset-based/other revenue. Shared-infrastructure, custody and wholesale analogue for Case C.'),
('M10','Annual Report 2025','Revolut','https://www.revolut.com/annual-report-2025/','2026','Business-account, FX and treasury distribution analogue for Case D. Use business model; hypothetical case numbers are separate.'),
('M11','Second-quarter 2026 results','Robinhood','https://investors.robinhood.com/news-releases/news-release-details/robinhood-reports-second-quarter-2026-results','2026-07-29','Reports $369bn Total Platform Assets; defines that measure separately from AUC. Describes advisor and agentic-account expansion. Case E is hypothetical.'),
('M12','Second-quarter 2026 results','BlackRock','https://www.blackrock.com/corporate/newsroom/media/press-releases/blackrock-reports-second-quarter-2026','2026-07-15','Reports $15.3tn AUM and 13% growth in technology services/subscriptions. AUM belongs to the asset manager; it is not the assets processed by its technology customers.'),
('M13','Whole Portfolio product overview','BlackRock / Aladdin','https://www.blackrock.com/aladdin/platforms/products/whole-portfolio','accessed 2026-09-17','Public/private portfolio views, integrated investment book, exposure, performance and risk. Case F and the institutional guide propose a neutral integration model; there is no proprietary integration or native product-support claim.'),
('M14','Studio API solutions','BlackRock / Aladdin','https://www.blackrock.com/aladdin/platforms/products/apis','accessed 2026-09-17','Official overview describes read/write access and operational services including trades, orders and compliance. Detailed customer API contracts are not publicly supplied; this package invents no proprietary endpoint.'),
('M15','Studio and data-cloud overview','BlackRock / Aladdin','https://www.blackrock.com/aladdin/platforms/products/aladdin-studio','accessed 2026-09-17','API-first platform and integration of platform and non-platform data. Supports generic adapter and data-warehouse architectural analysis.'),
('M16','x402 introduction','x402','https://docs.x402.org/introduction','accessed 2026-09-17','HTTP payment protocol for automated access to APIs/content. Payment rails can pay for more than operating consumption; BTX differentiates the managed object and lifecycle rather than claiming only it can transfer capital.'),
('T01','FAPI 2.0 Security Profile','OpenID Foundation','https://openid.net/specs/fapi-security-profile-2_0-final.html','final edition, reviewed 2026-09-17','Retain HCP authentication choices and sender constraints. No custom identity stack.'),
('T02','OAuth 2.0 security best current practice, RFC 9700','IETF','https://www.rfc-editor.org/rfc/rfc9700.html','2025-01','Authorization security baseline for provider-bound tokens.'),
('T03','OAuth DPoP, RFC 9449','IETF','https://www.rfc-editor.org/rfc/rfc9449.html','2023-09','Sender-binding precedent, not approval of an arbitrary business request body.'),
('T04','OAuth Rich Authorization Requests, RFC 9396','IETF','https://www.rfc-editor.org/rfc/rfc9396.html','2023-05','Structured authorization; retain exact HCP intent and capital-plan digest checks.'),
('T05','FDC3 Context Data 2.2','FINOS','https://fdc3.finos.org/docs/context/spec','2.2','Desktop context interoperability, private type namespaces and identifier conventions. BTX contexts are custom, not new official FDC3 standard types.'),
('T06','FDC3 2.2 standard','FINOS','https://fdc3.finos.org/docs/fdc3-standard','2025-04','Desktop interoperation consists of intents, context, API, directory and agent bridging. Adapters do not gain financial authorization merely by receiving context.'),
('T07','Level 2 LEI data: who owns whom','GLEIF','https://www.gleif.org/en/lei-data/access-and-use-lei-data/level-2-data-who-owns-whom','accessed 2026-09-17','Direct and ultimate accounting-consolidating parents. An LEI relationship is reference data, not authority to debit an entity or proof of every beneficial owner.'),
('T08','IAS 38 Intangible Assets overview','IFRS Foundation','https://www.ifrs.org/issued-standards/list-of-standards/ias-38-intangible-assets/','accessed 2026-09-17','Accounting mapping requires actual rights and recognition rules; operational usefulness is not automatic financial NAV.'),
('T09','WCAG 2.2','W3C','https://www.w3.org/TR/WCAG22/','2.2','Keyboard, focus, error and accessible-status behavior. Implementation must pass browser accessibility checks.'),
]
records=[dict(id=i,title=t,publisher=p,url=u,date=d,reviewed='2026-09-17',observation=o) for i,t,p,u,d,o in sources]
(R/'research/source-register.json').write_text(json.dumps(records,indent=2))
text='# Research register and anonymous-case provenance\n\nReviewed 17 September 2026. Facts below come from primary publications. The anonymous institutions and all adoption/revenue numbers in the strategy are designed scenarios. The mapping is editorial research provenance, not a provider profile, endorsement or implementation dependency.\n\n'
for s in records:text+=f"## {s['id']} — {s['publisher']}: {s['title']}\n\nDate: {s['date']}. Source: {s['url']}\n\n{s['observation']}\n\n"
text+='''# Case mapping — research only

A: regulated institutional digital-asset venue — business model grounded in M06.
B: global agent-enabled multi-asset venue — M07 and M08.
C: professional liquidity and wholesale infrastructure platform — M09.
D: international business-finance platform — M10.
E: retail and adviser-led wealth platform — M11.
F: global asset manager with a whole-portfolio operating system — M12–M15.
G: greenfield Cognitive Reserve institution — original scenario applying the common contract.
H: specialist fiat and reporting service provider — original role-composition scenario, not an assertion about any named payment provider’s acceptable-use policy.

No market company name is a normative feature, protocol role, SDK class, adapter selector, host allowlist or UI default. Public research citations are preserved rather than deleted by the brand-neutrality lint.

# Baseline documents

B01: BTX-HCP-001, original Hosted Control Plane specification, revision 1.0.
B02: BTX-HCP-011, Cognitive Reserve Framework, revision 1.1; full text read for this revision.
B03: BTX-SPEC-0348-CAPABILITY-01, JIT capability architecture.
B04: BTX-AHP-001, agent-readable package specification; superseded package profile allocation follows B03.

The copied compatibility contracts are exact bytes from the supplied v1.1 archive. They establish the existing design contract. Cursor audits their mapping to the private implementation before editing. No current private code or hardware execution is claimed by this document-generation package.
'''
(R/'research/RESEARCH_REGISTER.md').write_text(text)
