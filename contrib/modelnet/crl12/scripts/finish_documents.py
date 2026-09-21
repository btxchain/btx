from pathlib import Path
import json,re,shutil,csv
R=Path(__file__).resolve().parents[1]
# Exact inherited architecture files, used only as design baselines.
base=R/'compatibility/architecture';base.mkdir(exist_ok=True)
files=[('B01','BTX_0348_Hosted_Control_Plane_Spec.md','Hosted Control Plane v1.0'),('B02','BTX_CEX_v1_1_Implementation_Spec.md','Cognitive Reserve Framework v1.1'),('B03','BTX_0348_JIT_Capability_Development_Spec.md','Just-in-Time Capability Development Specification'),('B04','BTX_0348_Agent_Readable_Package_Spec.md','Agent-readable .btx Package Specification')]
for code,name,label in files:
 src=Path('/mnt/data')/name
 if src.exists():shutil.copy2(src,base/name)
sources={s['id']:s for s in json.loads((R/'research/source-register.json').read_text())}
for code,name,label in files:sources[code]={'id':code,'title':label,'url':'../compatibility/architecture/'+name,'publisher':'BTX design baseline','date':'September 2026'}
for p in sorted((R/'docs').glob('*.md')):
 text=p.read_text().split('\n<!-- READING_REFERENCES -->')[0]
 if p.name.startswith('02_'):
  text=text.split('\n<!-- CONTRACT_APPENDICES -->')[0]
  ops=json.loads((R/'schemas/operations-v1.2.json').read_text())['operations']
  text+='\n<!-- CONTRACT_APPENDICES -->\n\n# Appendix A. Complete operation contract\n\nAll paths are under the existing `/btx/hcp/v1` base. Every POST is idempotency-bound; every operation also enforces the entity, source, role and policy checks described in the specification. Job results are polled through getLayerJob.\n\n'
  for o in ops:
   text+=f"## {o['operation_id']}\n\n`{o['method']} {o['path']}`\n\n**Scope:** `{o['scope']}`. **Effect:** `{o['effect']}`. **Request:** `{o['request_schema'] or 'path/query only'}`. **Result:** `{o['response_schema']}`.\n\n{o['detail']}\n\n"
  D=json.loads((R/'schemas/CognitiveReserveLayer.schema.json').read_text())['$defs']
  text+='# Appendix B. Signed object fields\n\nAll new types require `schema_revision=1.2`, `provider_id` and `created_at`. The complete strict field types and nested structures are in CognitiveReserveLayer.schema.json. Nullable fields explicitly represent unavailable values; cross-field and authority checks are mandatory.\n\n'
  for n,d in D.items():
   if n.endswith('V1_2'):
    text+=f'## {n}\n\n'
    text+='; '.join('`'+k+'`' for k in d['properties'] if k not in {'schema_revision','provider_id','created_at'})+'.\n\n'
  text+='# Appendix C. Typed value rules\n\nQuantity is coefficient plus scale; Money is currency, exponent and integer minor units. ExactRef contains the exact signed object type and SHA-384 body ID. Scope is tenant/entity/portfolio. MetricResult uses either money or count, with source completeness and explicit unpriced/excluded counts. Export chunks bind ID, digest, byte length and rows. No generic text field creates financial or runtime authority.\n'
 # References are linkable primary-source labels; anonymous cases remain anonymous.
 used=set()
 for block in re.findall(r'\[([^\]]{1,55})\]',text):
  for prefix,a,b in re.findall(r'([MTB])(\d\d)[–-](?:[MTB])?(\d\d)',block):used.update(prefix+f'{i:02d}' for i in range(int(a),int(b)+1))
  used.update(re.findall(r'\b[MTB]\d\d\b',block))
 used&=sources.keys()
 if used:
  text+='\n<!-- READING_REFERENCES -->\n\n# Research and design references\n\nPrimary-source links below support the attributed facts and precedents. The scenario calculations and proposed BTX contracts are the document’s analysis. Full publisher attribution and research notes are in the accompanying research register.\n\n'
  for code in sorted(used):
   s=sources[code];text+=f"**[{code}] {s['title']}.** {s['date']}. [Source]({s['url']}).\n\n"
 p.write_text(text)
# Clear cross-document provenance for anonymous cases; research is not operational code.
case_sources={'A':['M06'],'B':['M07','M08'],'C':['M09'],'D':['M10'],'E':['M11'],'F':['M12','M13','M14','M15'],'G':[],'H':[]}
(R/'research/ANONYMOUS_CASE_PROVENANCE.json').write_text(json.dumps({'basis':'Public business-model analogues; all adoption and fee amounts are constructed scenarios, not actual partnerships.','case_sources':case_sources},indent=2))
rows=[
('A','new_institutional_customers',600,'count'),('A','average_reserve',3000000,'USD'),('A','average_custody',1800000000,'USD'),('A','custody_bps',8,'bps'),('A','executed_turnover',6,'per_year'),('A','execution_bps',4,'bps'),('A','administered_funding',500000000,'USD'),('A','admin_bps',25,'bps'),('A','gross_financial_revenue',7010000,'USD_per_year'),
('B','businesses',25000,'count'),('B','average_reserve',60000,'USD'),('B','separate_supplier_reserves',500000000,'USD'),('B','total_custody',2000000000,'USD'),
('C','intermediaries',200,'count'),('C','average_end_client_balances',12000000,'USD'),('C','serviced_custody',2400000000,'USD'),
('D','businesses',40000,'count'),('D','business_average',25000,'USD'),('D','institutional_portfolios',75,'count'),('D','institutional_average',5000000,'USD'),('D','product_assets',1375000000,'USD'),('D','internal_reallocation',875000000,'USD'),('D','external_inflows',500000000,'USD'),
('E','retail_customers',150000,'count'),('E','retail_average',4000,'USD'),('E','managed_portfolios',300,'count'),('E','managed_average',2000000,'USD'),('E','AUC_with_overlap',1200000000,'USD'),('E','AUM_subset',600000000,'USD'),
('F','strategy_AUM',5000000000,'USD'),('F','internal_reallocation',3000000000,'USD'),('F','external_inflows',2000000000,'USD'),('F','management_bps',20,'bps'),('F','management_fee',10000000,'USD_per_year'),('F','technology_clients',50,'count'),('F','technology_contract',200000,'USD_per_year'),('F','technology_revenue',10000000,'USD_per_year'),
('G','businesses',1000,'count'),('G','average_reserve',50000,'USD'),('G','custody_or_administered_by_role',50000000,'USD')]
with (R/'assets/case_scenarios.csv').open('w',newline='') as f:
 w=csv.writer(f);w.writerow(['anonymous_case','measure','value','unit']);w.writerows(rows)
(R/'assets/README.md').write_text('# Figures and data\n\nmarket_context uses primary source M01 and includes infrastructure within total annual AI spending. ownership_curve and asset_growth_bridge use explicitly illustrative assumptions. case_scenarios records the anonymous-case arithmetic. All PNG/SVG figures are original charts; no third-party illustration or font file is redistributed.\n')
print('Finished document appendices, references and scenario data.')
