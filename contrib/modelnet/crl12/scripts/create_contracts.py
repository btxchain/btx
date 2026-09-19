from pathlib import Path
import json,yaml,hashlib,copy
R=Path(__file__).resolve().parents[1]
def obj(p,req=None,description=''):
 return {'type':'object','properties':p,'required':list(p) if req is None else req,'additionalProperties':False,**({'description':description} if description else {})}
def ref(n):return {'$ref':'#/$defs/'+n}
def arr(s,n=256):return {'type':'array','items':s,'maxItems':n}
def enum(*xs):return {'type':'string','enum':list(xs)}
def nullable(s):return {'anyOf':[s,{'type':'null'}]}
D={
'Id':{'type':'string','pattern':r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'},
'Digest48':{'type':'string','pattern':'^[0-9a-f]{96}$'},
'Digest32':{'type':'string','pattern':'^[0-9a-f]{64}$'},
'UInt':{'type':'string','pattern':'^(0|[1-9][0-9]{0,76})$'},
'SInt':{'type':'string','pattern':'^(0|-?[1-9][0-9]{0,76})$'},
'Text':{'type':'string','maxLength':2048},
'Role':enum('DISCOVERY','CUSTODY','EXECUTION','FUNDING','TREASURY','DEVICE_HANDOFF','ASSET_SERVICING','PORTFOLIO_ANALYTICS','FIAT_RAIL'),
'AssetKind':enum('NATIVE_RESERVE','FINANCIAL_INSTRUMENT','CONTRACT_RIGHT','CAPABILITY_RESOURCE','RESEARCH_COMMITMENT'),
'Effect':enum('READ','RECORD','BIND','EXPORT','PLAN','TRANSLATE_TO_DRAFT','DRAFT_OR_POLICY','POLICY','AUTHORIZE','EXECUTE_APPROVED','CANCEL_SAFE_ONLY','MEMBERSHIP_ONLY','REFERRAL_ONLY','REPORT','PREPARE','SUBMIT','CANCEL'),
'Quantity':obj({'coefficient':ref('SInt'),'scale':{'type':'integer','minimum':0,'maximum':18}}),
'Money':obj({'currency':ref('Id'),'exponent':{'type':'integer','minimum':0,'maximum':18},'minor':ref('SInt')}),
'ExactRef':obj({'object_type':ref('Id'),'body_id':ref('Digest48')}),
'Identifier':obj({'namespace':ref('Id'),'value':{'type':'string','minLength':1,'maxLength':256},'authority_ref':nullable(ref('ExactRef'))}),
'Endpoint':obj({'operation_id':ref('Id'),'relative_path':{'type':'string','pattern':'^/[A-Za-z0-9/{}._-]{1,200}$'},'effect':ref('Effect')}),
'Scope':obj({'tenant_id':ref('Id'),'legal_entity_id':ref('Id'),'portfolio_id':ref('Id')}),
'Watermark':obj({'provider_id':ref('Id'),'stream_id':ref('Id'),'generation':ref('Id'),'sequence':ref('UInt'),'effective_at':ref('UInt')}),
'Link':obj({'target_ref':ref('ExactRef'),'relationship':enum('FINANCIAL_LOOKTHROUGH','CAPABILITY_DEPENDENCY','RIGHTS_DEPENDENCY'),'weight':nullable(ref('Quantity'))}),
'Chunk':obj({'chunk_id':ref('Id'),'digest':ref('Digest48'),'byte_length':ref('UInt'),'row_count':ref('UInt')}),
'Shock':obj({'factor':enum('RESERVE_PRICE','FX_PRICE','PROVIDER_OUTAGE','CAPABILITY_RETIREMENT','COST_MULTIPLIER','LOAD_DELAY_MS'),'target_ref':ref('ExactRef'),'value':ref('Quantity'),'unit':ref('Id')}),
'MetricResult':obj({'metric_ref':ref('ExactRef'),'value':nullable(ref('Money')),'count':nullable(ref('UInt')),'status':enum('COMPLETE','PARTIAL','UNAVAILABLE'),'eligible_count':ref('UInt'),'unpriced_count':ref('UInt'),'excluded_count':ref('UInt')}),
'Error':obj({'code':ref('Id'),'stage':ref('Id'),'retryable':{'type':'boolean'},'correlation_id':ref('Id'),'next_action':ref('Text')}),
}
common={'schema_revision':{'const':'1.2'},'provider_id':ref('Id'),'created_at':ref('UInt')}
types={
'LayerExtensionProfileV1_2':dict(extension_id=ref('Id'),parent_profile_ref=ref('ExactRef'),base_extension_ref=ref('ExactRef'),schema_digest=ref('Digest48'),operations_digest=ref('Digest48'),supported_features=arr(ref('Id'),64),expires_at=ref('UInt')),
'ProviderRoleManifestV1_2':dict(manifest_id=ref('Id'),profile_ref=ref('ExactRef'),roles=arr(ref('Role'),9),endpoints=arr(ref('Endpoint'),128),network_refs=arr(ref('Digest32'),16),conformance_refs=arr(ref('ExactRef'),32),sequence=ref('UInt'),expires_at=ref('UInt')),
'ServiceBindingV1_2':dict(binding_id=ref('Id'),scope=ref('Scope'),role=ref('Role'),remote_profile_ref=ref('ExactRef'),remote_role_ref=ref('ExactRef'),permitted_effects=arr(ref('Effect'),17),owner_policy_ref=ref('ExactRef'),generation=ref('UInt'),status=enum('PROPOSED','ACTIVE','REVOKED'),expires_at=ref('UInt')),
'AdapterCapabilityManifestV1_2':dict(adapter_id=ref('Id'),interface_name=ref('Id'),interface_revision=ref('Id'),schema_digest=ref('Digest48'),operations=arr(ref('Id'),128),support=enum('IMPLEMENTED','DISABLED','UNAVAILABLE'),ambiguity_contract_ref=ref('ExactRef'),evidence_refs=arr(ref('ExactRef'),64)),
'InstitutionalAssetRecordV1_2':dict(asset_id=ref('Id'),asset_kind=ref('AssetKind'),identifiers=arr(ref('Identifier'),32),native_resource_refs=arr(ref('ExactRef'),256),rights_ref=nullable(ref('ExactRef')),quantity_unit=ref('Id'),financial_status=enum('FINANCIAL','NONFINANCIAL','UNDETERMINED'),record_authority_ref=ref('ExactRef'),effective_at=ref('UInt'),generation=ref('UInt')),
'RightsStatementV1_2':dict(rights_id=ref('Id'),asset_ref=ref('ExactRef'),holder_entity_id=ref('Id'),rights_kind=enum('PUBLIC_USE','LICENSE','OWNERSHIP','CONTRACT_CLAIM','FUND_SHARE','SPONSOR_COMMITMENT'),transferability=enum('PERMITTED_BY_TERMS','PROHIBITED','UNDETERMINED'),contract_digest=nullable(ref('Digest48')),issuer_ref=ref('ExactRef'),valid_from=ref('UInt'),valid_until=nullable(ref('UInt'))),
'PositionObservationV1_2':dict(observation_id=ref('Id'),scope=ref('Scope'),asset_ref=ref('ExactRef'),economic_position_key=ref('Id'),custodian_position_ref=ref('Id'),quantity=ref('Quantity'),view=enum('DIRECT','LOOKTHROUGH','OPERATIONAL'),status=enum('OPEN','CLOSED','DISPUTED'),authority_ref=ref('ExactRef'),effective_at=ref('UInt'),recorded_at=ref('UInt'),sequence=ref('UInt'),supersedes=nullable(ref('ExactRef'))),
'ValuationObservationV1_2':dict(valuation_id=ref('Id'),asset_ref=ref('ExactRef'),position_ref=ref('ExactRef'),purpose=enum('MARKET_VALUE','COST_BASIS','REPLACEMENT_SCENARIO','UTILITY'),status=enum('CURRENT','STALE','UNAVAILABLE'),value=nullable(ref('Money')),valuation_policy_ref=ref('ExactRef'),evidence_refs=arr(ref('ExactRef'),64),effective_at=ref('UInt'),recorded_at=ref('UInt'),valid_until=ref('UInt')),
'ExposureLinkV1_2':dict(link_id=ref('Id'),scope=ref('Scope'),source_ref=ref('ExactRef'),links=arr(ref('Link'),256),financial_leverage_policy_ref=nullable(ref('ExactRef')),effective_at=ref('UInt'),coverage_bps={'type':'integer','minimum':0,'maximum':10000}),
'PortfolioProjectionV1_2':dict(projection_id=ref('Id'),scope=ref('Scope'),as_of=ref('UInt'),observed_cutoff=ref('UInt'),watermarks=arr(ref('Watermark'),32),metric_results=arr(ref('MetricResult'),32),position_refs=arr(ref('ExactRef'),1000),operational_refs=arr(ref('ExactRef'),1000),reconciliation_refs=arr(ref('ExactRef'),1000),next_cursor=nullable(ref('Id'))),
'MetricDefinitionV1_2':dict(metric_id=ref('Id'),metric_kind=enum('AUM','AUC','AUA','PLATFORM_ASSETS','FINANCIAL_NAV','CAPABILITY_COUNT','ACTUAL_COST','SCENARIO_VALUE'),scope_role=enum('MANAGER','CUSTODIAN','ADMINISTRATOR','PLATFORM','OWNER','OPERATOR'),inclusion_kinds=arr(ref('AssetKind'),5),basis=enum('DIRECT_ONLY','LOOKTHROUGH_ONLY','OPERATIONAL_ONLY'),valuation_purpose=enum('MARKET_VALUE','COST_BASIS','NONE','REPLACEMENT_SCENARIO'),mandate_required={'type':'boolean'},policy_ref=ref('ExactRef'),generation=ref('UInt')),
'ExportManifestV1_2':dict(export_id=ref('Id'),scope=ref('Scope'),projection_ref=ref('ExactRef'),format=enum('JSONL','CSV','DESKTOP_CONTEXT'),mapping_digest=ref('Digest48'),chunks=arr(ref('Chunk'),2048),total_rows=ref('UInt'),privacy_policy_ref=ref('ExactRef'),expires_at=ref('UInt')),
'PortfolioInstructionV1_2':dict(instruction_id=ref('Id'),scope=ref('Scope'),source_projection_ref=ref('ExactRef'),source_system_id=ref('Id'),requested_action=enum('DRAFT_RESERVE_ALLOCATION','DRAFT_RESEARCH_COMMITMENT','DRAFT_CAPABILITY_ACQUISITION','DRAFT_PRODUCT_REFERRAL'),objective=ref('Text'),maximum_exposure=ref('Money'),target_refs=arr(ref('ExactRef'),32),client_operation_id=ref('Id'),expires_at=ref('UInt')),
'InteroperabilityReceiptV1_2':dict(receipt_id=ref('Id'),scope=ref('Scope'),operation_id=ref('Id'),request_body_id=ref('Digest48'),state=enum('ACCEPTED','VALIDATED','APPLIED','REJECTED','RECONCILIATION_REQUIRED'),result_refs=arr(ref('ExactRef'),256),original_provider_ref=ref('ExactRef'),sequence=ref('UInt')),
'ScenarioDefinitionV1_2':dict(scenario_id=ref('Id'),scope=ref('Scope'),projection_ref=ref('ExactRef'),shocks=arr(ref('Shock'),64),method=enum('DETERMINISTIC_SHOCK_V1'),assumption_refs=arr(ref('ExactRef'),64),expires_at=ref('UInt')),
'ScenarioResultV1_2':dict(result_id=ref('Id'),scope=ref('Scope'),scenario_ref=ref('ExactRef'),financial_change=nullable(ref('Money')),unpriced_refs=arr(ref('ExactRef'),256),operational_impacts=arr(obj({'target_ref':ref('ExactRef'),'impact':ref('Id'),'value':nullable(ref('Quantity')),'unit':ref('Id')}),256),source_coverage_bps={'type':'integer','minimum':0,'maximum':10000},calculation_version=ref('Id')),
'ConformanceStatementV1_2':dict(statement_id=ref('Id'),role_manifest_ref=ref('ExactRef'),candidate_fingerprint=ref('Digest48'),test_manifest_digest=ref('Digest48'),evidence_level=enum('REFERENCE','NATIVE_UNIT','PROCESS_E2E','NATIVE_CHAIN','OPERATOR_PILOT'),passed_case_ids=arr(ref('Id'),512),unrun_case_ids=arr(ref('Id'),512),issuer_class=enum('SELF_ATTESTED','INDEPENDENT_REVIEW'),expires_at=ref('UInt')),
'ReconciliationBreakV1_2':dict(break_id=ref('Id'),scope=ref('Scope'),kind=enum('DUPLICATE_CLAIM','QUANTITY_MISMATCH','PRICE_MISSING','RIGHTS_UNKNOWN','STALE_SOURCE','IDENTIFIER_COLLISION','SEQUENCE_GAP'),source_refs=arr(ref('ExactRef'),32),state=enum('OPEN','ACKNOWLEDGED','RESOLVED_BY_EVIDENCE'),assigned_role=ref('Id'),resolution_refs=arr(ref('ExactRef'),32),generation=ref('UInt')),
}
for name,fields in types.items():
 D[name]=obj({**common,**fields})
 D[name+'Envelope']=obj({'object_type':{'const':name},'body':ref(name),'body_id':ref('Digest48'),'signer_key_id':ref('Id'),'signature':{'type':'string','pattern':'^[0-9a-f]{4840}$'}})
# Operation requests use exact bodies or constrained inputs; actual actor/scope is rechecked from authentication.
D['IdRequest']=obj({'expected_body_id':ref('Digest48'),'client_operation_id':ref('Id')})
D['BindingRevokeRequest']=obj({'expected_body_id':ref('Digest48'),'expected_generation':ref('UInt'),'client_operation_id':ref('Id')})
D['RecordRequest']=obj({'statement':{'oneOf':[ref(n+'Envelope') for n in types]},'client_operation_id':ref('Id')})
D['AdapterValidateRequest']=obj({'adapter_manifest_ref':ref('ExactRef'),'required_operations':arr(ref('Id'),128),'client_operation_id':ref('Id')})
D['PositionBatchRequest']=obj({'source_binding_ref':ref('ExactRef'),'batch_id':ref('Id'),'previous_watermark':nullable(ref('Watermark')),'statements':arr(ref('PositionObservationV1_2Envelope'),1000),'client_operation_id':ref('Id')})
D['ProjectionRequest']=obj({'scope':ref('Scope'),'as_of':ref('UInt'),'observed_cutoff':ref('UInt'),'metric_refs':arr(ref('ExactRef'),32),'source_binding_refs':arr(ref('ExactRef'),32),'client_operation_id':ref('Id')})
D['ExportRequest']=obj({'projection_ref':ref('ExactRef'),'format':enum('JSONL','CSV','DESKTOP_CONTEXT'),'mapping_digest':ref('Digest48'),'privacy_policy_ref':ref('ExactRef'),'client_operation_id':ref('Id')})
D['ImportValidateRequest']=obj({'manifest':ref('ExportManifestV1_2Envelope'),'staged_chunk_ids':arr(ref('Id'),2048),'source_binding_ref':ref('ExactRef'),'client_operation_id':ref('Id')})
D['ImportCommitRequest']=obj({'validation_receipt_ref':ref('ExactRef'),'manifest_body_id':ref('Digest48'),'expected_mapping_digest':ref('Digest48'),'client_operation_id':ref('Id')})
D['ResolveBreakRequest']=obj({'expected_generation':ref('UInt'),'evidence_refs':arr(ref('ExactRef'),32),'client_operation_id':ref('Id')})
D['InstructionRequest']=obj({'instruction':ref('PortfolioInstructionV1_2'),'client_operation_id':ref('Id')})
D['ScenarioRequest']=obj({'scenario':ref('ScenarioDefinitionV1_2'),'client_operation_id':ref('Id')})
D['StagedChunk']=obj({'staged_chunk_id':ref('Id'),'digest':ref('Digest48'),'byte_length':ref('UInt'),'expires_at':ref('UInt')})
D['Job']=obj({'job_id':ref('Id'),'state':enum('QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELED'),'result_ref':nullable(ref('ExactRef')),'status_path':ref('Text'),'error':nullable(ref('Error')),'cancel_disposition':enum('NOT_REQUESTED','CANCEL_REQUESTED','QUIESCENT','ALREADY_COMMITTED')})
D['Page']=obj({'items':arr(ref('ExactRef'),1000),'next_cursor':nullable(ref('Id')),'snapshot_ref':ref('ExactRef')})
D['Status']=obj({'receipt_ref':ref('ExactRef'),'state':enum('ACCEPTED','VALIDATED','APPLIED','REJECTED','RECONCILIATION_REQUIRED')})
ops=[]
def op(name,method,path,scope,effect,req,res,detail):ops.append(dict(operation_id=name,method=method,path='/btx/hcp/v1'+path,scope=scope,effect=effect,request_schema=req,response_schema=res,detail=detail))
op('getLayerExtension','GET','/extensions/cognitive-reserve/v1.2','catalog:read','READ',None,'LayerExtensionProfileV1_2Envelope','Read the pinned extension. No support inferred from a provider name.')
op('publishProviderRoles','POST','/layer/roles','layer:admin','RECORD','ProviderRoleManifestV1_2','ProviderRoleManifestV1_2Envelope','Provider administration only; endpoints must map to registered supported operations.')
op('getProviderRoles','GET','/layer/roles/{id}','catalog:read','READ',None,'ProviderRoleManifestV1_2Envelope','Read exact signed role manifest by ID; expired claims remain inspectable, not usable for new effects.')
op('listProviderRoles','GET','/layer/roles','catalog:read','READ',None,'Page','Local configured directory view only; no canonical global provider registry.')
op('createServiceBinding','POST','/layer/bindings','bindings:admin','BIND','ServiceBindingV1_2','ServiceBindingV1_2Envelope','Propose or activate only after owner policy, remote identity and allowed role/effects agree.')
op('getServiceBinding','GET','/layer/bindings/{id}','bindings:read','READ',None,'ServiceBindingV1_2Envelope','Return caller-scoped binding, without credentials.')
op('listServiceBindings','GET','/layer/bindings','bindings:read','READ',None,'Page','Snapshot-bound listing of the entity bindings.')
op('revokeServiceBinding','POST','/layer/bindings/{id}/revoke','bindings:admin','BIND','BindingRevokeRequest','ServiceBindingV1_2Envelope','Stop new effects; retain reconciliation access to already accepted financial actions.')
op('validateAdapterCapabilities','POST','/layer/adapters/validate','layer:admin','RECORD','AdapterValidateRequest','Job','Bounded test job; requires configured test environment and never probes arbitrary URLs.')
op('getAdapterCapabilityReport','GET','/layer/adapters/{id}','bindings:read','READ',None,'AdapterCapabilityManifestV1_2Envelope','Actual supported interface and evidence, not a brand-to-feature mapping.')
op('registerInstitutionalAsset','POST','/institutional/assets','assets:write','RECORD','InstitutionalAssetRecordV1_2','InstitutionalAssetRecordV1_2Envelope','Register namespaced identity; collisions open a break rather than merging.')
op('getInstitutionalAsset','GET','/institutional/assets/{id}','assets:read','READ',None,'InstitutionalAssetRecordV1_2Envelope','Scoped exact asset; a record does not establish title or a tradable instrument.')
op('listInstitutionalAssets','GET','/institutional/assets','assets:read','READ',None,'Page','List supported financial and operational categories separately.')
op('recordAssetRights','POST','/institutional/assets/{id}/rights','assets:write','RECORD','RightsStatementV1_2','RightsStatementV1_2Envelope','Rights assertion bound to issuer and evidence; no change to native ownership.')
op('ingestPositionBatch','POST','/institutional/positions/batches','positions:write','RECORD','PositionBatchRequest','Job','Validate entire bounded batch and source sequence; atomically stage/apply observations.')
op('getPositionObservation','GET','/institutional/positions/{id}','positions:read','READ',None,'PositionObservationV1_2Envelope','Return effective/recorded times, source authority and supersession.')
op('getPositionSnapshot','GET','/institutional/positions','positions:read','READ',None,'Page','Requires as_of and observed_cutoff; continuation pinned to both.')
op('recordValuationObservation','POST','/institutional/valuations','valuations:write','RECORD','ValuationObservationV1_2','ValuationObservationV1_2Envelope','A source mark is distinct from accepted accounting/metric policy.')
op('getValuationObservation','GET','/institutional/valuations/{id}','valuations:read','READ',None,'ValuationObservationV1_2Envelope','Preserve stale/unavailable state; no zero substitution.')
op('recordExposureLinks','POST','/institutional/exposures','exposures:write','RECORD','ExposureLinkV1_2','ExposureLinkV1_2Envelope','Typed financial lookthrough or operational dependencies; bounded graph validation.')
op('listExposureLinks','GET','/institutional/exposures','exposures:read','READ',None,'Page','Snapshot-filtered graph edges; financial and operational views stay distinct.')
op('defineInstitutionalMetric','POST','/institutional/metrics','metrics:admin','RECORD','MetricDefinitionV1_2','MetricDefinitionV1_2Envelope','Versioned policy configuration, not arbitrary formula code.')
op('listInstitutionalMetrics','GET','/institutional/metrics','metrics:read','READ',None,'Page','Display definitions, roles and eligibility beside each reported total.')
op('createPortfolioProjection','POST','/institutional/projections','projections:create','RECORD','ProjectionRequest','Job','Asynchronous consistent snapshot; unresolved inputs produce partial/unavailable metrics.')
op('getPortfolioProjection','GET','/institutional/projections/{id}','projections:read','READ',None,'PortfolioProjectionV1_2Envelope','Separate financial totals, commitments and operational capability inventory.')
op('createInstitutionalExport','POST','/institutional/exports','exports:create','EXPORT','ExportRequest','Job','Build redacted snapshot package under exact mapping and policy.')
op('getInstitutionalExport','GET','/institutional/exports/{id}','exports:read','READ',None,'ExportManifestV1_2Envelope','Manifest only; original financial and package envelopes remain exact.')
op('downloadInstitutionalExportChunk','GET','/institutional/exports/{id}/chunks/{chunk_id}','exports:read','READ',None,'BINARY','Authenticated chunk fetch; tenant-bound endpoint, no public bearer URL.')
op('validateInstitutionalImport','POST','/institutional/imports/validate','imports:write','RECORD','ImportValidateRequest','Job','Staged chunks, exact digests and mapping checks. No automatic ledger or financial action.')
op('commitInstitutionalImport','POST','/institutional/imports/{id}/commit','imports:write','RECORD','ImportCommitRequest','InteroperabilityReceiptV1_2Envelope','CAS over manifest and validation; publish read projection only, no custody mutation.')
op('getInstitutionalImport','GET','/institutional/imports/{id}','imports:read','READ',None,'InteroperabilityReceiptV1_2Envelope','Replayed identical import returns the same outcome.')
op('listReconciliationBreaks','GET','/institutional/breaks','reconciliation:read','READ',None,'Page','Prioritize by affected metric, scope and age; hidden error is not an empty position.')
op('getReconciliationBreak','GET','/institutional/breaks/{id}','reconciliation:read','READ',None,'ReconciliationBreakV1_2Envelope','Source comparison, responsibility and evidence without secret material.')
op('resolveReconciliationBreak','POST','/institutional/breaks/{id}/resolve','reconciliation:write','RECORD','ResolveBreakRequest','ReconciliationBreakV1_2Envelope','Resolve by accepted new evidence; never overwrite the native ledger to clear the UI.')
op('preparePortfolioInstruction','POST','/institutional/instructions','capital:prepare','PLAN','InstructionRequest','PortfolioInstructionV1_2Envelope','Read portfolio intent into a bounded proposal, not a financial instruction already approved.')
op('getPortfolioInstruction','GET','/institutional/instructions/{id}','capital:read','READ',None,'PortfolioInstructionV1_2Envelope','Immutable request and provenance; no token forwarding.')
op('translatePortfolioInstruction','POST','/institutional/instructions/{id}/translate','capital:prepare','TRANSLATE_TO_DRAFT','IdRequest','InteroperabilityReceiptV1_2Envelope','Create existing v1.1 CapitalPlan/AllocationPlan drafts; execution stays on executeAllocation after ordinary approvals.')
op('runInstitutionalScenario','POST','/institutional/scenarios','scenarios:create','RECORD','ScenarioRequest','Job','Deterministic bounded shocks, not unstated forecast or statistical VaR.')
op('getInstitutionalScenario','GET','/institutional/scenarios/{id}','scenarios:read','READ',None,'ScenarioResultV1_2Envelope','Return financial change separately from operational impacts and unpriced exposures.')
op('getLayerConformance','GET','/layer/conformance/{id}','catalog:read','READ',None,'ConformanceStatementV1_2Envelope','Per-role test scope and issuer; self-attestation is not centrally granted certification.')
op('getLayerJob','GET','/layer/jobs/{id}','jobs:read','READ',None,'Job','Owner-scoped durable job status; result_ref points to the typed resource getter. No poll URL from untrusted metadata.')
op('cancelLayerJob','POST','/layer/jobs/{id}/cancel','jobs:cancel','RECORD','IdRequest','Job','Cancel bounded projection/import/scenario work before commit or return the already committed result; no finance cancellation implied.')
op('stageInstitutionalImportChunk','POST','/institutional/imports/chunks','imports:write','RECORD','BINARY','StagedChunk','Stream an authenticated quota-bounded chunk, verify its declared hash, and return a tenant-owned opaque staged handle.')
assert len(ops)==43 and len(types)==18
schema={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:btx:crl:1.2:objects','$defs':D}
(R/'schemas/CognitiveReserveLayer.schema.json').write_text(json.dumps(schema,indent=2))
(R/'schemas/operations-v1.2.json').write_text(json.dumps({'revision':'1.2','new_operations':len(ops),'preserved_contract_operations':84,'operations':ops},indent=2))
base=yaml.safe_load((R/'compatibility/v1_1/schemas/openapi-v1.1.yaml').read_text())
# Refs converted to prefixed schema names; inherited components/operations are byte-semantically preserved.
def orefs(x):
 if isinstance(x,dict):return {k:('#/components/schemas/CR12_'+v.split('/')[-1] if k=='$ref' and v.startswith('#/$defs/') else orefs(v)) for k,v in x.items()}
 if isinstance(x,list):return [orefs(v) for v in x]
 return x
base['info']['title']='BTX Hosted Control Plane and Cognitive Reserve Layer'
base['info']['version']='1.2'
base.setdefault('components',{}).setdefault('schemas',{}).update({'CR12_'+k:orefs(v) for k,v in D.items()})
for o in ops:
 path=o['path'].removeprefix('/btx/hcp/v1');method=o['method'].lower()
 assert method not in base['paths'].get(path,{})
 ps=[]
 import re
 for name in re.findall(r'\{([^}]+)\}',path):ps.append({'name':name,'in':'path','required':True,'schema':orefs(ref('Id'))})
 if method=='get' and o['response_schema']=='Page':
  ps += [{'name':n,'in':'query','required':False,'schema':{'type':'string'}} for n in ['cursor','as_of','observed_cutoff','filter']]
  ps += [{'name':'limit','in':'query','schema':{'type':'integer','minimum':1,'maximum':1000,'default':100}}]
 if o['request_schema']=='BINARY':
  ps += [{'name':'X-Content-SHA384','in':'header','required':True,'schema':orefs(ref('Digest48'))},{'name':'Content-Length','in':'header','required':True,'schema':{'type':'integer','minimum':1,'maximum':16777216}}]
 if method=='post':ps.append({'name':'Idempotency-Key','in':'header','required':True,'schema':orefs(ref('Id'))})
 route={'operationId':o['operation_id'],'summary':o['detail'],'x-btx-effect':o['effect'],'x-btx-scope':o['scope'],'x-btx-extension':'CRL/1.2','security':[{'hcpOAuth':[o['scope']]}],'parameters':ps,'responses':{}}
 res=o['response_schema'];status='202' if res=='Job' else '200'
 content={'application/octet-stream':{'schema':{'type':'string','format':'binary'}}} if res=='BINARY' else {'application/json':{'schema':orefs(ref(res))}}
 route['responses'][status]={'description':'Typed result; no financial success implied by an accepted job.','content':content}
 route['responses']['default']={'description':'Structured boundary error','content':{'application/json':{'schema':orefs(ref('Error'))}}}
 if o['request_schema']:route['requestBody']={'required':True,'content':({'application/octet-stream':{'schema':{'type':'string','format':'binary'}}} if o['request_schema']=='BINARY' else {'application/json':{'schema':orefs(ref(o['request_schema']))}})}
 base['paths'].setdefault(path,{})[method]=route
# No fabricated auth server endpoints; provider enrollment supplies actual OAuth metadata.
base['components'].setdefault('securitySchemes',{})['hcpOAuth']={'type':'oauth2','flows':{'authorizationCode':{'authorizationUrl':'https://provider.example/oauth/authorize','tokenUrl':'https://provider.example/oauth/token','scopes':{o['scope']:o['scope'] for o in ops}}},'description':'Provider-resolved endpoints; example host is not a live service.'}
(R/'schemas/openapi-v1.2.yaml').write_text(yaml.safe_dump(base,sort_keys=False))
# Human contract sheets.
s='# New API operations — CRL/1.2\n\nAll paths below are under `/btx/hcp/v1`. Existing 84 contract operations remain unchanged. POST scopes never replace entity, source, policy and expected-version checks.\n\n'
for o in ops:
 s+=f"## {o['operation_id']}\n\n`{o['method']} {o['path']}`\n\nScope: `{o['scope']}`. Effect: `{o['effect']}`. Request: `{o['request_schema'] or 'path/query only'}`. Response: `{o['response_schema']}`.\n\n{o['detail']}\n\n"
(R/'schemas/OPERATIONS.md').write_text(s)
s='# Signed type contracts — CRL/1.2\n\nAll eighteen types have `schema_revision=1.2`, `provider_id` and `created_at`. They use the unchanged HCP body-domain formula with the exact type name. Every declared field is required; unavailable facts use an explicit nullable type where defined. Production validation enforces cross-field and authority constraints beyond JSON Schema.\n\n'
for n,fields in types.items():
 s+=f'## {n}\n\n'
 for k,v in fields.items():
  desc=v.get('$ref',v.get('const',v.get('enum',v.get('type','nullable/union'))))
  s+=f'- `{k}`: `{desc}`.\n'
 s+='\n'
(R/'schemas/TYPE_CONTRACTS.md').write_text(s)
(R/'schemas/contract-counts.json').write_text(json.dumps({'new_types':18,'new_operations':43,'base_operations':84,'total_operations':127},indent=2))
print('Created 18 signed types and 43 additive operations.')
