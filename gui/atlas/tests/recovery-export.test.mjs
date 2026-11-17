import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {installDom,fieldInput,buttonNamed,fire,settle,findAll,fakeApp} from './dom-stub.mjs';
import {operationDialog} from '../web/views/operations.js';
import {OPERATIONS} from '../web/core/catalog.js';
installDom();
const DUMMY='dummy-export-credential-not-real';
function fill(d,value=DUMMY){
 const input=fieldInput(d.element,'passphrase');
 if(input){input.value=value;fieldInput(d.element,'Repeat passphrase').value=value;}
 else fieldInput(d.element,'request').value=JSON.stringify({passphrase:value});
}
function fields(d){return findAll(d.element,n=>['INPUT','TEXTAREA'].includes(n.tagName));}
function cleared(d){assert.ok(fields(d).every(n=>!n.value.includes(DUMMY)),'Credential remains in a form field');}

test('export uses confirmed password fields and excludes raw JSON',()=>{
 const d=operationDialog(fakeApp(),'exportswaprecovery');
 for(const label of ['passphrase','Repeat passphrase']){
  const input=fieldInput(d.element,label);assert.ok(input,'Missing dedicated password field');assert.equal(input.getAttribute('type'),'password');
 }
 assert.equal(fieldInput(d.element,'Use exact JSON array/object').disabled,true);d.close();
});

for(const outcome of ['CANCELLED','UNKNOWN','success'])test('clear before native review and preserve request on '+outcome,async()=>{
 const app=fakeApp();let executions=0,prepared;
 app.bridge.read=async()=>assert.fail('Recovery export cannot be a silent read');
 const d=operationDialog(app,'exportswaprecovery');fill(d);
 app.bridge.execute=async()=>{executions++;cleared(d);if(outcome!=='success')throw Object.assign(Error('Controlled result'),{code:outcome,outcome_unknown:outcome==='UNKNOWN'});return {ok:true,result:{path:'dummy-output'}};};
 fire(buttonNamed(d.element,'Prepare for native review'),'click');await settle();
 assert.equal(app.prepared.length,1);assert.deepEqual(JSON.parse(app.prepared[0].json),[{passphrase:DUMMY}]);assert.equal(executions,1);cleared(d);
 if(outcome!=='success')assert.ok(d.element.textContent.includes(outcome));
 d.close();cleared(d);
});

test('object prefill stays in password controls, not raw JSON',()=>{
 const d=operationDialog(fakeApp(),'exportswaprecovery',[{passphrase:DUMMY}]);
 const input=fieldInput(d.element,'passphrase');assert.ok(input);assert.equal(input.value,DUMMY);assert.equal(input.getAttribute('type'),'password');
 assert.equal(fieldInput(d.element,'Repeat passphrase').value,DUMMY);
 const raw=findAll(d.element,n=>n.getAttribute('aria-label')==='Exact JSON RPC parameters')[0];assert.equal(raw.value.includes(DUMMY),false);d.close();cleared(d);
});

test('mismatched confirmation does not prepare or execute',async()=>{
 const app=fakeApp();app.bridge.execute=async()=>assert.fail('Mismatched credential was submitted');const d=operationDialog(app,'exportswaprecovery');fill(d);
 const repeat=fieldInput(d.element,'Repeat passphrase');assert.ok(repeat);repeat.value='different';fire(buttonNamed(d.element,'Prepare for native review'),'click');await settle();assert.equal(app.prepared.length,0);assert.ok(d.element.textContent.includes('do not match'));d.close();cleared(d);
});

test('ordinary JSON form retains exact single-object request and approval route',async()=>{
 const app=fakeApp();let calls=0;app.bridge.execute=async()=>{calls++;return {ok:true};};const d=operationDialog(app,'setswapassetpolicy');const request={policy:{asset:'test-asset'}};
 fieldInput(d.element,'request').value=JSON.stringify(request);assert.equal(fieldInput(d.element,'Use exact JSON array/object').disabled,false);fire(buttonNamed(d.element,'Prepare for native review'),'click');await settle();assert.deepEqual(JSON.parse(app.prepared[0].json),[request]);assert.equal(calls,1);d.close();
});

test('schema and generated catalogue agree',()=>{
 const schema=JSON.parse(fs.readFileSync(new URL('../schemas/operations.json',import.meta.url)));
 assert.deepEqual(OPERATIONS,schema.operations);
});
