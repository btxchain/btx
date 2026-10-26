import {el,button,field,note,jsonView,table} from '../components/ui.js';
import {JsonNumber,parseJsonExact} from '../core/json.js';
import {redactObservation} from '../core/qt-gaps.js';
import {operationDialog} from './operations.js';

const NOT_READ = 'Not read. A missing method or an RPC error is not success.';

function looksSensitive(value) {
 if (typeof value !== 'string' || value === '' || value === '[hidden]') return false;
 const lower = value.toLowerCase();
 if (lower.includes('x-amz-') || lower.includes('aws_secret') || lower.includes('secret_access_key') || lower.includes('presign')) return true;
 if (/https?:\/\//i.test(value) && value.includes('?')) return true;
 if (/cookie\s*[:=]/i.test(value)) return true;
 return false;
}

function scrub(value) {
 if (typeof value === 'string') {
  if (looksSensitive(value)) return '[hidden]';
  if (/credential_ref/i.test(value)) return value.replace(/credential_refs?/gi, '[hidden]');
  return value;
 }
 if (Array.isArray(value)) return value.map(scrub);
 if (value && typeof value === 'object') {
  const out = {};
  for (const [key, child] of Object.entries(value)) {
   if (key === 'credential_ref' || key === 'credential_refs') continue;
   out[key] = scrub(child);
  }
  return out;
 }
 return value;
}

function shown(value) {
 let redacted;
 try { redacted = redactObservation(value); }
 catch { return undefined; }
 if (redacted === undefined) return undefined;
 return scrub(redacted);
}

function failureText(message) {
 const text = String(message ?? 'Request failed');
 if (looksSensitive(text) || /credential_ref/i.test(text)) return 'The message was withheld because it contained a credential, cookie, query string, or presigned URL.';
 return text.length > 400 ? `${text.slice(0, 400)}…` : text;
}

function domainFailure(value) {
 if (!value || typeof value !== 'object') return '';
 if (value.unavailable === true) return 'unavailable';
 if (typeof value.error_code === 'string' && value.error_code) return value.error_code;
 if (value.error_code === 'HELPER_DOWN' || value.code === 'HELPER_DOWN') return 'HELPER_DOWN';
 return '';
}

function resultBox() {
 const box = el('div', {'aria-live':'polite'});
 box.append(note(NOT_READ));
 return box;
}

function panel(name, failClosed, refresh, ...rest) {
 return el('section', {class:'panel', dataset:{panel:name}}, el('div', {class:'row'}, el('h2', {}, name), refresh), note(failClosed), ...rest);
}

function idField(label) {
 const input = el('input', {type:'text', autocomplete:'off', spellcheck:'false', 'aria-label':label});
 return {input, node:field(label, input)};
}

function objectField(label, help) {
 const input = el('textarea', {rows:5, class:'mono', spellcheck:'false', autocomplete:'off', 'aria-label':label, placeholder:'{}'});
 return {input, node:field(label, input, help)};
}

function isZero(value) {
 if (value === 0 || value === '0') return true;
 return value instanceof JsonNumber && value.text === '0';
}

function forbidsSpend(value) {
 if (Array.isArray(value)) return value.some(forbidsSpend);
 if (value && typeof value === 'object') {
  for (const [key, child] of Object.entries(value)) {
   if (key === 'automatic_spend_atoms') { if (!isZero(child)) return true; }
   else if (forbidsSpend(child)) return true;
  }
 }
 return false;
}

function labelId(value) {
 if (value === '[hidden]' || looksSensitive(value)) return '(redacted)';
 if (typeof value !== 'string' || value === '') return '(unset)';
 return value;
}

function notRunLines(value, found = []) {
 if (found.length >= 12) return found;
 if (Array.isArray(value)) { for (const child of value) notRunLines(child, found); return found; }
 if (value && typeof value === 'object') {
  for (const [key, child] of Object.entries(value)) {
   if (typeof child === 'string' && /^NOT_RUN\b/.test(child) && child.length < 180 && !looksSensitive(child)) found.push(`${key}: ${child}`);
   else notRunLines(child, found);
   if (found.length >= 12) break;
  }
 }
 return found;
}

function smokeBlocked(value) {
 if (!value || typeof value !== 'object') return false;
 if (value.smoke_blocked === true || value.block_warmup === true) return true;
 if (value.smoke_passed === false) return true;
 if (value.smoke_performed === false && value.ready === true) return true;
 if (value.switch_ready === false) return true;
 const progress = value.progress;
 if (progress && typeof progress === 'object') {
  if (progress.smoke_blocked === true || progress.runtime_ready === false) return true;
  if (progress.first_useful_result === false && Number(progress.percent_ready) >= 100) return true;
 }
 return false;
}

function criticalPath(value) {
 if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
 const raw = value.wall_ms ?? value.ttc_critical_path_ms;
 if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
 if (typeof raw === 'string' && /^-?\d+$/.test(raw)) return Number(raw);
 return null;
}

function watchList(value) {
 if (Array.isArray(value)) return value;
 if (value && Array.isArray(value.watches)) return value.watches;
 if (value && typeof value === 'object' && value.watch_id) return [value];
 return null;
}

function watchRows(value) {
 const list = watchList(value);
 if (!list) return null;
 return list.filter(row => row && typeof row === 'object').map(row => {
  const kind = typeof row.kind === 'string' && row.kind !== '[hidden]' && !looksSensitive(row.kind) ? row.kind : '';
  let target = 'QUERY (string omitted)';
  if (/^publisher$/i.test(kind)) target = `PUBLISHER ${labelId(row.publisher_id)}`;
  else if (/^collection$/i.test(kind)) target = `COLLECTION ${labelId(row.collection_id)}`;
  else if (/^model$/i.test(kind)) target = `MODEL ${labelId(row.model_id)}`;
  else if (kind && !/^query$/i.test(kind)) target = `${kind} (query omitted)`;
  let action = typeof row.action === 'string' && row.action !== '[hidden]' && !looksSensitive(row.action) ? row.action : (row.action === '[hidden]' ? '(redacted)' : 'NOTIFY');
  if (/^prepare_funding$/i.test(action)) action = 'PREPARE_FUNDING (unsigned)';
  return {watch_id:labelId(row.watch_id), target, action};
 });
}

function eventRows(value) {
 const list = Array.isArray(value) ? value : value?.events;
 if (!Array.isArray(list)) return null;
 return list.filter(row => row && typeof row === 'object').map(row => {
  const seq = row.seq ?? row.sequence;
  return {
   seq: typeof seq === 'number' || (typeof seq === 'string' && !looksSensitive(seq)) ? seq : '—',
   event_type: labelId(row.event_type ?? row.type),
   stage: labelId(row.stage),
  };
 });
}

async function observe(host, app, method, params) {
 if (app.bridge.supported(method) === false) {
  host.append(note(`${method} is not on this helper (fails closed). This is not success.`, 'danger'));
  return undefined;
 }
 try {
  const envelope = await app.bridge.read(method, params);
  const value = envelope && Object.prototype.hasOwnProperty.call(envelope, 'result') ? envelope.result : undefined;
  if (value == null) {
   host.append(note(`${method} returned no result. This is not success.`, 'danger'));
   return undefined;
  }
  const displayed = shown(value);
  if (displayed === undefined) {
   host.append(note(`${method} result withheld. This is not success.`, 'danger'));
   return undefined;
  }
  const failure = domainFailure(displayed);
  if (failure) host.append(note(`${method} · ${failure}. This is not success.`, 'danger'));
  host.append(jsonView(displayed, {open:true, title:method}));
  return displayed;
 } catch (error) {
  host.append(note(`${method} · ${error.code || 'REQUEST'} · ${failureText(error.message)}. This is not success.`, 'danger'));
  return undefined;
 }
}

function refreshButton(name, run) {
 const refresh = button('Refresh', async () => {
  refresh.disabled = true;
  try { await run(); }
  finally { if (refresh.isConnected) refresh.disabled = false; }
 }, '', {'aria-label':`Refresh ${name}`});
 return refresh;
}

function readPanel(app, {name, method, failClosed, params = () => [], after}) {
 const host = resultBox();
 const refresh = refreshButton(name, async () => {
  host.replaceChildren();
  const displayed = await observe(host, app, method, params());
  if (displayed !== undefined && after) for (const node of after(displayed)) host.append(node);
 });
 return panel(name, failClosed, refresh, host);
}

function idReadPanel(app, {name, method, failClosed, idLabel, params, after}) {
 const host = resultBox();
 const id = idField(idLabel);
 const refresh = refreshButton(name, async () => {
  host.replaceChildren();
  const text = id.input.value.trim();
  if (!text) {
   host.append(note('An id is required. An empty id is not a successful read.', 'danger'));
   return;
  }
  const displayed = await observe(host, app, method, params(text));
  if (displayed !== undefined && after) for (const node of after(displayed)) host.append(node);
 });
 return panel(name, failClosed, refresh, id.node, host);
}

function openReview(app, method, input, status) {
 const text = input.value.trim();
 if (!text) {
  status.replaceChildren(note('Type one JSON object. An empty field is not a request.', 'danger'));
  return;
 }
 let obj;
 try { obj = parseJsonExact(text); }
 catch (error) {
  status.replaceChildren(note(failureText(error.message), 'danger'));
  return;
 }
 if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
  status.replaceChildren(note('The review parameter is one JSON object.', 'danger'));
  return;
 }
 if (forbidsSpend(obj)) {
  status.replaceChildren(note('automatic_spend_atoms stays 0. This panel will not open a review that sets a spend.', 'danger'));
  return;
 }
 try { operationDialog(app, method, [obj]); }
 catch (error) {
  status.replaceChildren(note(failureText(error.message), 'danger'));
  return;
 }
 status.replaceChildren(note(`Opened native review for ${method}. This panel did not execute it.`));
}

function reviewPanel(app, {name, methods, failClosed, help}) {
 const typed = objectField('Request object', help);
 const status = el('div');
 const buttons = methods.map(method => button(method, () => openReview(app, method, typed.input, status), '', {disabled:app.bridge.supported(method) === false}));
 return el('section', {class:'panel', dataset:{panel:name}}, el('h2', {}, name), note(failClosed), typed.node, el('div', {class:'actions'}, ...buttons), status);
}

export function modelPanels(app) {
 const directoryHost = resultBox();
 const directoryId = idField('Model id or btx://');
 const directoryRefresh = refreshButton('Directory', async () => {
  directoryHost.replaceChildren();
  const id = directoryId.input.value.trim();
  if (!id) {
   directoryHost.append(note('An id is required. An empty id is not a successful read.', 'danger'));
   return;
  }
  await observe(directoryHost, app, 'getmodeleconomyentry', [id]);
  await observe(directoryHost, app, 'getmodeldirectoryentry', [id]);
 });
 const watchesHost = resultBox();
 const watchesRefresh = refreshButton('Watches', async () => {
  watchesHost.replaceChildren();
  const displayed = await observe(watchesHost, app, 'listmodelwatches', []);
  const rows = displayed === undefined ? null : watchRows(displayed);
  if (rows) watchesHost.append(table(rows, ['watch_id', 'target', 'action'], {empty:'No publisher, collection, query, or model watches.'}));
 });
 const eventsHost = resultBox();
 const eventsReview = button('Review event read', () => {
  eventsHost.replaceChildren(note('getbtxcapabilityevents drops stored events at or below the cursor. The native dialog must confirm it. This button does not call the node.', 'warning'));
  operationDialog(app, 'getbtxcapabilityevents', [{cursor:0}]);
 }, '', {'aria-label':'Review getbtxcapabilityevents'});
 const searchHost = resultBox();
 const searchId = idField('query_id');
 const searchRefresh = refreshButton('Search', async () => {
  searchHost.replaceChildren();
  const queryId = searchId.input.value.trim();
  if (!queryId) {
   searchHost.append(note('query_id is required. An empty id is not a successful read.', 'danger'));
   return;
  }
  const displayed = await observe(searchHost, app, 'getsearchstatus', [queryId]);
  if (displayed !== undefined) searchHost.append(note('complete is never global-true.'));
 });
 return el('div', {class:'surface-stack'},
  readPanel(app, {
   name:'Profile',
   method:'getmodelprofile',
   failClosed:'Operator profile. A missing method fails closed. automatic_spend_atoms stays 0.',
   after(displayed) {
    if (!displayed || typeof displayed !== 'object' || Array.isArray(displayed)) return [note('getmodelprofile returned no object. This is not success.', 'danger')];
    return [];
   },
  }),
  readPanel(app, {
   name:'Cloud',
   method:'getcloudstorageinfo',
   failClosed:'Cloud backing is optional. Local pieces remain the swarm unit. Secrets are not shown here. automatic_spend_atoms stays 0.',
   after(displayed) {
    const nodes = [];
    if (!displayed || typeof displayed !== 'object' || Array.isArray(displayed)) nodes.push(note('getcloudstorageinfo returned no object. Cloud backing remains optional. This is not success.', 'danger'));
    if (notRunLines(displayed).length) nodes.push(note('Live cloud WAN stays NOT_RUN. NOT_RUN is not a pass.'));
    return nodes;
   },
  }),
  panel('Watches', 'listmodelwatches is the network watch list. Filesystem -modelwatch / getmodelwatchstatus is a different mechanism. A filesystem drop folder is not a publisher watch. PREPARE_FUNDING is unsigned. automatic_spend_atoms stays 0. This panel does not call wallet RPCs.', watchesRefresh, watchesHost),
  readPanel(app, {
   name:'Events',
   method:'getmodeleventsequence',
   failClosed:'Untrusted event text is not a command, path, RPC, or mandate. This panel reads getmodeleventsequence only. automatic_spend_atoms stays 0.',
  }),
  panel('Search', 'getsearchstatus reads one query id. complete is never global-true. searchpublishers and searchcollections open native review, so a network query stays on that path unless the catalog marks them read. Opening this panel does not run a network search.', searchRefresh, searchId.node, searchHost, el('div', {class:'actions'},
   button('searchpublishers', () => operationDialog(app, 'searchpublishers'), '', {disabled:app.bridge.supported('searchpublishers') === false}),
   button('searchcollections', () => operationDialog(app, 'searchcollections'), '', {disabled:app.bridge.supported('searchcollections') === false}),
  )),
  panel('Directory', 'getmodeleconomyentry and getmodeldirectoryentry. An empty id is not sent. This panel does not invent peers, liquidity, or qualification.', directoryRefresh, directoryId.node, directoryHost),
  readPanel(app, {
   name:'Feed sequence',
   method:'getmodelfeedsequence',
   failClosed:'Local feed_sequence only. This refresh does not fetch the network feed and does not download.',
   after(displayed) {
    const seq = displayed && typeof displayed === 'object' ? displayed.feed_sequence : undefined;
    if (typeof seq === 'number' && Number.isFinite(seq)) return [note(`Local feed_sequence ${seq}. This refresh does not fetch the network feed.`)];
    return [];
   },
  }),
  idReadPanel(app, {
   name:'Release economics',
   method:'getmodelreleaseeconomics',
   idLabel:'release_id or model_id',
   failClosed:'Lifecycle, pledged versus confirmed funded. Helper observation is not wallet authority. An empty id is not sent. automatic_spend_atoms stays 0.',
   params:id => [id],
  }),
  readPanel(app, {
   name:'Resource governor',
   method:'getresourcegovernorinfo',
   failClosed:'Local resource-governor status. A missing method fails closed. This status is not a spend grant.',
  }),
  readPanel(app, {
   name:'Bounty capabilities',
   method:'getbountycapabilities',
   failClosed:'Installed records, scripts, and executed evaluation profiles only. This panel does not invent peers, liquidity, or qualification.',
  }),
  readPanel(app, {
   name:'Runtime',
   method:'getbtxruntimecapabilities',
   failClosed:'Owner-local probed adapters. Absent hardware stays NOT_RUN. NOT_RUN is not a pass. Public HTTP is 405. automatic_spend_atoms stays 0.',
   after(displayed) {
    const nodes = [];
    const lines = notRunLines(displayed);
    if (lines.length) nodes.push(note(`Absent hardware stays NOT_RUN. ${lines.join(' · ')}`));
    else nodes.push(note('Absent hardware stays NOT_RUN. This result was not relabeled as a pass.'));
    if (smokeBlocked(displayed)) nodes.push(note('A blocked smoke test is not 100% ready.', 'danger'));
    if (displayed && displayed.remap_only === true) nodes.push(note('remap_only is not readiness.', 'danger'));
    if (domainFailure(displayed) === 'HELPER_DOWN') nodes.push(note('HELPER_DOWN. The monetary node continuing is not runtime readiness.', 'danger'));
    return nodes;
   },
  }),
  panel('Events list', 'Owner-local capability lifecycle events from getbtxcapabilityevents. The call drops stored events at or below the cursor, so it stays on native review. automatic_spend_atoms stays 0. remap_only is not readiness.', eventsReview, eventsHost),
  idReadPanel(app, {
   name:'Trace',
   method:'getbtxttctrace',
   idLabel:'job_id',
   failClosed:'Critical-path time, not occupancy. A blocked smoke test is not 100% ready. job_id is required. automatic_spend_atoms stays 0.',
   params:id => [{job_id:id}],
   after(displayed) {
    const ms = criticalPath(displayed);
    const nodes = [note(ms == null ? 'Critical-path time, not occupancy.' : `Critical-path time: ${ms} ms. This is critical-path time, not occupancy.`)];
    if (smokeBlocked(displayed)) nodes.push(note('A blocked smoke test is not 100% ready.', 'danger'));
    return nodes;
   },
  }),
  reviewPanel(app, {
   name:'Capability lifecycle',
   methods:['planbtxcapability', 'ensurebtxcapability', 'prefetchbtxcapability', 'sleepbtxcapability', 'wakebtxcapability', 'releasebtxcapability', 'planbtxcapabilityupdate', 'switchbtxcapability'],
   failClosed:'Owner-local. No public HTTP. automatic_spend_atoms stays 0. remap_only is not readiness. Each button opens native review with the object you type. This panel does not execute it. An absent method stays unavailable.',
   help:'One JSON object. The review dialog receives it as the only parameter.',
  }),
  reviewPanel(app, {
   name:'Cache encrypted model',
   methods:['cacheencryptedmodel'],
   failClosed:'cacheencryptedmodel is ciphertext only and does not auto-download. Plaintext stays sealed. automatic_spend_atoms stays 0. This button opens native review and does not execute it.',
   help:'One JSON object. Ciphertext only. This does not auto-download.',
  }),
  reviewPanel(app, {
   name:'Publish search record',
   methods:['publishmodelsearchrecord'],
   failClosed:'publishmodelsearchrecord is metadata only. automatic_spend_atoms stays 0. This button opens native review and does not execute it.',
   help:'One JSON object. Metadata only.',
  }),
 );
}
