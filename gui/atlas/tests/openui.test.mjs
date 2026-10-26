import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  EXAMPLE_PROGRAM,
  OPENUI_SCHEMA,
  extractOpenUIFence,
  mergeOpenUI,
  mergedSource,
  parseOpenUI,
  parseOpenUIStream,
  queryPlan,
  groupRuns,
  realizeOpenUI,
  rememberOpenUI,
  summarizeObservation,
  validateOpenUIDocument,
} from '../web/core/openui.js';
import promptDoc from '../web/core/openui-prompt.json' with {type: 'json'};

const emptyStack = 'root = Stack([])';

function document(title, program = emptyStack) {
  return {schema: OPENUI_SCHEMA, title, program};
}

test('example program plans one chain read and realizes the supplied observation', () => {
  const parsed = parseOpenUI(EXAMPLE_PROGRAM);
  assert.deepEqual(queryPlan(parsed), [{id: 'chain', method: 'getblockchaininfo'}]);
  const tree = realizeOpenUI(parsed, new Map([['chain', {ok: true, value: {blocks: 9}}]]));
  assert.equal(tree.type, 'Stack');
  assert.deepEqual(tree.children[0], {type: 'Text', text: 'This node, described in OpenUI Lang'});
  assert.deepEqual(tree.children[1], {type: 'Observation', method: 'getblockchaininfo', value: {blocks: 9}});
});

test('a query with an argument object is not planned and is not read', () => {
  const parsed = parseOpenUI('root = Stack([q])\nq = Query("getblockchaininfo", {height: 1})');
  assert.deepEqual(queryPlan(parsed), []);
  let read = false;
  const answers = new Map();
  const guard = new Proxy(answers, {get(target, prop, receiver) {
    if (prop === 'has' || prop === 'get') read = true;
    return Reflect.get(target, prop, receiver);
  }});
  const tree = realizeOpenUI(parsed, guard);
  assert.equal(read, false);
  assert.deepEqual(tree.children[0], {type: 'Refused', reason: 'Query was not run'});
});

test('a query with an empty argument object is still a read', () => {
  const parsed = parseOpenUI('root = Stack([q])\nq = Query("getblockchaininfo", {})');
  assert.deepEqual(queryPlan(parsed), [{id: 'q', method: 'getblockchaininfo'}]);
});

test('a missing or failed observation is refused and a mutation is never planned', () => {
  const parsed = parseOpenUI('root = Stack([chain, spend])\nchain = Query("getblockchaininfo")\nspend = Mutation("sendtoaddress", {address: "x"})');
  assert.deepEqual(queryPlan(parsed), [{id: 'chain', method: 'getblockchaininfo'}]);
  const missing = realizeOpenUI(parsed, new Map());
  assert.deepEqual(missing.children[0], {type: 'Refused', reason: 'No observation was supplied'});
  assert.match(missing.children[1].reason, /Atlas does not run a generated mutation/);
  assert.match(missing.children[1].reason, /spend/);
  const failed = realizeOpenUI(parsed, new Map([['chain', {ok: false, message: 'node unavailable'}]]));
  assert.deepEqual(failed.children[0], {type: 'Refused', reason: 'node unavailable'});
  assert.equal(failed.children[1].type, 'Refused');
});

test('navigate to network is kept and navigate to admin is refused', () => {
  const parsed = parseOpenUI('root = Stack([ok, bad, focus, loose])\nok = Button("Home", "navigate", "network")\nbad = Button("Nope", "navigate", "admin")\nfocus = Button("Node", "focus", "node:1")\nloose = Button("Bad", "focus", "bad target")');
  const tree = realizeOpenUI(parsed, new Map());
  assert.deepEqual(tree.children[0], {type: 'Button', label: 'Home', action: 'navigate', target: 'network'});
  assert.equal(tree.children[1].type, 'Refused');
  assert.deepEqual(tree.children[2], {type: 'Button', label: 'Node', action: 'focus', target: 'node:1'});
  assert.equal(tree.children[3].type, 'Refused');
});

test('summarizeObservation keeps six scalar facts and does not read anything else', () => {
  const chain = summarizeObservation('getblockchaininfo', {
    chain: 'main',
    blocks: 9,
    headers: 10,
    verificationprogress: 0.5,
    bestblockhash: 'ab',
    initialblockdownload: false,
  });
  assert.deepEqual(chain, {
    metrics: [
      {label: 'chain', value: 'main'},
      {label: 'blocks', value: 9},
      {label: 'headers', value: 10},
      {label: 'verificationprogress', value: '50.00%'},
    ],
    rest: true,
  });
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: 0}).metrics[0].value, '0.00%');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: 1}).metrics[0].value, '100.00%');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: 1.2}).metrics[0].value, 1.2);
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '1'}).metrics[0].value, '100.00%');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '0.5'}).metrics[0].value, '50.00%');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '1.0'}).metrics[0].value, '100.00%');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '0'}).metrics[0].value, '0.00%');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '1.2'}).metrics[0].value, '1.2');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '1e-1'}).metrics[0].value, '1e-1');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '00'}).metrics[0].value, '00');
  assert.equal(summarizeObservation('getblockchaininfo', {verificationprogress: '-0'}).metrics[0].value, '-0');

  const mempool = summarizeObservation('getmempoolinfo', {size: 62, bytes: 27155, usage: 145408});
  assert.deepEqual(mempool.metrics, [
    {label: 'size', value: 62},
    {label: 'bytes', value: '27155'},
  ]);
  assert.equal(mempool.rest, true);
  assert.equal(mempool.metrics[1].value, '27155');

  const totals = summarizeObservation('getnettotals', {
    totalbytesrecv: '48234496',
    totalbytessent: 20971520,
    timemillis: 5,
  });
  assert.deepEqual(totals.metrics, [
    {label: 'totalbytesrecv', value: '48234496'},
    {label: 'totalbytessent', value: '20971520'},
  ]);
  assert.equal(String(totals.metrics[0].value).includes('KiB') || String(totals.metrics[1].value).includes('MiB'), false);

  const network = summarizeObservation('getnetworkinfo', {
    connections: 18,
    networkactive: true,
    subversion: '/BTX/',
  });
  assert.deepEqual(network.metrics, [
    {label: 'connections', value: 18},
    {label: 'networkactive', value: true},
  ]);
  assert.equal(network.rest, true);

  let unread = 0;
  const capped = {
    chain: 'main',
    blocks: 1,
    headers: 2,
    verificationprogress: 0.25,
    connections: 3,
    networkactive: false,
  };
  Object.defineProperty(capped, 'size', {enumerable: true, get() { unread++; return 9; }});
  Object.defineProperty(capped, 'warnings', {enumerable: true, get() { unread++; return 'disk'; }});
  const summary = summarizeObservation('getblockchaininfo', capped);
  assert.equal(summary.metrics.length, 6);
  assert.deepEqual(summary.metrics.map(item => item.label), [
    'chain', 'blocks', 'headers', 'verificationprogress', 'connections', 'networkactive',
  ]);
  assert.equal(summary.metrics[3].value, '25.00%');
  assert.equal(summary.rest, true);
  assert.equal(unread, 0);

  assert.deepEqual(summarizeObservation('getblockchaininfo', {chain: 'regtest', blocks: '420000'}), {
    metrics: [{label: 'chain', value: 'regtest'}, {label: 'blocks', value: '420000'}],
    rest: false,
  });
  assert.deepEqual(summarizeObservation('getblockchaininfo', {}), {metrics: [], rest: false});
  assert.deepEqual(summarizeObservation('getblockchaininfo', {blocks: null, headers: Number.NaN}), {metrics: [], rest: true});
  assert.deepEqual(summarizeObservation('getmininginfo', {difficulty: 1, networkhashps: 5}), {metrics: [], rest: true});
  assert.deepEqual(summarizeObservation('getmininginfo', {blocks: 8}), {
    metrics: [{label: 'blocks', value: 8}],
    rest: false,
  });
  for (const value of [null, [], 'main', 1, true]) {
    assert.deepEqual(summarizeObservation('getblockchaininfo', value), {metrics: [], rest: true});
  }
  assert.deepEqual(summarizeObservation('listmodels', {chain: 'main', blocks: 1}), {metrics: [], rest: true});
  assert.deepEqual(summarizeObservation('getpeerinfo', {connections: 2}), {metrics: [], rest: true});
});

test('mergedSource returns merged program text only after it parses', () => {
  const saved = EXAMPLE_PROGRAM;
  const source = mergedSource(saved, 'heading = Text("Replaced heading")');
  assert.equal(typeof source, 'string');
  assert.equal(saved, EXAMPLE_PROGRAM);
  assert.deepEqual(parseOpenUI(source).root, mergeOpenUI(saved, 'heading = Text("Replaced heading")').root);
  assert.equal(parseOpenUI(source).root.props.children[0].props.text, 'Replaced heading');
  assert.throws(() => mergedSource(saved, 'heading = Chart("x")'));
  assert.equal(saved, EXAMPLE_PROGRAM);
  assert.equal(EXAMPLE_PROGRAM, 'root = Stack([heading, chain])\nheading = Text("This node, described in OpenUI Lang")\nchain = Query("getblockchaininfo")');
});

test('mergeOpenUI replaces one statement and reparses', () => {
  const saved = EXAMPLE_PROGRAM;
  const merged = mergeOpenUI(saved, 'heading = Text("Replaced heading")');
  assert.equal(saved, EXAMPLE_PROGRAM);
  assert.equal(merged.root.typeName, 'Stack');
  assert.equal(merged.root.props.children[0].props.text, 'Replaced heading');
  assert.deepEqual(queryPlan(merged), [{id: 'chain', method: 'getblockchaininfo'}]);
  assert.throws(() => mergeOpenUI(saved, 'heading = Chart("x")'));
  assert.equal(saved, EXAMPLE_PROGRAM);
});

test('two stream chunks match one parse of the joined source', () => {
  const chunks = [
    'root = Stack([heading, chain])\nheading = Text("This node, described in OpenUI Lang")\n',
    'chain = Query("getblockchaininfo")',
  ];
  const streamed = parseOpenUIStream(chunks);
  const full = parseOpenUI(chunks.join(''));
  assert.deepEqual(streamed.root, full.root);
});

test('a program longer than 32768 characters throws', () => {
  assert.throws(() => parseOpenUI(`root = Stack([])\n${' '.repeat(32768)}`));
  assert.throws(() => parseOpenUI('root = Stack([])\0'));
  assert.throws(() => parseOpenUI('root = Stack([])\r\n'));
});

test('an unknown component does not render as a component', () => {
  const source = 'root = Stack([u])\nu = Chart("x")';
  let parsed;
  try {
    parsed = parseOpenUI(source);
  } catch (error) {
    assert.match(String(error), /Chart/);
    return;
  }
  const tree = realizeOpenUI(parsed, new Map());
  const encoded = JSON.stringify(tree);
  assert.equal(encoded.includes('"type":"Chart"'), false);
  assert.equal(encoded.includes('Chart'), true);
  assert.equal(tree.type === 'Chart', false);
});

test('prompt text names the read and forbids a mutation and a cloud endpoint', () => {
  const prompt = JSON.stringify(promptDoc);
  assert.equal(prompt.includes('Do not emit Mutation'), true);
  assert.equal(prompt.includes('getblockchaininfo'), true);
  assert.equal(prompt.includes('openui.com/api'), false);
});

test('vendored parser source has no fetch call', () => {
  const source = fs.readFileSync(new URL('../web/vendor/openui-lang.js', import.meta.url), 'utf8');
  assert.equal(source.includes('fetch('), false);
});

test('extractOpenUIFence returns the first closed openui block only', () => {
  const program = 'root = Stack([])';
  const text = `intro\n\`\`\`js\nskip\n\`\`\`\n\`\`\`openui\n${program}\n\`\`\`\n\`\`\`openui\nsecond\n\`\`\`\n`;
  assert.equal(extractOpenUIFence(text), program);
  assert.equal(extractOpenUIFence('no fence'), null);
  assert.equal(extractOpenUIFence(`\`\`\`openui\n${program}`), null);
  assert.equal(extractOpenUIFence(`\`\`\`openui extra\n${program}\n\`\`\``), null);
  assert.equal(extractOpenUIFence(`\`\`\`openui\n${'a'.repeat(32769)}\n\`\`\``), null);
  assert.equal(extractOpenUIFence(`\`\`\`openui\n${'a'.repeat(32768)}\n\`\`\``).length, 32768);
});

test('groupRuns groups two or more consecutive buttons and leaves every other node alone', () => {
  const text = {type: 'Text', text: 'heading'};
  const home = {type: 'Button', label: 'Home', action: 'navigate', target: 'network'};
  const wallet = {type: 'Button', label: 'Wallet', action: 'navigate', target: 'wallet'};
  const note = {type: 'Note', text: 'aside'};
  const solo = {type: 'Button', label: 'Solo', action: 'focus', target: 'node:1'};
  const nodes = [text, home, wallet, note, solo];
  const before = nodes.map(item => ({...item}));
  const groups = groupRuns(nodes);
  assert.equal(groups.length, 4);
  assert.deepEqual(groups[0], {type: 'one', item: text});
  assert.equal(groups[0].item.type, 'Text');
  assert.deepEqual(groups[1], {type: 'buttons', items: [home, wallet]});
  assert.equal(groups[1].items.length, 2);
  assert.equal(groups[1].items[0], home);
  assert.equal(groups[1].items[1], wallet);
  assert.deepEqual(groups[2], {type: 'one', item: note});
  assert.equal(groups[2].item.type, 'Note');
  assert.deepEqual(groups[3], {type: 'one', item: solo});
  assert.equal(groups[3].item.type, 'Button');
  assert.deepEqual(nodes, before);
  assert.equal(nodes[1], home);
  assert.deepEqual(groupRuns([]), []);
  assert.throws(() => groupRuns(null));
  assert.throws(() => groupRuns(undefined));
  assert.throws(() => groupRuns({type: 'Button'}));
  const query = {type: 'Observation', method: 'getblockchaininfo', value: {blocks: 1}};
  const mutation = {type: 'Refused', reason: 'Atlas does not run a generated mutation'};
  assert.deepEqual(groupRuns([query, mutation]), [
    {type: 'one', item: query},
    {type: 'one', item: mutation},
  ]);
});

test('rememberOpenUI validates, dedupes, and keeps twelve newest first', () => {
  const first = rememberOpenUI([], document('Alpha'));
  const second = rememberOpenUI(first, document('Beta', 'root = Stack([t])\nt = Text("beta")'));
  assert.deepEqual(first.map(item => item.title), ['Alpha']);
  assert.deepEqual(second.map(item => item.title), ['Beta', 'Alpha']);
  const moved = rememberOpenUI(second, document('Alpha'));
  assert.equal(moved.length, 2);
  assert.deepEqual(moved.map(item => item.title), ['Alpha', 'Beta']);
  assert.deepEqual(Object.keys(moved[0]).sort(), ['program', 'schema', 'title']);
  let list = [];
  for (let i = 0; i < 14; i++) list = rememberOpenUI(list, document(`T${i}`, `root = Stack([t])\nt = Text("${i}")`));
  assert.equal(list.length, 12);
  assert.equal(list[0].title, 'T13');
  assert.equal(list.some(item => item.title === 'T0'), false);
  assert.equal(list.some(item => item.title === 'T1'), false);
  const kept = rememberOpenUI([{schema: 'nope', title: 'Junk', program: 'no'}], document('Kept'));
  assert.deepEqual(kept.map(item => item.title), ['Kept']);
  assert.throws(() => rememberOpenUI([], {schema: 'nope', title: 'A', program: emptyStack}));
  assert.throws(() => validateOpenUIDocument(document('')));
  assert.throws(() => validateOpenUIDocument(document('bad\ntitle')));
  assert.throws(() => validateOpenUIDocument(document('x'.repeat(81))));
  assert.equal(validateOpenUIDocument(document('Chain')).program, emptyStack);
});
