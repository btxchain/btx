import {el,button,heading,note,metric,table,jsonView,dialog,humanBytes,toast} from '../components/ui.js';
import {buildGraph} from '../core/graph.js';
import {JsonNumber} from '../core/json.js';
import {blockHeights,headerBars,moneyPeers,sessionSamples,trafficDelta} from '../core/network.js';
import {operationDialog} from './operations.js';

function sessionBytes(text) {
  if (typeof text !== 'string' || !/^(0|[1-9]\d*)$/.test(text)) return '—';
  const amount = Number(text);
  return Number.isSafeInteger(amount) ? humanBytes(amount) : `${text} B`;
}

export function networkView(app) {
  const root = el('div', {class:'page'}, heading('Peer network', 'Atlas is the window onto this node. Money and models move on the same BTX peer network. Counts and peers below are what this node has observed.'));
  const metricsHost = el('div', {class:'metrics'});
  const sessionHost = el('div');
  const moneyHost = el('div');
  const modelHost = el('div');
  const blocksHost = el('div');
  const mempoolHost = el('div');
  let blockGeneration = 0;
  let shownTip = null;
  root.append(
    el('div', {class:'row'},
      button('Open a BTX link', () => app.openResource()),
      button('Review addnode', () => operationDialog(app, 'addnode')),
      button('Banned peers', () => operationDialog(app, 'listbanned')),
      button('Open the network map', () => app.navigate('atlas'))),
    metricsHost,
    sessionHost,
    el('section', {class:'panel'}, el('h2', {}, 'Money peers'), note('Disconnect and ban open a native review. They do not run from this table.'), moneyHost),
    el('section', {class:'panel'}, el('h2', {}, 'Model peers'), note('A model peer is another participant this node has observed. It is not permission to train, seed, or spend.'), modelHost),
    el('section', {class:'panel'}, el('h2', {}, 'Recent blocks'), note('Headers from this node, newest first. This is not a second chain.'), blocksHost),
    el('section', {class:'panel'}, el('h2', {}, 'Mempool during this session'), note('Samples start when this page is open. They are not the node’s historical mempool.'), mempoolHost));
  function paint() {
    const sources = app.state.state.sources || {};
    const chain = sources.getblockchaininfo?.result || {};
    const network = sources.getnetworkinfo?.result || {};
    const modelnet = sources.getmodelnetworkinfo?.result || {};
    const totals = sources.getnettotals?.result || {};
    if (app.trafficBaseline == null && totals && typeof totals === 'object' && !Array.isArray(totals)) {
      const snapshot = {totalbytesrecv: totals.totalbytesrecv, totalbytessent: totals.totalbytessent};
      if (snapshot.totalbytesrecv != null && snapshot.totalbytessent != null && trafficDelta(snapshot, snapshot)) app.trafficBaseline = snapshot;
    }
    const session = trafficDelta(app.trafficBaseline, totals);
    const info = sources.getmempoolinfo?.result || {};
    const privacy = app.state.state.privacy !== false;
    metricsHost.replaceChildren(
      metric('Chain', chain.chain ?? '—', chain.blocks != null ? `${chain.blocks} blocks` : ''),
      metric('Money peers', network.connections ?? '—', network.networkactive === false ? 'Network inactive' : 'Network active'),
      metric('Model peers', modelnet.native_participation?.authenticated_peers ?? '—', 'Observed by this node'),
      metric('Received', humanBytes(totals.totalbytesrecv), 'Since this node started'),
      metric('Sent', humanBytes(totals.totalbytessent), 'Since this node started'),
      metric('Mempool', info.size ?? '—', humanBytes(info.bytes)));
    sessionHost.replaceChildren(session
      ? el('div', {class:'metrics'},
          metric('Session received', sessionBytes(session.received), 'Since this page first read totals'),
          metric('Session sent', sessionBytes(session.sent), 'Since this page first read totals'))
      : note('The session totals are unavailable.'));
    const peers = moneyPeers(sources.getpeerinfo?.result, {privacy});
    const rows = peers.map((peer, index) => ({index, address: peer.shown, direction: peer.direction, type: peer.type, ping: peer.ping, height: peer.height, version: peer.version}));
    const canToast = typeof toast === 'function';
    const actions = (_value, row) => {
      const endpoint = peers[row.index]?.endpoint || '';
      return el('div', {class:'row'},
        button('Copy', event => {
          event.stopPropagation();
          if (privacy) {
            if (canToast) toast('Address hidden while values are masked', 'warning');
            return;
          }
          if (endpoint) {
            const pending = app.bridge.copy(endpoint);
            if (pending && typeof pending.catch === 'function') pending.catch(error => { if (canToast) toast(error && error.message ? error.message : 'Copy failed', 'danger'); });
          }
        }, '', {disabled: privacy ? !canToast : !endpoint}),
        button('Disconnect', event => { event.stopPropagation(); if (endpoint) operationDialog(app, 'disconnectnode', [endpoint]); }, '', {disabled: !endpoint}),
        button('Ban', event => { event.stopPropagation(); if (endpoint) operationDialog(app, 'setban', [endpoint, 'add']); }, '', {disabled: !endpoint}));
    };
    moneyHost.replaceChildren(table(rows, ['address', 'direction', 'type', 'ping', 'height', 'version', {key:'actions', label:'Review', render: actions}], {empty:'No money peers observed.'}));
    const graph = buildGraph(sources, {privacy});
    const models = graph.nodes.filter(node => node.network === 'models').map(node => ({label: node.label, state: node.state, id: node.id}));
    modelHost.replaceChildren(table(models, ['label', 'state'], {onSelect: row => app.focus(row.id), empty:'No model peers observed.'}));
    app.mempoolSamples = sessionSamples(app.mempoolSamples, info, Date.now());
    const samples = app.mempoolSamples;
    const peak = Math.max(1, ...samples.map(sample => sample.size));
    mempoolHost.replaceChildren(samples.length ? el('div', {class:'mempool-bars', role:'img', 'aria-label':`${samples.length} mempool samples this session`}, ...samples.map(sample => el('span', {style:`height:${Math.max(4, Math.round(sample.size / peak * 48))}px`, title:`${sample.size} transactions`}))) : note('No mempool sample yet.'));
    const tip = chain.blocks;
    if (tip !== shownTip) {
      shownTip = tip;
      loadBlocks(tip);
    }
  }
  async function loadBlocks(tip) {
    const generation = ++blockGeneration;
    const heights = blockHeights(tip, 8);
    if (!heights.length) { blocksHost.replaceChildren(note('Block height is not available from this node.')); return; }
    blocksHost.replaceChildren(note('Reading recent block headers from this node.'));
    const rows = [];
    for (const height of heights) {
      if (generation !== blockGeneration) return;
      try {
        const hash = await app.bridge.read('getblockhash', [new JsonNumber(height)]);
        const id = typeof hash.result === 'string' ? hash.result : '';
        const block = id ? await app.bridge.read('getblock', [id, new JsonNumber('1')]) : null;
        const body = block?.result || {};
        rows.push({height, time: body.time ?? '', transactions: body.nTx ?? '', hash: body.hash || id});
      } catch (error) {
        rows.push({height, time:'', transactions:'', hash: error.message || 'Unreadable'});
      }
    }
    if (generation !== blockGeneration) return;
    if (!rows.some(row => row.hash)) { blocksHost.replaceChildren(note('This node did not return recent block hashes.')); return; }
    const bars = headerBars(rows);
    const peak = bars.reduce((max, bar) => Math.max(max, bar.transactions), 1);
    blocksHost.replaceChildren(
      table(rows, ['height', 'time', 'transactions', 'hash'], {onSelect: row => dialog(`Block ${row.height}`, jsonView(row, {open:true})), empty:'No blocks returned.'}),
      note('Transaction counts from the headers just read.'),
      el('div', {class:'mempool-bars', role:'img', 'aria-label':'Transaction counts from the headers just read'}, ...bars.map(bar => el('span', {style:`height:${Math.max(4, Math.round(bar.transactions / peak * 48))}px`, title:`${bar.transactions}`}))),
    );
  }
  const unsubscribe = app.state.subscribe(paint);
  app.cleanup = () => unsubscribe();
  paint();
  return root;
}
