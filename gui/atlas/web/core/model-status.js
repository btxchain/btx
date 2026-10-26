const FLAG_FIELDS = [
  ['identity_ready', 'Identity ready'],
  ['pq1_ready', 'PQ1 ready'],
  ['helper_ready', 'Helper ready'],
  ['ready_to_host', 'Ready to host'],
  ['ready_to_mine', 'Ready to mine'],
];
const NESTS = ['money', 'models', 'modelnet', 'model', 'helper', 'first_run', 'mining', 'chain'];

function plain(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value;
}

function readKey(root, key) {
  const obj = plain(root);
  if (!obj) return undefined;
  if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
  for (const name of NESTS) {
    const child = plain(obj[name]);
    if (child && Object.prototype.hasOwnProperty.call(child, key)) return child[key];
  }
  return undefined;
}

function shown(value) {
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
}

function addLine(lines, label, value) {
  const text = shown(value);
  if (text === null) return;
  lines.push(`${label}: ${text}`);
}

function isRateKey(key) {
  return /(?:^|_)(?:rate|bps)(?:$|_)|per_sec/.test(key);
}

function addRates(lines, source, seen) {
  const obj = plain(source);
  if (!obj) return;
  for (const key of Object.keys(obj)) {
    if (seen.has(key) || !isRateKey(key)) continue;
    const value = obj[key];
    if (typeof value !== 'string' && !(typeof value === 'number' && Number.isFinite(value))) continue;
    seen.add(key);
    lines.push(`${key}: ${typeof value === 'number' ? String(value) : value}`);
  }
}

function spendOf(setup) {
  const root = plain(setup);
  if (!root) return 'unknown';
  if (typeof root.automatic_spend_atoms === 'string') return root.automatic_spend_atoms;
  const modelnet = plain(root.modelnet);
  if (modelnet && typeof modelnet.automatic_spend_atoms === 'string') return modelnet.automatic_spend_atoms;
  return 'unknown';
}

export function modelNodeStatus(setup, profile) {
  const lines = [];
  for (const [key, label] of FLAG_FIELDS) addLine(lines, label, readKey(setup, key));
  const ibd = shown(readKey(setup, 'ibd'));
  const downloading = shown(readKey(setup, 'initialblockdownload'));
  if (ibd !== null) lines.push(`IBD: ${ibd}`);
  else if (downloading !== null) lines.push(`IBD: ${downloading}`);
  const host = plain(profile);
  if (host && Object.prototype.hasOwnProperty.call(host, 'local_generate')) addLine(lines, 'Local generate', host.local_generate);
  const seen = new Set();
  const root = plain(setup);
  if (root) {
    addRates(lines, root, seen);
    for (const name of NESTS) addRates(lines, root[name], seen);
  }
  addRates(lines, host, seen);
  return {lines, spend: spendOf(setup)};
}
