import {createParser, createStreamingParser, mergeStatements} from '../vendor/openui-lang.js';
import schema from './openui-schema.json' with {type: 'json'};

export const READ_QUERIES = [
  'getblockchaininfo',
  'getnetworkinfo',
  'getmempoolinfo',
  'getnettotals',
  'getmodelnetworkinfo',
  'getmodelhostprofile',
  'getsetupstatus',
  'listmodels',
  'getmininginfo',
];

export const VIEWS = [
  'network',
  'atlas',
  'models',
  'swarms',
  'work',
  'research',
  'neuronlab',
  'economy',
  'compute',
  'mining',
  'wallet',
  'activity',
  'tools',
  'settings',
];

export const EXAMPLE_PROGRAM = 'root = Stack([heading, chain])\nheading = Text("This node, described in OpenUI Lang")\nchain = Query("getblockchaininfo")';

export const OPENUI_SCHEMA = 'btx.atlas.openui/1';

const PROGRAM_MAX = 32768;
const STATEMENT_MAX = 64;
const TITLE_MAX = 80;
const REMEMBER_MAX = 12;
const OBSERVATION_JSON_MAX = 8192;
const FOCUS_TARGET = /^[A-Za-z0-9:._-]{1,80}$/;
const OPEN_FENCE = /^[ \t]*```openui[ \t]*$/;
const CLOSE_FENCE = /^[ \t]*```[ \t]*$/;
const KNOWN = new Set(['Stack', 'Text', 'Note', 'Metric', 'Table', 'Button']);
const READ_QUERY_SET = new Set(READ_QUERIES);
const VIEW_SET = new Set(VIEWS);
const parser = createParser(schema, 'Stack');

function refused(reason) {
  return {type: 'Refused', reason};
}

function assertSource(source) {
  if (typeof source !== 'string' || source.length < 1 || source.length > PROGRAM_MAX) {
    throw new Error('OpenUI program must be 1 to 32768 characters');
  }
  for (let i = 0; i < source.length; i++) {
    const code = source.charCodeAt(i);
    if (code === 0) throw new Error('OpenUI program contains NUL');
    if (code < 0x20 && code !== 0x0a && code !== 0x09) throw new Error('OpenUI program contains a forbidden control character');
  }
}

function assertParsed(parsed) {
  const meta = parsed && parsed.meta;
  const errors = meta && Array.isArray(meta.errors) ? meta.errors : null;
  if (!errors || errors.length !== 0) {
    const detail = (errors || []).map(error => error && (error.message || error.component || error.code)).filter(Boolean).join('; ');
    throw new Error(detail ? `OpenUI program was rejected: ${detail}` : 'OpenUI program was rejected');
  }
  if (meta.incomplete !== false) throw new Error('OpenUI program is incomplete');
  if (!Number.isInteger(meta.statementCount) || meta.statementCount < 1 || meta.statementCount > STATEMENT_MAX) {
    throw new Error('OpenUI program statement count must be 1 to 64');
  }
  if (!parsed.root || parsed.root.type !== 'element' || parsed.root.typeName !== 'Stack') {
    throw new Error('OpenUI program root must be a Stack');
  }
}

export function parseOpenUI(source) {
  assertSource(source);
  const parsed = parser.parse(source);
  assertParsed(parsed);
  return parsed;
}

export function parseOpenUIStream(chunks) {
  if (!Array.isArray(chunks)) throw new Error('OpenUI stream must be a list of chunks');
  const streaming = createStreamingParser(schema, 'Stack');
  let joined = '';
  let last = null;
  for (const chunk of chunks) {
    if (typeof chunk !== 'string') throw new Error('OpenUI stream chunk must be a string');
    joined += chunk;
    last = streaming.push(chunk);
  }
  assertSource(joined);
  if (!last) throw new Error('OpenUI stream produced no program');
  assertParsed(last);
  return parseOpenUI(joined);
}

export function mergedSource(original, patch) {
  if (typeof original !== 'string' || typeof patch !== 'string') throw new Error('OpenUI merge expects two programs');
  const source = mergeStatements(original, patch);
  parseOpenUI(source);
  return source;
}

export function mergeOpenUI(original, patch) {
  return parseOpenUI(mergedSource(original, patch));
}

function toolMethod(toolAST) {
  if (typeof toolAST === 'string') return toolAST;
  if (toolAST && toolAST.k === 'Str' && typeof toolAST.v === 'string') return toolAST.v;
  return null;
}

function emptyArgs(argsAST) {
  if (argsAST == null) return true;
  if (typeof argsAST !== 'object' || Array.isArray(argsAST)) return false;
  if (argsAST.k === 'Obj' && Array.isArray(argsAST.entries)) return argsAST.entries.length === 0;
  if (typeof argsAST.k === 'string') return false;
  return Object.keys(argsAST).length === 0;
}

export function queryPlan(parsed) {
  const statements = parsed && Array.isArray(parsed.queryStatements) ? parsed.queryStatements : [];
  const plan = [];
  for (const statement of statements) {
    if (!statement || statement.refType === 'mutation') continue;
    const method = toolMethod(statement.toolAST);
    if (!method || !READ_QUERY_SET.has(method)) continue;
    if (!emptyArgs(statement.argsAST) || statement.defaultsAST != null || statement.refreshAST != null) continue;
    const id = typeof statement.statementId === 'string' ? statement.statementId : statement.id;
    if (typeof id !== 'string' || !id) continue;
    plan.push({id, method});
  }
  return plan;
}

function isElement(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && value.type === 'element' && typeof value.typeName === 'string';
}

function isRuntimeRef(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && value.k === 'RuntimeRef';
}

function isPlainData(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isPlainData);
  return false;
}

function copyPlain(value) {
  return Array.isArray(value) ? value.map(copyPlain) : value;
}

const SUMMARY_METHODS = new Set([
  'getblockchaininfo',
  'getnetworkinfo',
  'getmempoolinfo',
  'getnettotals',
  'getmininginfo',
]);
const SUMMARY_KEYS = [
  'chain',
  'blocks',
  'headers',
  'verificationprogress',
  'connections',
  'networkactive',
  'size',
  'bytes',
  'totalbytesrecv',
  'totalbytessent',
];
const BYTE_KEYS = new Set(['bytes', 'totalbytesrecv', 'totalbytessent']);
const SUMMARY_CAP = 6;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isSummaryScalar(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return true;
  return typeof value === 'number' && Number.isFinite(value);
}

function decimalInteger(value) {
  if (Object.is(value, -0)) return '0';
  if (Number.isSafeInteger(value)) return String(value);
  const text = value.toLocaleString('en-US', {useGrouping: false, maximumFractionDigits: 0});
  return text === '-0' ? '0' : text;
}

function formatByte(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return value;
  if (Number.isInteger(value)) return decimalInteger(value);
  const text = String(value);
  if (!/[eE]/.test(text)) return text;
  return value.toLocaleString('en-US', {useGrouping: false, maximumFractionDigits: 20});
}

const CANONICAL_DECIMAL = /^(0|[1-9]\d*)(\.\d+)?$/;

function unitInterval(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1) return value;
  if (typeof value === 'string' && value.length <= 32 && CANONICAL_DECIMAL.test(value)) {
    const n = Number(value);
    if (Number.isFinite(n) && n >= 0 && n <= 1) return n;
  }
  return null;
}

function formatSummary(key, value) {
  if (key === 'verificationprogress') {
    const fraction = unitInterval(value);
    if (fraction !== null) return `${(fraction * 100).toFixed(2)}%`;
  }
  if (BYTE_KEYS.has(key)) return formatByte(value);
  return value;
}

export function summarizeObservation(method, value) {
  if (!SUMMARY_METHODS.has(method) || !isPlainObject(value)) return {metrics: [], rest: true};
  const own = new Set(Object.keys(value));
  const metrics = [];
  const shown = new Set();
  for (const key of SUMMARY_KEYS) {
    if (metrics.length >= SUMMARY_CAP) break;
    if (!own.has(key)) continue;
    const raw = value[key];
    if (!isSummaryScalar(raw)) continue;
    metrics.push({label: key, value: formatSummary(key, raw)});
    shown.add(key);
  }
  return {metrics, rest: [...own].some(key => !shown.has(key))};
}

function observation(method, value) {
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch {
    return refused('Observation could not be shown');
  }
  if (typeof encoded === 'string' && encoded.length > OBSERVATION_JSON_MAX) {
    return {type: 'Observation', method, value: encoded.slice(0, OBSERVATION_JSON_MAX)};
  }
  return {type: 'Observation', method, value};
}

function realizeRef(node, planById, answers) {
  const id = typeof node.n === 'string' ? node.n : '';
  if (node.refType === 'mutation') return refused(`${id}: Atlas does not run a generated mutation`);
  if (node.refType !== 'query') return refused('Query was not run');
  const planned = planById.get(id);
  if (!planned) return refused('Query was not run');
  if (!(answers instanceof Map) || !answers.has(id)) return refused('No observation was supplied');
  const answer = answers.get(id);
  if (!answer || answer.ok !== true) {
    if (answer && answer.ok === false && typeof answer.message === 'string') return refused(answer.message);
    return refused('No observation was supplied');
  }
  return observation(planned.method, answer.value);
}

function realizeElement(node, planById, answers) {
  const name = node.typeName;
  if (!KNOWN.has(name)) return refused(`Unknown component ${name}`);
  const props = node.props && typeof node.props === 'object' && !Array.isArray(node.props) ? node.props : {};
  for (const [key, value] of Object.entries(props)) {
    if (name === 'Stack' && key === 'children') continue;
    if (!isPlainData(value)) return refused(`${name} prop ${key} is not a plain value`);
  }
  if (name === 'Stack') {
    if (!Array.isArray(props.children)) return refused('Stack children are not a list');
    return {type: 'Stack', children: props.children.map(child => realizeNode(child, planById, answers))};
  }
  if (name === 'Text') {
    if (typeof props.text !== 'string') return refused('Text prop text is not a plain value');
    return {type: 'Text', text: props.text};
  }
  if (name === 'Note') {
    if (typeof props.text !== 'string') return refused('Note prop text is not a plain value');
    if (props.tone !== undefined && props.tone !== 'info' && props.tone !== 'warning') return refused('Note prop tone is not a plain value');
    return props.tone === undefined ? {type: 'Note', text: props.text} : {type: 'Note', text: props.text, tone: props.tone};
  }
  if (name === 'Metric') {
    if (typeof props.label !== 'string' || typeof props.value !== 'string') return refused('Metric prop is not a plain value');
    if (props.detail !== undefined && typeof props.detail !== 'string') return refused('Metric prop detail is not a plain value');
    return props.detail === undefined
      ? {type: 'Metric', label: props.label, value: props.value}
      : {type: 'Metric', label: props.label, value: props.value, detail: props.detail};
  }
  if (name === 'Table') {
    if (!isPlainData(props.columns) || !isPlainData(props.rows)) return refused('Table prop is not a plain value');
    return {type: 'Table', columns: copyPlain(props.columns), rows: copyPlain(props.rows)};
  }
  if (typeof props.label !== 'string' || typeof props.action !== 'string' || typeof props.target !== 'string') {
    return refused('Button prop is not a plain value');
  }
  if (props.action === 'navigate') {
    if (!VIEW_SET.has(props.target)) return refused('Button navigate target is not a view');
    return {type: 'Button', label: props.label, action: 'navigate', target: props.target};
  }
  if (props.action === 'focus') {
    if (!FOCUS_TARGET.test(props.target)) return refused('Button focus target is not allowed');
    return {type: 'Button', label: props.label, action: 'focus', target: props.target};
  }
  return refused('Button action is not allowed');
}

function realizeNode(node, planById, answers) {
  if (isRuntimeRef(node)) return realizeRef(node, planById, answers);
  if (isElement(node)) return realizeElement(node, planById, answers);
  return refused('Expression was not rendered');
}

export function realizeOpenUI(parsed, answers) {
  const planById = new Map(queryPlan(parsed).map(item => [item.id, item]));
  return realizeNode(parsed && parsed.root, planById, answers);
}

function isButtonNode(node) {
  return !!node && typeof node === 'object' && !Array.isArray(node) && node.type === 'Button';
}

export function groupRuns(nodes) {
  if (!Array.isArray(nodes)) throw new Error('OpenUI nodes must be a list');
  const groups = [];
  for (let index = 0; index < nodes.length;) {
    if (isButtonNode(nodes[index])) {
      let end = index + 1;
      while (end < nodes.length && isButtonNode(nodes[end])) end++;
      if (end - index >= 2) {
        groups.push({type: 'buttons', items: nodes.slice(index, end)});
        index = end;
        continue;
      }
    }
    groups.push({type: 'one', item: nodes[index]});
    index++;
  }
  return groups;
}

function hasControl(text) {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) return true;
  }
  return false;
}

export function validateOpenUIDocument(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('OpenUI document must be an object');
  if (doc.schema !== OPENUI_SCHEMA) throw new Error('OpenUI document schema is not btx.atlas.openui/1');
  if (typeof doc.title !== 'string' || doc.title.length < 1 || doc.title.length > TITLE_MAX || hasControl(doc.title)) {
    throw new Error('OpenUI title must be 1 to 80 characters without controls');
  }
  parseOpenUI(doc.program);
  return {schema: OPENUI_SCHEMA, title: doc.title, program: doc.program};
}

export function rememberOpenUI(list, doc) {
  const validated = validateOpenUIDocument(doc);
  const prior = [];
  if (Array.isArray(list)) {
    for (const item of list) {
      try {
        prior.push(validateOpenUIDocument(item));
      } catch {
        // Saved lists may contain junk. Only validated documents stay.
      }
    }
  }
  const rest = prior.filter(item => item.title !== validated.title || item.program !== validated.program);
  return [validated, ...rest].slice(0, REMEMBER_MAX);
}

function fenceLine(line) {
  return line.endsWith('\r') ? line.slice(0, -1) : line;
}

export function extractOpenUIFence(text) {
  if (typeof text !== 'string') return null;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!OPEN_FENCE.test(fenceLine(lines[i]))) continue;
    for (let j = i + 1; j < lines.length; j++) {
      if (!CLOSE_FENCE.test(fenceLine(lines[j]))) continue;
      const inside = lines.slice(i + 1, j).map(fenceLine).join('\n');
      if (inside.length > PROGRAM_MAX) return null;
      return inside;
    }
    return null;
  }
  return null;
}
