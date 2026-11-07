import {summarizeObservation} from './openui.js';
import {modelRecordRows} from './model-status.js';

const TITLES = Object.assign(Object.create(null), {
  getblockchaininfo: 'Chain',
  getnetworkinfo: 'Money network',
  getmempoolinfo: 'Mempool',
  getnettotals: 'Traffic',
  getmininginfo: 'Mining',
  getmodelnetworkinfo: 'Model network',
  getmodelpeers: 'Model peers',
  listmodels: 'Models',
  getmodelhostprofile: 'This node',
  getsetupstatus: 'Setup',
  getmemoryinfo: 'Memory',
  getmodelfeed: 'Feed',
  getfundablemodels: 'Fundable models',
  getrecentreleases: 'Recent releases',
  searchbounties: 'Bounties',
});

const ROW_CAP = 200;
const COLUMN_CAP = 6;

function titleFor(method) {
  return Object.prototype.hasOwnProperty.call(TITLES, method) ? TITLES[method] : method;
}

function metricsOf(method, value) {
  try {
    const metrics = summarizeObservation(method, value).metrics;
    return Array.isArray(metrics) ? metrics : [];
  } catch {
    return [];
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function rowsOf(value) {
  const listed = modelRecordRows(value);
  if (Array.isArray(listed) && listed.length) return listed;
  if (!isRecord(value) || !Object.prototype.hasOwnProperty.call(value, 'models') || !Array.isArray(value.models)) return [];
  const rows = [];
  for (const item of value.models) {
    if (!isRecord(item)) continue;
    rows.push(item);
    if (rows.length === ROW_CAP) break;
  }
  return rows;
}

function isColumnValue(value) {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function columnsOf(row) {
  if (!isRecord(row)) return [];
  const columns = [];
  for (const key of Object.keys(row)) {
    if (!isColumnValue(row[key])) continue;
    columns.push(key);
    if (columns.length === COLUMN_CAP) break;
  }
  return columns;
}

export function presentObservation(method, value) {
  const rows = rowsOf(value);
  return {
    title: titleFor(method),
    metrics: metricsOf(method, value),
    rows,
    columns: rows.length ? columnsOf(rows[0]) : [],
    rest: value !== null && value !== undefined && typeof value === 'object',
  };
}
