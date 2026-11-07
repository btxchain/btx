const DECIMAL = /^(0|[1-9]\d*)(\.\d+)?$/;
const FEE_BIN_CAP = 32;

function histogramScalar(value, count) {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (count && value < 0)) return null;
    return String(value);
  }
  if (typeof value === 'string' && value.length <= 128 && DECIMAL.test(value)) return value;
  return null;
}

function compareFeerate(left, right) {
  if (!DECIMAL.test(left) || !DECIMAL.test(right)) {
    const delta = Number(left) - Number(right);
    if (delta < 0) return -1;
    if (delta > 0) return 1;
    return 0;
  }
  const [leftInt, leftFrac = ''] = left.split('.');
  const [rightInt, rightFrac = ''] = right.split('.');
  if (leftInt.length !== rightInt.length) return leftInt.length - rightInt.length;
  if (leftInt !== rightInt) return leftInt < rightInt ? -1 : 1;
  const width = Math.max(leftFrac.length, rightFrac.length);
  const leftPad = leftFrac.padEnd(width, '0');
  const rightPad = rightFrac.padEnd(width, '0');
  if (leftPad === rightPad) return 0;
  return leftPad < rightPad ? -1 : 1;
}

function capHighest(rows) {
  if (rows.length <= FEE_BIN_CAP) return rows;
  const keep = new Set(rows
    .map((row, index) => ({index, feerate: row.feerate}))
    .sort((a, b) => compareFeerate(b.feerate, a.feerate) || a.index - b.index)
    .slice(0, FEE_BIN_CAP)
    .map((item) => item.index));
  return rows.filter((_, index) => keep.has(index));
}

export function feeBins(info) {
  const raw = info && info.fee_histogram;
  const rows = [];
  if (Array.isArray(raw)) {
    for (const pair of raw) {
      if (!Array.isArray(pair) || pair.length < 2) continue;
      const [feerate, count] = pair;
      if (typeof feerate !== 'number' || typeof count !== 'number' || !Number.isFinite(feerate) || !Number.isFinite(count) || count < 0) continue;
      rows.push({ feerate: String(feerate), count: String(count) });
    }
    return capHighest(rows);
  }
  if (!raw || typeof raw !== 'object') return [];
  for (const [key, bin] of Object.entries(raw)) {
    if (key === 'total_fees' || !bin || typeof bin !== 'object' || Array.isArray(bin)) continue;
    const feerate = histogramScalar(bin.from_feerate, false);
    const count = histogramScalar(bin.count, true);
    if (feerate === null || count === null) continue;
    rows.push({ feerate, count });
  }
  return capHighest(rows);
}
