const DECIMAL = /^(0|[1-9]\d*)(\.\d+)?$/;

function histogramScalar(value, count) {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (count && value < 0)) return null;
    return String(value);
  }
  if (typeof value === 'string' && value.length <= 128 && DECIMAL.test(value)) return value;
  return null;
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
      if (rows.length === 24) break;
    }
    return rows;
  }
  if (!raw || typeof raw !== 'object') return [];
  for (const [key, bin] of Object.entries(raw)) {
    if (key === 'total_fees' || !bin || typeof bin !== 'object' || Array.isArray(bin)) continue;
    const feerate = histogramScalar(bin.from_feerate, false);
    const count = histogramScalar(bin.count, true);
    if (feerate === null || count === null) continue;
    rows.push({ feerate, count });
    if (rows.length === 24) break;
  }
  return rows;
}
