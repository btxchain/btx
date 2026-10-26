export function feeBins(info) {
  const raw = info && info.fee_histogram;
  if (!Array.isArray(raw)) return [];
  const rows = [];
  for (const pair of raw) {
    if (!Array.isArray(pair) || pair.length < 2) continue;
    const [feerate, count] = pair;
    if (typeof feerate !== 'number' || typeof count !== 'number' || !Number.isFinite(feerate) || !Number.isFinite(count) || count < 0) continue;
    rows.push({ feerate: String(feerate), count: String(count) });
    if (rows.length === 24) break;
  }
  return rows;
}
