const LIMIT = 16;
function clean(value, max) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}
export function loadRequests(raw) {
  let parsed;
  try { parsed = JSON.parse(raw || '[]'); } catch { return []; }
  if (!Array.isArray(parsed)) return [];
  const out = [];
  for (const item of parsed) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const address = clean(item.address, 256);
    if (!address) continue;
    out.push({
      address,
      amount: clean(item.amount, 32),
      label: clean(item.label, 128),
      message: clean(item.message, 256),
      at: Number.isInteger(item.at) && item.at > 0 ? item.at : 0,
    });
    if (out.length === LIMIT) break;
  }
  return out;
}
export function requestSeconds(at) {
  return Number.isSafeInteger(at) && at > 0 ? Math.floor(at / 1000) : 0;
}
export function rememberRequest(raw, request) {
  const next = [{ ...request, at: request.at || Date.now() }, ...loadRequests(raw)];
  return loadRequests(JSON.stringify(next)).slice(0, LIMIT);
}
export function qrSvg(qr) {
  const width = Number(qr && qr.width), cells = qr && qr.cells;
  if (!Number.isInteger(width) || width < 1 || width > 177 || !Array.isArray(cells) || cells.length !== width * width) return null;
  if (!cells.every(cell => cell === true || cell === false)) return null;
  const quiet = 4, size = 5, span = (width + quiet * 2) * size;
  let marks = '';
  cells.forEach((dark, i) => {
    if (dark) marks += `<rect x="${(i % width + quiet) * size}" y="${(Math.floor(i / width) + quiet) * size}" width="${size}" height="${size}"/>`;
  });
  return `<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="${span}" height="${span}" viewBox="0 0 ${span} ${span}"><rect width="100%" height="100%" fill="#fff"/>${marks}</svg>\n`;
}
