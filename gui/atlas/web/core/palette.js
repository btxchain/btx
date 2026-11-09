// Command palette entries. Pure: app.js turns each entry into an action.
// A payment goes through the Wallet → Send composer (recipient check, fee cap,
// separate sign and broadcast reviews). The raw send templates bypass it, and
// their titles say so.
export const COMPOSER_BYPASS = new Set(['sendtoaddress', 'sendmany', 'sendrawtransaction']);

export function paletteEntries(views, operations, query = '') {
  const q = String(query).toLowerCase();
  return [
    ...views.map(([id, , label]) => ({kind: 'view', view: id, title: `Open ${label}`})),
    {kind: 'send', title: 'Send BTX · Wallet → Send composer'},
    ...operations.map((o) => ({kind: 'operation', method: o.method, title: `${o.title} · ${o.method}${COMPOSER_BYPASS.has(o.method) ? ' · bypasses Wallet → Send checks' : ''}`})),
  ].filter((x) => x.title.toLowerCase().includes(q)).slice(0, 25);
}
