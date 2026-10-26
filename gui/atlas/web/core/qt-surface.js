const FACTS = Object.freeze({
  name: 'BTX Atlas',
  role: 'Interface to this node on the BTX peer network',
  qualification: 'SOURCE_CANDIDATE_NOT_RELEASE_QUALIFIED',
  spends: 'A model cannot approve a spend or a peer change',
});

function whitespaceOrControl(value) {
  return /[\u0000-\u0020\u007f-\u009f]/u.test(value) || /\s/u.test(value);
}

export function txExplorerTemplate(value) {
  if (typeof value !== 'string') return '';
  if (value.length < 12 || value.length > 300) return '';
  if (whitespaceOrControl(value)) return '';
  if (value.slice(0, 8).toLowerCase() !== 'https://') return '';
  if (value.split('%s').length !== 2) return '';
  if (/javascript/i.test(value) || /data:/i.test(value)) return '';
  return value;
}

export function aboutFacts() {
  return FACTS;
}
