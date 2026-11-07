import test from 'node:test';
import assert from 'node:assert/strict';
import {CATALOG_LANGS, t, fontFamily} from '../web/core/i18n.js';
import en from '../web/locales/en.json' with { type: 'json' };
import fr from '../web/locales/fr.json' with { type: 'json' };

const LABELS = [
  'Network', 'Atlas', 'Models', 'Swarms', 'Work', 'Research', 'Economy', 'Compute', 'Mining', 'Wallet', 'Activity', 'Tools', 'Settings',
  'Mask values', 'Display unit', 'Display addresses', 'Coin control', 'Subtract fee by default', 'Peer stripes', 'Show tray icon', 'Minimize on close', 'Language', 'Money font', 'QR font',
];

test('t falls back to the english catalog, then to the key', () => {
  for (const key of LABELS) {
    assert.equal(en[key], key);
    assert.equal(t(key, 'en'), key);
  }
  assert.equal(t('not-a-catalog-key', 'en'), 'not-a-catalog-key');
  assert.equal(t('not-a-catalog-key', 'fr'), 'not-a-catalog-key');
  assert.equal(t('Atlas', 'fr'), 'Atlas');
  assert.equal(t('Wallet', 'fr'), fr.Wallet);
  assert.notEqual(fr.Wallet, 'Wallet');
});

test('unknown language uses english', () => {
  assert.ok(CATALOG_LANGS.includes('en'));
  assert.ok(CATALOG_LANGS.includes('fr'));
  assert.equal(CATALOG_LANGS.includes('zz'), false);
  assert.equal(t('Wallet', 'zz'), 'Wallet');
  assert.equal(t('Settings', 'en-US'), 'Settings');
  assert.equal(t('Mining', undefined), 'Mining');
  assert.equal(t('Economy', 'fr'), 'Economy');
});

test('fontFamily rejects url(http://x) and keeps only generic families', () => {
  assert.equal(fontFamily('url(http://x)'), '');
  assert.equal(fontFamily('URL(HTTP://x)'), '');
  assert.equal(fontFamily('sans-serif)'), '');
  assert.equal(fontFamily('a@font'), '');
  assert.equal(fontFamily('http://example'), '');
  assert.equal(fontFamily(''), '');
  assert.equal(fontFamily('Comic Sans'), '');
  for (const family of ['system-ui', 'ui-sans-serif', 'ui-serif', 'ui-monospace', 'sans-serif', 'serif', 'monospace']) {
    assert.equal(fontFamily(family), family);
  }
});
