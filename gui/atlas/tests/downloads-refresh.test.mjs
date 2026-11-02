import {test} from 'node:test';
import assert from 'node:assert/strict';
import {refreshDownloadsOnObservation} from '../web/views/models.js';

test('refreshDownloadsOnObservation repaints Downloads only for a sources observation', () => {
  assert.equal(refreshDownloadsOnObservation('Downloads', {sources: {}}), true);
  assert.equal(refreshDownloadsOnObservation('Downloads', {view: 'models'}), false);
  assert.equal(refreshDownloadsOnObservation('Catalogue', {sources: {}}), false);
  assert.equal(refreshDownloadsOnObservation('Shared', {sources: {}}), false);
  assert.equal(refreshDownloadsOnObservation('Downloads', {wallet: 'a'}), false);
  assert.equal(refreshDownloadsOnObservation('Downloads', null), false);
});
