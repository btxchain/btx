import test from 'node:test';
import assert from 'node:assert/strict';
import {feedSequenceNote} from '../web/views/model-panels.js';

const NOTE = 'Local feed_sequence 3. This refresh does not fetch the network feed.';

test('feedSequenceNote accepts a finite number or a canonical integer string', () => {
  assert.equal(feedSequenceNote(3), NOTE);
  assert.equal(feedSequenceNote('3'), NOTE);
  assert.equal(feedSequenceNote({feed_sequence: 3}), NOTE);
  assert.equal(feedSequenceNote({feed_sequence: '3'}), NOTE);
  assert.equal(feedSequenceNote('00'), '');
  assert.equal(feedSequenceNote('1.5'), '');
  assert.equal(feedSequenceNote({feed_sequence: '00'}), '');
  assert.equal(feedSequenceNote({feed_sequence: '1.5'}), '');
});
