import {test} from 'node:test';
import assert from 'node:assert/strict';
import {JsonNumber, encodeJson} from '../web/core/json.js';
import {prefillFieldText, rawPreferred} from '../web/views/operations.js';

test('a JsonNumber inside an object prefill stays numeric text', () => {
  const value = {id: new JsonNumber('5')};
  const encoded = encodeJson(value);
  const field = prefillFieldText('string', value);
  assert.equal(encoded.includes('"text"'), false);
  assert.equal(field.includes('"text"'), false);
  assert.equal(field, encoded);
  assert.equal(field, '{"id":5}');
  assert.equal(prefillFieldText('integer', new JsonNumber('5')), '5');
});

test('exact JSON is preferred unless the first catalog argument is json or long', () => {
  assert.equal(rawPreferred([{kind: 'string'}], [{id: new JsonNumber('5')}]), true);
  assert.equal(rawPreferred([{kind: 'json'}], [{cursor: new JsonNumber('0')}]), false);
  assert.equal(rawPreferred([{kind: 'long'}], [{cursor: new JsonNumber('0')}]), false);
  assert.equal(encodeJson([{id: new JsonNumber('5')}]).includes('"text"'), false);
});
