import {test} from 'node:test';
import assert from 'node:assert/strict';
import {JsonNumber, encodeJson, parseJsonExact} from '../web/core/json.js';
import {prefillFieldText, expandPrefill, prefillWireParams} from '../web/views/operations.js';

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

test('a named id object becomes the string parameter', () => {
  const args = [{name: 'id', kind: 'string'}];
  const prefill = [{id: new JsonNumber('5')}];
  const expanded = expandPrefill(args, prefill);
  const field = prefillFieldText(args[0].kind, expanded[0]);
  const wire = encodeJson(prefillWireParams(args, prefill));
  const parameter = parseJsonExact(wire)[0];
  assert.equal(expanded[0] instanceof JsonNumber, true);
  assert.equal(field, '5');
  assert.equal(wire, '["5"]');
  assert.equal(wire.includes('"text"'), false);
  assert.equal(typeof parameter, 'string');
  assert.equal(parameter, '5');
  const published = [{name: 'id', kind: 'string'}, {name: 'metadata', kind: 'json'}];
  const publishedValues = expandPrefill(published, prefill);
  assert.equal(publishedValues[1], undefined);
  assert.equal(encodeJson(prefillWireParams(published, prefill)), '["5"]');
});

test('a json request stays the object when its name is not a key', () => {
  const args = [{name: 'request', kind: 'json'}];
  const prefill = [{cursor: new JsonNumber('0')}];
  const expanded = expandPrefill(args, prefill);
  const field = prefillFieldText('json', expanded[0]);
  const wire = encodeJson(prefillWireParams(args, prefill));
  assert.equal(expanded, prefill);
  assert.equal(expanded[0] instanceof JsonNumber, false);
  assert.equal(typeof expanded[0], 'object');
  assert.equal(field, '{"cursor":0}');
  assert.equal(field.includes('"text"'), false);
  assert.equal(wire, '[{"cursor":0}]');
  assert.equal(typeof parseJsonExact(wire)[0], 'object');
});
