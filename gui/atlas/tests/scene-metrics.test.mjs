import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const cssPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../web/style.css');
const css = fs.readFileSync(cssPath, 'utf8');

function mediaBlock(source, query) {
  const start = source.indexOf(query);
  assert.notEqual(start, -1, `missing ${query}`);
  const open = source.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open, i + 1);
    }
  }
  throw new Error(`unclosed ${query}`);
}

test('the 1100px media block keeps scene metrics visible', () => {
  const block = mediaBlock(css, '@media(max-width:1100px)');
  assert.equal(block.includes('.scene-metrics{display:none}'), false);
  const rule = block.match(/[^{}]*scene-metrics[^{}]*\{[^}]*\}/);
  assert.ok(rule, '1100px block includes a scene-metrics rule');
  assert.match(rule[0], /display:\s*block/);
});
