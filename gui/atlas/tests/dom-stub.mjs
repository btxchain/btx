// A minimal DOM for driving view code under node:test. It covers only what
// web/components/ui.js (el, field, button, note, dialog) and the dialogs under
// test use. It is not a browser: no layout, no CSS, no focus.
class FakeNode {
  constructor() { this.parentNode = null; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
}
class FakeText extends FakeNode {
  constructor(text) { super(); this.data = String(text); }
  get textContent() { return this.data; }
}
class FakeElement extends FakeNode {
  constructor(tag) {
    super();
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.attributes = new Map();
    this.dataset = {};
    this.className = '';
    this.listeners = [];
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.selected = false;
    this.readOnly = false;
    this.open = false;
  }
  get children() { return this.childNodes.filter((n) => n instanceof FakeElement); }
  get firstChild() { return this.childNodes[0] ?? null; }
  get lastChild() { return this.childNodes.at(-1) ?? null; }
  get textContent() { return this.childNodes.map((n) => n.textContent).join(''); }
  set textContent(text) { this.replaceChildren(String(text)); }
  get isConnected() { return true; }
  get classList() {
    const names = () => this.className.split(/\s+/).filter(Boolean);
    return {
      contains: (n) => names().includes(n),
      toggle: (n, on) => { const has = names().includes(n); const want = on === undefined ? !has : !!on; this.className = want ? [...new Set([...names(), n])].join(' ') : names().filter((x) => x !== n).join(' '); return want; },
    };
  }
  setAttribute(k, v) { this.attributes.set(k, String(v)); }
  getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
  removeAttribute(k) { this.attributes.delete(k); }
  addEventListener(type, fn, options) { this.listeners.push({type, fn, once: !!(options && options.once)}); }
  dispatchEvent(event) {
    for (const entry of this.listeners.filter((x) => x.type === event.type)) {
      if (entry.once) this.listeners.splice(this.listeners.indexOf(entry), 1);
      entry.fn.call(this, event);
    }
    return true;
  }
  adopt(node) { const n = node instanceof FakeNode ? node : new FakeText(node); n.remove(); n.parentNode = this; return n; }
  append(...nodes) { for (const n of nodes) this.childNodes.push(this.adopt(n)); }
  prepend(...nodes) { this.childNodes.unshift(...nodes.map((n) => this.adopt(n))); }
  replaceChildren(...nodes) { for (const n of this.childNodes) n.parentNode = null; this.childNodes = []; this.append(...nodes); }
  removeChild(node) { const i = this.childNodes.indexOf(node); if (i >= 0) this.childNodes.splice(i, 1); node.parentNode = null; return node; }
  querySelector() { return null; }
  showModal() { this.open = true; }
  close() { if (!this.open) return; this.open = false; this.dispatchEvent({type: 'close', target: this}); }
  focus() {}
}
export function installDom() {
  globalThis.Node = FakeNode;
  globalThis.document = {
    body: new FakeElement('body'),
    createElement: (tag) => new FakeElement(tag),
    createTextNode: (text) => new FakeText(text),
    querySelector: () => null,
  };
  return globalThis.document;
}
export function findAll(root, predicate, out = []) {
  for (const n of root.childNodes || []) {
    if (!(n instanceof FakeElement)) continue;
    if (predicate(n)) out.push(n);
    findAll(n, predicate, out);
  }
  return out;
}
// The input inside the field() label captioned `caption` (a required field adds " *").
export function fieldInput(root, caption) {
  const label = findAll(root, (n) => n.tagName === 'LABEL' && n.children[0] && [caption, `${caption} *`].includes(n.children[0].textContent))[0];
  return label ? label.children[1] : undefined;
}
export function buttonNamed(root, text) {
  return findAll(root, (n) => n.tagName === 'BUTTON' && n.textContent === text)[0];
}
export function fire(node, type) {
  node.dispatchEvent({type, target: node, preventDefault() {}});
}
export const settle = () => new Promise((resolve) => setImmediate(resolve));
// An application object with a bridge that records prepare calls and never executes anything.
export function fakeApp() {
  const prepared = [];
  return {
    prepared,
    state: {state: {wallet: 'test'}},
    bridge: {
      supported: () => true,
      help: async () => '',
      prepare: async (method, json, context) => { prepared.push({method, json, context}); return {id: 'prepared-000000000000'}; },
      execute: async () => ({ok: true, result: null}),
    },
    refreshSoon() {},
  };
}
