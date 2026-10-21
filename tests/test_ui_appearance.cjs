const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
const bootstrap = html.match(/<script id="appearance-bootstrap">([\s\S]*?)<\/script>/)[1];
new vm.Script(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
assert.ok(html.indexOf('id="appearance-bootstrap"') < html.indexOf('<style>'), 'restore theme before first paint');

function fixture({ storage = new Map(), denied = false, dark = false } = {}) {
  const root = { dataset: {} }, events = {}, label = { hidden: false }, mediaEvents = {};
  const nodes = { 'ui-style': { value: '' }, 'color-mode': { value: '', closest: () => label } };
  const media = { matches: dark, addEventListener: (key, fn) => mediaEvents[key] = fn };
  const meta = { setAttribute: (key, value) => meta[key] = value };
  const context = vm.createContext({
    document: { documentElement: root, querySelector: () => meta, getElementById: key => nodes[key] || null },
    window: { addEventListener: (key, fn) => events[key] = fn }, matchMedia: () => media,
    localStorage: {
      getItem(key) { if (denied) throw Error('storage denied'); return storage.get(key) ?? null; },
      setItem(key, value) { if (denied) throw Error('storage denied'); storage.set(key, value); }
    }
  });
  vm.runInContext(bootstrap, context);
  return { api: context.mailAppearance, root, nodes, label, storage, meta,
    osDark(value) { media.matches = value; mediaEvents.change(); }, sync(key) { events.storage({ key }); } };
}
const initial = fixture();
assert.deepEqual({ ...initial.root.dataset }, { uiStyle: 'modern', theme: 'dark' });
assert.equal(initial.meta.content, '#181a1f');
initial.api.bind();
assert.equal(initial.nodes['ui-style'].value, 'modern');
initial.nodes['color-mode'].value = 'light'; initial.nodes['color-mode'].onchange();
assert.equal(initial.root.dataset.theme, 'light');
assert.equal(initial.meta.content, '#ffffff');
assert.equal(fixture({ storage: initial.storage }).root.dataset.theme, 'light', 'reload restores appearance');
initial.nodes['ui-style'].value = 'classic'; initial.nodes['ui-style'].onchange();
assert.equal(initial.root.dataset.uiStyle, 'classic'); assert.equal(initial.root.dataset.theme, 'dark');
assert.equal(initial.label.hidden, true); assert.equal(initial.meta.content, '#0b1220');
initial.nodes['ui-style'].value = 'modern'; initial.nodes['ui-style'].onchange();
assert.equal(initial.root.dataset.theme, 'light', 'classic preserves the preferred modern mode');
assert.equal(initial.label.hidden, false);
initial.api.setPreference('modern', 'system');
initial.osDark(true); assert.equal(initial.root.dataset.theme, 'dark');
initial.osDark(false); assert.equal(initial.root.dataset.theme, 'light');
initial.api.setPreference('modern', 'dark'); initial.osDark(false);
assert.equal(initial.root.dataset.theme, 'dark', 'explicit choice ignores OS changes');
initial.api.setPreference('classic', 'system'); initial.osDark(false);
assert.equal(initial.root.dataset.theme, 'dark', 'classic stays dark in system mode');
initial.api.setPreference('invalid', 'light'); assert.equal(initial.root.dataset.uiStyle, 'classic');
initial.api.setPreference('modern', 'invalid'); assert.equal(initial.root.dataset.uiStyle, 'classic');
initial.storage.set('mail_ui_style', 'modern'); initial.storage.set('mail_color_mode', 'light');
initial.sync('unrelated'); assert.equal(initial.root.dataset.uiStyle, 'classic');
initial.sync('mail_color_mode'); assert.equal(initial.root.dataset.uiStyle, 'modern');
assert.equal(initial.root.dataset.theme, 'light'); assert.equal(initial.nodes['color-mode'].value, 'light');
initial.storage.clear(); initial.sync(null); assert.equal(initial.root.dataset.theme, 'dark');
const invalid = fixture({ storage: new Map([['mail_ui_style', '<script>'], ['mail_color_mode', 'broken']]) });
assert.equal(invalid.root.dataset.uiStyle, 'modern'); assert.equal(invalid.root.dataset.theme, 'dark');
assert.doesNotMatch(invalid.api.markup(), /<script>/);
const blocked = fixture({ denied: true }); blocked.api.bind(); blocked.api.setPreference('modern', 'light');
assert.equal(blocked.root.dataset.theme, 'light', 'storage denial still permits switching');
console.log('PASS: pre-paint restore, default/invalid preferences, UI binding, reload persistence, classic fallback, OS mode, cross-tab sync and unavailable storage');
