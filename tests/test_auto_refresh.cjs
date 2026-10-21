const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(source); // Parse the whole real frontend, not a copied helper.

function load(storage) {
  const nodes = new Map();
  const intervals = new Map();
  let nextId = 1;
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {
      innerHTML: '', textContent: '', dataset: {}, value: '',
      classList: { toggle() {} }, append() {}, focus() {}, select() {},
      querySelectorAll() { return []; },
    });
    return nodes.get(id);
  };
  const document = {
    body: { classList: { toggle() {} } },
    querySelector(selector) {
      if (selector === '#inbox-shell' && !node('#page').innerHTML.includes('id="inbox-shell"')) return null;
      return node(selector);
    },
    querySelectorAll() { return []; },
    createElement() { return { style: {}, remove() {} }; },
  };
  const context = vm.createContext({
    document, localStorage: storage, console,
    fetch: async url => ({
      ok: true, status: 200,
      json: async () => url.endsWith('/domains') ? [{ domain: 'example.test' }] : { items: [], total: 0 },
    }),
    setInterval: (callback, delay) => { const id = nextId++; intervals.set(id, { callback, delay }); return id; },
    clearInterval: id => intervals.delete(id),
    setTimeout: () => 1, clearTimeout() {},
    URL, URLSearchParams, navigator: {},
  });
  vm.runInContext(source + '\nglobalThis.test={state,inboxPage,setAutoRefresh,logout};', context);
  return { test: context.test, node, intervals };
}

async function main() {
  const saved = new Map();
  const storage = {
    getItem: key => saved.get(key) ?? null,
    setItem: (key, value) => saved.set(key, String(value)),
    removeItem: key => saved.delete(key),
  };
  const first = load(storage);
  assert.equal(first.test.state.autoRefresh, false);
  await first.test.inboxPage();
  first.node('#auto-refresh').onchange({ target: { checked: true } });
  assert.equal(saved.get('mail_auto_refresh'), 'true');
  assert.equal(first.intervals.size, 1);

  // New JS runtime with the same browser storage simulates a hard refresh.
  const refreshed = load(storage);
  assert.equal(refreshed.test.state.autoRefresh, true);
  await refreshed.test.inboxPage();
  assert.match(refreshed.node('#page').innerHTML, /id="auto-refresh" type="checkbox" checked/);
  assert.equal(refreshed.intervals.size, 1);
  await refreshed.test.inboxPage();
  assert.equal(refreshed.intervals.size, 1, 'Refresh must not accumulate timers');
  refreshed.test.logout(false);
  assert.equal(refreshed.intervals.size, 0);
  assert.equal(saved.get('mail_auto_refresh'), 'true', 'Logout must retain preference');

  const loggedBackIn = load(storage);
  assert.equal(loggedBackIn.test.state.autoRefresh, true);
  await loggedBackIn.test.inboxPage();
  loggedBackIn.node('#auto-refresh').onchange({ target: { checked: false } });
  assert.equal(saved.get('mail_auto_refresh'), 'false');
  assert.equal(loggedBackIn.intervals.size, 0);
  const disabledReload = load(storage);
  await disabledReload.test.inboxPage();
  assert.equal(disabledReload.test.state.autoRefresh, false);
  assert.doesNotMatch(disabledReload.node('#page').innerHTML, /id="auto-refresh" type="checkbox" checked/);
  assert.equal(disabledReload.intervals.size, 0);

  const blockedStorage = {
    getItem() { return null; }, removeItem() {},
    setItem() { throw new Error('QuotaExceededError'); },
  };
  const blocked = load(blockedStorage);
  assert.doesNotThrow(() => blocked.test.setAutoRefresh(true));
  assert.equal(blocked.test.state.autoRefresh, true);
  assert.equal(blocked.intervals.size, 1);
  console.log('PASS: checkbox persistence, reload, logout/relogin, opt-out, single timer, storage write fallback');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
