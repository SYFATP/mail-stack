const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function fixture(fetch) {
  const nodes = new Map();
  const storage = new Map();
  const requests = [];
  const node = key => {
    if (!nodes.has(key)) nodes.set(key, {
      innerHTML: '', textContent: '', value: '', dataset: {},
      classList: { toggle() {} }, append() {}, remove() {},
    });
    return nodes.get(key);
  };
  const context = vm.createContext({
    console,
    document: {
      body: { classList: { toggle() {} } },
      querySelector: node, querySelectorAll: () => [],
      createElement: () => ({ className: '', textContent: '', remove() {} }),
    },
    localStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return fetch(url, options);
    },
    setTimeout: () => 1, clearTimeout() {},
    setInterval: () => 1, clearInterval() {},
  });
  vm.runInContext(source + '\nglobalThis.test={state,logout};', context);
  context.test.state.token = 'fixture-session';
  storage.set('mail_session', 'fixture-session');
  return { ...context.test, storage, requests, node };
}

(async () => {
  let release;
  const pending = fixture(() => new Promise(resolve => { release = resolve; }));
  pending.state.domainSelection.add('private.example.test');
  const request = pending.logout();
  assert.equal(pending.state.token, 'fixture-session');
  assert.equal(pending.storage.get('mail_session'), 'fixture-session');
  assert.equal(pending.requests.length, 1);
  assert.equal(pending.requests[0].url, '/api/v1/auth/logout');
  assert.equal(pending.requests[0].options.method, 'POST');
  assert.equal(pending.requests[0].options.headers['X-API-Key'], 'fixture-session');
  release({ ok: true, status: 200 });
  await request;
  assert.equal(pending.state.token, '');
  assert.equal(pending.storage.has('mail_session'), false);
  assert.equal(pending.state.domainSelection.size, 0);
  assert.match(pending.node('#app').innerHTML, /id="login-form"/);

  for (const failure of [
    () => { throw Error('fixture network error'); },
    () => ({ ok: false, status: 503 }),
  ]) {
    const failed = fixture(failure);
    await failed.logout();
    assert.equal(failed.state.token, 'fixture-session');
    assert.equal(failed.storage.get('mail_session'), 'fixture-session');
  }

  const expired = fixture(() => ({ ok: false, status: 401 }));
  await expired.logout();
  assert.equal(expired.state.token, '');
  assert.equal(expired.storage.has('mail_session'), false);

  const local = fixture(() => { throw Error('unexpected network request'); });
  await local.logout(false);
  assert.equal(local.requests.length, 0);
  assert.equal(local.state.token, '');
  assert.equal(local.storage.has('mail_session'), false);
  console.log('PASS: logout awaits revocation, preserves session on failure, clears expired sessions and supports local cleanup');
})().catch(error => { console.error(error); process.exitCode = 1; });
