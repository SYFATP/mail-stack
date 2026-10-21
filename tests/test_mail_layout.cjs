const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const messages = [
  { id: 1, actual_sender: 'noreply@tm.openai.com', actual_sender_source: 'hme_header', sender_parse_version: 1, subject: 'OpenAI - Access Deactivated [C-fixture-long-subject]', sender: 'OpenAI <trustandsafety_at_tm_openai_com_fixture_sender_a@icloud.com>', envelope_recipient: 'icloud1@example.test', actual_recipient: 'sample.alias+fixturetag@icloud.com', actual_recipient_source: 'hme_header', recipient_parse_version: 1, received_at: 1791071407 },
  { id: 2, actual_sender: 'noreply@email.openai.com', sender_parse_version: 1, subject: 'Get real help, not just answers', sender: 'ChatGPT <noreply_at_email_openai_com_fixture_sender_b@icloud.com>', envelope_recipient: 'icloud5@example.test', actual_recipient: 'sample.hide+signup@icloud.com', actual_recipient_source: 'hme_login_hint', recipient_parse_version: 1, received_at: 1791071231 },
  { id: 3, actual_sender: 'support@example.test', sender_parse_version: 1, subject: 'Got a question? Start here', sender: '"Support, Team" <support@example.test>', envelope_recipient: 'icloud0', actual_recipient: 'sample.alias@icloud.com', actual_recipient_source: 'hme_alias', recipient_parse_version: 1, received_at: 1791069913 },
  { id: 4, subject: 'Long sender and recipient', sender: `Sender with a very long display name ${'x'.repeat(80)} <${'long_alias_'.repeat(25)}@example.test>`, envelope_recipient: `${'recipient'.repeat(25)}@example.test`, received_at: 1791069920 },
  { id: 5, subject: '', sender: 'admin@example.test', envelope_recipient: '', received_at: null },
  { id: 6, sender_parse_version: 0, subject: 'Missing sender', sender: null, envelope_recipient: 'icloud5@example.test', recipient_parse_version: 0, received_at: 1791069920 },
  { id: 7, actual_sender: '<img src=x onerror=alert(1)>', subject: '<img src=x onerror=alert(1)>', sender: '"<img src=x onerror=alert(1)>" <evil@example.test>', envelope_recipient: 'user@example.test', actual_recipient: '<img src=x onerror=alert(1)>', received_at: 1791069920 },
];
function responseFor(url) {
  if (url.endsWith('/domains')) return [{ domain: 'example.test' }];
  if (url.includes('/messages?')) return { items: messages, total: messages.length };
  if (url.endsWith('/raw')) return { raw: 'From: OpenAI <relay@icloud.com>\nSubject: Preview\n\nPreview body' };
  if (url.endsWith('/attachments')) return [];
  if (url.endsWith('/content')) return { text: 'Preview body', content_type: 'text/plain', charset: 'utf-8' };
  return messages.find(m => url.endsWith(`/messages/${m.id}`)) || {};
}

async function test() {
  const nodes = new Map();
  const node = selector => {
    if (!nodes.has(selector)) nodes.set(selector, {
      innerHTML: '', textContent: '', value: '', dataset: {},
      classList: { toggle() {} }, append() {}, querySelectorAll() { return []; },
    });
    return nodes.get(selector);
  };
  const context = vm.createContext({
    document: {
      body: { classList: { toggle() {} } },
      querySelector: selector => selector === '#inbox-shell' && !node('#page').innerHTML.includes('id="inbox-shell"') ? null : node(selector),
      querySelectorAll: () => [],
    },
    localStorage: { getItem: () => null }, console,
    fetch: async url => ({ ok: true, status: 200, json: async () => responseFor(url) }),
    setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
  });
  vm.runInContext(source + '\nglobalThis.test={parseSender,renderSender,renderReceivedAt,renderActualRecipient,renderActualSender,state,inboxPage,showMessage};', context);
  const api = context.test;
  for (const [input, name, address] of [
    [messages[0].sender, 'OpenAI', 'trustandsafety_at_tm_openai_com_fixture_sender_a@icloud.com'],
    ['"Support, Team" <support@example.test>', 'Support, Team', 'support@example.test'],
    ['"A \\"quoted\\" name" <a@example.test>', 'A "quoted" name', 'a@example.test'],
    ['<a@example.test>', '', 'a@example.test'],
    ['admin@example.test', '', 'admin@example.test'],
    ['A <a@example.test>, B <b@example.test>', '', 'A <a@example.test>, B <b@example.test>'],
    [null, '', ''],
    ['Malformed <header>', '', 'Malformed <header>'],
  ]) {
    const parsed = api.parseSender(input);
    assert.equal(parsed.name, name);
    assert.equal(parsed.address, address);
  }
  assert.match(api.renderSender(messages[0].sender), /class="mail-sender-name">OpenAI<\/span>/);
  assert.match(api.renderSender(messages[0].sender), /title="OpenAI &lt;trustandsafety/);
  assert.doesNotMatch(api.renderSender(messages[6].sender), /<img|onerror="/);
  assert.equal(api.renderSender(null), '<span class="muted">—</span>');
  assert.equal(api.renderReceivedAt('invalid'), '<span class="muted">—</span>');
  assert.ok(api.renderReceivedAt(messages[0].received_at).includes(`datetime="${new Date(messages[0].received_at * 1000).toISOString()}"`));
  api.state.domains = [{ domain: 'example.test' }];
  await api.inboxPage();
  assert.match(node('#page').innerHTML, /class="table inbox-table"/);
  assert.match(node('#page').innerHTML, /<colgroup>/);
  assert.match(node('#page').innerHTML, /<th scope="col">实际收件人<\/th>/);
  assert.match(node('#page').innerHTML, /<th scope="col">实际发件人<\/th>/);
  const rows = node('#mail-table-body').innerHTML;
  assert.equal((rows.match(/class="data-row"/g) || []).length, messages.length);
  assert.match(rows, /class="mail-recipient" title="icloud0@example.test"/);
  assert.match(rows, /class="mail-subject" title="\(无主题\)"/);
  assert.match(rows, /class="mail-actual-recipient" title="sample.alias\+fixturetag@icloud.com"/);
  assert.doesNotMatch(rows, /HME 别名|未发现完整|mail-recipient-note/);
  assert.equal(api.renderActualRecipient(messages[2]), '<span class="mail-actual-recipient" title="sample.alias@icloud.com">sample.alias@icloud.com</span>');
  assert.match(rows, /解析中…/);
  assert.equal((rows.match(/<td[\s>]/g) || []).length, messages.length * 6);
  assert.doesNotMatch(rows, /<img/);
  assert.match(rows, /class="mail-actual-sender" title="noreply@tm.openai.com"/);
  assert.equal(api.renderActualSender({}), '<span class="muted">—</span>');
  assert.equal(api.renderActualSender({ sender_parse_version: 0 }), '<span class="muted">解析中…</span>');
  assert.doesNotMatch(api.renderActualSender(messages[6]), /<img|onerror="/);
  assert.equal(api.renderActualRecipient({}), '<span class="muted">—</span>');
  await api.showMessage(1);
  assert.match(node('#modal-root').innerHTML, /class="mail-sender-name">OpenAI/);
  assert.match(node('#modal-root').innerHTML, /trustandsafety_at_tm_openai_com_fixture_sender_a@icloud.com/);
  assert.match(node('#modal-root').innerHTML, /<label>实际收件人<\/label>/);
  assert.match(node('#modal-root').innerHTML, /sample.alias\+fixturetag@icloud.com/);
  assert.match(node('#modal-root').innerHTML, /<label>实际发件人<\/label>/);
  assert.match(node('#modal-root').innerHTML, /class="mail-actual-sender" title="noreply@tm.openai.com"/);
  await api.showMessage(3);
  assert.match(node('#modal-root').innerHTML, /sample.alias@icloud.com/);
  assert.doesNotMatch(node('#modal-root').innerHTML, /HME 别名|未发现完整|mail-recipient-note/);
  api.state.messages = [];
  api.state.total = 0;
  vm.runInContext('renderInboxResults()', context);
  assert.match(node('#mail-table-body').innerHTML, /colspan="6"/);
  console.log('PASS: sender parsing, actual recipient, six columns, pending/alias states, escaping, details, empty state');
}

if (process.argv.includes('--preview')) {
  const stub = `<script>localStorage.setItem('mail_session','layout-preview');const previewMessages=${JSON.stringify(messages).replace(/</g, '\\u003c')};const messages=previewMessages;${responseFor.toString()}window.fetch=async url=>({ok:true,status:200,json:async()=>responseFor(url)});</script>`;
  require('node:http').createServer((req, res) => {
    const currentHtml = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
    const preview = currentHtml.replace('<script>', stub + '<script>');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(preview);
  }).listen(18083, '127.0.0.1', () => console.log('Preview: http://127.0.0.1:18083 (synthetic messages only)'));
} else {
  test().catch(error => { console.error(error); process.exitCode = 1; });
}
