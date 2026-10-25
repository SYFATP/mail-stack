const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(source);

function fixture() {
  const nodes = new Map(), requests = [], classes = new Map();
  const domains = Array.from({length: 57}, (_, i) => ({
    domain: `domain-${String(i + 1).padStart(2, '0')}.example.test`,
    dns_provider: i % 3 === 0 ? 'digitalplat' : i % 3 === 1 ? 'cloudflare' : 'manual',
    mx: 'mx.example.test', users: [`user-${i + 1}`], enabled: true,
    receive_mode: 'catch_all', receive_enabled: true, send_enabled: false,
  }));
  let failNext = false, pending = null, delayMatch = () => true;
  const failures = new Map(), confirmations = [], toasts = [];
  const document = {body: {classList: {toggle(name, value) { classes.set(name, value); }}}, activeElement: null};
  const node = key => {
    if (!nodes.has(key)) nodes.set(key, {
      innerHTML: '', textContent: '', value: '', checked: false, disabled: false, dataset: {},
      isConnected: true, style: {}, classList: {toggle() {}}, append() {}, remove() {},
      focus() { document.activeElement = this; }, getClientRects() { return [{}]; },
    });
    return nodes.get(key);
  };
  document.querySelector = selector => selector === '#domain-dialog-bg' && !node('#modal-root').innerHTML ? null : node(selector);
  document.querySelectorAll = (selector) => {
    const match = selector.match(/^\[data-([\w-]+)\]$/);
    if (!match) return [];
    const attribute = match[1], key = attribute.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const markup = node('#domain-table-body').innerHTML + node('#domain-page-buttons').innerHTML;
    return [...markup.matchAll(new RegExp(`<(?:button|input)[^>]*data-${attribute}="([^"]*)"[^>]*>`, 'g'))].map(m => {
      const button = node(`${selector}:${m[1]}`);
      button.dataset[key] = m[1];
      const enabled = m[0].match(/data-enabled="([^"]+)"/);
      if (enabled) button.dataset.enabled = enabled[1];
      button.disabled = /\sdisabled(?:[\s>])/.test(m[0]);
      if (m[0].startsWith('<input')) button.checked = /\schecked(?:[\s>])/.test(m[0]);
      return button;
    });
  };
  document.createElement = () => ({style: {}, remove() {}});
  const context = vm.createContext({
    document, localStorage: {getItem: () => null, removeItem() {}}, console,
    setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
    fetch: async (url, options = {}) => {
      requests.push({url, options});
      if (pending && delayMatch(url, options)) await pending;
      const fail = [...failures.entries()].find(([part]) => url.includes(part));
      if (fail) { failures.delete(fail[0]); return {ok:false,status:400,json:async()=>({detail:fail[1]})}; }
      if (failNext) { failNext = false; return {ok: false, status: 400, json: async () => ({detail: 'fixture save failed'})}; }
      let data = {};
      const pathname = url.split('?')[0];
      if (pathname.endsWith('/mail-domains') && !options.method) data = domains.map(d=>({...d}));
      else if (url.endsWith('/dns/cloudflare/test')) data = {ok: true};
      else if (url.endsWith('/dns/cloudflare')) data = {configured: true, auth_mode: 'api_token', api_email: 'admin@example.test'};
      else if (options.method === 'POST' && url.split('?')[0].endsWith('/mail-domains')) domains.push(JSON.parse(options.body));
      else if (url.includes('/toggle?')) {
        const name=decodeURIComponent(pathname.split('/mail-domains/')[1].split('/')[0]);
        const domain=domains.find(d=>d.domain===name);domain.enabled=url.endsWith('enabled=true');data={...domain};
      } else if (url.endsWith('/dns/provision')) data={ok:true};
      else if (options.method === 'DELETE') domains.splice(domains.findIndex(d => url.endsWith('/' + encodeURIComponent(d.domain))), 1);
      return {ok: true, status: 200, json: async () => data};
    },
  });
  vm.runInContext(source + '\nglobalThis.t={readDomainList,warmDomainList,api,get domainListRequest(){return domainListRequest},state,domainPage,renderDomainResults,domainListData,showDomainEditor,showDnsAuth,closeModal,runDomainOperations,refreshManagedDomains,logout};', context);
  context.t.state.token = 'fixture-session'; context.t.state.tab = 'domains';
  context.confirmations=confirmations;context.toasts=toasts;context.confirmResult=true;
  vm.runInContext('appConfirm=async(message)=>{confirmations.push(message);return await confirmResult};toast=(text,bad=false)=>toasts.push({text,bad});',context);
  const setForm = () => {
    for (const [id, value] of Object.entries({
      'domain-name': 'new.example.test', 'domain-users': '', 'domain-selector': 'default',
      'domain-mx': 'mx.example.test', 'domain-spf': 'v=spf1 -all', 'domain-dmarc': 'v=DMARC1; p=none',
      'domain-receive-mode': 'catch_all', 'domain-depth': '3', 'domain-dns-provider': 'manual',
    })) node('#' + id).value = value;
    node('#domain-enabled').checked = true; node('#domain-receive-enabled').checked = true;
  };
  return {t: context.t, node, document, requests, domains, classes, setForm, confirmations, toasts,
    fail() {failNext = true;}, failRoute(part,message='fixture operation failed') {failures.set(part,message);}, confirm(value) {context.confirmResult=value;}, delay(promise,match=(_url,options)=>['POST','PATCH','PUT','DELETE'].includes(options.method)) {pending=promise;delayMatch=match;}};
}

(async () => {
  const shared=fixture();let releaseList;
  shared.delay(new Promise(resolve=>releaseList=resolve),url=>url.includes('/mail-domains?'));
  const reads=[shared.t.readDomainList(),shared.t.readDomainList()];
  assert.equal(shared.requests.length,1,'Simultaneous domain reads share one request');
  releaseList();await Promise.all(reads);
  shared.t.warmDomainList();await shared.t.readDomainList();
  assert.equal(shared.requests.length,1,'A recent prefetched list is reused');
  await shared.t.readDomainList(true);
  assert.equal(shared.requests.length,2,'Explicit refresh bypasses cached data');
  await shared.t.api('/mail-domains/test.example.test',{method:'PATCH',body:'{}'});
  await shared.t.readDomainList();
  assert.equal(shared.requests.length,4,'A domain mutation invalidates the prefetched list');
  shared.t.state.token='another-session';await shared.t.readDomainList();
  assert.equal(shared.requests.length,5,'A different session does not reuse data');
  shared.t.domainListRequest.loadedAt=Date.now()-6000;await shared.t.readDomainList();
  assert.equal(shared.requests.length,6,'Expired snapshots are read again');
  const failedList=fixture();failedList.failRoute('/mail-domains?summary=true');
  await assert.rejects(failedList.t.readDomainList(),/fixture operation failed/);
  await failedList.t.readDomainList();assert.equal(failedList.requests.length,2,'Failed reads can be retried');
  const claimed=fixture();claimed.domains[0].claim_id='claim-pending';
  claimed.domains[0].receive_ready=false;claimed.domains[0].send_ready=false;
  claimed.domains[1].claim_id='claim-ready';claimed.domains[1].receive_ready=true;claimed.domains[1].send_ready=true;
  await claimed.t.domainPage();
  assert.equal(claimed.t.state.mailDomains.some(d=>d.domain===claimed.domains[0].domain),false);
  assert.equal(claimed.t.state.mailDomains.some(d=>d.domain===claimed.domains[1].domain),true);
  const slowAuth=fixture();let releaseAuth;
  slowAuth.delay(new Promise(resolve=>releaseAuth=resolve),url=>url.endsWith('/dns/cloudflare'));
  const firstOpen=slowAuth.t.domainPage();
  await new Promise(setImmediate);
  assert.match(slowAuth.node('#page').innerHTML,/id="domain-table-body"/,'Domain rows must not wait for optional auth metadata');
  assert.match(slowAuth.node('#domain-table-body').innerHTML,/domain-01.example.test/);
  assert.match(slowAuth.node('#page').innerHTML,/正在读取…/);
  assert.equal(slowAuth.requests.length,2,'Domain and auth reads start together');
  releaseAuth();await firstOpen;await new Promise(setImmediate);
  assert.match(slowAuth.node('#domain-auth-summary').innerHTML,/已配置/);
  const failedAuth=fixture();failedAuth.failRoute('/dns/cloudflare','fixture auth read failed');
  await failedAuth.t.domainPage();await new Promise(setImmediate);
  assert.match(failedAuth.node('#domain-table-body').innerHTML,/domain-01.example.test/);
  assert.equal(failedAuth.t.state.cloudflare.error,'fixture auth read failed');
  const staleAuth=fixture();let releaseOldAuth;
  staleAuth.delay(new Promise(resolve=>releaseOldAuth=resolve),url=>url.endsWith('/dns/cloudflare'));
  await staleAuth.t.domainPage();await staleAuth.t.logout(false);
  staleAuth.t.state.token='new-session';
  releaseOldAuth();await new Promise(setImmediate);
  assert.equal(staleAuth.t.state.cloudflare,null,'Late auth data cannot populate a new session');
  const f = fixture(), {t, node, requests, domains, classes} = f;
  await t.domainPage();
  assert.equal(requests[0].url, '/api/v1/mail-domains?summary=true');
  assert.doesNotMatch(node('#page').innerHTML, /id="(?:domain-form|cf-form)"/);
  assert.equal((node('#domain-table-body').innerHTML.match(/<tr(?: [^>]*)?>/g) || []).length, 20);
  assert.match(node('#domain-pagination-summary').textContent, /匹配 57 个.*第 1 \/ 3 页/);
  assert.equal(node('#domain-prev-page').disabled, true);
  const beforeSearch = requests.length, originalPage = node('#page').innerHTML;
  node('#domain-next-page').onclick();
  assert.equal(t.state.domainPage, 2);
  assert.match(node('#domain-table-body').innerHTML, /domain-21.example.test/);
  node('#domain-jump-page').value = '999'; node('#domain-jump-btn').onclick();
  assert.equal(t.state.domainPage, 3); assert.equal(node('#domain-next-page').disabled, true);
  assert.equal((node('#domain-table-body').innerHTML.match(/<tr(?: [^>]*)?>/g) || []).length, 17);
  node('#domain-jump-page').value = '-4'; node('#domain-jump-page').onkeydown({key: 'Enter'});
  assert.equal(t.state.domainPage, 1);
  node('#domain-jump-page').value = '1.8'; node('#domain-jump-btn').onclick();
  assert.equal(t.state.domainPage, 1);
  node('#domain-search').oninput({target: {value: '  DOMAIN-57  '}});
  assert.equal(t.domainListData().total, 1); assert.equal(t.state.domainPage, 1);
  assert.match(node('#domain-table-body').innerHTML, /domain-57.example.test/);
  assert.equal(node('#page').innerHTML, originalPage, 'Typing must not replace the search input or lose focus');
  node('#domain-search').oninput({target: {value: 'DigitalPlat'}});
  assert.equal(t.domainListData().total, 19);
  node('#domain-search').oninput({target: {value: 'user-57'}});
  assert.equal(t.domainListData().total, 1);
  node('#domain-search').oninput({target: {value: 'mx.example.test'}});
  assert.equal(t.domainListData().total, 57);
  node('#domain-search').oninput({target: {value: 'no-such-domain'}});
  assert.match(node('#domain-table-body').innerHTML, /没有匹配的域名/);
  assert.match(node('#domain-pagination-summary').textContent, /显示 0–0/);
  node('#clear-domain-search').onclick();
  node('#domain-page-size').onchange({target: {value: '10'}});
  assert.equal(t.state.domainPageSize, 10); assert.equal(t.domainListData().totalPages, 6);
  node('#domain-page-size').onchange({target: {value: '0'}});
  assert.equal(t.state.domainPageSize, 10);
  assert.equal(requests.length, beforeSearch, 'Search/page navigation must not refetch data');

  node('#add-domain').focus(); node('#add-domain').onclick();
  assert.match(node('#modal-root').innerHTML, /role="dialog" aria-modal="true"/);
  assert.match(node('#modal-root').innerHTML, /<h3[^>]*>添加域名/);
  assert.equal(classes.get('modal-open'), true);
  node('#cancel-domain').onclick();
  assert.equal(node('#modal-root').innerHTML, ''); assert.equal(classes.get('modal-open'), false);
  node('#add-domain').onclick();
  node('#domain-dialog-bg').onkeydown({key: 'Escape', preventDefault() {}});
  assert.equal(node('#modal-root').innerHTML, '');
  t.showDomainEditor(domains[0].domain);
  assert.match(node('#modal-root').innerHTML, /<h3[^>]*>编辑域名/);
  assert.match(node('#modal-root').innerHTML, /id="domain-name"[^>]*readonly/);
  f.setForm(); f.fail(); await node('#domain-form').onsubmit({preventDefault() {}});
  assert.equal(node('#domain-msg').textContent, 'fixture save failed');
  assert.equal(node('#save-domain').disabled, false); assert.ok(node('#modal-root').innerHTML);
  assert.equal(requests.at(-1).options.method, 'PATCH');
  t.closeModal(); node('#add-domain').onclick(); f.setForm();
  let release; f.delay(new Promise(resolve => { release = resolve; }));
  const save = node('#domain-form').onsubmit({preventDefault() {}});
  await node('#domain-form').onsubmit({preventDefault() {}});
  assert.equal(requests.filter(r => r.options.method === 'POST' && r.url.split('?')[0].endsWith('/mail-domains')).length, 1);
  release(); await save; f.delay(null);
  assert.equal(node('#modal-root').innerHTML, ''); assert.equal(domains.length, 58);

  node('#open-dns-auth').onclick();
  assert.match(node('#modal-root').innerHTML, /id="cf-token" type="password"/);
  assert.doesNotMatch(node('#modal-root').innerHTML, /fixture-secret/);
  node('#cf-token').value = 'fixture-secret'; node('#cf-key').value = ''; node('#cf-email').value = 'admin@example.test';
  await node('#cf-form').onsubmit({preventDefault() {}});
  assert.equal(node('#cf-token').value, ''); assert.equal(node('#cf-key').value, '');
  assert.match(node('#cf-msg').textContent, /鉴权已保存/);
  assert.match(node('#domain-auth-summary').innerHTML, /已配置/);
  await node('#test-cf').onclick();
  assert.equal(node('#cf-msg').textContent, '鉴权成功');
  assert.equal(requests.at(-1).url, '/api/v1/dns/cloudflare/test');
  assert.equal(requests.at(-1).options.headers['X-API-Key'], 'fixture-session');
  t.closeModal();

  t.state.domainQuery = ''; t.state.domainPageSize = 10; t.state.domainPage = 6;
  domains.splice(50); t.state.mailDomains.splice(50); t.renderDomainResults();
  assert.equal(t.state.domainPage, 5, 'Deleting the last page must clamp pagination');
  t.state.domainQuery = '<img src=x onerror=alert(1)>';
  await t.domainPage();
  assert.doesNotMatch(node('#page').innerHTML, /value="<img/);
  t.state.domainQuery = ''; t.state.mailDomains = []; t.renderDomainResults();
  assert.match(node('#domain-table-body').innerHTML, /还没有域名/);
  assert.equal(node('#domain-prev-page').disabled, true); assert.equal(node('#domain-next-page').disabled, true);
  // Selection spans pages but search starts a new selection; operations preserve the page shell.
  const bulk=fixture(),b=bulk.t,bn=bulk.node,bd=bulk.domains;
  await b.domainPage();
  assert.match(bn('#page').innerHTML,/<th scope="col" aria-label="选择"><\/th><th scope="col">操作<\/th><th scope="col">域名<\/th>/);
  const firstCells=[...bn('#domain-table-body').innerHTML.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/g)].slice(0,3).map(m=>m[1]);
  assert.match(firstCells[0],/data-domain-select=/);assert.match(firstCells[1],/data-edit-domain=/);assert.match(firstCells[2],/<strong>domain-01/);
  bn('#domain-select-all').checked=true;bn('#domain-select-all').onchange();assert.equal(b.state.domainSelection.size,20);
  bn('#domain-next-page').onclick();
  const box=bulk.document.querySelectorAll('[data-domain-select]')[0];box.checked=true;box.onchange();
  assert.equal(b.state.domainSelection.size,21);assert.equal(bn('#domain-select-all').indeterminate,true);
  bn('#domain-prev-page').onclick();assert.equal(bn('#domain-select-all').checked,true);
  bn('#domain-search').oninput({target:{value:'domain-01'}});assert.equal(b.state.domainSelection.size,0);
  bn('#clear-domain-search').onclick();
  b.state.domainSelection.add(bd[0].domain);b.state.domainSelection.add(bd[1].domain);b.renderDomainResults();
  const shell=bn('#page').innerHTML;
  let releaseBulk;bulk.delay(new Promise(resolve=>releaseBulk=resolve));
  const disabling=bn('#domain-bulk-disable').onclick();
  assert.equal(b.state.domainBusy.size,2);assert.equal(bn('#domain-bulk-delete').disabled,true);
  assert.match(bn('#domain-table-body').innerHTML,/data-edit-domain="domain-01.example.test"[^>]*disabled/);
  assert.match(bn('#domain-table-body').innerHTML,/data-domain-select="domain-02.example.test"[^>]*disabled/);
  await bn('#domain-bulk-disable').onclick();
  await bn('[data-toggle-domain]:domain-01.example.test').onclick();
  assert.equal(bulk.requests.filter(r=>r.url.includes('/toggle?')).length,1,'Repeated bulk or row clicks must not duplicate pending mutations');
  releaseBulk();await disabling;bulk.delay(null);
  assert.equal(bd[0].enabled,false);assert.equal(bd[1].enabled,false);
  assert.equal(b.state.domainBusy.size,0);assert.equal(b.state.domainBatch,null);assert.equal(b.state.domainSelection.size,0);
  assert.equal(bn('#page').innerHTML,shell,'Completing a mutation must only refresh list data');
  assert.equal(bulk.toasts.length,1);assert.match(bulk.toasts[0].text,/成功 2 个/);
  assert.match(bn('#domain-bulk-result').innerHTML,/成功 2 个/);
  // A partial batch continues after failure and leaves failed entries selected for review.
  b.state.domainSelection.add(bd[0].domain);b.state.domainSelection.add(bd[1].domain);b.renderDomainResults();
  bulk.failRoute('/domain-01.example.test/toggle','<script>fixture error</script>');
  await bn('#domain-bulk-enable').onclick();
  assert.equal(bd[0].enabled,false);assert.equal(bd[1].enabled,true);assert.equal(b.state.domainSelection.size,1);
  assert.match(bn('#domain-bulk-result').innerHTML,/成功 1 个，失败 1 个/);
  assert.match(bn('#domain-bulk-result').innerHTML,/&lt;script&gt;/);assert.doesNotMatch(bn('#domain-bulk-result').innerHTML,/<script>/);
  assert.equal(bulk.toasts.length,2);assert.equal(bulk.toasts.at(-1).bad,true);
  // Synchronization is scoped to Cloudflare; DigitalPlat and manual DNS stay untouched.
  b.state.domainSelection.add(bd[1].domain);b.state.domainSelection.add(bd[2].domain);b.renderDomainResults();
  const syncReads=bulk.requests.filter(r=>r.url.endsWith('/dns/provision')).length;
  await bn('#domain-bulk-provision').onclick();
  const syncCalls=bulk.requests.filter(r=>r.url.endsWith('/dns/provision')).slice(syncReads);
  assert.equal(syncCalls.length,1);assert.ok(syncCalls[0].url.includes('domain-02.example.test'));
  assert.match(bn('#domain-bulk-result').innerHTML,/跳过 2 个/);
  assert.equal(b.state.domainSelection.size,2);
  // Cancellation writes nothing; confirmed deletion uses the immutable selected snapshot.
  bulk.confirm(false);const deletes=()=>bulk.requests.filter(r=>r.options.method==='DELETE');
  await bn('#domain-bulk-delete').onclick();assert.equal(deletes().length,0);assert.equal(b.state.domainBusy.size,0);
  assert.equal(bulk.confirmations.length,1);assert.match(bulk.confirmations[0],/domain-01.example.test/);
  let approve;bulk.confirm(new Promise(resolve=>approve=resolve));
  const deleting=bn('#domain-bulk-delete').onclick();assert.equal(b.state.domainBusy.size,2);assert.equal(deletes().length,0);
  b.state.domainSelection.clear();b.state.domainSelection.add(bd[3].domain);
  approve(true);await deleting;
  assert.equal(deletes().length,2);assert.ok(deletes().every(r=>/domain-(01|03)\.example.test/.test(r.url)));
  assert.equal(bd.length,55);assert.equal(b.state.domainSelection.size,1);assert.equal(bn('#page').innerHTML,shell);
  assert.equal(bulk.toasts.length,4,'Each completed batch should produce only one summary');
  // A row mutation also locks the row and refreshes data without rebuilding the page.
  bulk.confirm(true);let releaseRow;bulk.delay(new Promise(resolve=>releaseRow=resolve));
  const rowName=bd[0].domain,rowToggle=bn('[data-toggle-domain]:'+rowName);
  const toggling=rowToggle.onclick();assert.equal(b.state.domainBusy.has(rowName),true);
  assert.match(bn('#domain-table-body').innerHTML,new RegExp('data-edit-domain="'+rowName+'"[^>]*disabled'));
  releaseRow();await toggling;bulk.delay(null);assert.equal(b.state.domainBusy.size,0);assert.equal(bn('#page').innerHTML,shell);
  // Data returned after a session change must not update the next session or submit more rows.
  const stale=fixture();await stale.t.domainPage();
  stale.t.state.domainSelection.add(stale.domains[0].domain);stale.t.state.domainSelection.add(stale.domains[1].domain);
  let releaseStale;stale.delay(new Promise(resolve=>releaseStale=resolve));
  const oldBatch=stale.t.runDomainOperations('disable',[...stale.t.state.domainSelection],true);
  stale.t.logout(false);stale.t.state.token='next-session';stale.t.state.tab='domains';
  const replacement={domain:'next-session.test',enabled:true};stale.t.state.mailDomains=[replacement];
  const nextOperation={kind:'new'};stale.t.state.domainBusy.set(stale.domains[0].domain,nextOperation);
  releaseStale();await oldBatch;stale.delay(null);
  assert.equal(stale.requests.filter(r=>r.url.includes('/toggle?')).length,1);
  assert.equal(stale.t.state.mailDomains[0],replacement);assert.equal(stale.toasts.length,0);
  assert.equal(stale.t.state.domainBusy.get(stale.domains[0].domain),nextOperation);
  // An operation result survives refresh failure, with explicit feedback and no automatic write retry.
  const interrupted=fixture();await interrupted.t.domainPage();
  interrupted.t.state.domainSelection.add(interrupted.domains[0].domain);
  interrupted.failRoute('/mail-domains?summary=true','fixture refresh failed');
  await interrupted.t.runDomainOperations('disable',[...interrupted.t.state.domainSelection],true);
  assert.match(interrupted.node('#domain-bulk-result').innerHTML,/列表刷新失败/);
  assert.equal(interrupted.t.state.mailDomains[0].enabled,false);assert.equal(interrupted.t.state.domainBusy.size,0);
  assert.equal(interrupted.requests.filter(r=>r.options.method==='POST').length,1);
  console.log('PASS: domain selection across pages, action-column order, bulk enable/disable/Cloudflare sync/delete, row locks, duplicate guards, partial failures, confirmed snapshots, in-place refresh and session fencing; existing list/editor/auth regressions');
})().catch(error => {console.error(error); process.exitCode = 1;});
