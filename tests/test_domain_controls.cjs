const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'frontend/index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes = new Map();
const node = key => {
  if (!nodes.has(key)) nodes.set(key, {innerHTML:'', value:'', checked:false, dataset:{}, classList:{toggle(){}}, append(){}, focus(){}});
  return nodes.get(key);
};
const requests = [];
let clicked = false, revoked = false;
const context = vm.createContext({
  document: {body:{classList:{toggle(){}},append(){}}, querySelector:node, querySelectorAll:()=>[],
    createElement:()=>({click(){clicked=true},remove(){}})},
  localStorage:{getItem:()=>null}, console,
  fetch:async(url,options)=>{requests.push({url,options}); return {ok:true,status:200,json:async()=>[],blob:async()=>Buffer.from('bytes')}} ,
  URL:{createObjectURL:()=> 'blob:test',revokeObjectURL(){revoked=true}},
  setTimeout:fn=>{fn();return 1},clearTimeout(){},setInterval:()=>1,clearInterval(){},
});
vm.runInContext(source+'\nglobalThis.test={domainPage,showDomainEditor,state,downloadFile};',context);
(async()=>{
 const t=context.test;
 t.state.token='test-only-token';
 t.state.tab='domains';
 t.state.mailDomains=[{domain:'example.test',users:[],receive_mode:'catch_all',enabled:true,receive_enabled:false,send_enabled:true,receive_subdomains:true,max_subdomain_depth:3,routing_status:'pending',receive_ready:false,send_ready:false}];
 await t.domainPage();
 assert.doesNotMatch(node('#page').innerHTML,/id="domain-form"/);
 t.showDomainEditor();
 const addPage=node('#modal-root').innerHTML;
 assert.match(addPage,/id="domain-subdomains"[^>]*checked/);
 assert.match(addPage,/id="domain-depth"[^>]*value="6"/);
 assert.match(addPage,/id="domain-registration-random"[^>]*checked/);
 node('#cancel-domain').onclick();
 t.showDomainEditor('example.test');
 const page=node('#modal-root').innerHTML;
 assert.match(page,/id="domain-receive-mode"/);
 assert.match(page,/value="catch_all" selected/);
 assert.match(page,/id="domain-depth"[^>]*value="3"/);
 assert.match(page,/id="domain-receive-enabled" type="checkbox" >/);
 assert.match(node('#domain-table-body').innerHTML,/路由 pending/);
 assert.match(node('#domain-table-body').innerHTML,/收件 待验证/);
 node('#domain-name').value='example.test';
 node('#domain-users').value='';
 node('#domain-selector').value='default';
 node('#domain-mx').value='mail.example.test';
 node('#domain-spf').value='v=spf1 -all';
 node('#domain-dmarc').value='v=DMARC1; p=none';
 node('#domain-enabled').checked=true;
 node('#domain-receive-mode').value='catch_all';
 node('#domain-receive-enabled').checked=false;
 node('#domain-send-enabled').checked=true;
 node('#domain-subdomains').checked=true;
 node('#domain-depth').value='3';
 await node('#domain-form').onsubmit({preventDefault(){}});
 const sent=requests.find(r=>r.options?.method==='PATCH');
 const payload=JSON.parse(sent.options.body);
 assert.equal(payload.receive_mode,'catch_all');
 assert.equal(payload.receive_enabled,false);
 assert.equal(payload.receive_subdomains,true);
 assert.equal(payload.max_subdomain_depth,3);
 await t.downloadFile('/messages/1/raw?download=true','message-1.eml');
 const download=requests.find(r=>r.url.endsWith('/raw?download=true'));
 assert.equal(download.options.headers['X-API-Key'],'test-only-token');
 assert.equal(clicked,true);assert.equal(revoked,true);
 assert.match(html,/data-attachment-part/);
 assert.match(html,/id="download-raw"/);
 console.log('PASS: domain policy controls, pending/readiness display, PATCH fields and authenticated binary downloads');
})().catch(error=>{console.error(error);process.exitCode=1});
