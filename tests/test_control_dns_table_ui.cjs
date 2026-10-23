const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8'),source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(source);
function fixture(){
 const nodes=new Map(),requests=[];
 const domains=Array.from({length:57},(_,i)=>({domain:`domain-${String(i+1).padStart(2,'0')}.test`,
  dns_provider:['digitalplat','cloudflare','manual'][i%3],enabled:i%2===0,receive_ready:false,send_ready:false,dns_checks:{}}));
 const credentials=[{id:'dp-1',provider:'digitalplat',domain:'domain-01.test',label:'单域凭据'},
  {id:'dp-4',provider:'digitalplat',domain:'domain-04.test',label:'其他域凭据'},
  {id:'cf-account',provider:'cloudflare',domain:null,label:'Cloudflare account'},
  {id:'source-key',provider:'sfreg_mx',domain:null,label:'source secret'}];
 domains[0].dns_credential_ref='dp-1';
 domains[0].dns_checks={mx:{status:'passed',checked_at:1791300000},spf:{status:'failed',checked_at:1791300000}};
 domains[1].dns_credential_ref='cf-account';
 domains[1].dns_checks=Object.fromEntries(['mx','spf','dkim','dmarc'].map(k=>[k,{status:'passed',checked_at:1791300000}]));
 domains[3].dns_credential_ref='missing';
  let markup='',delay=null,fail=false,executable=false,previewDomain='domain-01.test',nextPlan=1,globalCloudflare=false,reconciliation=null;
 const document={body:{classList:{toggle(){}}},activeElement:null};
 function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',disabled:false,checked:false,dataset:{},style:{},
  classList:{toggle(){}},isConnected:true,focus(){document.activeElement=this},append(){},getClientRects(){return [{}]}});
  return nodes.get(id);}
 Object.defineProperty(node('#modal-root'),'innerHTML',{get(){return markup},set(v){markup=v;for(const id of ['domain-dialog-bg','control-credential','control-preview-summary','control-preview-output','control-dns-records','control-dns-context','control-apply-confirm','control-apply'])nodes.delete('#'+id)}});
 document.querySelector=id=>id==='#domain-dialog-bg'&&!markup?null:node(id);
 document.querySelectorAll=selector=>{
  const attribute=selector.match(/^\[data-([\w-]+)\]$/)?.[1];if(!attribute)return [];
  const key=attribute.replace(/-([a-z])/g,(_,c)=>c.toUpperCase());
  const content=node('#page').innerHTML+node('#control-dns-body').innerHTML+node('#control-dns-pages').innerHTML;
  return [...content.matchAll(new RegExp('data-'+attribute+'="([^"]+)"','g'))].map(m=>{const b=node(selector+':'+m[1]);b.dataset[key]=m[1];return b});
 };
 document.createElement=()=>({style:{},remove(){}});
 const context=vm.createContext({document,console,localStorage:{getItem:()=>null,removeItem(){}},URL,
  crypto:{randomUUID:()=>`fixture-${requests.length}`},setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
  fetch:async(url,opt={})=>{
   requests.push({url,opt});if(delay&&delay.match(url))await delay.promise;
   if(fail){fail=false;throw Error('fixture lost ACK')}
   let data={};
   if(url.endsWith('/domain-sources'))data={items:[]};
   else if(url.endsWith('/dns-credentials'))data={items:credentials,global_cloudflare:{configured:globalCloudflare,auth_mode:globalCloudflare?'global_api_key':''}};
   else if(url.includes('/domain-jobs?'))data={items:[],total:0};
   else if(url.endsWith('/mail-domains'))data=domains;
   else if(url.endsWith('/dns-preview'))data={id:`plan-${nextPlan++}`,domain:previewDomain,executable:executable&&!reconciliation,actions:[],conflicts:reconciliation?[{name:previewDomain,code:'unresolved_dns_write',operation_id:'old-write'}]:executable?[]:[{name:previewDomain,code:'foreign_record_conflict'}]};
   else if(url.endsWith('/dns-operations/old-write/reconcile')){
    if(reconciliation==='mismatch')return {ok:false,status:409,json:async()=>({detail:'current record is missing, ambiguous or changed'})};
    reconciliation=null;data={status:'observed',dns_writes:0,ownership_adopted:false};
   }
   else if(url.endsWith('/dns-binding/global-cloudflare')){
    const name=decodeURIComponent(url.split('/mail-domains/')[1].split('/')[0]),d=domains.find(d=>d.domain===name);
    const credential={id:'global-import-fixture',provider:'cloudflare',domain:name,label:'Cloudflare · 全局凭据导入'};
    credentials.push(credential);d.dns_credential_ref=credential.id;
    data={domain:name,dns_provider:'cloudflare',dns_credential_ref:credential.id};
   }else if(url.endsWith('/dns-binding')){
    const name=decodeURIComponent(url.split('/mail-domains/')[1].split('/')[0]),d=domains.find(d=>d.domain===name);
    const c=credentials.find(c=>c.id===JSON.parse(opt.body).credential_ref);
    data={...d,dns_provider:c.provider,dns_credential_ref:c.id,dns_checks:{}};Object.assign(d,data);
   }else if(url.endsWith('/dns'))data={provider:'manual',message:'手工 DNS 不读取在线库存',records:[]};
   else if(url.endsWith('/dns-plan'))data={domain:url.split('/mail-domains/')[1].split('/')[0],records:[]};
   else data={id:'job-fixture',status:'queued'};
   return {ok:true,status:200,json:async()=>data};
  }});
 vm.runInContext(source+'\nglobalThis.t={state,controlPage,controlDnsListData,controlUnifiedListData,controlDomainReady,refreshControlLists,renderControlDnsResults,renderControlUnifiedResults,controlDnsStatus,controlDnsBindingLabel,controlJobSummary,showControlDnsDialog,closeModal,controlJob,runControlBatch,stopControlJobWatchers,watchActiveDomainJobs,controlDomainReadBusy,controlDomainActivity,controlJobWatchers};',context);
 const t=context.t;t.state.token='fixture-session';t.state.tab='control';
 return {t,node,document,requests,domains,credentials,markup:()=>markup,fail(){fail=true},preview(value,domain='domain-01.test'){executable=value;previewDomain=domain},
   reconcile(value){reconciliation=value},globalCloudflare(value){globalCloudflare=value},delay(match,promise){delay={match,promise}},clearDelay(){delay=null}};
}
(async()=>{
 const f=fixture(),{t,node,document,requests,domains}=f;await t.controlPage();
 assert.match(node('#page').innerHTML,/id="control-stat-domains">57<\/strong>/);
 assert.match(node('#page').innerHTML,/id="control-stat-credentials">3<\/strong>/);
 assert.match(node('#page').innerHTML,/id="control-stat-source-credentials">1<\/strong>/);
 const counted=t.controlJobSummary({status_counts:{queued:1,running:2,unknown:4}});
 assert.equal(counted.active,3);assert.equal(counted.unknown,4);
 const fallback=t.controlJobSummary({items:[{status:'queued'},{status:'unknown'},{status:'succeeded'}]});
 assert.equal(fallback.active,1);assert.equal(fallback.unknown,1);
 assert.match(node('#page').innerHTML,/control-dns-table/);assert.doesNotMatch(node('#page').innerHTML,/id="control-domain"|id="control-apply"/);
 assert.equal((node('#control-dns-body').innerHTML.match(/<tr>/g)||[]).length,20);
 assert.match(node('#control-dns-summary').textContent,/匹配 57 个.*第 1 \/ 3 页/);
 assert.equal(t.state.controlDns.status,'pending');
 assert.equal(node('[data-control-dns-status]:pending').ariaSelected,'true');
 assert.equal(node('#control-dns-count-pending').textContent,'57');
 assert.equal(node('#control-dns-count-ready').textContent,'0');
 const pageMarkup=node('#page').innerHTML,readCount=requests.length;
 node('#control-dns-next').onclick();assert.equal(t.state.controlDns.page,2);assert.match(node('#control-dns-body').innerHTML,/domain-21.test/);
 node('#control-dns-jump').value='999';node('#control-dns-jump-btn').onclick();assert.equal(t.state.controlDns.page,3);assert.equal(node('#control-dns-next').disabled,true);
 node('#control-dns-jump').value='-4';node('#control-dns-jump').onkeydown({key:'Enter'});assert.equal(t.state.controlDns.page,1);
 node('#control-dns-size').onchange({target:{value:'10'}});assert.equal(t.controlDnsListData().pages,6);
 node('#control-dns-search').oninput({target:{value:' DOMAIN-57 '}});assert.equal(t.controlDnsListData().total,1);
 assert.equal(node('#page').innerHTML,pageMarkup,'Search must preserve the input and focus');
 node('#control-dns-search').oninput({target:{value:'单域凭据'}});assert.equal(t.controlDnsListData().total,1);
 node('#control-dns-search').oninput({target:{value:'检查异常'}});assert.equal(t.controlDnsListData().total,1);
 node('#clear-control-dns-search').onclick();node('#control-dns-provider').onchange({target:{value:'manual'}});assert.equal(t.controlDnsListData().total,19);
 node('#control-dns-search').oninput({target:{value:'no-match'}});assert.match(node('#control-dns-body').innerHTML,/没有匹配的域名/);assert.equal(t.state.controlDns.page,1);
 node('#clear-control-dns-search').onclick();assert.equal(requests.length,readCount,'Client pagination/search must not contact providers');
 const firstBox=document.querySelectorAll('[data-control-select]').find(b=>b.dataset.controlSelect==='domain-01.test');
 firstBox.checked=true;firstBox.onchange();
 assert.equal(node('#control-dns-selection-summary').textContent,'已选 1 个');
 assert.equal(node('#control-bulk-validate').textContent,'验证 DNS');
 assert.equal(node('#control-bulk-configure').textContent,'配置 DigitalPlat');
 let releaseValidation;const delayedValidation=new Promise(resolve=>releaseValidation=resolve);
 f.delay(url=>url.endsWith('/domain-01.test/dns-validate'),delayedValidation);
 const pendingBatch=t.runControlBatch('validate');
 assert.equal(t.controlUnifiedListData().counts.processing,1);
 assert.doesNotMatch(node('#control-dns-body').innerHTML,/data-control-select="domain-01.test"/);
 node('[data-control-dns-status]:processing').onclick();
 assert.match(node('#control-dns-body').innerHTML,/data-control-dns-config="domain-01\.test"[^>]*disabled/);
 releaseValidation();await pendingBatch;f.clearDelay();t.stopControlJobWatchers();
 node('[data-control-dns-status]:pending').onclick();
 assert.equal(t.controlDnsStatus(domains[0]),'检查异常');assert.equal(t.controlDnsStatus(domains[1]),'最近检查通过');
 assert.equal(t.controlDnsStatus(domains[2]),'手工配置');assert.equal(t.controlDnsStatus(domains[3]),'未验证');assert.equal(t.controlDnsStatus(domains[4]),'未验证');
 const subdomainStatus={...domains[1],receive_enabled:true,receive_subdomains:true,max_subdomain_depth:6,dns_checks:{...domains[1].dns_checks,wildcard_mx:{status:'failed'}}};
 assert.equal(t.controlDnsStatus(subdomainStatus),'检查异常','Wildcard failures must not show an all-passed badge');
 delete subdomainStatus.dns_checks.wildcard_mx;assert.equal(t.controlDnsStatus(subdomainStatus),'待验证');
 assert.equal(t.controlDnsBindingLabel(domains[3]),'凭据缺失');assert.equal(t.controlDnsBindingLabel(domains[4]),'未绑定 DNS 凭据');
 node('[data-control-dns-bind]:domain-01.test').onclick();
 assert.match(f.markup(),/DNS 绑定与变更 · domain-01.test/);assert.match(f.markup(),/单域凭据/);
 assert.doesNotMatch(f.markup(),/其他域凭据|Cloudflare account|source secret/);
 assert.equal(node('#control-credential').value,'dp-1');
 await node('#control-preview').onclick();assert.equal(node('#control-apply').disabled,true);assert.match(node('#control-preview-summary').textContent,/存在冲突/);
 f.preview(true);await node('#control-preview').onclick();assert.equal(node('#control-apply').disabled,true);
 f.reconcile('matching');await node('#control-preview').onclick();
 assert.equal(requests.filter(r=>r.url.endsWith('/dns-operations/old-write/reconcile')).length,1);
 assert.match(node('#control-preview-summary').textContent,/无冲突/);
 assert.equal(requests.filter(r=>r.url.endsWith('/dns-apply')).length,0,'Reconciliation must not apply DNS');
 f.reconcile('mismatch');await node('#control-preview').onclick();
 assert.equal(node('#control-apply').disabled,true);assert.match(node('#control-preview-summary').textContent,/missing, ambiguous or changed/);
 f.reconcile(null);await node('#control-preview').onclick();
 node('#control-apply-confirm').checked=true;node('#control-apply-confirm').onchange();assert.equal(node('#control-apply').disabled,false);
 node('#control-credential').value='';node('#control-credential').onchange();assert.equal(node('#control-apply').disabled,true);assert.equal(node('#control-preview').disabled,true);
 node('#control-credential').value='dp-1';node('#control-credential').onchange();await node('#control-bind').onclick();
 assert.equal(Object.keys(domains[0].dns_checks).length,0);assert.match(node('#control-preview-output').textContent,/旧 DNS checks 已清除/);
 f.preview(true,'wrong-domain.test');await node('#control-preview').onclick();assert.equal(node('#control-apply').disabled,true);assert.match(node('#control-preview-summary').textContent,/不匹配/);
 f.preview(true);await node('#control-preview').onclick();node('#control-apply-confirm').checked=true;node('#control-apply-confirm').onchange();
 f.fail();await node('#control-apply').onclick();const first=requests.at(-1),plan=JSON.parse(first.opt.body).plan_id;
 assert.match(node('#control-preview-summary').textContent,/lost ACK/);assert.ok(f.markup());assert.equal(node('#control-apply').disabled,false);
 await node('#control-apply').onclick();const applications=requests.filter(r=>r.url.endsWith('/dns-apply'));
 assert.equal(applications.length,2);assert.equal(applications[1].opt.headers['Idempotency-Key'],first.opt.headers['Idempotency-Key']);assert.equal(JSON.parse(applications[1].opt.body).plan_id,plan);assert.equal(f.markup(),'');
 let release;const delayed=new Promise(resolve=>release=resolve);
 t.showControlDnsDialog('domain-01.test');f.delay(url=>url.endsWith('/dns-preview'),delayed);const old=node('#control-preview').onclick();
 t.showControlDnsDialog('domain-03.test');release();await old;f.clearDelay();
 assert.match(f.markup(),/domain-03.test/);assert.equal(node('#control-apply').disabled,true);assert.equal(node('#control-preview-summary').textContent,'');
 const beforeManual=requests.length;await node('#control-inventory').onclick();assert.equal(requests.length,beforeManual+1);assert.ok(requests.at(-1).url.endsWith('/domain-03.test/dns'));
 assert.match(node('#control-preview-summary').textContent,/手工 DNS/);assert.doesNotMatch(node('#control-dns-context').textContent,/未绑定/);
 await node('#control-plan').onclick();assert.match(node('#control-preview-output').textContent,/domain-03.test/);
 await node('#control-validate').onclick();assert.ok(requests.find(r=>r.url.endsWith('/domain-03.test/dns-validate')));assert.equal(f.markup(),'');
 // A late mutation ACK must not close a newer dialog.
 t.showControlDnsDialog('domain-01.test');let releaseBinding;f.delay(url=>url.endsWith('/dns-binding'),new Promise(resolve=>releaseBinding=resolve));
 const pendingBinding=node('#control-bind').onclick();t.showControlDnsDialog('domain-03.test');releaseBinding();await pendingBinding;f.clearDelay();assert.match(f.markup(),/domain-03.test/);
 // Filtering survives a reload; shrinking lists clamp the selected page.
 t.closeModal();t.state.controlDns.query='domain';t.state.controlDns.page=6;await t.controlPage();assert.equal(t.state.controlDns.query,'domain');assert.equal(t.state.controlDns.page,6);
 domains.splice(5);t.renderControlDnsResults();assert.equal(t.state.controlDns.page,1);
 t.state.controlDns.query='';t.state.controlDns.status='all';await t.controlJob('/mail-domains/domain-01.test/dns-validate',{}, {notify:false});await t.controlPage();
 assert.match(node('#control-dns-body').innerHTML,/data-control-dns-config="domain-01\.test" disabled/,'A running row must lock its DNS actions');
 t.stopControlJobWatchers();
 const legacy=fixture();legacy.globalCloudflare(true);
 const oldDomain=legacy.domains[4];
 oldDomain.dns_checks=Object.fromEntries(['mx','spf','dkim','dmarc'].map(k=>[k,{status:'passed',checked_at:1791300000}]));
 await legacy.t.controlPage();
 assert.equal(legacy.t.controlDnsStatus(oldDomain),'最近检查通过','DNS health is independent of credential binding');
 assert.equal(legacy.t.controlDnsBindingLabel(oldDomain),'全局 Cloudflare 凭据');
 assert.match(legacy.node('#page').innerHTML,/<th>DNS 管理凭据<\/th>/);
 assert.match(legacy.node('#page').innerHTML,/<th>DNS 检查结果<\/th>/);
 legacy.t.showControlDnsDialog(oldDomain.domain,'binding');
 assert.match(legacy.markup(),/接入全局 Cloudflare 凭据/);
 assert.equal(legacy.node('#control-preview').disabled,true);
 const previousChecks=JSON.stringify(oldDomain.dns_checks);
 await legacy.node('#control-bind-global').onclick();
 assert.equal(oldDomain.dns_credential_ref,'global-import-fixture');
 assert.equal(JSON.stringify(oldDomain.dns_checks),previousChecks);
 assert.equal(legacy.node('#control-preview').disabled,false,'Imported credentials must enable normal immutable previews');
 assert.match(legacy.node('#control-preview-summary').textContent,/已加密接入/);
 assert.equal(legacy.requests.filter(r=>r.opt.method==='POST').length,1);
 assert.ok(legacy.requests.find(r=>r.url.endsWith('/dns-binding/global-cloudflare')));
 domains[0].domain='<img src=x onerror=alert(1)>';t.state.controlDns.query='';t.renderControlDnsResults();
 assert.doesNotMatch(node('#control-dns-body').innerHTML,/<img/);assert.match(node('#control-dns-body').innerHTML,/&lt;img/);
 // Status tabs use actual enabled capabilities, including requested subdomains.
 const grouped=fixture(),g=grouped.t,gn=grouped.node,gd=grouped.domains;
 Object.assign(gd[0],{receive_enabled:true,send_enabled:true,receive_ready:true,send_ready:true});
 Object.assign(gd[1],{enabled:true,receive_enabled:true,send_enabled:false,receive_ready:true,send_ready:false});
 Object.assign(gd[2],{receive_enabled:false,send_enabled:true,receive_ready:false,send_ready:true});
 Object.assign(gd[3],{enabled:true,receive_enabled:true,send_enabled:true,receive_ready:true,send_ready:true,receive_subdomains:true,max_subdomain_depth:1,subdomain_receive_ready:false,subdomain_send_ready:true});
 Object.assign(gd[4],{enabled:false,receive_ready:true,send_ready:true});
 Object.assign(gd[5],{enabled:true,receive_enabled:false,send_enabled:false,receive_ready:true,send_ready:true});
 Object.assign(gd[6],{receive_ready:true,send_ready:true,receive_subdomains:true,max_subdomain_depth:1,subdomain_receive_ready:true,subdomain_send_ready:false});
 assert.equal(g.controlDomainReady(gd[0]),true);
 assert.equal(g.controlDomainReady(gd[1]),true,'Receive-only domains do not require sending');
 assert.equal(g.controlDomainReady(gd[2]),true,'Send-only domains do not require receiving');
 for(const d of gd.slice(3,7))assert.equal(g.controlDomainReady(d),false,'Disabled domains/capabilities and unready subdomains stay pending');
 await g.controlPage();
 assert.equal(g.controlUnifiedListData().total,54);
 assert.equal(gn('#control-dns-count-pending').textContent,'54');
 assert.equal(gn('#control-dns-count-ready').textContent,'3');
 assert.equal(gn('#control-dns-count-all').textContent,'57');
 assert.doesNotMatch(gn('#control-dns-body').innerHTML,/data-control-select="domain-01.test"/);
 const groupedMarkup=gn('#page').innerHTML,groupedReads=grouped.requests.length;
 const tab=value=>gn('[data-control-dns-status]:'+value);
 g.state.controlSelection.add('domain-04.test');g.state.controlDns.page=3;
 tab('ready').onclick();
 assert.equal(g.state.controlDns.page,1);assert.equal(g.state.controlSelection.size,0);
 assert.equal(g.controlUnifiedListData().total,3);assert.equal(tab('ready').ariaSelected,'true');
 assert.equal(tab('ready').tabIndex,0);assert.equal(tab('pending').tabIndex,-1);
 assert.match(gn('#control-dns-body').innerHTML,/domain-01.test/);
 g.state.controlSelection.add('domain-01.test');tab('all').onclick();
 assert.equal(g.state.controlSelection.size,0);
 assert.equal(g.controlUnifiedListData().total,57);
 assert.equal(g.controlUnifiedListData().items[0].domain,'domain-04.test','All domains lists unready entries first');
 gn('#control-dns-search').oninput({target:{value:'domain-01'}});
 assert.equal(g.controlUnifiedListData().total,1);
 assert.equal(gn('#control-dns-count-pending').textContent,'0');assert.equal(gn('#control-dns-count-ready').textContent,'1');
 tab('pending').onclick();assert.match(gn('#control-dns-body').innerHTML,/当前没有未就绪的域名/);
 gn('#clear-control-dns-search').onclick();assert.equal(g.state.controlDns.status,'pending','Clearing search preserves the selected status');
 gn('#control-dns-provider').onchange({target:{value:'manual'}});
 assert.equal(g.controlUnifiedListData().total,18);
 assert.equal(gn('#control-dns-count-ready').textContent,'1');assert.equal(gn('#control-dns-count-all').textContent,'19');
 let prevented=false;tab('pending').onkeydown({key:'ArrowRight',preventDefault(){prevented=true}});
 assert.equal(prevented,true);assert.equal(g.state.controlDns.status,'processing');assert.equal(grouped.document.activeElement,tab('processing'));
 assert.match(gn('#control-dns-body').innerHTML,/当前没有处理中的域名/);
 tab('processing').onkeydown({key:'ArrowRight',preventDefault(){}});
 assert.equal(g.state.controlDns.status,'ready');assert.equal(grouped.document.activeElement,tab('ready'));
 tab('ready').onkeydown({key:'End',preventDefault(){}});assert.equal(g.state.controlDns.status,'all');
 tab('all').onkeydown({key:'Home',preventDefault(){}});assert.equal(g.state.controlDns.status,'pending');
 assert.equal(gn('#page').innerHTML,groupedMarkup,'Tabs must only update list data');
 assert.equal(grouped.requests.length,groupedReads,'Tab switching must not contact providers');
 gn('#clear-control-dns-search').onclick();g.state.controlSelection.add(gd[3].domain);
 gd[3].subdomain_receive_ready=true;
 await g.refreshControlLists();
 assert.equal(g.state.controlDns.status,'pending');assert.equal(g.controlUnifiedListData().total,53);
 assert.equal(gn('#control-dns-count-ready').textContent,'4');
 assert.equal(g.state.controlSelection.size,0,'Newly ready entries leave the pending selection after refresh');
 assert.doesNotMatch(gn('#control-dns-body').innerHTML,/data-control-select="domain-04.test"/);
 tab('ready').onclick();assert.match(gn('#control-dns-body').innerHTML,/domain-04.test/);
 g.state.controlDns.page=9;await g.controlPage();assert.equal(g.state.controlDns.status,'ready');assert.equal(g.state.controlDns.page,1);
 grouped.domains.splice(0,grouped.domains.length,...gd.filter(d=>g.controlDomainReady(d)));
 tab('pending').onclick();assert.match(gn('#control-dns-body').innerHTML,/当前没有未就绪的域名/);
 assert.equal(gn('#control-dns-count-ready').textContent,'4');
 // A held writer keeps conflicting writes fenced while read controls work.
 const paused=fixture(),pt=paused.t,pn=paused.node,name=paused.domains[0].domain;
 await pt.controlPage();
 const hold={id:'incident-held',kind:'dns_apply',scope:name,status:'queued',step:'persisted',wait_reason:'incident_hold',wait_until:null};
 pt.watchActiveDomainJobs({active_domain_jobs:[hold]});
 pn('[data-control-dns-status]:processing').onclick();pt.renderControlUnifiedResults();
 assert.equal(pt.controlUnifiedListData().counts.processing,1);
 const heldRow=pn('#control-dns-body').innerHTML.split('</tr>')[0];
 assert.match(heldRow,/写入已暂停，等待恢复/);assert.doesNotMatch(heldRow,/操作中|class="control-row-busy"/);
 assert.match(heldRow,/data-control-dns-bind="domain-01.test" disabled/);
 assert.match(heldRow,/data-control-dns-config="domain-01.test" disabled/);
 assert.doesNotMatch(heldRow,/data-control-dns-records="domain-01.test" disabled/);
 assert.equal(pt.controlDomainReadBusy(name),false);
 await pt.showControlDnsDialog(name,'records');
 assert.ok(paused.requests.at(-1).url.endsWith('/dns'));
 for(const id of ['bind','preview','apply'])assert.equal(pn('#control-'+id).disabled,true);
 for(const id of ['inventory','plan','validate'])assert.equal(pn('#control-'+id).disabled,false);
 const postsBefore=paused.requests.filter(r=>r.opt.method==='POST').length;
 await pn('#control-bind').onclick();await pn('#control-preview').onclick();await pn('#control-apply').onclick();
 assert.equal(paused.requests.filter(r=>r.opt.method==='POST').length,postsBefore,'Handler guards also fence disabled write actions');
 await pn('#control-plan').onclick();assert.ok(paused.requests.at(-1).url.endsWith('/dns-plan'));
 assert.equal(pt.state.controlBusyCounts.get(name),1,'Read completion must retain the held writer lock');
 const auto={id:'automatic-check',scope:name,kind:'dns_validate',status:'running',automatic:true,read_only:true};
 pt.watchActiveDomainJobs({active_domain_jobs:[hold,auto]});pt.renderControlUnifiedResults();
 assert.match(pt.controlDomainActivity(name),/后台自动验证中.*写入已暂停/);
 assert.equal(pt.controlDomainReadBusy(name),true);
 assert.equal(pn('#control-inventory').disabled,true,'An existing dialog follows running task state');
 // An extra batch submission lock must never be mistaken for a waiting lock.
 pt.stopControlJobWatchers();pt.watchActiveDomainJobs({active_domain_jobs:[hold]});
 pt.state.controlBusyCounts.set(name,2);assert.equal(pt.controlDomainReadBusy(name),true);
 pt.stopControlJobWatchers();
 // dynv6 migration is offered for disabled domains; account credentials stay scoped.
 const dyn=fixture();dyn.credentials.push({id:'dyn-account',provider:'dynv6',domain:null,label:'dynv6 HTTP fixture'});
 await dyn.t.controlPage();dyn.t.showControlDnsDialog('domain-01.test','binding');
 assert.doesNotMatch(dyn.markup(),/dynv6 HTTP fixture/,'An enabled domain must be disabled before provider migration');
 dyn.domains[0].enabled=false;dyn.t.showControlDnsDialog('domain-01.test','binding');
 assert.match(dyn.markup(),/dynv6 HTTP fixture/);assert.match(dyn.markup(),/My Domains.*Single zone/);
 dyn.node('#control-credential').value='dyn-account';await dyn.node('#control-bind').onclick();
 assert.equal(dyn.domains[0].dns_provider,'dynv6');assert.equal(dyn.domains[0].dns_credential_ref,'dyn-account');
 assert.equal(dyn.t.controlDnsBindingLabel(dyn.domains[0]),'dynv6 HTTP fixture');
 dyn.t.closeModal();dyn.node('#control-dns-provider').onchange({target:{value:'dynv6'}});
 assert.equal(dyn.t.controlDnsListData().total,1);assert.match(dyn.node('#control-dns-body').innerHTML,/dynv6/);
 assert.match(dyn.node('#control-dns-body').innerHTML,/dynv6 目标 NS/);
 assert.match(dyn.node('#control-dns-body').innerHTML,/按需切换父区委派并等待传播/);
 assert.doesNotMatch(dyn.node('#control-dns-body').innerHTML,/无需同步/);
 // An unverified Cloudflare migration must prepare its Zone before changing the binding.
 const migrating=fixture();migrating.domains[0].enabled=false;
 await migrating.t.controlPage();migrating.t.showControlDnsDialog('domain-01.test','binding');
 migrating.node('#control-credential').value='cf-account';migrating.node('#control-credential').onchange();
 assert.equal(migrating.node('#control-bind').textContent,'接入 Cloudflare');
 await migrating.node('#control-bind').onclick();
 assert.ok(migrating.requests.find(r=>r.opt.method==='POST'&&r.url.endsWith('/domain-01.test/cloudflare-hosting')));
 assert.equal(migrating.requests.some(r=>r.url.endsWith('/dns-binding')&&r.opt.method==='POST'),false);
 assert.equal(migrating.domains[0].dns_provider,'digitalplat');
 migrating.t.stopControlJobWatchers();
 // Saved credentials and managed domains have independent totals, including
 // shared accounts, preserved registrar credentials and unused credentials.
 const inventory=fixture(),it=inventory.t,inode=inventory.node;
 inventory.credentials.splice(0,inventory.credentials.length,
  ...Array.from({length:221},(_,i)=>({id:`registrar-${i}`,provider:'digitalplat',domain:`inventory-${i}.test`})),
  {id:'cloudflare-used',provider:'cloudflare'},{id:'cloudflare-unused',provider:'cloudflare'},
  {id:'dynv6-shared',provider:'dynv6'},{id:'sfreg-source',provider:'sfreg_mx'});
 inventory.domains.splice(0,inventory.domains.length,
  ...Array.from({length:221},(_,i)=>({domain:`inventory-${i}.test`,enabled:false,
   dns_provider:i<125?'digitalplat':'dynv6',dns_credential_ref:i<125?`registrar-${i}`:'dynv6-shared'})),
  {domain:'cloudflare.test',dns_provider:'cloudflare',dns_credential_ref:'cloudflare-used',enabled:false});
 await it.controlPage();
 assert.equal(inventory.credentials.length,225);
 assert.match(inode('#page').innerHTML,/id="control-stat-domains">222<\/strong>/);
 assert.match(inode('#page').innerHTML,/id="control-stat-credentials">224<\/strong>/);
 assert.match(inode('#page').innerHTML,/id="control-stat-source-credentials">1<\/strong>/);
 const overviewMarkup=inode('#page').innerHTML;
 inode('#control-dns-provider').onchange({target:{value:'dynv6'}});
 assert.equal(it.controlUnifiedListData().total,96);
 inode('#control-dns-search').oninput({target:{value:'inventory-220.test'}});
 assert.equal(it.controlUnifiedListData().total,1);
 await it.refreshControlLists();
 assert.equal(inode('#control-stat-domains').textContent,'222','Search/provider filters must not reduce the domain overview');
 assert.equal(inode('#control-stat-credentials').textContent,'224');
 assert.equal(inode('#control-stat-source-credentials').textContent,'1');
 assert.equal(inode('#page').innerHTML,overviewMarkup,'Refreshing totals must preserve the page and active filters');
 assert.equal(it.controlUnifiedListData().total,1);
 inventory.domains.push({domain:'newly-claimed.test',dns_provider:'dynv6',dns_credential_ref:'dynv6-new',enabled:false});
 inventory.credentials.push({id:'dynv6-new',provider:'dynv6'},
  {id:'legacy-source',provider:'legacy_digitalplat_pool'},{id:'import-source',provider:'cloudflare_import'});
 await it.refreshControlLists();
 assert.equal(inode('#control-stat-domains').textContent,'223');
 assert.equal(inode('#control-stat-credentials').textContent,'225');
 assert.equal(inode('#control-stat-source-credentials').textContent,'3');
 assert.equal(it.controlUnifiedListData().total,1,'A newly claimed domain must not reset the current search');
 const auth=requests.find(r=>r.url.endsWith('/dns-apply'));assert.equal(auth.opt.headers['X-API-Key'],'fixture-session');
 console.log('PASS: independent domain/DNS/source credential overview and filtered refresh; readiness tabs/counts/capability grouping/selection isolation/keyboard/data refresh; DNS table search/provider/paging/jump/empty/reload/escaping; scoped binding, manual DNS, preview confirmation, immutable domains, stable apply retries and stale response fencing');
})().catch(e=>{console.error(e);process.exitCode=1});
