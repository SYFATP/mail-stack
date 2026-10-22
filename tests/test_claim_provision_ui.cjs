const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8'),source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),requests=[];let pageMarkup='',modalMarkup='';
function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',disabled:false,checked:false,dataset:{},style:{},classList:{toggle(){}},append(){},focus(){}});return nodes.get(id)}
Object.defineProperty(node('#page'),'innerHTML',{get(){return pageMarkup},set(v){pageMarkup=v}});
Object.defineProperty(node('#modal-root'),'innerHTML',{get(){return modalMarkup},set(v){modalMarkup=v}});
const document={body:{classList:{toggle(){}}},querySelector:id=>id==='#page'?node('#page'):id==='#modal-root'?node('#modal-root'):node(id),querySelectorAll:selector=>{
 const attr=selector.match(/^\[data-([\w-]+)\]$/)?.[1];if(!attr)return [];
 const key=attr.replace(/-([a-z])/g,(_,c)=>c.toUpperCase());
 const markup=pageMarkup+'\n'+[...nodes.values()].map(n=>n.innerHTML||'').join('\n');
 return [...markup.matchAll(new RegExp('data-'+attr+'="([^"]+)"','g'))].map(m=>{const b=node(selector+':'+m[1]);b.dataset[key]=m[1];return b});
},createElement:()=>({style:{},remove(){}})};
const context=vm.createContext({document,localStorage:{getItem:()=>null,removeItem(){}},console,URL,crypto:{randomUUID:()=> 'fixture-'+requests.length},setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},fetch:async(url,opt={})=>{
 requests.push({url,opt});let data={};
 if(url.endsWith('/domain-sources'))data={items:[{id:'source-1',name:'SFREG',source_type:'sfreg_mx',client_id:'mail-stack',enabled:true}]};
 else if(url.endsWith('/dns-credentials'))data={items:[{id:'cred-1',provider:'digitalplat',domain:'demo.test',label:'demo DNS'}]};
 else if(url.includes('/domain-jobs?'))data={items:[],total:0,status_counts:{},blocked_claim_sources:[]};
 else if(url.endsWith('/mail-domains'))data=[{domain:'demo.test',claim_id:'claim-1',dns_provider:'digitalplat',dns_credential_ref:'cred-1',enabled:false,receive_ready:false,send_ready:false,dns_checks:{}},{domain:'other.test',claim_id:'claim-2',dns_provider:'digitalplat',dns_credential_ref:'cred-1',enabled:false,receive_ready:false,send_ready:false,dns_checks:{}}];
 else if(url.endsWith('/domain-claims'))data={items:[{id:'claim-1',source_id:'source-1',domain:'demo.test',external_id:'5330',upstream_claim_id:'up-1',status:'credential_ready',upstream_status:'synced',dns_credential_ref:'cred-1',nameservers:['ns1.digitalplat.org','ns2.digitalplat.org']},{id:'claim-2',source_id:'source-1',domain:'other.test',external_id:'5331',upstream_claim_id:'up-2',status:'credential_ready',upstream_status:'synced',dns_credential_ref:'cred-1',nameservers:[]}]};
 else if(url.includes('/domain-jobs/'))data={id:'job-provision',status:'succeeded'};
 else data={id:'job-provision',status:'queued'};
 return {ok:true,status:200,json:async()=>data};
}});
vm.runInContext(source+'\nglobalThis.t={state,controlPage};',context);
(async()=>{const t=context.t;t.state.token='fixture-session';t.state.tab='control';await t.controlPage();assert.match(node('#control-dns-body').innerHTML,/ns1\.digitalplat\.org/);assert.doesNotMatch(pageMarkup,/同步 Nameserver/);assert.doesNotMatch(pageMarkup,/data-claim-provision/);assert.doesNotMatch(pageMarkup,/control-bulk-provision/);node('#control-dns-all').checked=true;await node('#control-dns-all').onchange();assert.deepEqual([...t.state.controlSelection].sort(),['demo.test','other.test']);assert.equal(node('#control-bulk-configure').textContent,'配置 DigitalPlat');assert.equal(requests.filter(r=>r.url.includes('/domain-claims/')&&r.url.endsWith('/provision')).length,0);console.log('PASS: unified claim/DNS table keeps Nameserver as informational data, supports page select-all, and removes Nameserver provisioning actions')})().catch(e=>{console.error(e);process.exitCode=1});
