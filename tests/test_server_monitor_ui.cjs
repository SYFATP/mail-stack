const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(require('node:path').join(__dirname, '../frontend/index.html'), 'utf8');
const source = html.match(/<script id="server-monitor">([\s\S]*?)<\/script>/)[1]
  .replace('globalThis.mailServerMonitor={start,stop};', 'globalThis.mailServerMonitor={start,stop,refresh,open,save,level,validThresholds,getState:()=>({snapshot,error,refreshing,saving,dirty})};');
const defaults = {cpu:{warning:80,critical:95},memory:{warning:80,critical:95},disk:{warning:90,critical:95}};
const sample = () => ({cpu:{percent:10,cores:2},memory:{percent:82,total:1024,used:840,available:184},
  disk:{percent:96,total:2048,used:1966,available:82,path:'/app-data'},
  thresholds:structuredClone(defaults),sampled_at:1792560000,sample_age_seconds:0,scope_label:'Fixture system'});
const response = (data, status=200) => ({ok:status===200,status,json:async()=>data});
const flush = async () => {for(let i=0;i<4;i++)await new Promise(setImmediate)};
function fixture(fetcher=()=>response(sample())) {
  const nodes=new Map(),timers=new Map(),events=new Map();let timerId=0,clock=100000,expired=0;
  const node = id => {
    if(!nodes.has(id)){
      const n={id,value:'',textContent:'',className:'',disabled:false,open:false,style:{},
        showModal(){this.open=true},close(){this.open=false},
        querySelectorAll(){return [...nodes.values()].filter(x=>/^monitor-(cpu|memory|disk)-/.test(x.id)||['monitor-close','monitor-reset','monitor-save'].includes(x.id))}};
      let markup='';
      Object.defineProperty(n,'innerHTML',{get:()=>markup,set(value){markup=value;for(const match of value.matchAll(/\bid="([^"]+)"/g))node(match[1])}});
      nodes.set(id,n);
    }
    return nodes.get(id);
  };
  ['monitor-root','server-monitor-sidebar'].forEach(node);
  const document={hidden:false,querySelector:selector=>nodes.get(selector.slice(1))||null,
    addEventListener:(name,fn)=>events.set(name,fn),removeEventListener:name=>events.delete(name)};
  const requests=[];
  class FakeDate extends Date {static now(){return clock}}
  const context=vm.createContext({document,console,AbortController,Date:FakeDate,
    setTimeout:(fn,delay)=>{timers.set(++timerId,{fn,delay});return timerId},clearTimeout:id=>timers.delete(id),
    fetch:async(url,options)=>{requests.push({url,options});return fetcher(url,options)}});
  vm.runInContext(source,context);
  const monitor=context.mailServerMonitor;
  return {monitor,node,nodes,timers,events,requests,document,
    start:()=>monitor.start('fixture-session',()=>{expired++;monitor.stop()}),expired:()=>expired,
    tick(ms){clock+=ms;for(const [id,timer] of [...timers])if(timer.delay<=ms){timers.delete(id);timer.fn()}}};
}
(async()=>{
  const f=fixture();f.start();await flush();
  assert.equal(f.requests.length,1);
  assert.equal(f.nodes.has('server-monitor-floating'),false,'only the sidebar lights are rendered');
  assert.equal(f.requests[0].options.headers['X-API-Key'],'fixture-session');
  assert.equal(f.requests[0].options.cache,'no-store');
  assert.match(f.node('server-monitor-sidebar').innerHTML,/monitor-normal/);
  assert.match(f.node('server-monitor-sidebar').innerHTML,/monitor-warning/);
  assert.match(f.node('server-monitor-sidebar').innerHTML,/monitor-critical/);
  f.start();assert.equal(f.requests.length,1,'re-render does not add pollers');
  f.monitor.open('disk');
  assert.equal(f.node('server-monitor-dialog').open,true);
  f.node('monitor-cpu-warning').value='65';f.node('monitor-form').oninput();
  await f.monitor.refresh();
  assert.equal(f.node('monitor-cpu-warning').value,'65','polling preserves unsaved threshold input');
  f.tick(21000);await flush();
  // Force the cached sample itself to be old, independent of the browser clock.
  const old=fixture(()=>response({...sample(),sample_age_seconds:25}));old.start();await flush();
  assert.equal((old.node('server-monitor-sidebar').innerHTML.match(/monitor-unknown/g)||[]).length,3);
  assert.match(old.node('server-monitor-sidebar').innerHTML,/数据已过期/);
  assert.equal(f.monitor.level(null,defaults.cpu),'unknown');
  assert.equal(f.monitor.level(80,defaults.cpu),'warning');
  assert.equal(f.monitor.level(95,defaults.cpu),'critical');
  assert.equal(f.monitor.level(101,defaults.cpu),'unknown');

  let fail=false;
  const broken=fixture(()=>{if(fail)throw Error('fixture offline');return response(sample())});
  broken.start();await flush();fail=true;await broken.monitor.refresh();
  assert.equal((broken.node('server-monitor-sidebar').innerHTML.match(/monitor-unknown/g)||[]).length,3);
  assert.match(broken.node('server-monitor-sidebar').innerHTML,/读取失败/);
  fail=false;await broken.monitor.refresh();assert.equal(broken.monitor.getState().error,'');
  broken.document.hidden=true;broken.events.get('visibilitychange')();
  const count=broken.requests.length;await broken.monitor.refresh();assert.equal(broken.requests.length,count);
  broken.document.hidden=false;broken.events.get('visibilitychange')();await flush();
  assert.equal(broken.requests.length,count+1);

  const timeout=fixture((url,options)=>new Promise((resolve,reject)=>{
    options.signal.addEventListener('abort',()=>reject(Error('fixture aborted')),{once:true});
  }));
  timeout.start();timeout.tick(8000);await flush();
  assert.equal(timeout.monitor.getState().error,'监控请求超时');
  assert.match(timeout.node('server-monitor-sidebar').innerHTML,/monitor-unknown/);
  timeout.monitor.stop();

  let release;
  const pending=fixture(()=>new Promise(resolve=>release=resolve));pending.start();
  await pending.monitor.refresh();assert.equal(pending.requests.length,1,'no overlapping requests');
  pending.monitor.stop();assert.equal(pending.requests[0].options.signal.aborted,true);
  release(response(sample()));await flush();
  assert.equal(pending.monitor.getState().snapshot,null,'logout discards late replies');
  assert.equal(pending.timers.size,0);assert.equal(pending.events.size,0);
  assert.equal(pending.node('monitor-root').innerHTML,'');

  let saved;
  const saving=fixture((url,options)=>{
    if(options.method==='PUT'){saved=JSON.parse(options.body);return response({ok:true,thresholds:saved})}
    return response(sample());
  });
  saving.start();await flush();saving.monitor.open('cpu');
  saving.node('monitor-cpu-warning').value='70';saving.node('monitor-form').oninput();
  await saving.monitor.save({preventDefault(){}});
  assert.equal(saved.cpu.warning,70);assert.equal(saving.node('monitor-save-message').textContent,'阈值已保存');
  saving.node('monitor-disk-warning').value='99';saving.node('monitor-form').oninput();
  const writes=saving.requests.length;
  await saving.monitor.save({preventDefault(){}});
  assert.equal(saving.requests.length,writes,'invalid thresholds do not reach server');
  assert.match(saving.node('monitor-save-message').textContent,/黄色阈值/);
  assert.equal(saving.monitor.validThresholds({...defaults,cpu:{warning:'80',critical:95}}),false);

  // A GET begun before saving must not revert the confirmed configuration.
  let resolveGet,gets=0;
  const race=fixture((url,options)=>{
    if(options.method==='PUT')return response({ok:true,thresholds:JSON.parse(options.body)});
    return ++gets===1?response(sample()):new Promise(resolve=>resolveGet=resolve);
  });
  race.start();await flush();race.monitor.open('cpu');
  const inFlight=race.monitor.refresh();
  race.node('monitor-cpu-warning').value='50';race.node('monitor-form').oninput();
  await race.monitor.save({preventDefault(){}});
  resolveGet(response(sample()));await inFlight;
  assert.equal(race.monitor.getState().snapshot.thresholds.cpu.warning,50);

  const denied=fixture(()=>response({},401));denied.start();await flush();
  assert.equal(denied.expired(),1);assert.equal(denied.node('monitor-root').innerHTML,'');
  for(const item of [f,old,broken,saving,race])item.monitor.stop();
  console.log('PASS: real status levels, freshness, polling, draft preservation, visibility, logout/401 cleanup, threshold saving and concurrent response ordering');
})().catch(error=>{console.error(error);process.exitCode=1});
