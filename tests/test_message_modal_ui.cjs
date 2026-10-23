const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const tick=()=>new Promise(setImmediate);
function fixture(){
  const nodes=new Map(),requests=[],copies=[],downloads=[],toasts=[],gates=new Map(),failures=new Set();
  const fresh=()=>{const classes=new Set();return {innerHTML:'',textContent:'',disabled:false,dataset:{},children:[],attributes:{},
    classList:{toggle(name,on){if(on)classes.add(name);else classes.delete(name)},contains:name=>classes.has(name)},
    append(child){this.children.push(child)},setAttribute(name,value){this.attributes[name]=value},focus(){},querySelectorAll(selector){
      if(selector!=='[data-attachment-part]')return [];
      if(this.buttonMarkup!==this.innerHTML){this.buttonMarkup=this.innerHTML;this.buttons=[...this.innerHTML.matchAll(/data-attachment-part="([^"]+)"/g)].map(match=>{const button=fresh();button.dataset.attachmentPart=match[1];return button})}
      return this.buttons||[];
    }}};
  const node=key=>{if(!nodes.has(key))nodes.set(key,fresh());return nodes.get(key)};
  let markup='',modalKeys=[];
  Object.defineProperty(node('#modal-root'),'innerHTML',{get:()=>markup,set(value){for(const key of modalKeys)nodes.delete(key);markup=value;modalKeys=[...value.matchAll(/id="([^"]+)"/g)].map(m=>'#'+m[1]);for(const key of modalKeys)nodes.set(key,fresh())}});
  const rows=[1,2].map(id=>({id,subject:'Subject '+id,sender:'sender@example.test',actual_sender:'actual@example.test',envelope_recipient:'inbox@example.test',actual_recipient:'recipient@example.test',received_at:1792740000}));
  let htmlBody=false,attachmentRows=[];
  const context=vm.createContext({console,AbortController,setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
    localStorage:{getItem:()=>null,removeItem(){}},document:{body:{classList:{toggle(){}}},createElement:()=>fresh(),
      querySelector:key=>key==='#modal-bg'&&!markup.includes('id="modal-bg"')?null:node(key),querySelectorAll:()=>[]},
    fetch:async(url,options={})=>{
      const match=url.match(/\/messages\/(\d+)(.*)$/);assert.ok(match,'unexpected URL '+url);
      const id=Number(match[1]),suffix=match[2],key=id+suffix;requests.push({id,suffix,options});
      if(gates.has(key))await gates.get(key).promise; // Intentionally ignore abort to verify stale-response guards too.
      if(failures.delete(key))return {ok:false,status:500,json:async()=>({detail:'fixture failure'})};
      const data=suffix==='/content'?{text:'Body '+id,html:htmlBody?'<p>HTML '+id+'</p>':'',content_type:htmlBody?'text/html':'text/plain',charset:'utf-8'}:
        suffix==='/attachments'?attachmentRows:suffix==='/raw'?{raw:'From: sender@example.test\n\nRaw '+id}:
        rows.find(row=>row.id===id)||{id,subject:'Subject '+id,sender:'fallback@example.test'};
      return {ok:true,status:200,json:async()=>data};
    }});
  vm.runInContext(source+'\nglobalThis.test={state,showMessage,closeModal,logout,replyDialog};',context);
  context.copies=copies;context.downloads=downloads;context.toasts=toasts;
  vm.runInContext('copyText=async text=>copies.push(text);downloadFile=async(path,filename)=>downloads.push({path,filename});toast=(text,bad)=>toasts.push({text,bad});',context);
  const t=context.test;t.state.token='fixture';t.state.messages=rows;t.state.domains=[{domain:'example.test'}];
  return {t,node,requests,copies,downloads,toasts,rows,attachment(value){attachmentRows=[value]},html(){htmlBody=true},fail(id,suffix){failures.add(id+suffix)},
    pause(id,suffix){let release;const promise=new Promise(resolve=>release=resolve);gates.set(id+suffix,{promise,release});},
    release(id,suffix){const gate=gates.get(id+suffix);gates.delete(id+suffix);gate.release()}};
}
(async()=>{
  const slow=fixture();slow.pause(1,'/content');slow.pause(1,'/attachments');
  const opening=slow.t.showMessage(1);
  assert.match(slow.node('#modal-root').innerHTML,/id="modal-bg"/,'modal opens before any response');
  assert.equal(typeof slow.node('#close-modal').onclick,'function');
  assert.deepEqual(slow.requests.map(r=>r.suffix).sort(),['/attachments','/content'],'list metadata avoids another MIME parse and raw is lazy');
  slow.release(1,'/content');await tick();
  assert.match(slow.node('#mail-rendered').innerHTML,/Body 1/,'body renders while attachments remain pending');
  slow.release(1,'/attachments');await opening;

  const lazy=fixture();await lazy.t.showMessage(1);lazy.pause(1,'/raw');
  const showingRaw=lazy.node('#show-raw').onclick();const copying=lazy.node('#copy-raw').onclick();
  assert.equal(lazy.requests.filter(r=>r.suffix==='/raw').length,1,'raw tab and copy share a request');
  lazy.release(1,'/raw');await Promise.all([showingRaw,copying]);
  assert.equal(lazy.node('#raw-content').textContent,'From: sender@example.test\n\nRaw 1');
  assert.deepEqual(lazy.copies,['From: sender@example.test\n\nRaw 1']);
  await lazy.node('#show-raw').onclick();assert.equal(lazy.requests.filter(r=>r.suffix==='/raw').length,1);
  await lazy.node('#download-raw').onclick();assert.equal(lazy.downloads[0].path,'/messages/1/raw?download=true');

  const closed=fixture();closed.pause(1,'/content');const pending=closed.t.showMessage(1);
  closed.t.closeModal();assert.equal(closed.requests[0].options.signal.aborted,true);
  closed.release(1,'/content');await pending;assert.equal(closed.node('#modal-root').innerHTML,'','late completion cannot reopen a closed modal');
  assert.equal(closed.toasts.length,0);

  const switched=fixture();switched.pause(1,'/content');const old=switched.t.showMessage(1);
  await switched.t.showMessage(2);switched.release(1,'/content');await old;
  assert.match(switched.node('#mail-rendered').innerHTML,/Body 2/,'late response must not overwrite the selected message');
  assert.doesNotMatch(switched.node('#mail-rendered').innerHTML,/Body 1/);

  const replying=fixture();replying.pause(1,'/content');const beforeReply=replying.t.showMessage(1);
  replying.t.replyDialog(1,replying.rows[0]);replying.release(1,'/content');await beforeReply;
  assert.match(replying.node('#modal-root').innerHTML,/id="reply-form"/,'late mail loads preserve reply drafts');

  const fallback=fixture();await fallback.t.showMessage(7);
  assert.equal(fallback.requests.filter(r=>r.suffix==='').length,1,'direct opens fetch missing metadata');
  assert.equal(fallback.node('#reply-message').disabled,false);

  const retry=fixture();retry.fail(1,'/content');await retry.t.showMessage(1);
  assert.match(retry.node('#mail-rendered').innerHTML,/fixture failure/);
  await retry.node('#retry-message-content').onclick();assert.match(retry.node('#mail-rendered').innerHTML,/Body 1/);
  assert.equal(retry.requests.filter(r=>r.suffix==='/attachments').length,1,'retry is confined to the failed section');

  const rawRetry=fixture();await rawRetry.t.showMessage(1);rawRetry.fail(1,'/raw');
  await rawRetry.node('#show-raw').onclick();await rawRetry.node('#show-raw').onclick();
  assert.equal(rawRetry.requests.filter(r=>r.suffix==='/raw').length,2,'a failed raw fetch remains retryable');
  assert.match(rawRetry.node('#raw-content').textContent,/Raw 1/);

  const attachment=fixture();attachment.attachment({part_id:'3',filename:'file <attachment>.txt'});await attachment.t.showMessage(1);
  assert.match(attachment.node('#mail-attachments').innerHTML,/file &lt;attachment&gt;\.txt/);
  await attachment.node('#mail-attachments').querySelectorAll('[data-attachment-part]')[0].onclick();
  assert.equal(attachment.downloads[0].path,'/messages/1/attachments/3');
  assert.equal(attachment.downloads[0].filename,'file <attachment>.txt');

  const attachmentRetry=fixture();attachmentRetry.fail(1,'/attachments');await attachmentRetry.t.showMessage(1);
  assert.match(attachmentRetry.node('#mail-rendered').innerHTML,/Body 1/);
  await attachmentRetry.node('#retry-message-attachments').onclick();
  assert.equal(attachmentRetry.requests.filter(r=>r.suffix==='/content').length,1);
  assert.equal(attachmentRetry.requests.filter(r=>r.suffix==='/attachments').length,2);

  const cancelledCopy=fixture();await cancelledCopy.t.showMessage(1);cancelledCopy.pause(1,'/raw');
  const oldCopy=cancelledCopy.node('#copy-raw').onclick();cancelledCopy.t.closeModal();
  cancelledCopy.release(1,'/raw');await oldCopy;assert.equal(cancelledCopy.copies.length,0,'closed messages must not copy a late raw response');

  const html=fixture();html.html();await html.t.showMessage(1);
  assert.equal(html.node('#mail-rendered').children[0].attributes.sandbox,'');
  assert.equal(html.node('#mail-rendered').children[0].srcdoc,'<p>HTML 1</p>');

  const loggedOut=fixture();loggedOut.pause(1,'/content');const beforeLogout=loggedOut.t.showMessage(1);
  await loggedOut.t.logout(false);loggedOut.release(1,'/content');await beforeLogout;
  assert.equal(loggedOut.node('#modal-root').innerHTML,'');assert.equal(loggedOut.t.state.token,'');
  console.log('PASS: immediate modal; independent content/attachments; lazy/deduplicated/retryable raw; metadata reuse; close/switch/reply/logout isolation; scoped retry; sandboxed HTML; EML download');
})().catch(error=>{console.error(error);process.exitCode=1});
