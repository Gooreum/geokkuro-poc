// DOM state regression, not a layout/browser test.
// DOM_ROOT=/path/to/node_modules node poc/web/verify-ui.cjs
const {createRequire}=require('node:module');
const {parseHTML}=createRequire(process.env.DOM_ROOT+'/')('linkedom');
const {readFileSync,writeFileSync}=require('node:fs');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const assert=require('node:assert/strict');
const path=require('node:path');
const root=__dirname;
const checks=[],snapshots=[],errors=[];
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,what){for(let i=0;i<300;i++){if(fn())return;await delay(10);}throw new Error('Timeout '+what+' '+errors.join(';'));}
function harness(entry='index.html',initialHash='#scene-1',store=new Map()){
 const {window:dom,document}=parseHTML(readFileSync(path.join(root,entry),'utf8'));
 const listeners=new Map(),timers=new Map();let timerId=0,hash=initialHash;
 const location={protocol:'file:',get href(){return 'file://'+path.join(root,entry)+hash;},get hash(){return hash;},set hash(v){hash=v.startsWith('#')?v:'#'+v;for(const f of listeners.get('hashchange')||[])queueMicrotask(f);}};
 const sandbox={document,location,history:{replaceState(a,b,c){hash=c;}},navigator:{onLine:true},crypto:webcrypto,TextEncoder,TextDecoder,URL,Blob,btoa,atob,console:{...console,error:(...a)=>errors.push(a.join(' '))},localStorage:{getItem:k=>store.get(k)||null,setItem:(k,v)=>store.set(k,v)},setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId;},clearTimeout:id=>timers.delete(id),setInterval:()=>0,addEventListener:(k,f)=>listeners.set(k,[...(listeners.get(k)||[]),f])};
 sandbox.window=sandbox;
 const dialog=document.getElementById('sheet');dialog.showModal=function(){this.open=true;};dialog.close=function(){this.open=false;};
 dom.HTMLElement.prototype.focus=function(){};
 const context=vm.createContext(sandbox);
 for(const f of ['data.js','protocol.browser.js','vendor/qrcode.js','app.js'])vm.runInContext(readFileSync(path.join(root,f),'utf8'),context,{filename:f});
 const q=selector=>document.querySelector(selector);
 function click(selector){const el=q(selector);assert.ok(el,'button '+selector);assert.equal(el.hasAttribute('disabled'),false,'Enabled '+selector);el.dispatchEvent(new dom.Event('click',{bubbles:true}));}
 async function act(action){click(`[data-action="${action}"]`);await delay(35);}
 function input(id,value){const el=document.getElementById(id);el.value=value;el.dispatchEvent(new dom.Event('input',{bubbles:true}));}
 function submit(id){document.getElementById(id).dispatchEvent(new dom.Event('submit',{bubbles:true,cancelable:true}));}
 async function ready(n){await until(()=>sandbox.__demo?.state().scene===n&&q('#phone[data-ready="true"]'),'scene '+n);await delay(20);}
 async function nav(n){location.hash='#scene-'+n;await ready(n);assert.equal(q('#toast').hidden,true);}
 async function result(code){await until(()=>q(`[data-result="${code}"]`),'result '+code);assert.equal(q('#tabbar').hidden,true);}
 function pass(label){checks.push(label);snapshots.push({label,html:document.documentElement.outerHTML});console.log('PASS '+label);}
 return {q,click,act,input,submit,ready,nav,result,pass,document,dialog,sandbox,store,timers,listeners};
}
(async()=>{
 const h=harness(),{q,act,click,input,submit,ready,nav,result,pass,sandbox,store,timers,dialog}=h;
 await ready(1);assert.match(q('h1').textContent,/문을 열기 전에/);pass('실제 앱 첫 화면과 단일 상대 확인 CTA');
 await act('onboard');await act('prepare');await act('allow-camera');assert.equal(sandbox.__demo.state().camera,'allowed');pass('온보딩·목록 저장·권한 허용');
 await nav(2);const goodToken=sandbox.__demo.token();await act('scan');await result('OK');assert.equal(q('#toast').hidden,true);assert.equal(sandbox.__demo.state().reportCount,0);pass('정상 ECDSA 확인·초록 화면·자동 신고 없음');
 const external=harness('check.html','#'+goodToken);await external.result('OK');external.pass('별도 휴대폰 check.html에서 실제 토큰 검증');
 await nav(3);const forgedCheck=harness('check.html','#'+sandbox.__demo.token());await forgedCheck.result('TAMPERED');forgedCheck.pass('실폰 경로 check.html 위조 QR 빨강');assert.match(q('#employee-desktop').textContent,/메신저 사진/);assert.match(q('#employee-desktop').textContent,/이○호/);assert.notEqual(goodToken,sandbox.__demo.token());await act('scan');await result('TAMPERED');assert.equal(sandbox.__demo.state().reportCount,0);pass('위조 화면·다른 서명 QR·결과만으로 신고되지 않음');
 await act('report');await act('send-report');assert.equal(sandbox.__demo.state().reportCount,0);assert.match(q('#report-error').textContent,/동의/);q('#report-consent').checked=true;await act('send-report');assert.equal(sandbox.__demo.state().reportCount,1);assert.ok(q('[data-action="report"]').disabled);assert.equal(q('#toast').hidden,false);assert.equal([...timers.values()].some(t=>t.ms===3000),true);for(const [id,t] of timers){if(t.ms===3000){t.fn();timers.delete(id);}}assert.equal(q('#toast').hidden,true);pass('신고 동의·중복 방지·3초 토스트 만료');
 await nav(4);const staleCheck=harness('check.html','#'+sandbox.__demo.token());await staleCheck.result('STALE');staleCheck.pass('실폰 경로 check.html 캡처 QR 만료');assert.match(q('#employee-desktop').textContent,/1분 전/);assert.equal(q('#employee-desktop [data-ttl-label]'),null);await act('scan');await result('STALE');pass('캡처 사진·카운트다운 없음·만료 검증');
 await nav(5);assert.match(q('#employee-desktop').textContent,/최○진/);assert.match(q('#employee-desktop').textContent,/E2019-0231/);await act('scan');await result('REVOKED');pass('다른 퇴직자·폐지목록 실제 검증');
 await nav(6);assert.match(q('.spoken-code').textContent,/\d{3} \d{3}/);const recordsBeforeFill=sandbox.__demo.state().recordCount;assert.equal(q('[data-action="fill-code"]').getAttribute('type'),'button');await act('fill-code');assert.equal(sandbox.__demo.state().recordCount,recordsBeforeFill);assert.ok(q('#call-form'));const first=q('#call-code').value;assert.match(first,/^\d{6}$/);submit('call-form');await result('OK');assert.equal(q('#toast').hidden,true);pass('모바일에서도 발급된 6자리 표시·전화 정상 확인');
 await nav(7);assert.match(q('#employee-desktop').textContent,/걸려 온 전화/);await act('fill-code');submit('call-form');await result('NO_MATCH');assert.match(q('.result-details').textContent,/남은 기회 4회/);assert.equal(sandbox.__demo.state().reportCount,1);await act('report');q('#report-consent').checked=true;await act('send-report');assert.equal(sandbox.__demo.state().reportCount,2);assert.equal(q('#toast').hidden,false);pass('사칭 전화 첫 실패·남은 4회·신고 두 건');
 for(let i=2;i<=5;i++){await act('retry-code');input('call-code','999999');submit('call-form');await result(i===5?'LOCKED':'NO_MATCH');assert.equal(sandbox.__demo.state().callTries,i);}
 assert.match(q('.result-details').textContent,/잠금 해제 \d{2}:\d{2}/);assert.equal(sandbox.__demo.state().reportCount,2);assert.ok(sandbox.__demo.state().lockUntil>Date.now());pass('실제 5회 조회 후 잠금·해제 시각·자동 신고 없음');
 const reloaded=harness('index.html','#scene-7',store);await reloaded.ready(7);assert.ok(reloaded.q('#call-code').disabled);reloaded.pass('새로고침에도 입력 잠금 유지');
 const expiredState=JSON.parse(store.get('geokkuro-service-v2'));expiredState.lockUntil=Date.now()-1;store.set('geokkuro-service-v2',JSON.stringify(expiredState));for(const fn of h.listeners.get('storage')||[])fn({key:'geokkuro-service-v2'});assert.equal(sandbox.__demo.state().callTries,0);assert.equal(q('#call-code').disabled,false);pass('잠금 시간 종료 후 입력 화면 복구');
 await nav(8);assert.equal(q('#toast').hidden,true);assert.match(q('#app-content').textContent,/카메라를쓸 수 없어요/);assert.equal(q('.scanner'),null);assert.equal(q('#employee-desktop').textContent,'');await act('permission-call');assert.equal(q('#call-form button[type="submit"]').disabled,false);assert.match(q('#app-content').textContent,/카메라 접근 거부/);assert.equal(sandbox.__demo.state().exceptionMode,'camera');await act('exception-offline');assert.equal(sandbox.__demo.state().camera,'allowed');await act('call-view');assert.ok(q('#call-form button[type="submit"]').disabled);assert.match(q('#app-content').textContent,/연결되면 다시/);assert.doesNotMatch(q('#app-content').textContent,/카메라 접근 거부/);await act('back-qr');await act('scan');await result('OK');assert.match(q('#app-content').textContent,/마지막 동기화/);pass('권한 거부와 오프라인 분리·허용 상태의 QR만 검증');
 await nav(9);assert.equal(sandbox.__demo.state().staffCount,412);assert.match(q('#staff-list').textContent,/최○진/);assert.match(q('#staff-list').textContent,/정○원/);assert.doesNotMatch(q('#staff-list').textContent,/박○민/);assert.equal(h.document.querySelectorAll('.staff-row').length,100);input('staff-search','E2024-0410');assert.equal(h.document.querySelectorAll('.staff-row').length,1);input('staff-search','찾을수없음');assert.match(q('#staff-list').textContent,/찾는 직원이 없어요/);input('staff-search','');pass('경찰서 직원 412명 유효·구청 제외·100행 검색·빈 상태');
 await act('notifications');assert.equal(h.document.querySelectorAll('[data-action="ack-report"]').length,2);await act('ack-report');assert.match(q('#app-content').textContent,/접수됨/);pass('시민이 보낸 두 신고만 관리자에 반영·접수');
 await act('issue-form');const newId=q('#staff-id').value;input('staff-name','정○원');q('#staff-role').value='수사관';submit('issue-form');await until(()=>!dialog.open,'issued');assert.equal(sandbox.__demo.state().staffCount,413);click('[data-action="admin-tab"][data-tab="staff"]');await delay(30);click(`[data-action="staff-qr"][data-id="${newId}"]`);await until(()=>dialog.open,'new QR');await act('verify-staff');await result('OK');pass('새 직원 발급·실제 QR·시민 검증 연결');
 await nav(9);click(`[data-action="revoke"][data-id="${newId}"]`);await delay(20);assert.equal(dialog.open,true);assert.equal(sandbox.__demo.state().staffCount,413);assert.equal(h.document.querySelectorAll('#sheet button.secondary[data-action="close"]').length,1);click('#sheet button.secondary[data-action="close"]');assert.equal(dialog.open,false);assert.equal(sandbox.__demo.state().staffCount,413);click(`[data-action="revoke"][data-id="${newId}"]`);await delay(20);await act('confirm-revoke');assert.equal(sandbox.__demo.state().staffCount,412);pass('자체 폐지 확인 바텀시트·취소 전 변동 없음·확정 반영');
 await act('history');input('record-search','기관없음');assert.match(q('#record-list').textContent,/찾는 기록이 없어요/);await act('delete-records');assert.equal(sandbox.__demo.state().recordCount,0);click('[data-action="undo"]');await delay(20);assert.ok(sandbox.__demo.state().recordCount>0);pass('기록 검색·빈 상태·삭제 되돌리기');
 for(const [action,code] of [['unknown-qr','UNTRUSTED_ISSUER'],['device-qr','DEVICE_MISMATCH'],['wrong-qr','BAD_FORMAT']]){await nav(3);await act('qr-options');await act(action);await act('scan');await result(code);pass('추가 QR 예외 '+code);}
 await nav(8);await act('exception-offline');await act('call-view');input('call-code','123456');await act('connect');assert.equal(q('#call-code').value,'123456');pass('재연결 시 입력 내용 유지');
 await nav(3);for(const fn of h.listeners.get('offline')||[])fn();await act('scan');await result('TAMPERED');await act('report');q('#report-consent').checked=true;await act('send-report');let saved=JSON.parse(store.get('geokkuro-service-v2'));assert.equal(saved.reports.filter(r=>r.pending).length,1);assert.match(q('[data-action="report"]').textContent,/전송 대기/);await act('help');await act('connect');assert.equal(JSON.parse(store.get('geokkuro-service-v2')).reports.filter(r=>r.pending).length,1);await act('flush-reports');assert.equal(JSON.parse(store.get('geokkuro-service-v2')).reports.filter(r=>r.pending).length,0);pass('오프라인 신고 저장·연결 후 직접 다시 보내기');
 await nav(1);await act('help');await act('permission');await act('deny-camera');await ready(6);assert.ok(q('#call-code'));pass('카메라 거부 후 전화 확인으로 자연스러운 전환');
 // The guide shortcut uses the identical lookup path and increments actual attempts.
 const short=harness('index.html','#scene-7');await short.ready(7);await short.act('fill-code');short.submit('call-form');await short.result('NO_MATCH');await short.act('lock-preview');await short.result('LOCKED');assert.equal(short.sandbox.__demo.state().callTries,5);assert.equal(short.sandbox.__demo.state().recordCount,5);short.pass('상단 잠금 단축도 실제 다섯 조회를 기록');
 assert.deepEqual(errors,[]);pass('전체 DOM 상호작용에서 런타임 오류 없음');
 writeFileSync(path.join(root,'../../_codex/demo-dom-round3.json'),JSON.stringify({checks,errors,note:'LinkeDOM state regression only; no rendering, camera, speech, device sharing or browser navigation verification.'},null,2));
 writeFileSync('/private/tmp/demo-round3-snapshots.json',JSON.stringify(snapshots));
 console.log(checks.length+' DOM checks passed.');
})().catch(e=>{console.error(e);process.exitCode=1;});
