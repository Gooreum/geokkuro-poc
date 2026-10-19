// Dependency-free regression checks. Run explicitly: node poc/web/verify.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import * as P from './protocol.mjs';

const original = await readFile(new URL('../protocol.mjs', import.meta.url), 'utf8');
const moduleSource = await readFile(new URL('./protocol.mjs', import.meta.url), 'utf8');
const browserSource = await readFile(new URL('./protocol.browser.js', import.meta.url), 'utf8');
assert.equal(moduleSource.trim(), original.trim(), 'The protocol module must preserve the original PoC implementation.');
const plainSource = moduleSource.replace(/^export /gm, '').trim();
assert.ok(browserSource.includes(plainSource), 'The browser IIFE must contain the unchanged protocol source with export removed.');
const browserCode = browserSource.replace(/^(?:\s|\/\/[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)+/, '').trim();
assert.match(browserCode, /^\(\(\)\s*=>\s*\{/u, 'The browser protocol must use an IIFE.');
assert.match(browserCode, /\}\)\(\);?$/u, 'The browser protocol IIFE must close and execute.');
assert.doesNotMatch(browserSource, /^export /m, 'Classic browser scripts cannot contain ESM exports.');
const sandbox = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob };
sandbox.window = sandbox;
runInNewContext(browserSource, sandbox, { filename: 'protocol.browser.js', timeout: 5000 });
assert.ok(sandbox.Protocol, 'The browser IIFE must expose window.Protocol.');
assert.deepEqual(Object.keys(sandbox.Protocol).sort(), Object.keys(P).sort(), 'Browser and Node must expose the same protocol API.');
for (const name of Object.keys(P)) assert.equal(typeof sandbox.Protocol[name], typeof P[name], `API type must match: ${name}`);
console.log('PASS  original protocol + browser IIFE source/API parity');

const police = await P.createIssuer('KR-POLICE-SEOUL-GN', '서울강남경찰서');
const fakeOrg = await P.createIssuer('KR-POLICE-SEOUL-GN', '서울강남경찰서');
const trustList = P.trustListOf([police]);
const employee = { id: 'E2026-0412', org: '서울강남경찰서 수사과', role: '수사관(방문 조사)', maskedName: '김○수', officeTel: '02-0000-0000' };
const phone = await P.createDevice();
const credential = await P.issueCredential(police, phone, employee);
const now = P.nowSec();
const results = [];
async function scenario(name, expected, token, options = {}) {
  const result = await P.verify(token, { trustList, now, ...options });
  results.push({ name, expected, actual: result.code });
}

await scenario('정상: 방금 만든 재직 직원 QR', 'OK', await P.present(credential, phone, { now }));
const fakePhone = await P.createDevice();
const fakeCredential = await P.issueCredential(fakeOrg, fakePhone, employee);
await scenario('위조: 동일 기관 이름과 ID, 다른 발급키', 'TAMPERED', await P.present(fakeCredential, fakePhone, { now }));
const unknown = await P.createIssuer('KR-FSS-INVESTIGATION', '금융감독원 특별수사팀');
const unknownCredential = await P.issueCredential(unknown, fakePhone, { ...employee, org: '금융감독원 특별수사팀' });
await scenario('위조: 신뢰목록에 없는 기관', 'UNTRUSTED_ISSUER', await P.present(unknownCredential, fakePhone, { now }));

const altered = (await P.present(credential, phone, { now })).split('.');
const body = JSON.parse(new TextDecoder().decode(P.unb64u(altered[1])));
body.role = '검사(계좌 동결 담당)';
altered[1] = P.b64u(new TextEncoder().encode(JSON.stringify(body)));
await scenario('변조: 진짜 QR의 직무 문구 변경', 'TAMPERED', altered.join('.'));
await scenario('재사용: 60초 전 화면 캡처', 'STALE', await P.present(credential, phone, { now: now - 60 }));
const seen = new Set();
const reused = await P.present(credential, phone, { now });
await P.verify(reused, { trustList, now, seen });
await scenario('재사용: 이미 확인한 QR', 'REPLAY', reused, { seen });
await scenario('폐지: 퇴직자 자격 증명', 'REVOKED', await P.present(credential, phone, { now }), { revoked: new Set([`${police.id}:${employee.id}`]) });
await scenario('복제: 다른 휴대폰에서 제시', 'DEVICE_MISMATCH', await P.present(credential, fakePhone, { now }));
await scenario('형식: 일반 웹 URL', 'BAD_FORMAT', 'https://example.com/pay?id=1');

const server = P.createCallCodeServer();
const verified = await P.verify(await P.present(credential, phone, { now }), { trustList, now });
const code = await server.issue(verified.info, { now });
results.push({ name: '전화: 유효한 확인번호', expected: 'OK', actual: server.lookup(code, 'citizen-A', { now: now + 10 }).code });
results.push({ name: '전화: 1회용 번호 재사용', expected: 'NO_MATCH', actual: server.lookup(code, 'citizen-A', { now: now + 20 }).code });
const expiredCode = await server.issue(verified.info, { now });
results.push({ name: '전화: 70초 지난 확인번호', expected: 'NO_MATCH', actual: server.lookup(expiredCode, 'citizen-B', { now: now + 70 }).code });
// An isolated server avoids a random issued code accidentally matching the wrong-code fixture.
const guessingServer = P.createCallCodeServer();
for (let i = 0; i < P.CALL_CODE_MAX_TRIES; i += 1) guessingServer.lookup('000000', 'citizen-C', { now });
results.push({ name: '전화: 5회 오입력 후 잠금', expected: 'LOCKED', actual: guessingServer.lookup('123456', 'citizen-C', { now }).code });

assert.equal(results.length, 13, 'All original 13 PoC scenarios must be covered.');
for (const result of results) console.log(`${result.actual === result.expected ? 'PASS' : 'FAIL'}  ${result.name} → ${result.actual}`);
const failures = results.filter(result => result.actual !== result.expected);
assert.deepEqual(failures, [], 'Protocol result regression detected.');
console.log(`${results.length}/${results.length} protocol scenarios passed.`);
