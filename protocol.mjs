// 거꾸로 신분증 PoC — 직무 자격 증명 발급·제시·검증 프로토콜
// WebCrypto(ECDSA P-256)만 쓰므로 Node 20+ 와 브라우저에서 같은 코드가 돈다.

const subtle = globalThis.crypto.subtle;
const ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', hash: 'SHA-256' };
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PREFIX = 'MIDR1';          // Mobile ID Reverse v1
export const QR_TTL_SEC = 30;           // 제시 QR 유효시간(화면 캡처 재사용 차단)
export const CALL_CODE_TTL_SEC = 60;    // 전화 확인번호 유효시간
export const CALL_CODE_MAX_TRIES = 5;   // 시민 기기당 오입력 허용 횟수

// ---------- base64url ----------
export function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function keyPair() {
  return subtle.generateKey(ALG, true, ['sign', 'verify']);
}
async function exportRaw(pub) {
  return new Uint8Array(await subtle.exportKey('raw', pub));
}
async function importRaw(raw) {
  return subtle.importKey('raw', raw, ALG, true, ['verify']);
}
async function sign(priv, bytes) {
  return new Uint8Array(await subtle.sign(SIG, priv, bytes));
}
async function verifySig(pub, sig, bytes) {
  try {
    return await subtle.verify(SIG, pub, sig, bytes);
  } catch {
    return false;
  }
}

// ---------- 발급기관(경찰서·구청 등) ----------
// 실제 서비스에서는 행정안전부가 관리하는 '신뢰 발급기관 목록'에 공개키가 등록된다.
export async function createIssuer(id, name) {
  const keys = await keyPair();
  return { id, name, keys, pubRaw: await exportRaw(keys.publicKey) };
}

export function trustListOf(issuers) {
  const list = {};
  for (const i of issuers) list[i.id] = { name: i.name, pub: b64u(i.pubRaw) };
  return list;
}

// ---------- 직원 단말 ----------
// 기기 키는 단말 보안영역에서 만들어지고 밖으로 나가지 않는다고 가정한다.
export async function createDevice() {
  const keys = await keyPair();
  return { keys, pubRaw: await exportRaw(keys.publicKey) };
}

// 기관이 직원 단말 공개키에 묶은 '직무 자격 증명'을 발급한다.
// 시민 화면에 필요한 최소 항목만 담는다(성명은 가운데 글자 가림, 주민번호·주소 없음).
export async function issueCredential(issuer, device, emp, { now = nowSec(), days = 365 } = {}) {
  const body = {
    iss: issuer.id,
    sub: emp.id,
    org: emp.org,
    role: emp.role,
    nm: emp.maskedName,
    tel: emp.officeTel,
    dev: b64u(device.pubRaw),
    exp: now + days * 86400,
  };
  const bodyBytes = enc.encode(JSON.stringify(body));
  const sig = await sign(issuer.keys.privateKey, bodyBytes);
  return `${b64u(bodyBytes)}.${b64u(sig)}`;
}

// 직원 앱이 QR_TTL_SEC 마다 새로 만드는 제시 토큰.
export async function present(cred, device, { now = nowSec() } = {}) {
  const nonce = b64u(globalThis.crypto.getRandomValues(new Uint8Array(8)));
  const msg = enc.encode(`${cred}|${now}|${nonce}`);
  const sig = await sign(device.keys.privateKey, msg);
  return `${PREFIX}.${cred}.${now}.${nonce}.${b64u(sig)}`;
}

// ---------- 시민 앱 검증 ----------
export const RESULT = {
  OK: '확인됨 — 실제 재직 중인 직원입니다',
  BAD_FORMAT: '모바일신분증 확인 QR이 아닙니다',
  UNTRUSTED_ISSUER: '등록되지 않은 기관이 만든 QR입니다',
  TAMPERED: 'QR 내용이 위·변조되었습니다',
  CRED_EXPIRED: '자격 증명 유효기간이 지났습니다',
  REVOKED: '퇴직·정지 등으로 효력이 없는 신분입니다',
  DEVICE_MISMATCH: '등록된 본인 휴대폰에서 만든 QR이 아닙니다',
  STALE: '오래된 QR입니다(화면 캡처·사진 재사용 의심)',
  REPLAY: '이미 사용된 QR입니다',
};

// trustList: {issuerId: {name, pub}}, revoked: Set("iss:sub"), seen: Set(nonce)
export async function verify(token, { trustList, revoked = new Set(), seen = new Set(), now = nowSec() }) {
  const fail = (code) => ({ ok: false, code, message: RESULT[code] });
  const parts = String(token).trim().split('.');
  if (parts.length !== 6 || parts[0] !== PREFIX) return fail('BAD_FORMAT');
  const [, bodyB64, credSigB64, tStr, nonce, devSigB64] = parts;

  let body;
  try {
    body = JSON.parse(dec.decode(unb64u(bodyB64)));
  } catch {
    return fail('BAD_FORMAT');
  }
  const issuer = trustList[body.iss];
  if (!issuer) return fail('UNTRUSTED_ISSUER');

  const issuerPub = await importRaw(unb64u(issuer.pub));
  if (!(await verifySig(issuerPub, unb64u(credSigB64), unb64u(bodyB64)))) return fail('TAMPERED');
  if (now > body.exp) return fail('CRED_EXPIRED');
  if (revoked.has(`${body.iss}:${body.sub}`)) return fail('REVOKED');

  let devPub;
  try {
    devPub = await importRaw(unb64u(body.dev));
  } catch {
    return fail('TAMPERED');
  }
  const msg = enc.encode(`${bodyB64}.${credSigB64}|${tStr}|${nonce}`);
  if (!(await verifySig(devPub, unb64u(devSigB64), msg))) return fail('DEVICE_MISMATCH');

  const t = Number(tStr);
  if (!Number.isFinite(t) || Math.abs(now - t) > QR_TTL_SEC) return fail('STALE');
  if (seen.has(nonce)) return fail('REPLAY');
  seen.add(nonce);

  return {
    ok: true,
    code: 'OK',
    message: RESULT.OK,
    info: { issuer: issuer.name, org: body.org, role: body.role, name: body.nm, officeTel: body.tel, issuedAt: t },
  };
}

// ---------- 전화 확인번호(비대면) ----------
// 직원 앱이 기관 서버에 1회용 6자리 번호를 요청하고, 시민이 통화 중 그 번호를 앱에 넣으면
// 서버가 기관·직무를 돌려준다. 번호는 재직 증명이 있는 단말만 받을 수 있다.
export function createCallCodeServer() {
  const codes = new Map();   // code -> {info, exp}
  const tries = new Map();   // citizenDevice -> 실패 횟수
  return {
    async issue(verifiedInfo, { now = nowSec() } = {}) {
      let code;
      do {
        const n = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
        code = String(n).padStart(6, '0');
      } while (codes.has(code));
      codes.set(code, { info: verifiedInfo, exp: now + CALL_CODE_TTL_SEC });
      return code;
    },
    lookup(code, citizenDevice, { now = nowSec() } = {}) {
      const used = tries.get(citizenDevice) ?? 0;
      if (used >= CALL_CODE_MAX_TRIES) return { ok: false, code: 'LOCKED', message: '입력 횟수를 넘었습니다. 112 또는 기관 대표번호로 확인하세요' };
      const hit = codes.get(code);
      if (!hit || now > hit.exp) {
        tries.set(citizenDevice, used + 1);
        return { ok: false, code: 'NO_MATCH', message: '일치하는 확인번호가 없습니다 — 사칭 가능성이 높습니다' };
      }
      codes.delete(code); // 1회용
      return { ok: true, code: 'OK', message: RESULT.OK, info: hit.info };
    },
  };
}

export function nowSec() {
  return Math.floor(Date.now() / 1000);
}
