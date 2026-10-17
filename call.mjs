// 전화 확인번호(비대면) 시연. 실서비스에서는 직원 앱이 기관 서버에 1회용 번호를 받고,
// 시민 앱이 그 번호를 기관 서버에 조회한다. 정적 데모라 서버가 없으므로
// '기관 서버' 역할을 공개 데모 키(call-key.json)로 흉내 낸다: 번호 = HMAC(키, 직원ID|1분 구간) 앞 6자리.
export const CALL_TTL_SEC = 60;
export const MAX_TRIES = 5;

// 데모 기관에 등록된 직원(시민 확인 화면에 보일 최소 정보)
export const STAFF = [
  { id: 'E2026-0412', org: '서울강남경찰서 수사과', role: '수사관', name: '김○수', tel: '02-000-0000', active: true },
  { id: 'E2025-0099', org: '서울강남경찰서 수사과', role: '수사관(퇴직)', name: '이○호', tel: '02-000-0000', active: false },
];

const slotOf = (now) => Math.floor(now / CALL_TTL_SEC);

async function hmacKey(keyB64u) {
  const raw = Uint8Array.from(atob(keyB64u.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((keyB64u.length + 3) % 4)), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

export async function codeFor(keyB64u, staffId, slot) {
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(keyB64u), new TextEncoder().encode(`${staffId}|${slot}`)));
  const n = ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]) >>> 0;
  return String(n % 1_000_000).padStart(6, '0');
}

// 직원 앱: 지금 구간의 번호와 남은 초
export async function issue(keyB64u, staffId, now = Math.floor(Date.now() / 1000)) {
  return { code: await codeFor(keyB64u, staffId, slotOf(now)), left: CALL_TTL_SEC - (now % CALL_TTL_SEC) };
}

// 시민 앱 조회: 현재·직전 구간(최대 약 2분)까지 인정, 퇴직자는 거절
export async function lookup(keyB64u, code, now = Math.floor(Date.now() / 1000)) {
  const c = String(code).replace(/\D/g, '');
  if (c.length !== 6) return { ok: false, code: 'BAD_INPUT' };
  for (const s of STAFF) {
    for (const slot of [slotOf(now), slotOf(now) - 1]) {
      if ((await codeFor(keyB64u, s.id, slot)) === c) return s.active ? { ok: true, code: 'OK', info: s } : { ok: false, code: 'REVOKED' };
    }
  }
  return { ok: false, code: 'NO_MATCH' };
}
