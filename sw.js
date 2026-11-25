// 멀티뷰 서비스 워커
// 1) 크롬이 "앱 설치"를 제공하려면 서비스 워커가 있어야 함
// 2) 이 사이트 파일은 항상 인터넷에서 최신을 먼저 받아오고(network-first), 인터넷이 없을 때만 저장본 사용
//    → 휴대폰이 예전 화면을 기억해서 업데이트가 늦게 보이는 문제 방지
// 연결 요청(ntfy.sh)·상태(HiveMQ)·화면(WebRTC)은 다른 주소라 건드리지 않음
const CACHE = 'multiview-v1';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  e.respondWith((async () => {
    try {
      const res = await fetch(req, { cache: 'no-store' });
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {}); }
      return res;
    } catch {
      const hit = await caches.match(req, { ignoreSearch: true });
      return hit || new Response('인터넷 연결을 확인하세요.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }
  })());
});
