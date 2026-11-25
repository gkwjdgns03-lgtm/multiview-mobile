'use strict';
// 멀티뷰 모바일: 휴대폰 브라우저에서 PC 멀티뷰에 ID·비밀번호로 접속해 보고 조작
// 연결 방식은 PC 앱과 같음: ntfy.sh(암호화된 연결 요청) + HiveMQ(켜짐/꺼짐) + WebRTC(화면·소리·입력 직접 연결)
const $ = (id) => document.getElementById(id);

// ---------- 버전 / 업데이트 ----------
// 홈 화면에 설치한 앱에는 새로고침 버튼이 없으므로, 새 버전이 올라오면 앱 안에서 알려주고 바로 업데이트
const APP_VERSION = '2026.11.25-4';
async function checkUpdate(manual) {
  try {
    const r = await fetch('version.json?t=' + Date.now(), { cache: 'no-store' });
    const { v } = await r.json();
    if (v && v !== APP_VERSION) { showUpdate(v); return true; }
    if (manual) toast('최신 버전이에요 (' + APP_VERSION + ')');
  } catch { if (manual) toast('업데이트를 확인하지 못했어요. 인터넷 연결을 확인하세요.'); }
  return false;
}
// 주소에 버전을 붙여 다시 열면 휴대폰에 저장된 예전 파일 대신 새 파일을 받아옴
function applyUpdate(v) { location.replace(location.pathname + '?v=' + encodeURIComponent(v || Date.now())); }
function showUpdate(v) {
  const b = document.getElementById('updateBar'); if (!b) return;
  b.querySelector('span').textContent = '새 버전이 있어요 (' + v + ')';
  b.querySelector('button').onclick = () => applyUpdate(v);
  b.classList.remove('hidden');
}

// ---------- 공통 ----------
const RELAY = 'https://ntfy.sh';
const PRESENCE_URL = 'wss://broker.hivemq.com:8884/mqtt';
const enc = new TextEncoder();
const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
const fmtId = (id) => String(id).replace(/(\d{3})(\d{3})(\d{3})/, '$1 $2 $3');
let toastTimer;
function toast(msg, ms = 3500) { const t = $('toast'); t.textContent = msg; t.classList.remove('hidden'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), ms); }
function show(id) { for (const s of ['home', 'add', 'settings', 'session']) $(s).classList.toggle('hidden', s !== id); }
function busy(text) { $('busy').classList.toggle('hidden', !text); if (text) $('busyText').textContent = text; }

// 설정 (기기에 저장)
const settings = Object.assign({ res: '1080', turnUrl: '', turnUser: '', turnPass: '' }, (() => { try { return JSON.parse(localStorage.getItem('mv-settings') || '{}'); } catch { return {}; } })());
const saveSettings = () => { try { localStorage.setItem('mv-settings', JSON.stringify(settings)); } catch {} };
for (const [id, k] of [['setRes', 'res'], ['setTurnUrl', 'turnUrl'], ['setTurnUser', 'turnUser'], ['setTurnPass', 'turnPass']]) {
  $(id).value = settings[k]; $(id).addEventListener('change', () => { settings[k] = $(id).value.trim(); saveSettings(); });
}

// ---------- 암호화·중계 (PC 앱과 동일) ----------
async function deriveKey(id, pw) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  // extractable=false: 키를 꺼낼 수 없게 만들어 기기에 보관 (비밀번호 자체는 저장하지 않음)
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode('remotelink/v1/' + id), iterations: 200000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function sha(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
async function topicFor(id) { const h = await sha('remotelink/topic/' + id); return 'rl' + [...h.slice(0, 15)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
async function presenceTopic(id) { const h = await sha('remotelink/presence/' + id); return 'remotelink/p1/' + [...h.slice(0, 16)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
async function seal(key, obj) {
  const z = new Uint8Array(await new Response(new Blob([JSON.stringify(obj)]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer());
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, z));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return b64(out);
}
async function unseal(key, s) {
  const u = unb64(s);
  const z = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
  return JSON.parse(await new Response(new Blob([z]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text());
}
async function publish(topic, body) {
  const r = await fetch(`${RELAY}/${topic}`, { method: 'POST', body, headers: { Cache: 'no', Firebase: 'no' } });
  if (!r.ok) throw new Error(`중계 서버 오류 (${r.status})`);
}
function subscribe(topic, onMsg, onState) {
  const es = new EventSource(`${RELAY}/${topic}/sse`);
  es.onopen = () => onState && onState('open');
  es.onerror = () => onState && onState('error');
  es.onmessage = async (ev) => {
    let d; try { d = JSON.parse(ev.data); } catch { return; }
    if (d.event && d.event !== 'message') return;
    let body = d.message;
    if (d.attachment && d.attachment.url && d.attachment.url.startsWith(RELAY + '/')) { try { body = await (await fetch(d.attachment.url)).text(); } catch { return; } }
    if (typeof body === 'string') onMsg(body);
  };
  return es;
}
function mungeOpus(sdp) {
  const m = /a=rtpmap:(\d+) opus\/48000\/2/i.exec(sdp); if (!m) return sdp;
  const pt = m[1];
  return sdp.replace(new RegExp(`a=fmtp:${pt} ([^\\r\\n]*)`), (_l, p) => `a=fmtp:${pt} ${[...p.split(';').filter((kv) => kv && !/^(stereo|sprop-stereo|maxaveragebitrate|minptime)=/.test(kv)), 'stereo=1', 'sprop-stereo=1', 'maxaveragebitrate=160000', 'minptime=10'].join(';')}`);
}
function turnServers() {
  const list = String(settings.turnUrl || '').split(/[\s,]+/).filter((u) => /^turns?:/i.test(u));
  if (!list.length) return [];
  const urls = [];
  for (const u of list) { if (/[?&]transport=/i.test(u) || /^turns:/i.test(u)) urls.push(u); else urls.push(u, u + (u.includes('?') ? '&' : '?') + 'transport=tcp'); }
  return [{ urls, username: settings.turnUser || '', credential: settings.turnPass || '' }];
}
const iceServers = () => [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }, ...turnServers()];
function waitIce(pc, ms = 4000) {
  return new Promise((res) => {
    if (pc.iceGatheringState === 'complete') return res();
    const t = setTimeout(res, ms);
    pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); res(); } });
  });
}

// ---------- 저장된 PC (IndexedDB: 비밀번호 대신 꺼낼 수 없는 암호 키만 보관) ----------
function db() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('multiview', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('pcs', { keyPath: 'id' });
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function dbAll() { const d = await db(); return new Promise((res) => { const q = d.transaction('pcs').objectStore('pcs').getAll(); q.onsuccess = () => res(q.result || []); q.onerror = () => res([]); }); }
async function dbPut(v) { const d = await db(); return new Promise((res, rej) => { const t = d.transaction('pcs', 'readwrite'); t.objectStore('pcs').put(v); t.oncomplete = res; t.onerror = () => rej(t.error); }); }
async function dbDel(id) { const d = await db(); return new Promise((res) => { const t = d.transaction('pcs', 'readwrite'); t.objectStore('pcs').delete(id); t.oncomplete = res; }); }

// ---------- 켜짐/꺼짐 상태 ----------
let watchClient = null; const watchTopics = new Map(); const pcStatus = {};
const STATUS = { '1': ['on', '켜짐'], '2': ['busy', '사용 중'], '0': ['off', '꺼짐'] };
async function watchSaved(ids) {
  if (typeof mqtt === 'undefined') return;
  const want = new Map(); for (const id of ids) want.set(await presenceTopic(id), id);
  if (!watchClient) {
    watchClient = mqtt.connect(PRESENCE_URL, { keepalive: 30, reconnectPeriod: 5000, connectTimeout: 10000, timerVariant: 'native' });
    watchClient.on('connect', () => { if (watchTopics.size) watchClient.subscribe([...watchTopics.keys()], { qos: 1 }); updateDots(); });
    watchClient.on('close', updateDots);
    watchClient.on('message', (t, p) => { const id = watchTopics.get(t); if (id) { pcStatus[id] = p.toString() || '0'; updateDots(); } });
  }
  const add = [...want.keys()].filter((t) => !watchTopics.has(t));
  const del = [...watchTopics.keys()].filter((t) => !want.has(t));
  for (const t of del) watchTopics.delete(t);
  for (const t of add) watchTopics.set(t, want.get(t));
  if (watchClient.connected) { if (del.length) watchClient.unsubscribe(del); if (add.length) watchClient.subscribe(add, { qos: 1 }); }
  updateDots();
}
function statusOf(id) { if (!watchClient || !watchClient.connected) return ['', '확인 중']; return STATUS[pcStatus[id]] || ['off', '꺼짐']; }
function updateDots() {
  for (const el of document.querySelectorAll('.pc[data-id]')) {
    const [cls, label] = statusOf(el.dataset.id);
    el.querySelector('.dot').className = 'dot ' + cls;
    const st = el.querySelector('.st'); st.className = 'st ' + cls; st.textContent = label;
  }
}

// ---------- 목록 화면 ----------
async function renderList() {
  const list = await dbAll();
  const box = $('list'); box.textContent = '';
  if (!list.length) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = '아직 추가한 PC가 없어요.'; box.append(e); }
  for (const p of list) {
    const el = document.createElement('div'); el.className = 'card pc'; el.dataset.id = p.id;
    const dot = document.createElement('span'); dot.className = 'dot';
    const info = document.createElement('div'); info.className = 'info';
    const name = document.createElement('div'); name.className = 'name'; name.textContent = p.name || fmtId(p.id);
    const sub = document.createElement('div'); sub.className = 'sub';
    const st = document.createElement('span'); st.className = 'st'; st.textContent = '확인 중';
    sub.append(st, document.createTextNode(' · ' + fmtId(p.id)));
    info.append(name, sub);
    const more = document.createElement('button'); more.className = 'more'; more.textContent = '⋯';
    more.onclick = async (e) => {
      e.stopPropagation();
      const v = prompt('이름 바꾸기 (비우고 확인하면 삭제할지 물어봐요)', p.name || '');
      if (v === null) return;
      if (!v.trim()) { if (confirm(`${p.name || fmtId(p.id)}을(를) 목록에서 삭제할까요?`)) { await dbDel(p.id); renderList(); } return; }
      p.name = v.trim().slice(0, 30); await dbPut(p); renderList();
    };
    el.append(dot, info, more);
    el.onclick = () => startSession(p);
    box.append(el);
  }
  watchSaved(list.map((p) => p.id));
}

$('goAdd').onclick = () => { $('addName').value = ''; $('addId').value = ''; $('addPw').value = ''; $('addMsg').textContent = ''; show('add'); };
$('goSettings').onclick = () => show('settings');
document.querySelectorAll('[data-back]').forEach((b) => (b.onclick = () => { show('home'); renderList(); }));
$('addSave').onclick = async () => {
  const id = $('addId').value.replace(/\D/g, ''), pw = $('addPw').value, name = $('addName').value.trim().slice(0, 30);
  if (!/^\d{9}$/.test(id)) return ($('addMsg').textContent = 'ID는 숫자 9자리예요.');
  if (!pw) return ($('addMsg').textContent = '비밀번호를 입력하세요.');
  $('addSave').disabled = true;
  try {
    const rec = { id, name, key: await deriveKey(id, pw) };
    await dbPut(rec);
    show('home'); renderList();
    startSession(rec);
  } catch (e) { $('addMsg').textContent = '저장 실패: ' + e.message; }
  $('addSave').disabled = false;
};

// 중계 서버 테스트
$('turnTest').onclick = async () => {
  const out = $('turnResult'); const servers = turnServers();
  if (!servers.length) return (out.textContent = '주소를 먼저 입력하세요 (turn:로 시작).');
  out.textContent = '확인 중…';
  const t = new RTCPeerConnection({ iceServers: servers, iceTransportPolicy: 'relay' });
  const got = new Set(), errs = new Set();
  t.onicecandidate = (e) => { if (e.candidate && e.candidate.type === 'relay') got.add((e.candidate.relayProtocol || e.candidate.protocol || '').toUpperCase()); };
  t.onicecandidateerror = (e) => { if (e.errorCode) errs.add(e.errorCode); };
  t.createDataChannel('t'); await t.setLocalDescription(await t.createOffer());
  await new Promise((r) => setTimeout(r, 6000)); t.close();
  out.textContent = got.size ? '✅ 중계 서버 연결됨 (' + [...got].join('·') + ')' : errs.has(401) ? '❌ 아이디 또는 비밀번호가 틀렸어요.' : '❌ 중계 서버에 접속하지 못했어요. 주소를 확인하세요.';
};

// ---------- 접속 ----------
let pc = null, ctl = null, mv = null, cancelConnect = null, connectTimer = null, wakeLock = null, statsTimer = null, prevStats = null;
const video = $('v'), audio = $('a');
function sendCtl(m) { if (ctl && ctl.readyState === 'open') ctl.send(JSON.stringify(m)); }
function sendMv(m) { if (mv && mv.readyState === 'open' && mv.bufferedAmount < 65536) mv.send(JSON.stringify(m)); }

async function startSession(rec) {
  if (pc) return;
  // 사용자가 누른 순간에 전체 화면·소리 허용을 받아 둠 (나중엔 브라우저가 막음)
  try { if (document.documentElement.requestFullscreen && !document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {}); } catch {}
  try { audio.muted = false; audio.play().catch(() => {}); } catch {}
  const [cls] = statusOf(rec.id);
  if (cls === 'off') toast('이 PC는 꺼져 있는 것 같아요. 그래도 접속을 시도합니다…');
  let cancelled = false; cancelConnect = () => { cancelled = true; };
  busy((rec.name || fmtId(rec.id)) + ' 연결 중…');
  let es = null;
  try {
    const hostTopic = await topicFor(rec.id);
    const replyTopic = 'rl' + randHex(15), sid = randHex(8);
    let sent = false;
    const offerSdp = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('응답이 없어요. PC가 꺼져 있거나 멀티뷰가 실행 중이 아니에요.')), 25000);
      const fail = (m) => { clearTimeout(timer); reject(new Error(m)); };
      cancelConnect = () => { cancelled = true; fail('취소했어요.'); };
      es = subscribe(replyTopic, async (raw) => {
        let env; try { env = JSON.parse(raw); } catch { return; }
        if (env.e === 'denied') return fail('비밀번호가 틀렸어요. 목록에서 ⋯ → 삭제 후 다시 추가해 주세요.');
        if (env.e === 'locked') return fail('비밀번호를 여러 번 틀려서 PC가 10분간 접속을 막았어요.');
        if (env.e !== 'ok') return;
        let m; try { m = await unseal(rec.key, env.c); } catch { return; }
        if (m.sid !== sid) return;
        if (m.t === 'busy') return fail('PC가 이미 다른 사람과 연결 중이에요.');
        if (m.t === 'error') return fail('PC에서 화면 공유를 시작하지 못했어요: ' + m.v);
        if (m.t === 'offer') { clearTimeout(timer); resolve(m.sdp); }
      }, async (st) => {
        if (st !== 'open' || sent) return; sent = true;
        try { await publish(hostTopic, JSON.stringify({ r: replyTopic, c: await seal(rec.key, { t: 'hello', sid, ts: Date.now(), ice: turnServers() }) })); }
        catch (e) { fail('중계 서버에 연결하지 못했어요: ' + e.message); }
      });
      setTimeout(() => { if (!sent) fail('인터넷 연결을 확인하세요 (중계 서버 접속 실패).'); }, 10000);
    });
    if (cancelled) throw new Error('취소했어요.');
    busy('화면 연결 중…');
    await openPeer(offerSdp);
    await publish(hostTopic, JSON.stringify({ r: replyTopic, c: await seal(rec.key, { t: 'answer', sid, sdp: pc.localDescription.sdp, ts: Date.now() }) }));
    $('info').dataset.name = rec.name || fmtId(rec.id); $('info').textContent = $('info').dataset.name;
  } catch (e) {
    endSession(); busy(''); toast(e.message, 6000);
  } finally { setTimeout(() => es && es.close(), 3000); }
}
$('busyCancel').onclick = () => { if (cancelConnect) cancelConnect(); endSession(); busy(''); };

async function openPeer(offerSdp) {
  pc = new RTCPeerConnection({ iceServers: iceServers() });
  const myPc = pc;
  pc.ontrack = (e) => {
    try { e.receiver.jitterBufferTarget = 0; } catch {}
    const ms = new MediaStream([e.track]);
    if (e.track.kind === 'audio') { audio.srcObject = ms; audio.play().then(() => setSound(true), () => setSound(false)); }
    else video.srcObject = ms;
  };
  pc.ondatachannel = (e) => {
    const ch = e.channel;
    if (ch.label === 'ctl') {
      ctl = ch;
      // 휴대폰은 커서가 없으니 PC 커서를 영상에 그대로 보여 달라고 요청
      const prefs = () => sendCtl({ t: 'prefs', res: settings.res || '1080', cursor: 'remote' });
      if (ch.readyState === 'open') prefs(); else ch.addEventListener('open', prefs);
    } else if (ch.label === 'mv') mv = ch;
    ch.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.t === 'mons') renderMonitors(m.list, m.cur);
      else if (m.t === 'mon-ok') markMonitor(m.cur);
      else if (m.t === 'warn') toast(m.v, 8000);
      else if (m.t === 'bye') { endSession(); toast('PC가 연결을 끊었어요.'); }
    };
  };
  pc.addEventListener('connectionstatechange', () => {
    if (pc !== myPc) return;
    const s = pc.connectionState;
    if (s === 'connected') { clearTimeout(connectTimer); busy(''); enterSession(); }
    else if (s === 'failed') diagnose().then((why) => { endSession(); busy(''); toast(why, 9000); });
    else if (s === 'disconnected') toast('연결이 불안정해요…');
  });
  connectTimer = setTimeout(() => { if (pc === myPc && pc.connectionState !== 'connected') diagnose().then((why) => { endSession(); busy(''); toast(why, 9000); }); }, 20000);
  await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
  const ans = await pc.createAnswer();
  await pc.setLocalDescription({ type: 'answer', sdp: mungeOpus(ans.sdp) });
  await waitIce(pc);
}
async function diagnose() {
  const loc = new Set(); try { (await pc.getStats()).forEach((s) => { if (s.type === 'local-candidate') loc.add(s.candidateType); }); } catch {}
  if (!loc.has('relay')) return turnServers().length
    ? '중계 서버(TURN)에 접속하지 못했어요. 설정 → 중계 서버 테스트로 확인해 주세요.'
    : '직접 연결이 막힌 네트워크라 연결하지 못했어요 (통신사망·회사망). 설정에서 중계 서버(TURN)를 입력해 주세요.';
  return '연결하지 못했어요. 잠시 후 다시 시도해 주세요.';
}
async function enterSession() {
  show('session'); resetView();
  try { wakeLock = await navigator.wakeLock.request('screen'); } catch {}
  statsTimer = setInterval(pollStats, 1000);
}
function endSession() {
  orient = null; cssRot = false; session.style.cssText = '';
  try { screen.orientation.unlock(); } catch {}
  clearTimeout(connectTimer); clearInterval(statsTimer); prevStats = null;
  if (ctl && ctl.readyState === 'open') try { ctl.send(JSON.stringify({ t: 'bye' })); } catch {}
  releaseMods();
  if (pc) try { pc.close(); } catch {}
  pc = ctl = mv = null;
  video.srcObject = null; audio.srcObject = null;
  try { wakeLock && wakeLock.release(); } catch {} wakeLock = null;
  $('kb').blur(); $('keys').classList.add('hidden'); $('kbBtn').classList.remove('on');
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  show('home'); renderList();
}
$('endBtn').onclick = () => endSession();
async function pollStats() {
  if (!pc) return;
  let rtp = null, pair = null; const rep = await pc.getStats();
  rep.forEach((s) => { if (s.type === 'inbound-rtp' && s.kind === 'video') rtp = s; if (s.type === 'transport' && s.selectedCandidatePairId) pair = rep.get(s.selectedCandidatePairId); });
  if (!rtp) return;
  const local = pair && rep.get(pair.localCandidateId);
  const parts = [$('info').dataset.name || ''];
  if (rtp.framesPerSecond != null) parts.push(Math.round(rtp.framesPerSecond) + 'fps');
  if (prevStats) parts.push(((rtp.bytesReceived - prevStats.b) * 8 / ((rtp.timestamp - prevStats.t) / 1000) / 1e6).toFixed(1) + 'Mbps');
  if (pair && pair.currentRoundTripTime != null) parts.push('왕복 ' + Math.round(pair.currentRoundTripTime * 1000) + 'ms');
  if (local) parts.push(local.candidateType === 'relay' ? '중계' : '직접');
  prevStats = { b: rtp.bytesReceived, t: rtp.timestamp };
  $('info').textContent = parts.filter(Boolean).join(' · ');
}

// 소리
function setSound(on) { audio.muted = !on; $('soundBtn').textContent = on ? '🔊' : '🔇'; }
$('soundBtn').onclick = () => { if (audio.muted || audio.paused) { audio.muted = false; audio.play().then(() => setSound(true), () => toast('소리를 켤 수 없어요.')); } else setSound(false); };

// 모니터 전환
let monCount = 0;
function renderMonitors(list, cur) {
  const box = $('monBtns'); box.textContent = ''; monCount = Array.isArray(list) ? list.length : 0;
  if (monCount < 2) return;
  list.forEach((m, i) => { const b = document.createElement('button'); b.textContent = '🖥' + (i + 1); b.onclick = () => sendCtl({ t: 'mon', i }); box.append(b); });
  markMonitor(cur);
}
function markMonitor(cur) { [...$('monBtns').children].forEach((b, j) => b.classList.toggle('on', j === cur)); }
$('barToggle').onclick = () => $('bar').classList.toggle('collapsed');

// ---------- 화면 확대/이동 ----------
const zoomer = $('zoomer'), stage = $('stage');
const view = { s: 1, tx: 0, ty: 0 };
function applyView() {
  const w = stage.clientWidth, h = stage.clientHeight;
  view.s = Math.min(5, Math.max(1, view.s));
  view.tx = Math.min(0, Math.max(w - w * view.s, view.tx));
  view.ty = Math.min(0, Math.max(h - h * view.s, view.ty));
  zoomer.style.transform = `translate(${view.tx}px, ${view.ty}px) scale(${view.s})`;
  $('zoomReset').classList.toggle('on', view.s > 1.01);
}
function resetView() { view.s = 1; view.tx = 0; view.ty = 0; applyView(); }
$('zoomReset').onclick = resetView;
window.addEventListener('resize', applyView);

// ---------- 가로/세로 보기 ----------
// 휴대폰이 지원하면 실제 화면 방향을 고정하고, 안 되면 원격 화면을 90도 돌려서 보여줌
let orient = null, cssRot = false;
const session = $('session');
function physicalLandscape() { return window.innerWidth > window.innerHeight; }
function applyRotation() {
  cssRot = !!orient && (orient === 'landscape') !== physicalLandscape();
  if (cssRot) {
    session.style.width = window.innerHeight + 'px'; session.style.height = window.innerWidth + 'px';
    session.style.right = 'auto'; session.style.bottom = 'auto';
    session.style.transformOrigin = 'top left'; session.style.transform = 'rotate(90deg) translateY(-100%)';
  } else { session.style.cssText = ''; }
  const want = orient || (physicalLandscape() ? 'landscape' : 'portrait');
  $('rotBtn').textContent = want === 'landscape' ? '↻ 세로' : '↻ 가로';
  applyView();
}
async function setOrientation(mode) {
  orient = mode;
  try {
    if (!document.fullscreenElement && document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
    await screen.orientation.lock(mode);
  } catch {} // 잠금이 안 되는 브라우저면 화면을 돌려서 보여줌
  setTimeout(applyRotation, 300); applyRotation();
}
$('rotBtn').onclick = () => {
  const cur = orient || (physicalLandscape() ? 'landscape' : 'portrait');
  setOrientation(cur === 'landscape' ? 'portrait' : 'landscape');
};
window.addEventListener('resize', () => { if (orient) applyRotation(); });
// 손가락 위치(화면 기준) → 원격 화면 영역 안 좌표 (90도 돌린 상태면 되돌려 계산)
function toLocal(x, y) { return cssRot ? { x: y, y: window.innerWidth - x } : { x, y }; }

// 화면 좌표 → PC 화면 비율 좌표 (0~1). 확대 상태와 레터박스 반영 (cx, cy는 toLocal 좌표)
function norm(cx, cy) {
  const r = { left: view.tx, top: view.ty, width: stage.clientWidth * view.s, height: stage.clientHeight * view.s };
  const vw = video.videoWidth, vh = video.videoHeight; if (!vw || !vh) return null;
  const s = Math.min(r.width / vw, r.height / vh), dw = vw * s, dh = vh * s;
  const x = (cx - (r.left + (r.width - dw) / 2)) / dw, y = (cy - (r.top + (r.height - dh) / 2)) / dh;
  return { x: Math.min(1, Math.max(0, x)), y: Math.min(1, Math.max(0, y)), inside: x >= 0 && y >= 0 && x <= 1 && y <= 1 };
}
function ripple(x, y, color) {
  const r = $('ripple'); r.style.left = x + 'px'; r.style.top = y + 'px'; r.style.borderColor = color || 'var(--accent)';
  r.style.opacity = '1'; clearTimeout(r._t); r._t = setTimeout(() => (r.style.opacity = '0'), 250);
}

// ---------- 터치 조작 ----------
// 탭=클릭 · 꾹 눌렀다 떼기=우클릭 · 꾹 누른 채 끌기=드래그 · 한 손가락 이동=마우스 이동(확대 중엔 화면 이동)
// 두 손가락 위아래=스크롤 · 벌리기/오므리기=확대 · 두 손가락 탭=우클릭
const T = { mode: null, start: null, last: null, hold: null, pressed: false, two: null, lastTap: null };
const pt = (t) => toLocal(t.clientX, t.clientY);
const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
function click(p, button) {
  const n = norm(p.x, p.y); if (!n || !n.inside) return;
  let x = n.x, y = n.y;
  // 빠른 두 번 탭은 같은 위치로 보정 → PC에서 더블클릭으로 인식 (손가락은 위치가 조금씩 달라짐)
  if (button === 0 && T.lastTap && Date.now() - T.lastTap.t < 450 && dist(p, T.lastTap.p) < 30) { x = T.lastTap.n.x; y = T.lastTap.n.y; }
  sendCtl({ t: 'd', b: button, x, y }); sendCtl({ t: 'u', b: button, x, y });
  if (button === 0) T.lastTap = { t: Date.now(), p, n: { x, y } };
  ripple(p.x, p.y, button === 2 ? 'var(--warn)' : null);
}
stage.addEventListener('touchstart', (e) => {
  e.preventDefault();
  const ts = e.touches;
  if (ts.length === 1) {
    T.start = T.last = pt(ts[0]); T.mode = 'tap'; T.pressed = false; T.t0 = Date.now();
    clearTimeout(T.hold);
    T.hold = setTimeout(() => { if (T.mode === 'tap') { T.mode = 'hold'; navigator.vibrate && navigator.vibrate(25); ripple(T.start.x, T.start.y, 'var(--ok)'); } }, 420);
  } else if (ts.length === 2) {
    clearTimeout(T.hold);
    if (T.pressed) { const n = norm(T.last.x, T.last.y); sendCtl({ t: 'u', b: 0, ...(n ? { x: n.x, y: n.y } : {}) }); T.pressed = false; }
    const a = pt(ts[0]), b = pt(ts[1]); const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    T.mode = 'two'; T.two = { d0: dist(a, b), mid0: mid, last: mid, s0: view.s, tx0: view.tx, ty0: view.ty, pinch: false, moved: false, t0: Date.now(), acc: 0 };
  }
}, { passive: false });
stage.addEventListener('touchmove', (e) => {
  e.preventDefault();
  const ts = e.touches;
  if (T.mode === 'two' && ts.length >= 2) {
    const a = pt(ts[0]), b = pt(ts[1]), d = dist(a, b), mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }, t = T.two;
    if (!t.pinch && Math.abs(d - t.d0) > 30) t.pinch = true;
    if (dist(mid, t.mid0) > 8) t.moved = true;
    if (t.pinch) {
      // 두 손가락 가운데 지점을 고정한 채 확대
      const s = Math.min(5, Math.max(1, t.s0 * d / t.d0));
      view.tx = mid.x - (t.mid0.x - t.tx0) * (s / t.s0); view.ty = mid.y - (t.mid0.y - t.ty0) * (s / t.s0); view.s = s; applyView();
    } else if (t.moved) {
      const dy = mid.y - t.last.y, dx = mid.x - t.last.x;
      if (view.s > 1.01) { view.tx += dx; view.ty += dy; applyView(); }
      else { t.acc += dy * 3; if (Math.abs(t.acc) >= 30) { sendCtl({ t: 'w', dx: 0, dy: Math.round(t.acc) }); t.acc = 0; } }
    }
    t.last = mid; return;
  }
  if (ts.length !== 1 || !T.start) return;
  const p = pt(ts[0]), moved = dist(p, T.start) > 10;
  if (T.mode === 'tap' && moved) { clearTimeout(T.hold); T.mode = view.s > 1.01 ? 'pan' : 'move'; }
  if (T.mode === 'hold' && moved) {
    // 꾹 누른 뒤 움직이면 드래그 시작 (누른 위치에서 왼쪽 버튼 누름)
    const n0 = norm(T.start.x, T.start.y); if (n0) { sendCtl({ t: 'd', b: 0, x: n0.x, y: n0.y }); T.pressed = true; }
    T.mode = 'drag';
  }
  if (T.mode === 'drag' || T.mode === 'move') { const n = norm(p.x, p.y); if (n) sendMv({ t: 'm', x: n.x, y: n.y }); }
  else if (T.mode === 'pan') { view.tx += p.x - T.last.x; view.ty += p.y - T.last.y; applyView(); }
  T.last = p;
}, { passive: false });
stage.addEventListener('touchend', (e) => {
  e.preventDefault();
  if (T.mode === 'two') {
    if (e.touches.length === 0) {
      const t = T.two;
      if (!t.pinch && !t.moved && Date.now() - t.t0 < 350) click(t.mid0, 2); // 두 손가락 탭 = 우클릭
      T.mode = null;
    }
    return;
  }
  clearTimeout(T.hold);
  if (T.mode === 'tap') click(T.start, 0);
  else if (T.mode === 'hold') click(T.start, 2); // 꾹 눌렀다 떼기 = 우클릭
  else if (T.mode === 'drag' && T.pressed) { const n = norm(T.last.x, T.last.y); sendCtl({ t: 'u', b: 0, ...(n ? { x: n.x, y: n.y } : {}) }); }
  T.mode = null; T.pressed = false;
}, { passive: false });
stage.addEventListener('touchcancel', () => { clearTimeout(T.hold); if (T.pressed) sendCtl({ t: 'u', b: 0 }); T.mode = null; T.pressed = false; });

// ---------- 키보드 ----------
const kb = $('kb');
const SENTINEL = '  ';
const mods = new Set();
function resetKb() { kb.value = SENTINEL; try { kb.setSelectionRange(SENTINEL.length, SENTINEL.length); } catch {} }
function key(code, k) { sendCtl({ t: 'kd', c: code, k: k || '' }); sendCtl({ t: 'ku', c: code, k: k || '' }); }
function releaseMods() { for (const m of mods) sendCtl({ t: 'ku', c: m, k: '' }); mods.clear(); document.querySelectorAll('#keys [data-mod]').forEach((b) => b.classList.remove('on')); }
// 글자 보내기: Ctrl/Alt가 켜져 있으면 단축키로(예: Ctrl+C), 아니면 그대로 입력(한글 포함)
function typeText(s) {
  if (!s) return;
  if (mods.size && /^[a-z0-9]$/i.test(s)) { key(/\d/.test(s) ? 'Digit' + s : 'Key' + s.toUpperCase()); releaseMods(); return; }
  sendCtl({ t: 'text', v: s });
  if (mods.size) releaseMods();
}
let composing = false;
kb.addEventListener('compositionstart', () => { composing = true; });
kb.addEventListener('compositionend', (e) => { composing = false; typeText(e.data); resetKb(); });
kb.addEventListener('beforeinput', (e) => {
  if (composing || e.isComposing) return;
  if (e.inputType === 'insertText') { typeText(e.data); e.preventDefault(); resetKb(); }
  else if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') { key('Enter'); e.preventDefault(); resetKb(); }
  else if (e.inputType === 'deleteContentBackward') { key('Backspace'); e.preventDefault(); resetKb(); }
});
// 일부 키보드는 beforeinput을 막을 수 없어서 input에서 한 번 더 정리
kb.addEventListener('input', (e) => { if (!composing && !e.isComposing && kb.value !== SENTINEL) resetKb(); });
$('kbBtn').onclick = () => {
  const on = !$('kbBtn').classList.contains('on');
  $('kbBtn').classList.toggle('on', on); $('keys').classList.toggle('hidden', !on);
  if (on) { resetKb(); kb.focus(); } else { kb.blur(); releaseMods(); }
};
document.querySelectorAll('#keys button').forEach((b) => {
  b.addEventListener('pointerdown', (e) => e.preventDefault()); // 키보드가 닫히지 않게 포커스 유지
  b.onclick = () => {
    if (b.dataset.mod) {
      const m = b.dataset.mod;
      if (mods.has(m)) { mods.delete(m); sendCtl({ t: 'ku', c: m, k: '' }); b.classList.remove('on'); }
      else { mods.add(m); sendCtl({ t: 'kd', c: m, k: '' }); b.classList.add('on'); }
      return;
    }
    if (b.dataset.combo) { const [m, k] = b.dataset.combo.split('+'); sendCtl({ t: 'kd', c: m, k: '' }); key(k); sendCtl({ t: 'ku', c: m, k: '' }); return; }
    key(b.dataset.k, b.dataset.key);
    if (mods.size) releaseMods();
  };
});
// 휴대폰 키보드가 올라오면 특수키 줄을 키보드 바로 위로
if (window.visualViewport) {
  const place = () => { const vv = window.visualViewport; $('keys').style.bottom = Math.max(0, window.innerHeight - vv.height - vv.offsetTop) + 'px'; };
  visualViewport.addEventListener('resize', place); visualViewport.addEventListener('scroll', place);
}

// 화면을 벗어나면(다른 앱으로 전환 등) 눌린 키·버튼 정리
document.addEventListener('visibilitychange', () => { if (document.hidden) { releaseMods(); if (T.pressed) { sendCtl({ t: 'u', b: 0 }); T.pressed = false; } } });

renderList();
document.getElementById('appVersion').textContent = APP_VERSION;
document.getElementById('updateCheck').onclick = async () => { if (!(await checkUpdate(true))) {} };
document.getElementById('hardReload').onclick = () => applyUpdate();
checkUpdate(false);
// 서비스 워커: 크롬 '앱 설치' 지원 + 항상 최신 파일 받기
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
// 다시 앱으로 돌아왔을 때(원격 화면이 아닐 때만) 확인
document.addEventListener('visibilitychange', () => { if (!document.hidden && !pc) checkUpdate(false); });
