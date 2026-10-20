/* PrivRoom room page: chat, encrypted files, presence, call UI, and the v2 upgrades:
 *   - signed messages + verified senders        - "server's view" (ciphertext X-ray)
 *   - reactions and read receipts               - disappearing messages
 *   - burn room                                 - screen sharing
 * Everything that leaves this page for the server is encrypted first (see crypto.js).
 * All user-supplied text is rendered with textContent, never innerHTML.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const ROOM_RE = /^[A-Za-z0-9_-]{8,32}$/;
  const SECRET_RE = /^[A-Za-z0-9_-]{43}$/;
  const FILE_ID_RE = /^[a-f0-9]{32}$/;
  const PUBKEY_RE = /^[A-Za-z0-9_-]{87}$/;
  const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
  const REACTIONS = ['👍', '❤️', '😂', '🎉', '😮', '🙏'];
  const DEFAULT_TTLS = [30, 300, 3600];
  const MAX_FILE = 10 * 1024 * 1024;
  const MAX_TEXT = 4000;
  const MAX_FILES_AT_ONCE = 5;

  const roomId = location.pathname.split('/').filter(Boolean).pop() || '';
  const secret = location.hash.slice(1);

  const els = {
    app: $('app'),
    side: $('side'),
    sideBackdrop: $('sideBackdrop'),
    sideToggle: $('sideToggle'),
    invite: $('inviteLink'),
    copy: $('copyInvite'),
    safety: $('safetyCode'),
    members: $('members'),
    memberCount: $('memberCount'),
    btnSound: $('btnMuteSound'),
    soundIcon: $('soundIcon'),
    soundLabel: $('soundLabel'),
    roomLabel: $('roomLabel'),
    status: $('statusPill'),
    callBadge: $('callBadge'),
    btnVoice: $('btnVoice'),
    btnVideo: $('btnVideo'),
    btnXray: $('btnXray'),
    xrayBanner: $('xrayBanner'),
    btnBurn: $('btnBurn'),
    burnDialog: $('burnDialog'),
    stage: $('callStage'),
    grid: $('grid'),
    btnMute: $('btnMute'),
    btnCam: $('btnCam'),
    btnShare: $('btnShare'),
    btnLeave: $('btnLeave'),
    dropZone: $('dropZone'),
    dropHint: $('dropHint'),
    messages: $('messages'),
    typing: $('typing'),
    composer: $('composer'),
    attach: $('attach'),
    fileInput: $('fileInput'),
    ttl: $('ttlSelect'),
    text: $('textInput'),
    send: $('sendBtn'),
    nameDialog: $('nameDialog'),
    nameInput: $('nameInput'),
  };

  const state = {
    key: null,
    name: '',
    sign: null, // { priv, pub, fp }: my signing identity in this room
    socket: null,
    myId: null,
    soundMuted: false,
    members: new Map(), // socket id -> { name, pk, fp, conflict }
    fpByName: new Map(), // display name -> fingerprint first seen for it (trust on first use)
    typing: new Map(),
    callMembers: [],
    call: null,
    tiles: new Map(),
    screens: new Set(), // ids of remote people currently presenting (the notice can arrive before their tile exists)
    typingSent: false,
    typingTimer: null,
    pinned: true, // is the message list scrolled to the bottom?
    maxFile: MAX_FILE,
    // message bookkeeping (reset whenever the view is rebuilt)
    gen: 0, // bumps on rebuild so stale async renders can bail out
    chain: Promise.resolve(), // messages are processed strictly in order
    seq: 0,
    rowsById: new Map(), // server message id -> row entry
    ownRows: [],
    reactions: new Map(), // msg id -> emoji -> person fp -> { on, idx, name }
    seenUpTo: new Map(), // person fp -> { name, idx }
    expiring: new Set(),
    urls: new Set(),
    skew: 0, // server clock minus my clock
    ttlSet: new Set(DEFAULT_TTLS),
    lastMsgId: null,
    lastSeenSent: null,
    seenTimer: null,
    burned: false,
  };

  // ------------------------------------------------------------------ boot
  function fatal(msg, title) {
    $('fatalTitle').textContent = title || "Can't open this room";
    $('fatalMsg').textContent = msg;
    $('fatal').hidden = false;
    els.app.hidden = true;
  }

  if (!ROOM_RE.test(roomId) || !SECRET_RE.test(secret)) {
    fatal('This link is incomplete. Invite links look like /room/ID#KEY. Make sure you copied everything, including the part after the # sign.');
    return;
  }
  if (!window.isSecureContext || !(window.crypto && window.crypto.subtle)) {
    fatal('Your browser blocked encryption on this page. Open the app via http://localhost:3000 or an https:// address.');
    return;
  }

  boot().catch((e) => fatal(e && e.message ? e.message : String(e)));

  async function boot() {
    const keys = await PR.deriveKeys(secret, roomId);
    state.key = keys.key;
    els.safety.textContent = keys.safetyCode;
    els.invite.value = location.origin + location.pathname + '#' + secret;
    els.roomLabel.textContent = 'Room ' + roomId.slice(0, 6);
    try {
      state.soundMuted = localStorage.getItem('privroom-sound-muted') === '1';
    } catch {
      state.soundMuted = false;
    }
    updateSoundUi();
    wireUi();
    state.name = await askName();
    state.sign = await loadSigningKeys();
    setInterval(tickExpiry, 1000);
    connect();
  }

  function askName() {
    return new Promise((resolve) => {
      let saved = '';
      try { saved = localStorage.getItem('privroom-name') || ''; } catch { /* storage unavailable */ }
      els.nameInput.value = saved;
      els.nameDialog.addEventListener(
        'close',
        () => {
          const n = els.nameInput.value.trim().slice(0, 32) || 'Guest ' + Math.floor(1000 + Math.random() * 9000);
          try { localStorage.setItem('privroom-name', n); } catch { /* ignore */ }
          resolve(n);
        },
        { once: true }
      );
      els.nameDialog.showModal();
      els.nameInput.focus();
      els.nameInput.select();
    });
  }

  // ---- signing identity: one key pair per (room, display name), kept in IndexedDB so a page
  //      refresh keeps your identity. The private key is non-extractable.
  function idb() {
    return new Promise((resolve, reject) => {
      const r = indexedDB.open('privroom', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('keys');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }
  async function idbGet(k) {
    const db = await idb();
    return new Promise((resolve, reject) => {
      const q = db.transaction('keys').objectStore('keys').get(k);
      q.onsuccess = () => resolve(q.result);
      q.onerror = () => reject(q.error);
    });
  }
  async function idbSet(k, v) {
    const db = await idb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').put(v, k);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  async function loadSigningKeys() {
    const id = roomId + ':' + state.name;
    let keys = null;
    try { keys = await idbGet(id); } catch { /* storage unavailable (private mode): fall back to memory */ }
    if (!keys || !keys.priv || !PUBKEY_RE.test(keys.pub || '')) {
      keys = await PR.generateSigningKeys();
      try { await idbSet(id, { priv: keys.priv, pub: keys.pub }); } catch { /* ignore */ }
    }
    return { priv: keys.priv, pub: keys.pub, fp: await PR.keyFingerprint(keys.pub) };
  }

  // ------------------------------------------------------------------ socket
  function connect() {
    const socket = io({ transports: ['websocket', 'polling'] });
    state.socket = socket;
    state.call = new PRCall.CallManager({
      socket,
      seal: (o) => PR.encryptJSON(state.key, o),
      open: (b) => PR.decryptJSON(state.key, b),
      hooks: { onLocal, onRemote, onRemoteGone, onEnded, onLocalScreen, onRemoteScreen },
    });

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', () => { if (!state.burned) setStatus('Server unreachable, retrying…', 'err'); });

    socket.on('member:join', async ({ id, name }) => {
      const m = await readMember(name);
      m.conflict = !registerIdentity(m.name, m.fp);
      state.members.set(id, m);
      renderMembers();
      notice(m.name + ' joined' + (m.conflict ? ' (⚠ this name is already used by a different key)' : ''));
    });
    socket.on('member:leave', ({ id }) => {
      const m = state.members.get(id);
      state.members.delete(id);
      clearTypingFor(id);
      renderMembers();
      if (m) notice(m.name + ' left');
    });
    socket.on('message', (msg) => {
      clearTypingFor(msg.from);
      addMessageRow(msg, true);
    });
    socket.on('ctl', onCtl);
    socket.on('typing', onTyping);
    socket.on('room:burned', onBurned);
    socket.on('call:state', ({ members }) => {
      state.callMembers = Array.isArray(members) ? members : [];
      updateCallUi();
      renderMembers();
    });
    socket.on('call:signal', (sig) => state.call.handleSignal(sig));
    socket.on('call:peer-left', ({ id }) => state.call.peerLeft(id));
  }

  async function onConnect() {
    setStatus('Joining…', 'warn');
    const nameBox = await PR.encryptJSON(state.key, { n: state.name, pk: state.sign.pub });
    state.socket.emit('join', { room: roomId, name: nameBox }, async (res) => {
      if (!res || !res.ok) {
        fatal((res && res.error) || 'Could not join the room.');
        state.socket.disconnect();
        return;
      }
      state.myId = res.id;
      if (res.limits && res.limits.maxFileBytes) state.maxFile = Math.min(MAX_FILE, res.limits.maxFileBytes);
      state.ttlSet = new Set((res.limits && res.limits.ttl) || DEFAULT_TTLS);
      state.skew = typeof res.now === 'number' ? res.now - Date.now() : 0;

      // Rebuild the view from the server's snapshot (also handles reconnects).
      resetView();
      state.members.clear();
      registerIdentity(state.name, state.sign.fp); // mine first, so nobody can pre-claim my name in my own view
      state.members.set(res.id, { name: state.name, pk: state.sign.pub, fp: state.sign.fp, me: true });
      for (const m of res.history) addMessageRow(m, false);
      state.callMembers = Array.isArray(res.call) ? res.call : [];
      renderMembers();
      updateCallUi();
      enableComposer(true);
      setStatus('End-to-end encrypted', 'ok');

      const others = await Promise.all(res.members.map(async (m) => ({ id: m.id, info: await readMember(m.name) })));
      for (const { id, info } of others) { // join order = older members register their names first
        info.conflict = !registerIdentity(info.name, info.fp);
        state.members.set(id, info);
      }
      renderMembers();
      refreshTileLabels();
    });
  }

  function onDisconnect() {
    if (state.burned) return;
    setStatus('Reconnecting…', 'warn');
    enableComposer(false);
    if (state.call && state.call.joined) {
      state.call.leave(false);
      notice('Call ended because the connection was lost.', 'err');
    }
  }

  function resetView() {
    state.gen++;
    state.chain = Promise.resolve();
    state.seq = 0;
    state.rowsById.clear();
    state.ownRows = [];
    state.reactions.clear();
    state.seenUpTo.clear();
    state.expiring.clear();
    state.lastMsgId = null;
    state.lastSeenSent = null;
    state.pinned = true;
    state.typing.clear();
    renderTyping();
    els.messages.textContent = '';
  }

  // ------------------------------------------------------------------ UI wiring
  function wireUi() {
    els.copy.addEventListener('click', copyInvite);
    els.invite.addEventListener('focus', () => els.invite.select());

    els.sideToggle.addEventListener('click', () => {
      const open = els.side.classList.toggle('open');
      els.sideToggle.setAttribute('aria-expanded', String(open));
      if (els.sideBackdrop) els.sideBackdrop.classList.toggle('open', open);
    });
    if (els.sideBackdrop) {
      els.sideBackdrop.addEventListener('click', () => {
        els.side.classList.remove('open');
        els.sideToggle.setAttribute('aria-expanded', 'false');
        els.sideBackdrop.classList.remove('open');
      });
    }
    document.querySelector('.main').addEventListener('click', (e) => {
      if (els.side.classList.contains('open') && !e.target.closest('#sideToggle')) {
        els.side.classList.remove('open');
        els.sideToggle.setAttribute('aria-expanded', 'false');
        if (els.sideBackdrop) els.sideBackdrop.classList.remove('open');
      }
    });
    document.addEventListener('click', closePickers);
    document.addEventListener('visibilitychange', maybeSendSeen);
    window.addEventListener('focus', maybeSendSeen);

    els.messages.addEventListener('scroll', () => {
      state.pinned = nearBottom();
      if (state.pinned) maybeSendSeen();
    });

    els.composer.addEventListener('submit', (e) => {
      e.preventDefault();
      sendText();
    });
    els.text.addEventListener('input', onInput);
    els.text.addEventListener('paste', (e) => {
      const files = e.clipboardData && e.clipboardData.files;
      if (files && files.length) {
        e.preventDefault();
        sendFiles(files);
      }
    });
    els.ttl.addEventListener('change', () => els.ttl.classList.toggle('on', els.ttl.value !== '0'));

    els.attach.addEventListener('click', () => els.fileInput.click());
    els.fileInput.addEventListener('change', () => {
      sendFiles(els.fileInput.files);
      els.fileInput.value = '';
    });

    const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
    ['dragenter', 'dragover'].forEach((ev) =>
      els.dropZone.addEventListener(ev, (e) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        els.dropHint.hidden = false;
      })
    );
    els.dropZone.addEventListener('dragleave', (e) => {
      if (!els.dropZone.contains(e.relatedTarget)) els.dropHint.hidden = true;
    });
    els.dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      els.dropHint.hidden = true;
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) sendFiles(e.dataTransfer.files);
    });

    els.btnXray.addEventListener('click', () => {
      const on = document.body.classList.toggle('xray-on');
      els.btnXray.setAttribute('aria-pressed', String(on));
      els.xrayBanner.hidden = !on;
    });

    els.btnBurn.addEventListener('click', () => els.burnDialog.showModal());
    els.burnDialog.addEventListener('close', () => {
      if (els.burnDialog.returnValue === 'burn') {
        state.socket.emit('room:burn', {}, (res) => {
          if (!res || !res.ok) notice('Could not burn the room.', 'err');
        });
      }
      els.burnDialog.returnValue = '';
    });

    els.btnVoice.addEventListener('click', () => startCall(false));
    els.btnVideo.addEventListener('click', () => startCall(true));
    els.btnLeave.addEventListener('click', () => state.call.leave(true));
    els.btnMute.addEventListener('click', () => {
      const m = state.call.setMuted(!state.call.muted);
      els.btnMute.setAttribute('aria-pressed', String(m));
      els.btnMute.textContent = m ? '🔇 Unmute' : '🎙️ Mute';
    });
    els.btnCam.addEventListener('click', () => {
      const off = state.call.setCameraOff(!state.call.camOff);
      els.btnCam.setAttribute('aria-pressed', String(off));
      els.btnCam.textContent = off ? '📷 Camera on' : '📷 Camera off';
    });
    els.btnShare.addEventListener('click', async () => {
      els.btnShare.disabled = true;
      try {
        if (state.call.screen) await state.call.stopScreenShare();
        else await state.call.startScreenShare();
      } catch (e) {
        notice(e.message || 'Screen sharing failed.', 'err');
      } finally {
        els.btnShare.disabled = false;
        updateShareButton();
      }
    });

    if (els.btnSound) els.btnSound.addEventListener('click', toggleSound);
    document.addEventListener('click', unlockAudio, { passive: true });
    document.addEventListener('keydown', unlockAudio, { passive: true });
    document.addEventListener('touchstart', unlockAudio, { passive: true });
  }

  // ------------------------------------------------------------------ notification sound
  let audioCtx = null;
  function getAudioContext() {
    if (!audioCtx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) audioCtx = new AudioCtx();
    }
    return audioCtx;
  }

  function unlockAudio() {
    const ctx = getAudioContext();
    if (ctx && ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
  }

  function playNotificationSound() {
    if (state.soundMuted) return;
    try {
      const ctx = getAudioContext();
      if (!ctx) return;
      if (ctx.state === 'suspended') {
        ctx.resume().catch(() => {});
      }
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      // Gentle two-tone notification chime: 587.33 Hz (D5) -> 880 Hz (A5)
      osc.frequency.setValueAtTime(587.33, now);
      osc.frequency.setValueAtTime(880, now + 0.08);

      gain.gain.setValueAtTime(0.001, now);
      gain.gain.linearRampToValueAtTime(0.18, now + 0.015);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.25);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now);
      osc.stop(now + 0.25);
    } catch {
      // Best-effort notification audio
    }
  }

  function updateSoundUi() {
    if (!els.btnSound) return;
    const muted = !!state.soundMuted;
    els.btnSound.setAttribute('aria-pressed', String(muted));
    if (els.soundIcon) els.soundIcon.textContent = muted ? '🔕' : '🔔';
    if (els.soundLabel) els.soundLabel.textContent = muted ? 'Sound muted' : 'Sound on';
    els.btnSound.title = muted
      ? 'Notification sound is muted (click to unmute)'
      : 'Notification sound is on (click to mute)';
  }

  function toggleSound() {
    unlockAudio();
    state.soundMuted = !state.soundMuted;
    try {
      localStorage.setItem('privroom-sound-muted', state.soundMuted ? '1' : '0');
    } catch { /* storage unavailable */ }
    updateSoundUi();
  }

  async function copyInvite() {
    const link = els.invite.value;
    try {
      await navigator.clipboard.writeText(link);
    } catch {
      els.invite.select();
      document.execCommand('copy');
    }
    els.copy.textContent = 'Copied ✓';
    setTimeout(() => { els.copy.textContent = 'Copy'; }, 1500);
  }

  function setStatus(text, kind) {
    els.status.textContent = text;
    els.status.className = 'pill ' + (kind || '');
  }

  function enableComposer(on) {
    els.text.disabled = !on;
    els.send.disabled = !on;
    els.attach.disabled = !on;
    els.ttl.disabled = !on;
    els.btnBurn.disabled = !on;
    els.btnVoice.disabled = !on;
    els.btnVideo.disabled = !on;
    if (on) els.text.focus();
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function initial(name) {
    const ch = Array.from(String(name || '').trim())[0];
    return ch ? ch.toUpperCase() : '?';
  }

  // ------------------------------------------------------------------ identities
  /** Decrypt a member's join box: { n: name, pk: signing public key }. */
  async function readMember(box) {
    try {
      const p = await PR.decryptJSON(state.key, box);
      const name = String((p && p.n) || 'Guest').slice(0, 32);
      let pk = '';
      let fp = '';
      if (p && typeof p.pk === 'string' && PUBKEY_RE.test(p.pk)) {
        try { fp = await PR.keyFingerprint(p.pk); pk = p.pk; } catch { /* invalid key: treat as unsigned */ }
      }
      return { name, pk, fp, conflict: false };
    } catch {
      return { name: 'Unknown (wrong key)', pk: '', fp: '', conflict: false };
    }
  }

  /** Trust on first use: the first key seen for a name owns it. Returns false on a clash. */
  function registerIdentity(name, fp) {
    if (!fp) return true;
    const known = state.fpByName.get(name);
    if (!known) {
      state.fpByName.set(name, fp);
      return true;
    }
    return known === fp;
  }

  const fpCache = new Map();
  async function fingerprintOf(pk) {
    let f = fpCache.get(pk);
    if (!f) {
      f = await PR.keyFingerprint(pk);
      if (fpCache.size > 200) fpCache.clear();
      fpCache.set(pk, f);
    }
    return f;
  }

  /** Verify a decrypted payload's signature and check the claimed name against what we know. */
  async function checkSender(p) {
    if (!p || typeof p !== 'object' || !(await PR.verifyMessage(roomId, p))) return { status: 'invalid' };
    const fp = await fingerprintOf(p.pk);
    const name = String(p.n || 'Someone').slice(0, 32);
    return { status: registerIdentity(name, fp) ? 'ok' : 'impersonation', fp, name };
  }

  const nameOf = (id) => (state.members.get(id) || {}).name || 'Someone';

  function renderMembers() {
    els.members.textContent = '';
    for (const [id, m] of state.members) {
      const li = document.createElement('li');
      const av = el('span', 'avatar', initial(m.name));
      const who = el('span', 'who');
      who.append(el('span', 'nm', m.name + (id === state.myId ? ' (you)' : '')));
      who.append(
        el(
          'span',
          'fp' + (m.conflict || !m.fp ? ' warn' : ''),
          m.fp ? (m.conflict ? '⚠ ' + m.fp + ' · name already used by another key' : '🔑 ' + m.fp) : 'unsigned client'
        )
      );
      li.append(av, who);
      if (state.callMembers.includes(id)) li.append(el('span', 'tag', '📞 in call'));
      els.members.appendChild(li);
    }
    els.memberCount.textContent = String(state.members.size);
  }

  // ------------------------------------------------------------------ messages
  const nearBottom = () => els.messages.scrollHeight - els.messages.scrollTop - els.messages.clientHeight < 120;
  const scrollDown = () => { els.messages.scrollTop = els.messages.scrollHeight; };

  function notice(text, kind) {
    const d = el('div', 'sys' + (kind === 'err' ? ' err' : ''), text);
    els.messages.appendChild(d);
    if (state.pinned) scrollDown();
    return d;
  }

  /** What the server holds for this message: only ciphertext (plus an optional expiry time). */
  function buildXray(msg) {
    const d = el('div', 'xray');
    const ct = msg.body.ct;
    d.append(el('b', '', 'SERVER HOLDS  '));
    d.append(
      document.createTextNode(
        'iv ' + msg.body.iv + ' · ct ' + ct.slice(0, 56) + '… (' + ct.length + ' chars ≈ ' + Math.ceil((ct.length * 3) / 4) + ' bytes)' +
          (msg.exp ? ' · plaintext metadata: deletes itself at ' + new Date(msg.exp).toLocaleTimeString() : '')
      )
    );
    return d;
  }

  function addMessageRow(msg, isLive = false) {
    const gen = state.gen;
    const stick = state.pinned;
    const entry = { id: msg.id, idx: state.seq++, row: el('div', 'msg'), urls: [], own: false, isLive: !!isLive };
    entry.meta = el('div', 'meta');
    entry.wrap = el('div', 'bubble-wrap');
    entry.bubble = el('div', 'bubble', 'Decrypting…');
    entry.wrap.append(entry.bubble);
    entry.chips = el('div', 'chips');
    entry.receipt = el('div', 'receipt');
    entry.xray = buildXray(msg);
    entry.row.append(entry.meta, entry.wrap, entry.chips, entry.receipt, entry.xray);
    state.rowsById.set(msg.id, entry);
    els.messages.appendChild(entry.row); // appended synchronously so order is preserved
    if (stick) scrollDown();
    state.chain = state.chain
      .then(() => (gen === state.gen ? fillMessage(entry, msg, gen) : null))
      .then(() => { if (stick && gen === state.gen) scrollDown(); })
      .catch((e) => console.warn('render error', e));
  }

  async function fillMessage(entry, msg, gen) {
    const { row, meta, bubble } = entry;
    const time = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    let p;
    try {
      p = await PR.decryptJSON(state.key, msg.body);
    } catch {
      if (gen !== state.gen) return;
      bubble.className = 'bubble bad';
      bubble.textContent = '🔒 Could not decrypt this message (different key?)';
      meta.textContent = time;
      return;
    }
    if (gen !== state.gen) return;

    if (p && p.k === 'r') { // a reaction: no bubble of its own, only a chip on its target
      row.className = 'msg rx';
      while (row.firstChild) row.removeChild(row.firstChild);
      row.appendChild(entry.xray);
      state.rowsById.delete(msg.id);
      await handleReaction(entry, p);
      return;
    }

    const v = await checkSender(p);
    if (gen !== state.gen) return;
    if (v.status === 'invalid') {
      bubble.className = 'bubble bad';
      bubble.textContent = '⚠ Could not verify who sent this message, so it is not shown.';
      meta.textContent = time;
      return;
    }

    const mine = v.fp === state.sign.fp;
    entry.own = mine;
    if (mine) row.classList.add('mine');
    meta.textContent = (mine ? 'You' : v.name) + ' · ' + time;
    const badge = el('span', 'badge ' + (v.status === 'ok' ? 'ok' : 'warn'), v.status === 'ok' ? '✓' : '⚠');
    badge.title = v.status === 'ok' ? 'Signed with key ' + v.fp : 'Signed with key ' + v.fp + ', but this name was first used by a different key';
    meta.append(badge);
    if (v.status === 'impersonation') {
      row.classList.add('suspect');
      row.insertBefore(el('div', 'warnline', '⚠ "' + v.name + '" is already used by a different key. Compare fingerprints before trusting this.'), entry.wrap);
    }

    if (p.k === 't' && typeof p.t === 'string') {
      bubble.textContent = p.t.slice(0, MAX_TEXT);
    } else if (p.k === 'f' && FILE_ID_RE.test(String(p.id)) && typeof p.fn === 'string') {
      buildFile(entry, p);
    } else {
      bubble.className = 'bubble bad';
      bubble.textContent = 'Unsupported message';
      return;
    }

    addReactionPicker(entry);
    renderChips(entry.id);
    if (mine) {
      state.ownRows.push(entry);
      renderReceipts();
    } else {
      state.lastMsgId = entry.id;
      maybeSendSeen();
      if (entry.isLive) {
        playNotificationSound();
      }
    }
    trackExpiry(entry, p, msg);
  }

  /** Every message, reaction and file descriptor is signed, then encrypted, then sent. */
  async function sendSigned(base, ttl) {
    const p = { ...base, n: state.name, ts: Date.now(), pk: state.sign.pub };
    if (ttl) p.x = ttl;
    p.sig = await PR.signMessage(state.sign.priv, roomId, p);
    const box = await PR.encryptJSON(state.key, p);
    state.socket.emit('message', ttl ? { ...box, ttl } : box);
  }

  function currentTtl() {
    const t = Number(els.ttl.value) || 0;
    return t && state.ttlSet.has(t) ? t : 0;
  }

  function sendText() {
    const t = els.text.value.trim().slice(0, MAX_TEXT);
    if (!t || !state.socket || !state.socket.connected) return;
    els.text.value = '';
    stopTyping();
    sendSigned({ k: 't', t }, currentTtl()).catch(() => notice('Could not encrypt that message.', 'err'));
  }

  // ------------------------------------------------------------------ reactions
  function closePickers() {
    document.querySelectorAll('.picker').forEach((p) => { p.hidden = true; });
  }

  function addReactionPicker(entry) {
    const btn = el('button', 'react-btn', '☺');
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Add a reaction');
    const picker = el('div', 'picker');
    picker.hidden = true;
    for (const e of REACTIONS) {
      const b = el('button', '', e);
      b.type = 'button';
      b.addEventListener('click', (ev) => {
        ev.stopPropagation();
        picker.hidden = true;
        toggleReaction(entry.id, e);
      });
      picker.append(b);
    }
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      const wasOpen = !picker.hidden;
      closePickers();
      picker.hidden = wasOpen;
    });
    entry.wrap.append(btn, picker);
  }

  function toggleReaction(targetId, emoji) {
    if (!state.socket || !state.socket.connected) return;
    const cur = state.reactions.get(targetId)?.get(emoji)?.get(state.sign.fp);
    sendSigned({ k: 'r', m: targetId, e: emoji, on: !(cur && cur.on) }, 0).catch(() => notice('Could not send that reaction.', 'err'));
  }

  async function handleReaction(entry, p) {
    const v = await checkSender(p);
    if (v.status === 'invalid') return; // forged or damaged reactions are ignored
    if (typeof p.m !== 'string' || !REACTIONS.includes(p.e)) return;
    let byEmoji = state.reactions.get(p.m);
    if (!byEmoji) state.reactions.set(p.m, (byEmoji = new Map()));
    let byWho = byEmoji.get(p.e);
    if (!byWho) byEmoji.set(p.e, (byWho = new Map()));
    const prev = byWho.get(v.fp);
    if (!prev || entry.idx > prev.idx) byWho.set(v.fp, { on: p.on === true, idx: entry.idx, name: v.name }); // latest wins
    renderChips(p.m);
  }

  function renderChips(targetId) {
    const target = state.rowsById.get(targetId);
    if (!target) return;
    target.chips.textContent = '';
    const byEmoji = state.reactions.get(targetId);
    if (!byEmoji) return;
    for (const emoji of REACTIONS) {
      const byWho = byEmoji.get(emoji);
      if (!byWho) continue;
      const people = [...byWho.entries()].filter(([, v]) => v.on);
      if (!people.length) continue;
      const chip = el('button', 'chip' + (people.some(([fp]) => fp === state.sign.fp) ? ' mine' : ''), emoji + ' ' + people.length);
      chip.type = 'button';
      chip.title = people.map(([, v]) => v.name).join(', ');
      chip.addEventListener('click', () => toggleReaction(targetId, emoji));
      target.chips.append(chip);
    }
  }

  // ------------------------------------------------------------------ read receipts
  function maybeSendSeen() {
    if (document.visibilityState !== 'visible' || !state.pinned || !state.socket || !state.socket.connected) return;
    clearTimeout(state.seenTimer);
    state.seenTimer = setTimeout(async () => {
      const last = state.lastMsgId;
      if (!last || last === state.lastSeenSent || !state.socket.connected) return;
      state.lastSeenSent = last;
      const box = await PR.encryptJSON(state.key, { k: 'seen', m: last, n: state.name, f: state.sign.fp });
      state.socket.emit('ctl', box); // relayed, never stored
    }, 300);
  }

  async function onCtl({ from, body }) {
    let p;
    try { p = await PR.decryptJSON(state.key, body); } catch { return; }
    if (!p || p.k !== 'seen' || typeof p.m !== 'string') return;
    const target = state.rowsById.get(p.m);
    if (!target) return;
    const who = typeof p.f === 'string' ? p.f : from;
    if (who === state.sign.fp) return;
    const prev = state.seenUpTo.get(who);
    if (!prev || target.idx > prev.idx) state.seenUpTo.set(who, { name: String(p.n || 'Someone').slice(0, 32), idx: target.idx });
    renderReceipts();
  }

  function renderReceipts() {
    const own = state.ownRows.filter((e) => e.row.isConnected);
    own.forEach((e) => { e.receipt.textContent = ''; });
    const last = own[own.length - 1];
    if (!last) return;
    const names = [...state.seenUpTo.values()].filter((v) => v.idx >= last.idx).map((v) => v.name);
    last.receipt.textContent = names.length ? '👁 Seen by ' + names.join(', ') : '✓ Delivered';
  }

  // ------------------------------------------------------------------ disappearing messages
  function fmtLeft(ms) {
    const s = Math.max(0, Math.ceil(ms / 1000));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  }

  function trackExpiry(entry, p, msg) {
    const x = Number(p.x);
    if (!x || !state.ttlSet.has(x)) return;
    const badge = el('div', 'ttl-badge');
    entry.row.insertBefore(badge, entry.xray);
    state.expiring.add({ entry, at: msg.ts + x * 1000 - state.skew, badge });
    tickExpiry();
  }

  function removeEntry(entry) {
    entry.urls.forEach((u) => { URL.revokeObjectURL(u); state.urls.delete(u); });
    entry.row.remove();
    state.rowsById.delete(entry.id);
    state.reactions.delete(entry.id);
    state.ownRows = state.ownRows.filter((e) => e !== entry);
    renderReceipts();
  }

  function tickExpiry() {
    const now = Date.now();
    for (const item of Array.from(state.expiring)) {
      const left = item.at - now;
      if (left <= 0) {
        state.expiring.delete(item);
        removeEntry(item.entry);
      } else {
        item.badge.textContent = '⏳ disappears in ' + fmtLeft(left);
      }
    }
  }

  // ------------------------------------------------------------------ burn
  function wipeLocal() {
    state.gen++;
    state.expiring.clear();
    state.urls.forEach((u) => URL.revokeObjectURL(u));
    state.urls.clear();
    state.rowsById.clear();
    state.reactions.clear();
    state.ownRows = [];
    els.messages.textContent = '';
    els.members.textContent = '';
  }

  function onBurned({ by }) {
    if (state.burned) return;
    state.burned = true;
    const who = by === state.myId ? 'You' : nameOf(by);
    if (state.call && state.call.joined) state.call.leave(false);
    wipeLocal();
    state.socket.disconnect();
    fatal(
      who + ' burned this room. Every message and file was deleted from the server. Copies already saved on devices (downloads, screenshots) are not affected.',
      '🔥 Room burned'
    );
  }

  // ------------------------------------------------------------------ typing
  function onInput() {
    if (!state.socket || !state.socket.connected) return;
    if (!state.typingSent) {
      state.typingSent = true;
      state.socket.emit('typing', true);
    }
    clearTimeout(state.typingTimer);
    state.typingTimer = setTimeout(stopTyping, 2000);
  }

  function stopTyping() {
    clearTimeout(state.typingTimer);
    if (state.typingSent) {
      state.typingSent = false;
      if (state.socket && state.socket.connected) state.socket.emit('typing', false);
    }
  }

  function onTyping({ id, on }) {
    const prev = state.typing.get(id);
    if (prev) clearTimeout(prev.t);
    if (on) {
      state.typing.set(id, { t: setTimeout(() => { state.typing.delete(id); renderTyping(); }, 4000) });
    } else {
      state.typing.delete(id);
    }
    renderTyping();
  }

  function clearTypingFor(id) {
    const prev = state.typing.get(id);
    if (prev) clearTimeout(prev.t);
    state.typing.delete(id);
    renderTyping();
  }

  function renderTyping() {
    const names = Array.from(state.typing.keys()).map(nameOf);
    els.typing.textContent =
      names.length === 0 ? '' :
      names.length === 1 ? names[0] + ' is typing…' :
      names.slice(0, 2).join(' and ') + (names.length > 2 ? ' and others' : '') + ' are typing…';
  }

  // ------------------------------------------------------------------ files
  const fmtSize = (n) =>
    n < 1024 ? n + ' B' : n < 1024 * 1024 ? (n / 1024).toFixed(1) + ' KB' : (n / 1024 / 1024).toFixed(1) + ' MB';

  const safeFilename = (n) => String(n || 'file').replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 120) || 'file';

  async function fetchDecrypted(fileId) {
    const res = await fetch('/api/file/' + roomId + '/' + fileId, {
      headers: { 'x-sid': state.myId || '' },
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(res.status === 404 ? 'File expired or missing' : 'Download failed (' + res.status + ')');
    return PR.decryptBytes(state.key, new Uint8Array(await res.arrayBuffer()));
  }

  function buildFile(entry, p) {
    const bubble = entry.bubble;
    bubble.className = 'bubble file';
    bubble.textContent = '';
    const size = Number(p.fs) || 0;
    const isImage = IMAGE_TYPES.has(p.ft) && size <= MAX_FILE; // whitelist: never render SVG/HTML

    if (isImage) {
      const img = el('img', 'thumb');
      img.alt = safeFilename(p.fn);
      bubble.appendChild(img);
      loadImage(entry, img, p);
    }

    const info = el('div', 'file-info');
    const label = el('div');
    label.append(el('div', 'nm', '📄 ' + safeFilename(p.fn)), el('div', 'sz', fmtSize(size) + ' · encrypted'));
    const btn = el('button', 'btn', 'Download');
    btn.type = 'button';
    btn.addEventListener('click', () => download(p, btn));
    info.append(label, btn);
    bubble.appendChild(info);
  }

  async function loadImage(entry, img, p) {
    try {
      const bytes = await fetchDecrypted(p.id);
      const url = URL.createObjectURL(new Blob([bytes], { type: p.ft }));
      entry.urls.push(url);
      state.urls.add(url);
      img.addEventListener('load', () => { if (state.pinned) scrollDown(); }, { once: true });
      img.addEventListener('click', () => window.open(url, '_blank', 'noopener'));
      img.src = url;
    } catch (e) {
      img.replaceWith(el('div', 'sz', 'Preview unavailable: ' + e.message));
    }
  }

  async function download(p, btn) {
    btn.disabled = true;
    btn.textContent = 'Decrypting…';
    try {
      const bytes = await fetchDecrypted(p.id);
      const type = IMAGE_TYPES.has(p.ft) ? p.ft : 'application/octet-stream';
      const url = URL.createObjectURL(new Blob([bytes], { type }));
      const a = document.createElement('a');
      a.href = url;
      a.download = safeFilename(p.fn);
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      btn.textContent = 'Download again';
    } catch (e) {
      btn.textContent = 'Failed, retry';
      notice(e.message, 'err');
    } finally {
      btn.disabled = false;
    }
  }

  async function sendFiles(list) {
    const files = Array.from(list).slice(0, MAX_FILES_AT_ONCE);
    for (const f of files) await sendFile(f);
  }

  async function sendFile(file) {
    if (!state.socket || !state.socket.connected) return;
    if (file.size === 0) return notice(file.name + ' is empty.', 'err');
    if (file.size > state.maxFile) return notice(file.name + ' is too large (max ' + fmtSize(state.maxFile) + ').', 'err');

    const ttl = currentTtl();
    const note = notice('Encrypting & uploading ' + file.name + '…');
    try {
      const sealed = await PR.encryptBytes(state.key, new Uint8Array(await file.arrayBuffer()));
      const headers = { 'content-type': 'application/octet-stream', 'x-sid': state.myId || '' };
      if (ttl) headers['x-ttl'] = String(ttl); // the server deletes the blob when the message expires
      const res = await fetch('/api/upload/' + roomId, { method: 'POST', headers, body: sealed });
      if (!res.ok) {
        let reason = 'status ' + res.status;
        try { reason = (await res.json()).error || reason; } catch { /* not JSON */ }
        throw new Error(reason);
      }
      const { id } = await res.json();
      await sendSigned({ k: 'f', id, fn: file.name.slice(0, 200), ft: file.type || 'application/octet-stream', fs: file.size }, ttl);
    } catch (e) {
      notice('Upload failed: ' + (e.message || e), 'err');
    } finally {
      note.remove();
    }
  }

  // ------------------------------------------------------------------ calls
  function updateCallUi() {
    if (!state.call) return;
    const n = state.callMembers.length;
    const inCall = state.call.joined;
    els.callBadge.hidden = n === 0 || inCall;
    els.callBadge.textContent = '● Call in progress (' + n + ')';
    els.btnVoice.hidden = inCall;
    els.btnVideo.hidden = inCall;
    els.btnVoice.textContent = n > 0 ? '🎤 Join voice' : '🎤 Voice call';
    els.btnVideo.textContent = n > 0 ? '📹 Join video' : '📹 Video call';
  }

  function updateShareButton() {
    const on = !!(state.call && state.call.screen);
    els.btnShare.setAttribute('aria-pressed', String(on));
    els.btnShare.textContent = on ? '🛑 Stop sharing' : '🖥️ Share screen';
    els.btnShare.hidden = !(state.call && state.call.canShareScreen);
  }

  async function startCall(withVideo) {
    els.btnVoice.disabled = true;
    els.btnVideo.disabled = true;
    try {
      await state.call.join(withVideo);
    } catch (e) {
      notice(e.message || 'Could not start the call.', 'err');
    } finally {
      const online = !!(state.socket && state.socket.connected);
      els.btnVoice.disabled = !online;
      els.btnVideo.disabled = !online;
      updateCallUi();
    }
  }

  function addTile(id, label, stream, local) {
    let t = state.tiles.get(id);
    if (!t) {
      const tile = el('div', 'tile' + (local ? ' local' : ''));
      const av = el('span', 'avatar');
      const video = document.createElement('video');
      video.autoplay = true;
      video.playsInline = true;
      if (local) video.muted = true; // never play your own microphone back to yourself
      const lb = el('span', 'label');
      tile.append(av, video, lb);
      els.grid.appendChild(tile);
      t = { el: tile, video, av, lb };
      state.tiles.set(id, t);
    }
    if (t.video.srcObject !== stream) t.video.srcObject = stream;
    t.lb.textContent = label;
    t.av.textContent = initial(label);
    const hasVideo = stream.getVideoTracks().some((tr) => tr.readyState === 'live' && !tr.muted);
    t.el.classList.toggle('novideo', !hasVideo);
    if (!local && state.screens.has(id)) {
      t.el.classList.add('screen');
      t.lb.classList.add('screen-label');
    }
    const playing = t.video.play();
    if (playing && playing.catch) playing.catch(() => {});
    return t;
  }

  function onLocal(stream) {
    els.stage.hidden = false;
    addTile('local', 'You', stream, true);
    els.btnMute.setAttribute('aria-pressed', 'false');
    els.btnMute.textContent = '🎙️ Mute';
    els.btnCam.setAttribute('aria-pressed', 'false');
    els.btnCam.textContent = '📷 Camera off';
    els.btnCam.hidden = stream.getVideoTracks().length === 0;
    updateShareButton();
    updateCallUi();
  }

  function onRemote(id, stream) {
    addTile(id, nameOf(id), stream, false);
  }

  function dropTile(id) {
    const t = state.tiles.get(id);
    if (t) {
      t.video.srcObject = null;
      t.el.remove();
      state.tiles.delete(id);
    }
  }

  function onRemoteGone(id) {
    state.screens.delete(id);
    dropTile(id);
  }

  function onLocalScreen(stream) {
    if (!stream) {
      dropTile('local-screen');
    } else {
      const t = addTile('local-screen', 'Your screen', stream, true);
      t.el.classList.add('screen');
      t.lb.classList.add('screen-label');
    }
    updateShareButton();
  }

  function onRemoteScreen(id, on) {
    if (on) state.screens.add(id);
    else state.screens.delete(id);
    const t = state.tiles.get(id);
    if (!t) return;
    t.el.classList.toggle('screen', on);
    t.lb.classList.toggle('screen-label', on);
  }

  function onEnded() {
    for (const t of state.tiles.values()) {
      t.video.srcObject = null;
      t.el.remove();
    }
    state.tiles.clear();
    state.screens.clear();
    els.stage.hidden = true;
    updateShareButton();
    updateCallUi();
  }

  function refreshTileLabels() {
    for (const [id, t] of state.tiles) {
      if (id === 'local' || id === 'local-screen') continue;
      t.lb.textContent = nameOf(id);
      t.av.textContent = initial(nameOf(id));
    }
  }
})();
