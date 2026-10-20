'use strict';
/**
 * PrivRoom server
 * ---------------
 * A deliberately "dumb" relay. It never sees keys or plaintext:
 *   - chat messages, reactions, member names, file blobs, read receipts and WebRTC
 *     signaling all arrive already encrypted in the browser (AES-256-GCM, key lives
 *     in the URL #fragment)
 *   - the server only routes them to the right room / peer and keeps a short,
 *     in-memory history of ciphertext.
 *
 * The only plaintext "metadata" a client may attach is an expiry time for
 * disappearing messages (the server has to know *when* to delete the ciphertext).
 *
 * Everything is ephemeral: rooms live in memory, uploads are deleted when a room
 * has been empty for ROOM_TTL_MS (and wiped on every server start). Any member can
 * also "burn" a room, which deletes everything immediately.
 */

const path = require('path');
const fs = require('fs');
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const express = require('express');
const { Server } = require('socket.io');

// ---------- limits (tweak here) ----------
const PORT = Number(process.env.PORT) || 3000;
const DEFAULT_UPLOAD_DIR = process.env.UPLOAD_DIR || (process.env.VERCEL ? path.join(os.tmpdir(), 'privroom-uploads') : path.join(__dirname, 'uploads'));
const MAX_FILE_BYTES = 10 * 1024 * 1024; // plaintext file limit
const MAX_UPLOAD_BODY = MAX_FILE_BYTES + 1024; // + IV and GCM tag overhead
const MAX_ROOM_UPLOAD_BYTES = 100 * 1024 * 1024; // per-room storage cap
const MAX_HISTORY = 50;
const MAX_ROOM_MEMBERS = 20;
const MAX_CALL_MEMBERS = 4; // WebRTC mesh: every peer sends to every other peer
const ROOM_TTL_MS = 30 * 60 * 1000; // delete an empty room after 30 minutes
const RATE_BURST = 150; // socket events a client may send in a burst
const RATE_PER_SEC = 30; // sustained events per second
const DEFAULT_TTL_OPTIONS = [30, 300, 3600]; // allowed lifetimes (seconds) for disappearing messages

// size caps (in base64url characters) for encrypted payloads
const MAX_MESSAGE_CT = 24000; // ~4000 chars of text, or a file descriptor (+ signature)
const MAX_NAME_CT = 2000;
const MAX_CTL_CT = 4000; // read receipts and other tiny control messages
const MAX_SIGNAL_CT = 64000; // SDP offers/answers can be several KB

const ROOM_RE = /^[A-Za-z0-9_-]{8,32}$/;
const FILE_RE = /^[a-f0-9]{32}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;

/** A valid AES-GCM box from the client: { iv: 12 bytes b64url, ct: b64url }. */
function toCipher(c, maxCt) {
  if (!c || typeof c !== 'object') return null;
  const { iv, ct } = c;
  if (typeof iv !== 'string' || typeof ct !== 'string') return null;
  if (iv.length !== 16 || !B64U_RE.test(iv)) return null; // 12 bytes -> 16 chars
  if (ct.length < 22 || ct.length > maxCt || !B64U_RE.test(ct)) return null; // >= 16-byte tag
  return { iv, ct }; // strip any extra fields
}

function createServer(opts = {}) {
  const uploadDir = opts.uploadDir || DEFAULT_UPLOAD_DIR;
  const ttlOptions = new Set(opts.ttlOptions || DEFAULT_TTL_OPTIONS);
  fs.mkdirSync(uploadDir, { recursive: true });
  // Uploads are ephemeral by design: start clean.
  for (const f of fs.readdirSync(uploadDir)) {
    if (f.endsWith('.bin')) {
      try { fs.unlinkSync(path.join(uploadDir, f)); } catch { /* ignore */ }
    }
  }

  /** @type {Map<string, {id:string, members:Map<string,{name:object}>, history:object[], call:Set<string>, files:Set<string>, bytes:number, timer:any, burned:boolean}>} */
  const rooms = new Map();

  function getRoom(id) {
    let room = rooms.get(id);
    if (!room) {
      room = { id, members: new Map(), history: [], call: new Set(), files: new Set(), bytes: 0, timer: null, burned: false };
      rooms.set(id, room);
    }
    return room;
  }

  function destroyRoom(room) {
    clearTimeout(room.timer);
    for (const fid of room.files) {
      fs.unlink(path.join(uploadDir, fid + '.bin'), () => {});
    }
    room.files.clear();
    if (rooms.get(room.id) === room) rooms.delete(room.id);
  }

  function scheduleCleanup(room) {
    clearTimeout(room.timer);
    room.timer = setTimeout(() => {
      if (room.members.size === 0) destroyRoom(room);
    }, opts.roomTtlMs || ROOM_TTL_MS);
    if (room.timer.unref) room.timer.unref();
  }

  function dropFromHistory(room, msgId) {
    const i = room.history.findIndex((m) => m.id === msgId);
    if (i >= 0) room.history.splice(i, 1);
  }

  /** History without expired disappearing messages (belt and braces next to the timers). */
  function liveHistory(room) {
    const now = Date.now();
    return room.history.filter((m) => !m.exp || m.exp > now);
  }

  const unref = (t) => { if (t && t.unref) t.unref(); return t; };

  // ---------- HTTP ----------
  const app = express();
  app.disable('x-powered-by');

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), display-capture=(self), geolocation=()');
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' blob: data:",
        "media-src 'self' blob:",
        "connect-src 'self' ws: wss:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; ')
    );
    next();
  });

  app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

  app.get('/room/:id', (req, res) => {
    if (!ROOM_RE.test(req.params.id)) return res.status(404).send('Not found');
    res.sendFile(path.join(__dirname, 'public', 'room.html'));
  });

  // Encrypted file upload. The body is an opaque blob: IV(12) || ciphertext || tag(16).
  // The caller must be a connected member of the room (x-sid = their socket id).
  // Optional x-ttl (seconds) makes the blob disappear, matching a disappearing message.
  app.post(
    '/api/upload/:room',
    express.raw({ type: () => true, limit: MAX_UPLOAD_BODY }),
    async (req, res) => {
      const room = ROOM_RE.test(req.params.room) ? rooms.get(req.params.room) : null;
      if (!room) return res.status(404).json({ error: 'Unknown room' });
      if (!room.members.has(String(req.get('x-sid') || ''))) {
        return res.status(403).json({ error: 'Not a member of this room' });
      }
      const ttl = Number(req.get('x-ttl') || 0);
      if (ttl && !ttlOptions.has(ttl)) return res.status(400).json({ error: 'Unsupported expiry' });
      const body = req.body;
      if (!Buffer.isBuffer(body) || body.length < 29) return res.status(400).json({ error: 'Empty upload' });
      if (room.bytes + body.length > MAX_ROOM_UPLOAD_BYTES) {
        return res.status(413).json({ error: 'Room storage limit reached' });
      }
      const id = crypto.randomBytes(16).toString('hex');
      try {
        await fs.promises.writeFile(path.join(uploadDir, id + '.bin'), body);
      } catch {
        return res.status(500).json({ error: 'Could not store file' });
      }
      room.files.add(id);
      room.bytes += body.length;
      if (ttl) {
        unref(setTimeout(() => {
          if (room.files.delete(id)) {
            room.bytes -= body.length;
            fs.unlink(path.join(uploadDir, id + '.bin'), () => {});
          }
        }, ttl * 1000));
      }
      res.json({ id });
    }
  );

  app.get('/api/file/:room/:id', (req, res) => {
    const room = ROOM_RE.test(req.params.room) ? rooms.get(req.params.room) : null;
    if (!room || !FILE_RE.test(req.params.id) || !room.files.has(req.params.id)) {
      return res.status(404).json({ error: 'File not found' });
    }
    if (!room.members.has(String(req.get('x-sid') || ''))) {
      return res.status(403).json({ error: 'Not a member of this room' });
    }
    const file = path.join(uploadDir, req.params.id + '.bin');
    fs.stat(file, (err, st) => {
      if (err) return res.status(404).json({ error: 'File expired' });
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', st.size);
      res.setHeader('Cache-Control', 'no-store');
      fs.createReadStream(file).pipe(res);
    });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'File too large (max 10 MB)' });
    if (res.headersSent) return next(err);
    res.status(err && err.status ? err.status : 500).json({ error: 'Server error' });
  });

  // ---------- Socket.io ----------
  const server = http.createServer(app);
  const io = new Server(server, { maxHttpBufferSize: 128 * 1024 });

  io.on('connection', (socket) => {
    /** @type {null | object} */
    let room = null;
    const active = () => room && !room.burned;

    // Token bucket: 150-event burst, refills at 30/s. Sized so a 4-person mesh call can
    // exchange all its ICE candidates in one go, while a flood still gets cut off.
    const bucket = { tokens: RATE_BURST, last: Date.now() };
    socket.use((packet, next) => {
      const now = Date.now();
      bucket.tokens = Math.min(RATE_BURST, bucket.tokens + ((now - bucket.last) / 1000) * RATE_PER_SEC);
      bucket.last = now;
      if (bucket.tokens < 1) return next(new Error('rate limited'));
      bucket.tokens -= 1;
      next();
    });
    socket.on('error', () => {});

    const reply = (ack, payload) => { if (typeof ack === 'function') ack(payload); };

    socket.on('join', (p, ack) => {
      if (room) return reply(ack, { ok: false, error: 'Already joined' });
      const name = p && typeof p.room === 'string' && ROOM_RE.test(p.room) ? toCipher(p.name, MAX_NAME_CT) : null;
      if (!name) return reply(ack, { ok: false, error: 'Bad join request' });

      const r = getRoom(p.room);
      if (r.members.size >= MAX_ROOM_MEMBERS) return reply(ack, { ok: false, error: 'Room is full' });
      clearTimeout(r.timer);

      const others = [...r.members].map(([id, m]) => ({ id, name: m.name }));
      r.members.set(socket.id, { name });
      socket.join(r.id);
      room = r;

      reply(ack, {
        ok: true,
        id: socket.id,
        now: Date.now(), // lets clients correct for clock skew when timing disappearing messages
        members: others,
        history: liveHistory(r),
        call: [...r.call],
        limits: { maxFileBytes: MAX_FILE_BYTES, maxCall: MAX_CALL_MEMBERS, ttl: [...ttlOptions] },
      });
      socket.to(r.id).emit('member:join', { id: socket.id, name });
    });

    // A chat message (or reaction, or file descriptor): an opaque encrypted box.
    // An optional plaintext `ttl` (seconds) asks the server to delete the ciphertext on time.
    socket.on('message', (box) => {
      if (!active()) return;
      const body = toCipher(box, MAX_MESSAGE_CT);
      if (!body) return;
      let ttl = 0;
      if (box.ttl !== undefined && box.ttl !== 0) {
        ttl = Number(box.ttl);
        if (!ttlOptions.has(ttl)) return;
      }
      const msg = { id: crypto.randomBytes(6).toString('hex'), from: socket.id, ts: Date.now(), body };
      if (ttl) {
        msg.exp = msg.ts + ttl * 1000;
        const r = room;
        unref(setTimeout(() => dropFromHistory(r, msg.id), ttl * 1000));
      }
      room.history.push(msg);
      if (room.history.length > MAX_HISTORY) room.history.shift();
      io.to(room.id).emit('message', msg); // echo to sender too = "delivered" confirmation
    });

    // Small encrypted control messages (read receipts). Relayed to the others, never stored.
    socket.on('ctl', (box) => {
      if (!active()) return;
      const body = toCipher(box, MAX_CTL_CT);
      if (!body) return;
      socket.to(room.id).emit('ctl', { from: socket.id, body });
    });

    socket.on('typing', (on) => {
      if (!active()) return;
      socket.to(room.id).emit('typing', { id: socket.id, on: on === true });
    });

    // Burn: any member can wipe the room for everyone. History and files go immediately.
    socket.on('room:burn', (_p, ack) => {
      if (!active()) return reply(ack, { ok: false, error: 'No active room' });
      const r = room;
      r.burned = true;
      r.history.length = 0;
      r.call.clear();
      io.to(r.id).emit('room:burned', { by: socket.id });
      destroyRoom(r);
      reply(ack, { ok: true });
    });

    // ----- call signaling (media itself flows peer-to-peer via WebRTC) -----
    const callState = () => io.to(room.id).emit('call:state', { members: [...room.call] });

    socket.on('call:join', (_p, ack) => {
      if (!active()) return reply(ack, { ok: false, error: 'Join a room first' });
      if (room.call.has(socket.id)) return reply(ack, { ok: false, error: 'Already in call' });
      if (room.call.size >= MAX_CALL_MEMBERS) {
        return reply(ack, { ok: false, error: `Call is full (max ${MAX_CALL_MEMBERS} people)` });
      }
      const peers = [...room.call];
      room.call.add(socket.id);
      reply(ack, { ok: true, peers });
      callState();
    });

    socket.on('call:signal', (p) => {
      if (!active() || !p || typeof p.to !== 'string') return;
      if (!room.call.has(socket.id) || !room.call.has(p.to)) return;
      const data = toCipher(p.data, MAX_SIGNAL_CT);
      if (!data) return;
      io.to(p.to).emit('call:signal', { from: socket.id, data });
    });

    const leaveCall = () => {
      if (active() && room.call.delete(socket.id)) {
        io.to(room.id).emit('call:peer-left', { id: socket.id });
        callState();
      }
    };
    socket.on('call:leave', leaveCall);

    socket.on('disconnect', () => {
      if (!room) return;
      const r = room;
      if (r.burned) return; // already torn down
      leaveCall();
      r.members.delete(socket.id);
      io.to(r.id).emit('member:leave', { id: socket.id });
      if (r.members.size === 0) scheduleCleanup(r);
    });
  });

  return { app, server, io, rooms, uploadDir };
}

module.exports = { createServer };

if (require.main === module) {
  const { server } = createServer();
  server.listen(PORT, () => {
    console.log(`PrivRoom running  ->  http://localhost:${PORT}`);
  });
}
