'use strict';
/**
 * Smoke tests for PrivRoom: crypto, presence, encrypted relay, history,
 * file access control, and call signaling. Run with:  npm test
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { io: connect } = require('socket.io-client');
const PR = require('../public/js/crypto.js');
const { createServer } = require('../server.js');

const TEST_UPLOADS = path.join(__dirname, '.test-uploads');
const ROOM = PR.randomId(9);
const OTHER_ROOM = PR.randomId(9);
const SECRET = PR.generateSecret();

let ctx;
let base;
let keys;
const sockets = [];

const client = () =>
  new Promise((resolve, reject) => {
    const s = connect(base, { transports: ['websocket'], forceNew: true, reconnection: false });
    sockets.push(s);
    s.on('connect', () => resolve(s));
    s.on('connect_error', reject);
  });

const ack = (s, ev, payload, ms = 2000) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('ack timeout: ' + ev)), ms);
    s.emit(ev, payload, (r) => { clearTimeout(t); resolve(r); });
  });

const next = (s, ev, ms = 2000) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout waiting for ' + ev)), ms);
    s.once(ev, (d) => { clearTimeout(t); resolve(d); });
  });

const silent = (s, ev, ms = 300) =>
  new Promise((resolve, reject) => {
    const h = () => reject(new Error('unexpected event: ' + ev));
    s.once(ev, h);
    setTimeout(() => { s.off(ev, h); resolve(); }, ms);
  });

async function join(s, name, room = ROOM) {
  return ack(s, 'join', { room, name: await PR.encryptJSON(keys.key, { n: name }) });
}

test.before(async () => {
  fs.rmSync(TEST_UPLOADS, { recursive: true, force: true });
  ctx = createServer({ uploadDir: TEST_UPLOADS, ttlOptions: [1, 30] }); // 1s lifetime keeps the expiry test fast
  await new Promise((r) => ctx.server.listen(0, r));
  base = 'http://localhost:' + ctx.server.address().port;
  keys = await PR.deriveKeys(SECRET, ROOM);
});

test.after(async () => {
  sockets.forEach((s) => s.close());
  ctx.io.close();
  await new Promise((r) => ctx.server.close(r));
  fs.rmSync(TEST_UPLOADS, { recursive: true, force: true });
});

test('PrivRoom end-to-end', async (t) => {
  let alice, bob, carol;
  let uploadedFileId;

  await t.test('crypto: round trip, wrong key, tampering', async () => {
    const box = await PR.encryptJSON(keys.key, { t: 'hello 👋' });
    assert.deepEqual(await PR.decryptJSON(keys.key, box), { t: 'hello 👋' });

    const wrong = await PR.deriveKeys(PR.generateSecret(), ROOM);
    await assert.rejects(PR.decryptJSON(wrong.key, box));

    const tampered = { iv: box.iv, ct: (box.ct[0] === 'A' ? 'B' : 'A') + box.ct.slice(1) };
    await assert.rejects(PR.decryptJSON(keys.key, tampered));

    // Same secret in a different room derives a different key (salt = room id)
    const otherRoomKeys = await PR.deriveKeys(SECRET, OTHER_ROOM);
    await assert.rejects(PR.decryptJSON(otherRoomKeys.key, box));

    const bytes = new Uint8Array(1024 * 1024).map((_, i) => (i * 31) & 255);
    const sealed = await PR.encryptBytes(keys.key, bytes);
    assert.equal(sealed.length, bytes.length + 12 + 16);
    assert.deepEqual(await PR.decryptBytes(keys.key, sealed), bytes);

    assert.match(keys.safetyCode, /^[0-9A-F]{4}( [0-9A-F]{4}){2}$/);
    assert.equal((await PR.deriveKeys(SECRET, ROOM)).safetyCode, keys.safetyCode);
  });

  await t.test('signing: valid signatures verify; tampering, other rooms and other keys are rejected', async () => {
    const a = await PR.generateSigningKeys();
    const b = await PR.generateSigningKeys();
    const p = { k: 't', n: 'Alice', c: 'abc', ts: Date.now(), pk: a.pub, t: 'hello' };
    p.sig = await PR.signMessage(a.priv, ROOM, p);
    assert.equal(await PR.verifyMessage(ROOM, p), true);
    assert.equal(await PR.verifyMessage(ROOM, { ...p, t: 'HELLO' }), false, 'edited text');
    assert.equal(await PR.verifyMessage(ROOM, { ...p, n: 'Bob' }), false, 'edited name');
    assert.equal(await PR.verifyMessage(OTHER_ROOM, p), false, 'replayed in another room');
    assert.equal(await PR.verifyMessage(ROOM, { ...p, pk: b.pub }), false, 'swapped public key');
    assert.equal(await PR.verifyMessage(ROOM, { ...p, sig: await PR.signMessage(b.priv, ROOM, p) }), false, 'signed by a different key');
    assert.equal(await PR.verifyMessage(ROOM, { ...p, sig: undefined }), false, 'missing signature');
    assert.equal(await PR.verifyMessage(ROOM, { ...p, pk: 'AAAA' }), false, 'garbage key');
    assert.match(await PR.keyFingerprint(a.pub), /^[0-9A-F]{4}( [0-9A-F]{4}){2}$/);
  });

  await t.test('presence: join, member list, typing, leave', async () => {
    alice = await client();
    const a = await join(alice, 'Alice');
    assert.equal(a.ok, true);
    assert.deepEqual(a.members, []);

    bob = await client();
    const joined = next(alice, 'member:join');
    const b = await join(bob, 'Bob');
    assert.equal(b.members.length, 1);
    assert.equal(b.members[0].id, alice.id);
    assert.equal((await PR.decryptJSON(keys.key, b.members[0].name)).n, 'Alice');
    const evt = await joined;
    assert.equal((await PR.decryptJSON(keys.key, evt.name)).n, 'Bob');

    const typing = next(alice, 'typing');
    bob.emit('typing', true);
    assert.deepEqual(await typing, { id: bob.id, on: true });
  });

  await t.test('server rejects plaintext names and malformed joins', async () => {
    const x = await client();
    assert.equal((await ack(x, 'join', { room: ROOM, name: 'Mallory' })).ok, false);
    assert.equal((await ack(x, 'join', { room: 'x', name: await PR.encryptJSON(keys.key, {}) })).ok, false);
    assert.equal((await ack(x, 'join', { room: '../../etc/passwd', name: await PR.encryptJSON(keys.key, {}) })).ok, false);
    x.close();
  });

  await t.test('messages are relayed and stored as ciphertext only', async () => {
    const secretText = 'launch code: PURPLE-ELEPHANT-42';
    const toBob = next(bob, 'message');
    const toAlice = next(alice, 'message');
    alice.emit('message', await PR.encryptJSON(keys.key, { k: 't', n: 'Alice', t: secretText }));
    const [m1, m2] = await Promise.all([toBob, toAlice]);
    assert.equal(m1.id, m2.id);
    assert.equal(m1.from, alice.id);
    assert.deepEqual(Object.keys(m1.body).sort(), ['ct', 'iv']);
    assert.equal((await PR.decryptJSON(keys.key, m1.body)).t, secretText);

    const stored = JSON.stringify(ctx.rooms.get(ROOM).history);
    assert.ok(!stored.includes('PURPLE'), 'plaintext leaked into server history');
    assert.ok(!Buffer.from(m1.body.ct, 'base64url').includes('PURPLE'), 'plaintext visible in ciphertext');

    // a client with the wrong key sees only noise
    const wrong = await PR.deriveKeys(PR.generateSecret(), ROOM);
    await assert.rejects(PR.decryptJSON(wrong.key, m1.body));
  });

  await t.test('malformed message payloads are dropped', async () => {
    const quiet = silent(bob, 'message');
    alice.emit('message', 'just plain text');
    alice.emit('message', { iv: 'short', ct: 'nope' });
    alice.emit('message', { iv: 'A'.repeat(16), ct: 'A'.repeat(30000) });
    await quiet;
  });

  await t.test('late joiner receives decryptable history', async () => {
    carol = await client();
    const c = await join(carol, 'Carol');
    assert.equal(c.history.length, 1);
    assert.match((await PR.decryptJSON(keys.key, c.history[0].body)).t, /PURPLE/);
    assert.equal(c.members.length, 2);
  });

  await t.test('files: stored encrypted, member-only access', async () => {
    const plain = Buffer.from('TOP-SECRET-PAYLOAD '.repeat(2000));
    const sealed = await PR.encryptBytes(keys.key, new Uint8Array(plain));

    const up = await fetch(`${base}/api/upload/${ROOM}`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'x-sid': alice.id },
      body: sealed,
    });
    assert.equal(up.status, 200);
    const { id } = await up.json();
    assert.match(id, /^[a-f0-9]{32}$/);
    uploadedFileId = id;

    const onDisk = fs.readFileSync(path.join(TEST_UPLOADS, id + '.bin'));
    assert.ok(!onDisk.includes('TOP-SECRET'), 'plaintext found on disk');

    const get = await fetch(`${base}/api/file/${ROOM}/${id}`, { headers: { 'x-sid': bob.id } });
    assert.equal(get.status, 200);
    const back = new Uint8Array(await get.arrayBuffer());
    assert.deepEqual(Buffer.from(await PR.decryptBytes(keys.key, back)), plain);

    assert.equal((await fetch(`${base}/api/file/${ROOM}/${id}`)).status, 403, 'no socket id');
    assert.equal((await fetch(`${base}/api/file/${ROOM}/${id}`, { headers: { 'x-sid': 'bogus' } })).status, 403);

    const outsider = await client();
    await join(outsider, 'Eve', OTHER_ROOM);
    assert.equal((await fetch(`${base}/api/file/${ROOM}/${id}`, { headers: { 'x-sid': outsider.id } })).status, 403, 'other room member');
    assert.equal((await fetch(`${base}/api/file/${OTHER_ROOM}/${id}`, { headers: { 'x-sid': outsider.id } })).status, 404, 'file id from another room');
    assert.equal((await fetch(`${base}/api/file/${ROOM}/..%2F..%2Fserver`, { headers: { 'x-sid': bob.id } })).status, 404, 'path traversal');

    const noAuth = await fetch(`${base}/api/upload/${ROOM}`, { method: 'POST', body: sealed });
    assert.equal(noAuth.status, 403);

    const huge = await fetch(`${base}/api/upload/${ROOM}`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'x-sid': alice.id },
      body: new Uint8Array(10 * 1024 * 1024 + 4096),
    });
    assert.equal(huge.status, 413);
  });

  await t.test('calls: signaling is relayed only between call members', async () => {
    const r1 = await ack(alice, 'call:join');
    assert.deepEqual(r1, { ok: true, peers: [] });

    const state = next(alice, 'call:state');
    const r2 = await ack(bob, 'call:join');
    assert.deepEqual(r2, { ok: true, peers: [alice.id] });
    assert.deepEqual((await state).members.sort(), [alice.id, bob.id].sort());
    assert.equal((await ack(bob, 'call:join')).ok, false, 'double join');

    const offer = { t: 'offer', sdp: 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n' };
    const got = next(alice, 'call:signal');
    bob.emit('call:signal', { to: alice.id, data: await PR.encryptJSON(keys.key, offer) });
    const sig = await got;
    assert.equal(sig.from, bob.id);
    assert.deepEqual(await PR.decryptJSON(keys.key, sig.data), offer);

    // Carol is in the room but not in the call: she can neither send nor receive signals
    const quiet1 = silent(alice, 'call:signal');
    carol.emit('call:signal', { to: alice.id, data: await PR.encryptJSON(keys.key, offer) });
    await quiet1;
    const quiet2 = silent(carol, 'call:signal');
    alice.emit('call:signal', { to: carol.id, data: await PR.encryptJSON(keys.key, offer) });
    await quiet2;

    // Unencrypted/garbage signaling is dropped
    const quiet3 = silent(alice, 'call:signal');
    bob.emit('call:signal', { to: alice.id, data: { iv: 'x', ct: 'y' } });
    await quiet3;
  });

  await t.test('calls: capacity limit and peer-left notifications', async () => {
    const d = await client(); await join(d, 'Dan');
    const e = await client(); await join(e, 'Erin');
    assert.equal((await ack(d, 'call:join')).ok, true); // 3rd
    assert.equal((await ack(e, 'call:join')).ok, true); // 4th
    const full = await ack(carol, 'call:join'); // 5th
    assert.equal(full.ok, false);
    assert.match(full.error, /full/i);

    const left = next(alice, 'call:peer-left');
    bob.emit('call:leave');
    assert.equal((await left).id, bob.id);

    const left2 = next(alice, 'call:peer-left');
    const eid = e.id;
    e.close(); // abrupt disconnect also frees the slot
    assert.equal((await left2).id, eid);
  });

  await t.test('leaving the room notifies others', async () => {
    const gone = next(alice, 'member:leave');
    const cid = carol.id;
    carol.close();
    assert.equal((await gone).id, cid);
  });

  await t.test('control messages (read receipts) are relayed to others only and never stored', async () => {
    const before = ctx.rooms.get(ROOM).history.length;
    const got = next(alice, 'ctl');
    bob.emit('ctl', await PR.encryptJSON(keys.key, { k: 'seen', m: 'x', n: 'Bob' }));
    const c = await got;
    assert.equal(c.from, bob.id);
    assert.equal((await PR.decryptJSON(keys.key, c.body)).k, 'seen');

    const noEcho = silent(bob, 'ctl');
    bob.emit('ctl', await PR.encryptJSON(keys.key, { k: 'seen', m: 'y', n: 'Bob' }));
    await noEcho;
    assert.equal(ctx.rooms.get(ROOM).history.length, before, 'a receipt was stored');

    await new Promise((r) => setTimeout(r, 100));
    const rejected = silent(alice, 'ctl');
    bob.emit('ctl', 'seen');
    bob.emit('ctl', { iv: 'x', ct: 'y' });
    await rejected;
  });

  await t.test('disappearing messages and files: the server deletes the ciphertext on time', async () => {
    const n0 = ctx.rooms.get(ROOM).history.length;
    const got = next(bob, 'message');
    alice.emit('message', { ...(await PR.encryptJSON(keys.key, { k: 't', t: 'vanish' })), ttl: 1 });
    const m = await got;
    assert.equal(m.exp - m.ts, 1000);
    assert.equal(ctx.rooms.get(ROOM).history.length, n0 + 1);
    await new Promise((r) => setTimeout(r, 1300));
    assert.equal(ctx.rooms.get(ROOM).history.length, n0, 'message still stored after expiry');

    const quiet = silent(bob, 'message');
    alice.emit('message', { ...(await PR.encryptJSON(keys.key, { k: 't', t: 'x' })), ttl: 5 }); // not an allowed lifetime
    await quiet;

    const sealed = await PR.encryptBytes(keys.key, new Uint8Array(Buffer.from('short-lived file')));
    const up = await fetch(`${base}/api/upload/${ROOM}`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'x-sid': alice.id, 'x-ttl': '1' },
      body: sealed,
    });
    assert.equal(up.status, 200);
    const { id } = await up.json();
    const file = path.join(TEST_UPLOADS, id + '.bin');
    assert.ok(fs.existsSync(file));
    await new Promise((r) => setTimeout(r, 1300));
    assert.equal(fs.existsSync(file), false, 'file still on disk after expiry');

    const bad = await fetch(`${base}/api/upload/${ROOM}`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'x-sid': alice.id, 'x-ttl': '7' },
      body: sealed,
    });
    assert.equal(bad.status, 400);
  });

  await t.test('burn: history and files are wiped for everyone, and later events are ignored', async () => {
    assert.ok(fs.existsSync(path.join(TEST_UPLOADS, uploadedFileId + '.bin')), 'precondition: a file exists');
    const told = next(alice, 'room:burned');
    assert.deepEqual(await ack(bob, 'room:burn', {}), { ok: true });
    assert.equal((await told).by, bob.id);
    assert.equal(ctx.rooms.has(ROOM), false);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(fs.existsSync(path.join(TEST_UPLOADS, uploadedFileId + '.bin')), false, 'file survived the burn');
    assert.equal((await fetch(`${base}/api/file/${ROOM}/${uploadedFileId}`, { headers: { 'x-sid': alice.id } })).status, 404);

    const quiet = silent(alice, 'message');
    alice.emit('message', await PR.encryptJSON(keys.key, { k: 't', t: 'after burn' }));
    await quiet;
  });

  await t.test('flooding is rate limited without crashing the server', async () => {
    const flooder = await client();
    await join(flooder, 'Flood');
    for (let i = 0; i < 1000; i++) flooder.emit('typing', true);
    await new Promise((r) => setTimeout(r, 300));
    const probe = await client();
    assert.equal((await join(probe, 'Probe')).ok, true, 'server still healthy');
  });
});
