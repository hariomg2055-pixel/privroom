/* PrivRoom crypto helpers.
 * Web Crypto only, zero dependencies. Runs in browsers and in Node 18+ (used by the tests).
 *
 * Key model
 *   The URL fragment holds a random 32-byte secret:  /room/<roomId>#<secret>
 *   Browsers never send the fragment to the server. From the secret we derive,
 *   with HKDF-SHA-256 (salt = roomId):
 *     - a non-extractable AES-256-GCM key (encrypts messages, names, files, call signaling)
 *     - a 48-bit "safety code" users can compare out-of-band to confirm they share the same key
 */
(function (root, factory) {
  const webcrypto = root.crypto || require('node:crypto').webcrypto;
  const api = factory(webcrypto);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PR = api;
})(typeof self !== 'undefined' ? self : globalThis, function (webcrypto) {
  'use strict';

  const subtle = webcrypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const IV_BYTES = 12;
  const VERSION = 'privroom-v1';

  // ---------- base64url ----------
  function toB64u(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64u(str) {
    let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    return webcrypto.getRandomValues(new Uint8Array(n));
  }

  /** Short random identifier, e.g. a room id (9 bytes -> 12 chars). */
  function randomId(bytes = 9) {
    return toB64u(randomBytes(bytes));
  }

  /** The room secret that goes into the URL fragment (32 bytes -> 43 chars). */
  function generateSecret() {
    return toB64u(randomBytes(32));
  }

  async function deriveKeys(secretB64u, roomId) {
    if (!subtle) throw new Error('Web Crypto is unavailable. Use https:// or http://localhost.');
    const secret = fromB64u(secretB64u);
    if (secret.length !== 32) throw new Error('Invalid room key in the link.');
    const base = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey', 'deriveBits']);
    const salt = enc.encode(roomId);

    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(VERSION + '/aes-gcm') },
      base,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable: page scripts cannot read the raw key back out
      ['encrypt', 'decrypt']
    );

    const bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(VERSION + '/safety-code') },
      base,
      48
    );
    const hex = Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return { key, safetyCode: hex.match(/.{4}/g).join(' ') };
  }

  // ---------- JSON boxes (messages, names, signaling) ----------
  async function encryptJSON(key, obj) {
    const iv = randomBytes(IV_BYTES);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { iv: toB64u(iv), ct: toB64u(new Uint8Array(ct)) };
  }

  async function decryptJSON(key, box) {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64u(box.iv) }, key, fromB64u(box.ct));
    return JSON.parse(dec.decode(pt));
  }

  // ---------- binary blobs (files): IV || ciphertext || tag ----------
  async function encryptBytes(key, bytes) {
    const iv = randomBytes(IV_BYTES);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
    const out = new Uint8Array(IV_BYTES + ct.length);
    out.set(iv, 0);
    out.set(ct, IV_BYTES);
    return out;
  }

  async function decryptBytes(key, blob) {
    const iv = blob.subarray(0, IV_BYTES);
    const ct = blob.subarray(IV_BYTES);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  }

  // ---------- sender authentication (ECDSA P-256) ----------
  // The room key proves "this person is in the room". It cannot prove *who* in the room wrote a
  // message, because every member holds the same key. So each person also gets a signing key pair:
  // the private half never leaves their browser, the public half travels inside encrypted boxes.
  const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
  const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' };
  const pubCache = new Map();

  async function generateSigningKeys() {
    const pair = await subtle.generateKey(ECDSA, false, ['sign', 'verify']); // private key non-extractable
    const pub = toB64u(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
    return { priv: pair.privateKey, pubKey: pair.publicKey, pub };
  }

  /** Short human-comparable fingerprint of a public key, e.g. "A1B2 C3D4 E5F6". */
  async function keyFingerprint(pubB64u) {
    const h = new Uint8Array(await subtle.digest('SHA-256', fromB64u(pubB64u)));
    const hex = Array.from(h.subarray(0, 6), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.match(/.{4}/g).join(' ');
  }

  /**
   * The exact bytes that get signed. Fixed field order, bound to the room, so a signature cannot be
   * replayed in another room or have its fields reshuffled. Missing fields are null.
   */
  function canonicalMessage(roomId, p) {
    const f = (v) => (v === undefined ? null : v);
    return enc.encode(
      JSON.stringify([
        VERSION + '/msg', roomId,
        f(p.k), f(p.n), f(p.c), f(p.ts), f(p.pk),
        f(p.t), f(p.id), f(p.fn), f(p.ft), f(p.fs), // text / file descriptor
        f(p.x), // disappearing-message lifetime
        f(p.m), f(p.e), f(p.on), // reaction target / emoji / on-off
      ])
    );
  }

  async function signMessage(privKey, roomId, p) {
    const sig = await subtle.sign(SIGN_ALG, privKey, canonicalMessage(roomId, p));
    return toB64u(new Uint8Array(sig));
  }

  /** True only if p.sig is a valid signature over p by the key in p.pk. Never throws. */
  async function verifyMessage(roomId, p) {
    try {
      if (!p || typeof p.pk !== 'string' || typeof p.sig !== 'string') return false;
      let key = pubCache.get(p.pk);
      if (!key) {
        key = await subtle.importKey('raw', fromB64u(p.pk), ECDSA, false, ['verify']);
        if (pubCache.size > 500) pubCache.clear();
        pubCache.set(p.pk, key);
      }
      return await subtle.verify(SIGN_ALG, key, fromB64u(p.sig), canonicalMessage(roomId, p));
    } catch {
      return false;
    }
  }

  return {
    toB64u, fromB64u, randomId, generateSecret, deriveKeys,
    encryptJSON, decryptJSON, encryptBytes, decryptBytes,
    generateSigningKeys, keyFingerprint, canonicalMessage, signMessage, verifyMessage,
  };
});
