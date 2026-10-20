(function () {
  'use strict';

  const ROOM_RE = /^[A-Za-z0-9_-]{8,32}$/;
  const SECRET_RE = /^[A-Za-z0-9_-]{43}$/;

  const $ = (id) => document.getElementById(id);

  if (!window.isSecureContext || !(window.crypto && window.crypto.subtle)) {
    $('insecure').hidden = false;
    $('create').disabled = true;
  }

  // Create: the room id and the secret are generated here, in the browser.
  $('create').addEventListener('click', () => {
    const id = PR.randomId(9);
    const secret = PR.generateSecret();
    location.href = '/room/' + id + '#' + secret;
  });

  // Join: accept a full link, or just "/room/<id>#<secret>".
  $('joinForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const err = $('joinError');
    err.hidden = true;
    let raw = $('joinLink').value.trim();
    try {
      if (!raw.startsWith('http://') && !raw.startsWith('https://') && !raw.startsWith('/')) {
        raw = '/' + raw;
      }
      const url = new URL(raw, location.origin);
      const m = url.pathname.match(/^\/room\/([^/]+)\/?$/);
      const secret = url.hash.replace(/^#+/, '').trim();
      if (!m || !ROOM_RE.test(m[1]) || !SECRET_RE.test(secret)) throw new Error('bad link');
      location.href = '/room/' + m[1] + '#' + secret;
    } catch {
      err.textContent = 'That doesn\'t look like a complete invite link. Make sure you copied the part after the # too.';
      err.hidden = false;
    }
  });
})();
