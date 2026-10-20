/* PrivRoom call manager: WebRTC mesh (up to 4 people), signaling over Socket.io.
 *
 * - Media flows peer-to-peer and is always encrypted by WebRTC (DTLS-SRTP).
 * - Signaling (offers, answers, ICE candidates, "screen on/off" notices) is additionally
 *   encrypted with the room key, so the server can neither read nor silently alter it.
 * - The person who joins the call later always sends the first offers, so two peers never
 *   "glare" during setup. After setup, either side may renegotiate (e.g. to start sharing
 *   their screen); simultaneous renegotiations are resolved with the "perfect negotiation"
 *   pattern: one side of each pair is "polite" and backs down on a collision.
 */
(function (root) {
  'use strict';

  const RTC_CONFIG = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

  function friendlyMediaError(e) {
    switch (e && e.name) {
      case 'NotAllowedError':
      case 'SecurityError':
        return 'Microphone/camera permission was blocked. Allow it in the browser address bar and try again.';
      case 'NotFoundError':
      case 'OverconstrainedError':
        return 'No microphone or camera was found on this device.';
      case 'NotReadableError':
        return 'The camera or microphone is being used by another app or tab. Close it, or try a voice-only call.';
      default:
        return 'Could not access the microphone/camera' + (e && e.message ? ' (' + e.message + ')' : '') + '.';
    }
  }

  const videoTransceiver = (pc) =>
    pc.getTransceivers().find((t) => t.receiver && t.receiver.track && t.receiver.track.kind === 'video');

  class CallManager {
    /**
     * @param {object} o
     * @param {any} o.socket        connected socket.io client
     * @param {(obj:any)=>Promise<{iv:string,ct:string}>} o.seal   encrypt a JSON object
     * @param {(box:any)=>Promise<any>} o.open                      decrypt a box
     * @param {object} o.hooks  onLocal, onRemote, onRemoteGone, onEnded, [onLocalScreen, onRemoteScreen]
     */
    constructor({ socket, seal, open, hooks }) {
      this.socket = socket;
      this.seal = seal;
      this.open = open;
      this.hooks = hooks;
      this.local = null;
      this.screen = null; // { stream, track } while sharing
      this.peers = new Map();
      this.joined = false;
      this.joining = false;
      this.muted = false;
      this.camOff = false;
      this.queue = Promise.resolve();
    }

    get canShareScreen() {
      return !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);
    }

    _emitAck(ev, payload) {
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('The server did not respond.')), 5000);
        this.socket.emit(ev, payload || {}, (r) => { clearTimeout(t); resolve(r); });
      });
    }

    _stopLocal() {
      if (this.local) this.local.getTracks().forEach((t) => t.stop());
      this.local = null;
    }

    async join(withVideo) {
      if (this.joined || this.joining) return;
      this.joining = true;
      try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          throw new Error('Calls need a secure page (https:// or http://localhost).');
        }
        if (typeof RTCPeerConnection === 'undefined') throw new Error('This browser does not support WebRTC calls.');

        let stream;
        try {
          stream = await navigator.mediaDevices.getUserMedia(
            withVideo
              ? { audio: { echoCancellation: true, noiseSuppression: true }, video: { width: { ideal: 640 }, height: { ideal: 360 } } }
              : { audio: { echoCancellation: true, noiseSuppression: true } }
          );
        } catch (e) {
          throw new Error(friendlyMediaError(e));
        }
        this.local = stream;
        this.muted = false;
        this.camOff = false;

        let res;
        try {
          res = await this._emitAck('call:join');
        } catch (e) {
          this._stopLocal();
          throw e;
        }
        if (!res || !res.ok) {
          this._stopLocal();
          throw new Error((res && res.error) || 'Could not join the call.');
        }

        this.joined = true;
        this.hooks.onLocal(stream);
        for (const id of res.peers) {
          try { await this._offerTo(id); } catch (e) { console.warn('offer failed', id, e); }
        }
      } finally {
        this.joining = false;
      }
    }

    _peer(id) {
      let p = this.peers.get(id);
      if (p) return p;
      const pc = new RTCPeerConnection(RTC_CONFIG);
      p = {
        id, pc, pending: [], stream: new MediaStream(),
        polite: String(this.socket.id) < String(id), // deterministic: exactly one side of each pair is polite
        makingOffer: false, ignoreOffer: false,
        ready: false, // true once the first offer/answer round is under way
      };
      this.peers.set(id, p);

      for (const t of this.local.getTracks()) pc.addTrack(t, this.local);

      pc.onicecandidate = (e) => {
        if (e.candidate) this._send(id, { t: 'ice', c: e.candidate.toJSON() }).catch(() => {});
      };
      pc.ontrack = (e) => {
        if (!p.stream.getTracks().includes(e.track)) p.stream.addTrack(e.track);
        e.track.onmute = e.track.onunmute = () => this.hooks.onRemote(id, p.stream);
        this.hooks.onRemote(id, p.stream);
      };
      pc.onconnectionstatechange = () => {
        if (this.hooks.onPeerState) this.hooks.onPeerState(id, pc.connectionState);
      };
      // Later renegotiation (e.g. screen share added to a voice-only connection).
      pc.onnegotiationneeded = async () => {
        if (!p.ready) return; // the initial offer is sent explicitly in _offerTo
        try {
          p.makingOffer = true;
          const offer = await pc.createOffer();
          if (pc.signalingState !== 'stable') return;
          await pc.setLocalDescription(offer);
          await this._send(id, { t: 'offer', sdp: pc.localDescription.sdp });
        } catch (e) {
          console.warn('renegotiation failed', e);
        } finally {
          p.makingOffer = false;
        }
      };
      return p;
    }

    async _send(to, obj) {
      const data = await this.seal(obj);
      this.socket.emit('call:signal', { to, data });
    }

    async _broadcast(obj) {
      for (const id of this.peers.keys()) await this._send(id, obj).catch(() => {});
    }

    async _offerTo(id) {
      const p = this._peer(id);
      // A voice-only joiner can still *receive* others' video (and, later, shared screens).
      if (!this.local.getVideoTracks().length) p.pc.addTransceiver('video', { direction: 'recvonly' });
      p.makingOffer = true;
      try {
        const offer = await p.pc.createOffer();
        await p.pc.setLocalDescription(offer);
        p.ready = true; // from here on, further changes renegotiate via onnegotiationneeded
        await this._send(id, { t: 'offer', sdp: p.pc.localDescription.sdp });
      } finally {
        p.makingOffer = false;
      }
    }

    /** Incoming signal from the server. Handled strictly in order. */
    handleSignal(sig) {
      this.queue = this.queue.then(() => this._handle(sig)).catch((e) => console.warn('signal error', e));
      return this.queue;
    }

    async _flush(p) {
      const list = p.pending.splice(0);
      for (const c of list) { try { await p.pc.addIceCandidate(c); } catch { /* ignore stale candidates */ } }
    }

    async _handle({ from, data }) {
      if (!this.joined || !this.local) return;
      let msg;
      try {
        msg = await this.open(data); // throws if the key is wrong or the box was tampered with
      } catch {
        return;
      }
      if (!msg || typeof msg.t !== 'string') return;
      const p = this._peer(from);
      const pc = p.pc;

      if (msg.t === 'offer' && typeof msg.sdp === 'string') {
        // Perfect negotiation: on a collision the impolite side ignores the incoming offer,
        // the polite side accepts it (the browser rolls back its own pending offer).
        const collision = p.makingOffer || pc.signalingState !== 'stable';
        p.ignoreOffer = !p.polite && collision;
        if (p.ignoreOffer) return;
        await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        await this._flush(p);
        const answer = await pc.createAnswer();
        p.ready = true;
        await pc.setLocalDescription(answer);
        await this._send(from, { t: 'answer', sdp: pc.localDescription.sdp });
        // A newcomer joined while we are presenting: give them the screen too.
        if (this.screen) {
          await this._useVideoTrack(p, this.screen.track);
          this._send(from, { t: 'screen', on: true }).catch(() => {});
        }
      } else if (msg.t === 'answer' && typeof msg.sdp === 'string') {
        if (pc.signalingState !== 'have-local-offer') return;
        p.ready = true;
        await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
        await this._flush(p);
      } else if (msg.t === 'ice' && msg.c) {
        if (pc.remoteDescription) {
          try { await pc.addIceCandidate(msg.c); } catch (e) { if (!p.ignoreOffer) console.warn('ice failed', e); }
        } else {
          p.pending.push(msg.c);
        }
      } else if (msg.t === 'screen') {
        if (this.hooks.onRemoteScreen) this.hooks.onRemoteScreen(from, !!msg.on);
      }
    }

    peerLeft(id) {
      const p = this.peers.get(id);
      if (!p) return;
      try { p.pc.close(); } catch { /* ignore */ }
      this.peers.delete(id);
      this.hooks.onRemoteGone(id);
    }

    // ---------------------------------------------------------------- screen sharing
    /** Put `track` (or null) on this peer's video sender, switching direction if needed. */
    async _useVideoTrack(p, track) {
      const tx = videoTransceiver(p.pc);
      if (!tx) return;
      await tx.sender.replaceTrack(track);
      // A voice-only connection negotiated video as receive-only; flipping the direction
      // triggers a renegotiation (handled by onnegotiationneeded).
      if (track && (tx.direction === 'recvonly' || tx.direction === 'inactive')) tx.direction = 'sendrecv';
    }

    async startScreenShare() {
      if (!this.joined || this.screen) return;
      if (!this.canShareScreen) throw new Error('Screen sharing is not supported in this browser.');
      let stream;
      try {
        stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      } catch (e) {
        if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) throw new Error('Screen sharing was cancelled.');
        throw new Error('Could not start screen sharing.');
      }
      const track = stream.getVideoTracks()[0];
      this.screen = { stream, track };
      track.onended = () => this.stopScreenShare(); // the browser's own "Stop sharing" bar
      for (const p of this.peers.values()) await this._useVideoTrack(p, track);
      await this._broadcast({ t: 'screen', on: true });
      if (this.hooks.onLocalScreen) this.hooks.onLocalScreen(stream);
    }

    async stopScreenShare() {
      const s = this.screen;
      if (!s) return;
      this.screen = null;
      const cam = (this.local && this.local.getVideoTracks()[0]) || null;
      for (const p of this.peers.values()) {
        try { await this._useVideoTrack(p, cam); } catch { /* peer already gone */ }
      }
      s.stream.getTracks().forEach((t) => { t.onended = null; t.stop(); });
      if (this.joined) await this._broadcast({ t: 'screen', on: false });
      if (this.hooks.onLocalScreen) this.hooks.onLocalScreen(null);
    }

    // ---------------------------------------------------------------- leaving
    leave(notify = true) {
      const was = this.joined;
      this.joined = false;
      if (this.screen) {
        this.screen.stream.getTracks().forEach((t) => { t.onended = null; t.stop(); });
        this.screen = null;
        if (this.hooks.onLocalScreen) this.hooks.onLocalScreen(null);
      }
      for (const p of this.peers.values()) {
        try { p.pc.close(); } catch { /* ignore */ }
      }
      this.peers.clear();
      this._stopLocal();
      if (notify && was && this.socket.connected) this.socket.emit('call:leave', {});
      if (was) this.hooks.onEnded();
    }

    setMuted(m) {
      this.muted = m;
      if (this.local) this.local.getAudioTracks().forEach((t) => { t.enabled = !m; });
      return m;
    }

    setCameraOff(off) {
      this.camOff = off;
      if (this.local) this.local.getVideoTracks().forEach((t) => { t.enabled = !off; });
      return off;
    }
  }

  root.PRCall = { CallManager };
})(typeof self !== 'undefined' ? self : globalThis);
