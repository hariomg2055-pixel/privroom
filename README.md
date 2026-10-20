# PrivRoom: a private room in one link

End-to-end encrypted real-time chat with file sharing, voice/video calls and screen sharing.
Built with **Node.js + Express + Socket.io** on the server and plain **HTML/CSS/JS + Web Crypto + WebRTC** in the browser. No build step, no database, no accounts.

> **Pitch line:** *Create a room, share the link, and chat, share files and call. The server relays everything but can read none of it, and you can watch it fail to.*

**What's in it**

| Feature | What it does |
|---|---|
| Rooms by link | No signup. The encryption key lives in the link's `#` part, which browsers never send to the server |
| E2E-encrypted chat, files, photos | AES-256-GCM in the browser. Files up to 10 MB, images preview inline |
| **Server's view** (X-ray) | A toggle that shows, under each message, the exact ciphertext the server holds |
| **Signed messages, verified senders** | Every message is signed. Impersonation of a name is detected and flagged |
| **Reactions and read receipts** | Both travel as encrypted messages. Receipts are relayed, never stored |
| **Sound alerts & mute toggle** | Web Audio chime on incoming messages; sidebar mute toggle (🔔/🔕) persisted in storage |
| **Disappearing messages and files** | 30 s / 5 min / 1 h timers. The server deletes the ciphertext on time |
| **Burn room** | One button wipes every message and file from the server, for everyone |
| Voice and video calls | WebRTC mesh, up to 4 people, signaling encrypted |
| **Screen sharing** | Share during a call; works from voice-only calls too |

---

## 1. Quick start (Windows)

1. Install **Node.js LTS** (v18.11 or newer) from <https://nodejs.org>. Check with `node -v`.
2. Open **Command Prompt** (or PowerShell) in this folder and run:

```bat
npm install
npm start
```

3. Open **http://localhost:3000** in Chrome or Edge, click **Create a private room**, enter a name.
4. Open the invite link in a second tab (or send it to someone) to chat.

Run the automated tests any time with `npm test`.

> `localhost` counts as a secure context, so encryption, the camera, the microphone and screen sharing all work without HTTPS. Anything else (a LAN IP, for example) does **not** work, because browsers disable Web Crypto and `getUserMedia` there. See section 3.

---

## 2. Demo script (about 4 minutes)

1. **Create** a room in Tab 1 as *Alice*. Point at the URL: `/room/abc123…#KEY`. *"The part after `#` is the key. Browsers never send it to the server."*
2. **Open the invite link** in a second browser or profile as *Bob*. Show the matching **safety code** and each person's **🔑 key fingerprint** in the sidebar.
3. **Chat and sound alerts.** Send a few messages. Notice the notification chime on incoming messages from others. Toggle the sidebar mute button (`🔔 Sound on` / `🔕 Sound muted`) to mute or unmute. Show the ✓ badge next to each name: *"every message is signed by its sender."*
4. **Click 🔍 Server's view.** Under each message appears `SERVER HOLDS iv … ct …`. *"This is everything the server stores. Your browser decrypts it locally."* This is the moment that sells the encryption.
5. **Reactions and receipts:** react with 👍 (hover a message, click ☺); Alice's last message flips from *Delivered* to *Seen by Bob*. *"Both are encrypted messages too."*
6. **Send a photo and a document** (📎 or drag and drop). The photo previews inline.
7. **Disappearing:** choose ⏳ 30 sec in the dropdown and send a message. It counts down and vanishes from both screens and from the server.
8. **Call:** Alice clicks *Video call*, Bob clicks *Join voice*. Then **🖥️ Share screen**.
9. **Optional attack demo:** open a third tab with the same room id but a *wrong* key: it sees only "Could not decrypt", and its safety code differs.
10. **🔥 Burn room.** Confirm. Everyone is told, the room is wiped. Finish on the honest limits (section 6).

> Two tabs in the **same** browser sharing one physical camera can fail on some browsers ("camera in use"). Use a second browser/profile, a phone, or make one side voice-only.

---

## 3. Demo on two devices (phone + laptop)

Phones need **HTTPS** for the camera and encryption to work. The easiest way is a free Cloudflare quick tunnel:

```bat
winget install --id Cloudflare.cloudflared
cloudflared tunnel --url http://localhost:3000
```

It prints an address like `https://random-words.trycloudflare.com`.

1. Open **that https address on your laptop** and create the room there. The invite link is built from the address you are on, so it must be the https one.
2. Send the invite link (including the `#…` part) to your phone, for example via a note-to-self message.

The tunnel provider terminates TLS and can see traffic metadata, but chat, names, files and call signaling are already encrypted before they leave the browser. Alternatives: `ngrok http 3000`, or `npx localtunnel --port 3000`.

Screen sharing is not available in most **mobile** browsers; the button simply does not appear there.

---

## 3.1 Cloud Deployment

### A. Deploy to Vercel (Frontend & Serverless)
PrivRoom includes `vercel.json` and `/api` serverless handler preconfigured for Vercel:

1. Push this repository to your GitHub account (or import directly).
2. Go to [vercel.com/new](https://vercel.com/new) and select your `privroom` repository.
3. Keep default settings (Framework preset: `Other`, Root directory: `./`).
4. Click **Deploy**. Vercel will provide your production `https://*.vercel.app` URL.

> **Note on Vercel:** Vercel runs on ephemeral serverless Lambdas. For production real-time chat, persistent rooms, and WebRTC signaling that require 24/7 continuous WebSocket connections, continuous server platforms (Render, Railway, or VPS) are recommended.

### B. 1-Click Free Continuous Deployment (Render / Railway)
For persistent WebSocket rooms and WebRTC signaling with 0 configuration:

- **Render:** Connect your GitHub repository at [dashboard.render.com](https://dashboard.render.com), choose **Web Service**, and select the included `render.yaml` blueprint (or `npm install` / `npm start`).
- **Railway:** Connect your GitHub repository at [railway.app](https://railway.app); the included `Procfile` and `package.json` deploy automatically.


---

## 4. How it works

```
   Browser A                          Node.js server                         Browser B
 ┌────────────┐   ciphertext only   ┌────────────────┐   ciphertext only   ┌────────────┐
 │ AES-GCM key│ ─── Socket.io ────▶ │ rooms (memory) │ ─── Socket.io ────▶ │ AES-GCM key│
 │ from #KEY  │                     │ 50-msg history │                     │ from #KEY  │
 │ signing key│                     │ encrypted blobs│                     │ signing key│
 └─────┬──────┘                     └────────────────┘                     └─────┬──────┘
       └──────────────── WebRTC audio/video/screen, peer to peer (DTLS-SRTP) ─────┘
                      (offers/answers/ICE travel through the server, encrypted)
```

**Key model.** Creating a room generates 32 random bytes in the browser and puts them in the URL fragment (`#…`). From that secret the page derives, with **HKDF-SHA-256** (salt = room id):

- a non-extractable **AES-256-GCM** key that encrypts everything below, each time with a fresh random 96-bit IV
- a 48-bit **safety code** to compare out loud

**Sender authentication.** The room key proves someone is *in* the room, not *who* wrote a message, because everyone holds the same key. So each browser also makes an **ECDSA P-256 signing key** (private half non-extractable, stored in IndexedDB per room and name). Every message, reaction and file descriptor is signed over a fixed field order that includes the room id, then encrypted. Receivers verify the signature and apply **trust on first use**: the first key seen for a display name owns that name in your view. A different key claiming the same name gets a ⚠ warning, and unsigned or tampered messages are not shown at all. Compare the 🔑 fingerprints out loud for real assurance.

**What is encrypted:**

| Data | Protection |
|---|---|
| Messages, reactions, display names, signing keys | AES-256-GCM in the browser; the server stores/relays `{iv, ct}` only |
| Read receipts | Same, relayed to the others and never stored |
| Files and photos | Encrypted before upload; the server stores opaque blobs (`IV‖ciphertext‖tag`) |
| Call signaling (SDP/ICE, "screen on/off") | AES-256-GCM with the room key, so the server can neither read nor alter it |
| Call and screen media | WebRTC's mandatory DTLS-SRTP, peer to peer |

**What the server can still see (metadata):** room ids, how many people are connected, IP addresses, timing, message and file sizes, who is in a call, and, for disappearing messages, **the expiry time** (it has to know when to delete the ciphertext). That expiry value is the only plaintext a client attaches to a message.

**Disappearing messages.** The sender picks a lifetime. The server deletes the ciphertext (and the encrypted file blob) when it expires, and every client removes the message from its screen on its own timer, corrected for clock skew. Nothing can stop someone from screenshotting or copying a message before it disappears, or a modified client from keeping it.

**Burn room.** Any member can burn the room. The server wipes history, files and call state, tells everyone, and every browser clears its screen and drops the connection. Copies already saved on devices (downloads, screenshots) stay there. The link afterwards still opens a *fresh, empty* room with the same id, so stop sharing a burned link.

**Screen sharing.** Uses `getDisplayMedia` and swaps the shared screen onto the existing video connection. When a voice-only connection has to start sending video, the browsers renegotiate, with the "perfect negotiation" pattern so two people starting at the same moment cannot deadlock. Someone who joins mid-presentation receives the screen automatically.

**Notification audio.** Incoming messages and files from other participants trigger a subtle 2-tone chime synthesized directly via the browser's Web Audio API. Audio plays only for live verified messages from others (never for your own messages or during history reloads), requires zero audio assets or external CDNs, and can be silenced via the sidebar mute toggle (persisted in `localStorage`).

**Other safeguards:** strict CSP (no inline scripts, same-origin only), all user text rendered with `textContent` (no HTML injection), image previews limited to PNG/JPEG/GIF/WebP, member-only file access, input validation on every socket event, a per-socket rate limit, and size caps (messages, files, rooms, uploads).

**Data lifetime:** everything lives in server memory. Rooms and their uploaded files are deleted 30 minutes after the last person leaves, and the `uploads/` folder is wiped on every server start.

---

## 5. Project layout

```
server.js              Express + Socket.io: rooms, relay, signaling, expiry, burn, encrypted upload/download
public/index.html      Landing page (create / join)
public/room.html       Room page (chat, files, calls)
public/css/style.css   All styling, light and dark mode
public/js/crypto.js    Web Crypto helpers: keys, AES-GCM, ECDSA signing (also used by the tests)
public/js/room.js      Chat, presence, signed messages, reactions, receipts, audio alerts, expiry, burn, files, call UI
public/js/call.js      WebRTC mesh, screen sharing, encrypted signaling
public/js/landing.js   Landing page logic
test/smoke.test.js     End-to-end server tests (real sockets, real HTTP)
uploads/               Encrypted blobs (ephemeral)
```

Tunable limits are constants at the top of `server.js`: file size (10 MB), history length (50), room size (20), call size (4), room TTL (30 min), allowed message lifetimes, rate limit.

---

## 6. Honest limits and the production roadmap

This is a hackathon MVP. Say these before anyone asks:

| Limit | Why it matters | Production fix |
|---|---|---|
| **Anyone with the full link can read the room** | The link *is* the key | Per-user identity keys and invites; accounts or SSO |
| **No forward secrecy / post-compromise security** | One static room key for the room's lifetime | **Signal Protocol** (X3DH + Double Ratchet) for 1:1, **MLS** for groups |
| **Identity is "first key seen for a name"** | A real user who clears browser storage gets a new key and is flagged as a name clash; the very first claim on a name is trusted | Verified identities, key transparency, QR-code verification |
| **A malicious server could ship malicious JavaScript** | The server delivers the code that holds the key. This is the core limit of any web E2EE app | Signed native or browser-extension clients, subresource integrity, reproducible builds |
| **Disappearing messages are best-effort** | Screenshots, copies and modified clients; the server also sees the expiry time | Platform-level screenshot protections, sealed timers |
| **Read receipts show when you are looking** | A privacy trade-off | Per-room switch to disable |
| **Mesh calls cap at about 4 people** | Every peer uploads to every other peer; screen share adds more | An SFU (mediasoup / LiveKit) with insertable-streams E2EE |
| **STUN only, no TURN** | Some strict networks cannot connect peer to peer | Run a **coturn** TURN server |
| **In-memory state, single server** | A restart loses rooms; cannot scale horizontally | PostgreSQL/Redis for rooms and history, the Socket.io Redis adapter, S3 for blobs |
| **No malware scanning or content policy** | Files are opaque to the server | Client-side checks, abuse reporting, per-user quotas |
| **Metadata is visible to the operator** | IPs, timing, sizes, expiry times | Padding, relays/mixnets (research territory) |

Why not Signal Protocol today: doing it correctly (prekey bundles, ratchet state, multi-device, group fan-out) takes weeks, and hand-rolled crypto is a liability. A shared-secret model built only on standard primitives, plus signatures for sender authentication, is the defensible one-day choice.

---

## 7. Testing

`npm test` starts the real server on a random port and drives it with real Socket.io clients and real HTTP. It covers:

- crypto round trips, wrong key, tampered ciphertext, key separation between rooms
- signing: valid signatures, tampering, cross-room replay, swapped or wrong keys
- join/leave, presence, typing relay, rejection of plaintext or malformed input
- messages relayed and stored as ciphertext only, history cap, late-joiner history
- encrypted read receipts (relayed, not stored)
- disappearing messages and files (validated lifetimes, deleted on time)
- file upload/download, member-only access, path traversal, oversize uploads, no plaintext on disk
- call signaling relay, call capacity, peer-left notifications, non-members cannot signal
- burn (history and files wiped, later events ignored) and flood protection

The browser UI and calls are best verified by hand with the demo script above. During development, they were also exercised in headless Chromium: forged and impersonated messages, reactions, receipts, expiry, a 3-person call, screen-share renegotiation including simultaneous starts, and burn.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `npm` is blocked in PowerShell ("running scripts is disabled") | Use **Command Prompt** instead, or run `npm.cmd install` / `npm.cmd start` |
| Port 3000 in use | Command Prompt: `set PORT=3001 && npm start`. PowerShell: `$env:PORT=3001; npm start` |
| Windows Firewall prompt | Allow Node.js on **private** networks |
| "Your browser blocked encryption on this page" | You opened it via a LAN IP over http. Use `http://localhost:3000` or an https tunnel (section 3) |
| "This link is incomplete" | The invite link lost its `#…` part. Copy the whole link, including everything after `#` |
| Message shows "Could not decrypt" | That person has a different key, or the link was altered. Compare safety codes |
| "⚠ name already used by a different key" | Two different people (or a browser with cleared storage) are using one display name. Compare 🔑 fingerprints out loud before trusting messages from that name |
| "unsigned client" under a name | That member's browser did not send a signing key. Their messages will not be shown |
| Camera or microphone permission denied | Click the lock icon in the address bar and allow it, then retry |
| "Camera in use by another app or tab" | Close the other tab/app, use another browser or device, or start a voice-only call |
| No "Share screen" button | Your browser does not support screen capture (most mobile browsers) |
| Call connects on one network but not another | Strict NAT/firewall needs a TURN server (see roadmap). Same Wi-Fi or a hotspot works |
| Video from a voice-only joiner is missing | By design: voice-only joiners send no video but still see everyone else's |

---

## 9. Extending it

Natural next steps, roughly in order of value: accounts and per-user keys, QR-code identity verification, a TURN server, persistence, per-room settings (turn receipts off, default message lifetime), and moving to the Signal Protocol or MLS. The data layer in `server.js` is a plain `Map`, so swapping in a database is a contained change.
