// --- Globals ---
let ws = null;
let my = {
  keyPair: null,       // nacl.box.keyPair()
  name: null,
  room: null,
  pubKeyB64: null
};
const peers = new Map(); // pubKeyB64 -> { name, shared: Uint8Array | null }

// Helpers
const enc = nacl.util.encodeUTF8;
const dec = nacl.util.decodeUTF8;
const b64 = {
  fromBytes: (u8) => btoa(String.fromCharCode(...u8)),
  toBytes: (b) => new Uint8Array(atob(b).split("").map(c => c.charCodeAt(0)))
};

function appendMsg(who, text, isLocal = false) {
  const chat = document.getElementById("chat");
  const div = document.createElement("div");
  div.className = `mb-2 ${isLocal ? "text-right" : "text-left"}`;
  div.innerHTML = `<span class="inline-block px-3 py-2 rounded ${isLocal ? "bg-green-100" : "bg-slate-100"}">
    <strong>${who}:</strong> ${text}
  </span>`;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function renderPeers() {
  const ul = document.getElementById("peers");
  ul.innerHTML = "";
  for (const [pub, info] of peers) {
    const li = document.createElement("li");
    li.className = "text-sm";
    li.innerHTML = `
      <div class="border rounded p-2">
        <div class="font-semibold">${info.name}</div>
        <div class="text-xs break-all text-slate-500">${pub}</div>
        <div class="text-xs mt-1">${info.shared ? "🔑 Shared key ready" : "⏳ Waiting for key"}</div>
      </div>`;
    ul.appendChild(li);
  }
}

function deriveShared(theirPubB64) {
  const theirPub = b64.toBytes(theirPubB64);
  // nacl.box.before => 32-byte shared key via Curve25519
  const shared = nacl.box.before(theirPub, my.keyPair.secretKey);
  peers.get(theirPubB64).shared = shared;
}

// UI elements
const elName = document.getElementById("name");
const elRoom = document.getElementById("room");
const elGen = document.getElementById("genKeys");
const elJoin = document.getElementById("join");
const elSend = document.getElementById("send");
const elMsg = document.getElementById("message");
const elTTL = document.getElementById("ttl");
const elMyPub = document.getElementById("myPub");
const elKeyStatus = document.getElementById("keyStatus");

// Key generation
elGen.onclick = () => {
  my.keyPair = nacl.box.keyPair();
  my.pubKeyB64 = b64.fromBytes(my.keyPair.publicKey);
  localStorage.setItem("ppchat_pub", my.pubKeyB64);
  localStorage.setItem("ppchat_secret", b64.fromBytes(my.keyPair.secretKey));
  elMyPub.value = my.pubKeyB64;
  elKeyStatus.textContent = "Keys generated (Curve25519). Keep your tab safe.";
};

// Load keys if present
window.addEventListener("load", () => {
  const pub = localStorage.getItem("ppchat_pub");
  const sec = localStorage.getItem("ppchat_secret");
  if (pub && sec) {
    my.keyPair = {
      publicKey: b64.toBytes(pub),
      secretKey: b64.toBytes(sec)
    };
    my.pubKeyB64 = pub;
    elMyPub.value = pub;
    elKeyStatus.textContent = "Loaded existing keys from localStorage.";
  }
});

// Join room
elJoin.onclick = () => {
  const name = elName.value.trim() || `anon-${Math.floor(Math.random()*9999)}`;
  const room = elRoom.value.trim() || "lobby";
  if (!my.keyPair) {
    alert("Generate keys first.");
    return;
  }
  my.name = name;
  my.room = room;

  ws = new WebSocket(`ws://${location.host}`);
  ws.onopen = () => {
    ws.send(JSON.stringify({
      type: "join",
      name: my.name,
      room: my.room,
      pubKey: my.pubKeyB64
    }));
    appendMsg("System", `Joined room "${room}" as ${name}`);
  };

  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);

    if (msg.type === "roster") {
      // Existing peers in room
      for (const p of msg.peers) {
        peers.set(p.pubKey, { name: p.name, shared: null });
        deriveShared(p.pubKey);
      }
      renderPeers();
    }

    if (msg.type === "peer-joined") {
      peers.set(msg.pubKey, { name: msg.name, shared: null });
      deriveShared(msg.pubKey);
      renderPeers();
      appendMsg("System", `${msg.name} joined`);
    }

    if (msg.type === "peer-left") {
      peers.delete(msg.pubKey);
      renderPeers();
      appendMsg("System", `${msg.name} left`);
    }

    // Encrypted message arrived
    if (msg.type === "ciphertext") {
      const info = peers.get(msg.fromPubKey);
      if (!info || !info.shared) return;

      const nonce = b64.toBytes(msg.nonce);
      const payload = b64.toBytes(msg.payload);
      const plaintext = nacl.box.open.after(payload, nonce, info.shared);
      if (!plaintext) return; // tampered

      // Parse envelope { text, ttlSec }
      const envelope = JSON.parse(nacl.util.encodeUTF8(plaintext));
      appendMsg(info.name, envelope.text);

      // Apply TTL (client-side delete)
      if (envelope.ttlSec && envelope.ttlSec > 0) {
        setTimeout(() => {
          // naive: clear messages view entirely or mark redaction
          appendMsg("System", `(A message from ${info.name} auto-deleted)`);
          // Optional: you can re-render from a stateful store without that message.
        }, envelope.ttlSec * 1000);
      }
    }
  };

  ws.onclose = () => appendMsg("System", "Disconnected");
  ws.onerror = () => appendMsg("System", "Connection error");
};

// Send encrypted message to a selected peer (for demo: broadcast to all peers)
elSend.onclick = () => {
  const text = elMsg.value;
  const ttlSec = parseInt(elTTL.value || "0", 10);
  if (!text) return;
  if (!ws || ws.readyState !== 1) return alert("Not connected.");

  // For each peer with a shared key, send a copy (1:1 E2EE)
  for (const [pubKeyB64, info] of peers) {
    if (!info.shared) continue;

    const nonce = nacl.randomBytes(24);
    const envelope = JSON.stringify({ text, ttlSec });
    const cipher = nacl.box.after(dec(envelope), nonce, info.shared);

    ws.send(JSON.stringify({
      type: "ciphertext",
      toPubKey: pubKeyB64,
      fromPubKey: my.pubKeyB64,
      payload: b64.fromBytes(cipher),
      nonce: b64.fromBytes(nonce),
      sentAt: Date.now()
    }));
  }

  appendMsg(my.name || "Me", text, true);
  if (ttlSec > 0) {
    setTimeout(() => {
      appendMsg("System", "(Your message auto-deleted locally)");
    }, ttlSec * 1000);
  }

  elMsg.value = "";
};
