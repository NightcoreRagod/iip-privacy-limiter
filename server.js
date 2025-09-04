import express from "express";
import { WebSocketServer } from "ws";
import http from "http";

const app = express();
app.use(express.static("public"));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// In-memory: roomName -> Set(ws)
const rooms = new Map();
// ws -> { name, room, pubKey (base64) }
const peers = new Map();

function broadcast(room, data, exceptWs = null) {
  const set = rooms.get(room);
  if (!set) return;
  for (const client of set) {
    if (client.readyState === 1 && client !== exceptWs) {
      client.send(JSON.stringify(data));
    }
  }
}

wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // {type:"join", room, name, pubKey}
    if (msg.type === "join") {
      peers.set(ws, { name: msg.name, room: msg.room, pubKey: msg.pubKey });
      if (!rooms.has(msg.room)) rooms.set(msg.room, new Set());
      rooms.get(msg.room).add(ws);

      // Notify existing members about new peer's pubKey
      broadcast(msg.room, {
        type: "peer-joined",
        name: msg.name,
        pubKey: msg.pubKey
      }, ws);

      // Send current roster (pubKeys) to the newcomer
      const roster = [];
      for (const client of rooms.get(msg.room)) {
        if (client !== ws && peers.has(client)) {
          const p = peers.get(client);
          roster.push({ name: p.name, pubKey: p.pubKey });
        }
      }
      ws.send(JSON.stringify({ type: "roster", peers: roster }));
    }

    // Relay encrypted messages (ciphertext only)
    // {type:"ciphertext", toPubKey, fromPubKey, payload, ttlSec?, nonce, sentAt}
    if (msg.type === "ciphertext") {
      const meta = peers.get(ws);
      if (!meta) return;
      const set = rooms.get(meta.room);
      if (!set) return;
      for (const client of set) {
        if (client.readyState !== 1) continue;
        const p = peers.get(client);
        if (!p) continue;
        if (p.pubKey === msg.toPubKey) {
          client.send(JSON.stringify(msg));
        }
      }
    }
  });

  ws.on("close", () => {
    const meta = peers.get(ws);
    if (meta) {
      const { room, name, pubKey } = meta;
      peers.delete(ws);
      const set = rooms.get(room);
      if (set) {
        set.delete(ws);
        if (set.size === 0) rooms.delete(room);
      }
      broadcast(room, { type: "peer-left", name, pubKey });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`relay server running at http://localhost:${PORT}`);
});
