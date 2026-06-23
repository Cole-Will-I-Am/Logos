// Logos web client — onboarding + 1:1 end-to-end-encrypted messaging.
//
// The crypto runs in WebAssembly (the same Rust crates the iOS app uses): keys
// are generated locally, and only public material, the signed registration body,
// and sealed (unreadable) envelopes ever leave the browser. The relay is reached
// same-origin via the Worker's /v1/* proxy, so there is no CORS and the relay
// needs no changes. JS owns transport (fetch) and persistence (IndexedDB);
// `WasmClient` owns the identity, prekeys, and per-conversation ratchet sessions.

import init, {
  check_username,
  build_registration,
  compute_safety_number,
  WasmClient,
} from "/wasm/logos_wasm.js";

const $ = (id) => document.getElementById(id);
const show = (id) => {
  for (const v of ["onboard", "recovery", "app", "loading"]) {
    $("view-" + v).classList.toggle("hidden", v !== id);
  }
};
const bytesToHex = (a) => Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
const short = (hex, n = 8) => hex.slice(0, n) + "…" + hex.slice(-n);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nowSecs = () => Math.floor(Date.now() / 1000);
const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const initial = (s) => (s[0] || "?").toUpperCase();

// ---------- tiny IndexedDB key/value store ----------
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("logos", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function dbGet(key) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv", "readonly").objectStore("kv").get(key);
    t.onsuccess = () => res(t.result ?? null);
    t.onerror = () => rej(t.error);
  });
}
async function dbSet(key, val) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv", "readwrite").objectStore("kv").put(val, key);
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}
async function dbDel(key) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv", "readwrite").objectStore("kv").delete(key);
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}

// ---------- at-rest encryption ----------
// The full client state (identity seed + prekey secrets + live ratchet sessions)
// and the message history are AES-GCM-encrypted under a NON-EXTRACTABLE WebCrypto
// key kept in IndexedDB and bound to this origin, so secrets never sit in storage
// or back-ups as readable bytes. This blocks disk/offline scraping; it does NOT
// stop a live XSS on the origin — the strict CSP in worker.js is the control for
// that, and a user passphrase (PBKDF2/Argon2) is the next hardening step (HANDOFF).
async function getKey() {
  let k = await dbGet("seckey");
  if (!k) {
    k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await dbSet("seckey", k);
  }
  return k;
}
async function encStr(s) {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(s));
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}
async function decStr(blob) {
  const key = await getKey();
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(blob.iv) }, key, new Uint8Array(blob.ct));
  return new TextDecoder().decode(pt);
}

// ---------- app state ----------
let CLIENT = null; // WasmClient — the messaging engine
let LOGS = {}; // { peerUsername: [{ dir:"in"|"out"|"sys", text, ts }] }
let ACTIVE = null; // username of the open conversation, or null (list view)
const UNREAD = new Set();
let polling = false;
let pollTimer = null;

async function saveState() {
  await dbSet("state", await encStr(CLIENT.export()));
}
async function saveLogs() {
  await dbSet("logs", await encStr(JSON.stringify(LOGS)));
}

// ---------- relay transport (same-origin via the Worker /v1/* proxy) ----------
async function relay(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "content-type": "application/json" } : undefined,
    body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  if (!res.ok) {
    const e = new Error("relay " + res.status);
    e.status = res.status;
    throw e;
  }
  return text ? JSON.parse(text) : null;
}

async function ensureCert() {
  if (CLIENT.needs_cert(nowSecs())) {
    const r = await relay("POST", "/v1/cert", CLIENT.cert_request());
    CLIENT.set_cert(JSON.stringify(r.certificate));
  }
}
async function ensureServerKey() {
  if (!CLIENT.has_server_key()) {
    const r = await relay("GET", "/v1/server-key");
    CLIENT.set_server_key(JSON.stringify(r));
  }
}

// ---------- sending ----------
async function sendMessage(to, text) {
  await ensureCert();
  let bundle = null;
  if (!CLIENT.has_session(to)) {
    const dir = await relay("GET", "/v1/directory/" + encodeURIComponent(to)); // 404 → not registered
    bundle = JSON.stringify(dir.bundle);
  }
  const prep = JSON.parse(CLIENT.prepare_send(to, bundle, text));
  await saveState(); // durability: the ratchet advance MUST be persisted before the ciphertext leaves
  await relay("POST", "/v1/mailbox/" + prep.mailbox, prep.post_body);
  CLIENT.confirm_sent(to);
  await saveState();
}

// ---------- receiving ----------
async function pollOnce() {
  if (!CLIENT || polling) return;
  polling = true;
  try {
    await ensureServerKey();
    const r = await relay("POST", "/v1/fetch", CLIENT.fetch_request());
    if (r.envelopes && r.envelopes.length) {
      const out = JSON.parse(CLIENT.process_incoming(JSON.stringify(r.envelopes), nowSecs()));
      await saveState(); // durability: persist decrypted state before ACK-deleting on the relay (F-07)
      if (out.ack_ids.length) await relay("POST", "/v1/ack", CLIENT.ack_request(JSON.stringify(out.ack_ids)));
      if (out.messages.length) await onIncoming(out.messages);
    }
  } catch (_) {
    // transient network/relay hiccup — the next poll retries.
  } finally {
    polling = false;
  }
}
function startPolling() {
  stopPolling();
  pollOnce();
  pollTimer = setInterval(pollOnce, 3500);
}
function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function onIncoming(messages) {
  for (const m of messages) {
    (LOGS[m.from] ||= []).push({ dir: "in", text: m.text, ts: Date.now() });
    if (ACTIVE !== m.from) UNREAD.add(m.from);
  }
  await saveLogs();
  if (ACTIVE && messages.some((m) => m.from === ACTIVE)) renderThread(ACTIVE);
  else renderList();
}

// ===================== UI =====================

function peerList() {
  const names = new Set([...(CLIENT ? CLIENT.peers() : []), ...Object.keys(LOGS)]);
  return [...names].sort((a, b) => {
    const la = (LOGS[a] || []).at(-1)?.ts || 0;
    const lb = (LOGS[b] || []).at(-1)?.ts || 0;
    return lb - la;
  });
}

function renderList() {
  ACTIVE = null;
  $("chat-back").classList.add("hidden");
  $("chat-title").textContent = "Conversations";
  $("chat-sub").textContent = "End-to-end encrypted · post-quantum · sealed sender";
  const input = $("composer-input");
  input.disabled = true;
  input.placeholder = "Open a conversation to start…";
  $("composer-send").disabled = true;

  const body = $("chat-body");
  const peers = peerList();
  body.classList.remove("is-empty");
  let html =
    '<div class="newchat">' +
    '<div class="field"><span class="at">@</span>' +
    '<input id="new-peer" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="username to message"></div>' +
    '<button class="ghost" id="new-go">Start</button></div>';

  if (peers.length === 0) {
    html +=
      '<div class="inner" style="padding:34px 22px;text-align:center;margin:0 auto">' +
      '<div style="font-size:30px;margin-bottom:8px">💬</div>' +
      '<h2 style="margin-bottom:6px">No conversations yet</h2>' +
      '<p class="small muted">Enter a Logos username above to start a private, end-to-end-encrypted chat — they can be on the iOS app or the web.</p></div>';
  } else {
    html += '<div class="convlist">';
    for (const p of peers) {
      const last = (LOGS[p] || []).at(-1);
      const prevText = last ? (last.dir === "out" ? "You: " : "") + last.text : "New conversation";
      const unread = UNREAD.has(p);
      html +=
        `<button class="convitem" data-peer="${esc(p)}">` +
        `<div class="avatar-sm">${esc(initial(p))}</div>` +
        `<div class="ci-main"><div class="ci-name">@${esc(p)}</div>` +
        `<div class="ci-prev${unread ? " unread" : ""}">${unread ? "● " : ""}${esc(prevText)}</div></div>` +
        `</button>`;
    }
    html += "</div>";
  }
  body.innerHTML = html;

  const go = () => {
    const name = ($("new-peer").value || "").trim().toLowerCase();
    if (!name) return;
    const reason = check_username(name);
    if (reason) {
      $("new-peer").focus();
      return;
    }
    openThread(name);
  };
  $("new-go").addEventListener("click", go);
  $("new-peer").addEventListener("keydown", (e) => {
    if (e.key === "Enter") go();
  });
  body.querySelectorAll(".convitem").forEach((el) =>
    el.addEventListener("click", () => openThread(el.dataset.peer))
  );
}

function openThread(peer) {
  ACTIVE = peer;
  UNREAD.delete(peer);
  renderThread(peer);
  setTimeout(() => $("composer-input").focus(), 0);
}

function renderThread(peer) {
  $("chat-back").classList.remove("hidden");
  $("chat-title").textContent = "@" + peer;

  // Safety number (only once a session exists, i.e. after the first exchange).
  let sub = "End-to-end encrypted";
  try {
    const sn = CLIENT.peer_safety_number(peer);
    if (sn) sub = `Safety № <span class="safety-num">${esc(sn)}</span> · <span class="verify-link" id="verify-link">compare to verify</span>`;
  } catch (_) {}
  $("chat-sub").innerHTML = sub;

  const body = $("chat-body");
  body.classList.remove("is-empty");
  const msgs = LOGS[peer] || [];
  let html = '<div class="thread" id="thread">';
  if (msgs.length === 0) {
    html +=
      '<div class="sysmsg">No messages yet — say hello. Your first message sets up the encrypted session.</div>';
  }
  for (const m of msgs) {
    if (m.dir === "sys") {
      html += `<div class="sysmsg">${esc(m.text)}</div>`;
    } else {
      html += `<div class="bubble ${m.dir}">${esc(m.text)}<span class="meta">${fmtTime(m.ts)}</span></div>`;
    }
  }
  html += "</div>";
  body.innerHTML = html;
  body.scrollTop = body.scrollHeight;

  const vl = $("verify-link");
  if (vl)
    vl.addEventListener("click", () => {
      const sn = CLIENT.peer_safety_number(peer);
      alert(
        `Safety number with @${peer}:\n\n${sn}\n\nCompare these digits with @${peer} in person or over a call you trust. If they match on both devices, no one is intercepting your messages.`
      );
    });

  const input = $("composer-input");
  input.disabled = false;
  input.placeholder = "Message @" + peer + "…";
  $("composer-send").disabled = false;
}

function appendLocal(peer, entry) {
  (LOGS[peer] ||= []).push(entry);
  if (ACTIVE === peer) renderThread(peer);
}

// ---------- onboarding ----------
let checkTimer = null;
function wireOnboarding() {
  const input = $("username");
  const hint = $("username-hint");
  const btn = $("create-btn");

  input.addEventListener("input", () => {
    const name = input.value.trim().toLowerCase();
    if (input.value !== name) input.value = name;
    btn.disabled = true;
    hint.className = "hint";
    hint.textContent = "";
    clearTimeout(checkTimer);
    if (!name) return;
    checkTimer = setTimeout(() => {
      const reason = check_username(name);
      if (reason) {
        hint.className = "hint bad";
        hint.textContent = reason;
        btn.disabled = true;
      } else {
        hint.className = "hint ok";
        hint.textContent = "✓ looks good";
        btn.disabled = false;
      }
    }, 120);
  });

  btn.addEventListener("click", async () => {
    const name = input.value.trim().toLowerCase();
    if (check_username(name)) return;
    btn.disabled = true;
    const original = btn.textContent;
    btn.innerHTML = '<span class="spin"></span> Generating keys…';
    try {
      // Generate identity + prekey pools entirely in-browser (32 one-time X25519
      // + 32 one-time ML-KEM prekeys, matching the iOS client).
      const accountJson = build_registration(name, 32, 32);
      const acct = JSON.parse(accountJson);

      // Publish ONLY the public registration body to the relay.
      const resp = await fetch("/v1/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(acct.register_request),
      });
      if (resp.status === 409) throw new Error("That username is already taken — try another.");
      if (resp.status === 429) throw new Error("The relay is busy (rate limit). Give it a moment and retry.");
      if (!resp.ok) throw new Error("Registration failed (" + resp.status + "). Please try again.");

      // Build the messaging client and persist encrypted state.
      CLIENT = WasmClient.from_account(accountJson);
      LOGS = {};
      await saveState();
      await saveLogs();

      // Recovery screen (seed shown once).
      $("rec-username").textContent = "@" + name;
      $("rec-seed").textContent = acct.secret_state.seed_hex;
      show("recovery");
    } catch (e) {
      btn.innerHTML = original;
      btn.disabled = false;
      hint.className = "hint bad";
      hint.textContent = (e && e.message) || "Something went wrong.";
    }
  });
}

function wireRecovery() {
  $("rec-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("rec-seed").textContent);
      $("rec-copy").textContent = "Copied ✓";
    } catch {
      $("rec-copy").textContent = "Select & copy manually";
    }
  });
  $("rec-done").addEventListener("click", () => enterApp());
}

// ---------- identity card + lookup + composer ----------
function enterApp() {
  $("whoami").hidden = false;
  $("whoami-name").textContent = "@" + CLIENT.username();
  $("me-name").textContent = CLIENT.username();
  $("me-avatar").textContent = initial(CLIENT.username());
  $("me-fpr").textContent = short(CLIENT.identity_ed_hex(), 10);
  $("me-mailbox").textContent = short(CLIENT.mailbox(), 10);
  show("app");
  renderList();
  startPolling();
}

function wireApp() {
  $("me-seed-btn").addEventListener("click", async () => {
    try {
      const state = JSON.parse(CLIENT.export());
      alert(
        "Recovery seed for @" +
          CLIENT.username() +
          ":\n\n" +
          state.seed_hex +
          "\n\nKeep this private and safe — it's the only way to recover this identity."
      );
    } catch {
      alert("Couldn’t read the recovery seed on this device.");
    }
  });

  $("chat-back").addEventListener("click", () => renderList());

  // composer
  $("composer").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("composer-input");
    const text = input.value.trim();
    if (!text || !ACTIVE) return;
    const to = ACTIVE;
    input.value = "";
    input.disabled = true;
    $("composer-send").disabled = true;
    appendLocal(to, { dir: "out", text, ts: Date.now() });
    try {
      await sendMessage(to, text);
      await saveLogs();
    } catch (err) {
      let msg = "Couldn’t send — please try again.";
      if (err && err.status === 404) msg = "@" + to + " isn’t registered on Logos.";
      else if (err && /changed/.test(err.message || "")) msg = err.message;
      appendLocal(to, { dir: "sys", text: msg, ts: Date.now() });
      await saveLogs();
    } finally {
      if (ACTIVE === to) {
        $("composer-input").disabled = false;
        $("composer-send").disabled = false;
        $("composer-input").focus();
      }
    }
    // Pick up a fast reply.
    pollOnce();
  });

  // lookup
  const doLookup = async () => {
    const name = $("lookup").value.trim().toLowerCase();
    const box = $("peer-result");
    if (!name) return;
    box.classList.remove("hidden");
    box.innerHTML = '<span class="spin"></span> <span class="muted small">Looking up @' + esc(name) + "…</span>";
    try {
      const resp = await fetch("/v1/directory/" + encodeURIComponent(name));
      if (resp.status === 404) {
        box.innerHTML =
          '<span class="badge missing">not found</span> <span class="small muted">@' +
          esc(name) +
          " isn’t registered on this relay.</span>";
        return;
      }
      if (resp.status === 429) {
        box.innerHTML = '<span class="small muted">Rate limited — try again in a moment.</span>';
        return;
      }
      if (!resp.ok) throw new Error("status " + resp.status);
      const data = await resp.json();
      const id = data.bundle.identity;
      const peerEd = bytesToHex(id.ed);
      const peerDh = bytesToHex(id.dh);
      const sn = compute_safety_number(CLIENT.identity_ed_hex(), CLIENT.identity_dh_hex(), peerEd, peerDh);
      const self = name === CLIENT.username();
      box.innerHTML =
        '<span class="badge found">found</span> <b>@' +
        esc(name) +
        "</b>" +
        '<div class="kv" style="margin-top:10px">Their identity key<br><span class="mono">' +
        short(peerEd, 10) +
        "</span></div>" +
        (self
          ? '<div class="note" style="margin-top:12px"><span class="ico">🪞</span><span>That’s you.</span></div>'
          : '<div class="kv" style="margin-top:10px">Safety number (compare in person / on a call)<br><span class="mono" style="font-size:13px">' +
            sn +
            "</span></div>" +
            '<button class="primary msgbtn" id="msg-peer">Message @' +
            esc(name) +
            "</button>");
      const mb = $("msg-peer");
      if (mb) mb.addEventListener("click", () => openThread(name));
    } catch (e) {
      box.innerHTML = '<span class="small muted">Lookup failed. ' + esc((e && e.message) || "") + "</span>";
    }
  };
  $("lookup-btn").addEventListener("click", doLookup);
  $("lookup").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doLookup();
  });

  // Poll more eagerly when the tab regains focus.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && CLIENT) pollOnce();
  });
}

// ---------- boot ----------
async function restoreClient() {
  // Current format: an encrypted full-client-state blob under "state".
  const state = await dbGet("state");
  if (state) {
    CLIENT = WasmClient.load(await decStr(state));
    const logs = await dbGet("logs");
    LOGS = logs ? JSON.parse(await decStr(logs)) : {};
    return true;
  }
  // Migrate a pre-messaging identity (Phase-1 builds stored secret_state only).
  const legacyClear = await dbGet("me"); // oldest: plaintext account under "me"
  const legacyPub = await dbGet("pub"); // newer: public fields + encrypted "sec"
  const legacySec = await dbGet("sec");
  try {
    if (legacyClear && legacyClear.username && legacyClear.secret_state) {
      CLIENT = WasmClient.from_account(JSON.stringify(legacyClear));
    } else if (legacyPub && legacyPub.username && legacySec) {
      const secret_state = JSON.parse(await decStr(legacySec));
      CLIENT = WasmClient.from_account(JSON.stringify({ username: legacyPub.username, secret_state }));
    } else {
      return false;
    }
  } catch {
    return false;
  }
  LOGS = {};
  await saveState();
  await saveLogs();
  await dbDel("me");
  await dbDel("pub");
  await dbDel("sec");
  return true;
}

(async function main() {
  show("loading");
  await init(); // load the wasm module
  wireOnboarding();
  wireRecovery();
  wireApp();

  let restored = false;
  try {
    restored = await restoreClient();
  } catch (_) {
    restored = false;
  }
  if (restored && CLIENT) enterApp();
  else show("onboard");
})();
