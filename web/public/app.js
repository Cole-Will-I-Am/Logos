// Logos web client — Phase 1: in-browser identity + registration + peer lookup.
//
// The crypto runs in WebAssembly (the same Rust crates the iOS app uses): keys
// are generated locally and only public material + the signed registration body
// ever leave the browser. The relay is reached same-origin via the Worker's
// /v1/* proxy, so there is no CORS and the relay needs no changes.

import init, { check_username, build_registration, compute_safety_number } from "/wasm/logos_wasm.js";

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

// ---------- tiny IndexedDB store (single 'account' record) ----------
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
    t.onsuccess = () => res(t.result || null);
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

// ---------- at-rest encryption of the secret material ----------
// Public account info (username, public keys, mailbox, registration body) is stored
// in the clear so the UI can render without unlocking. The SECRET material (identity
// seed + prekey secrets) is encrypted with a non-extractable AES-GCM key kept in
// IndexedDB and bound to this origin, so the seed never sits in storage/back-ups as
// readable bytes. This raises the bar against disk/offline access; it does NOT stop a
// live XSS on the origin — the strict CSP in worker.js is the control for that. A user
// passphrase (PBKDF2/Argon2 → key) is the next hardening step; see HANDOFF.md.
async function persistAccount(acct) {
  const { secret_state, ...pub } = acct;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(secret_state));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  await dbSet("pub", pub);
  await dbSet("seckey", key); // non-extractable CryptoKey (structured-clone stored)
  await dbSet("sec", { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) });
}
async function decryptSecret() {
  const key = await dbGet("seckey");
  const blob = await dbGet("sec");
  if (!key || !blob) return null;
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(blob.iv) }, key, new Uint8Array(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

let ACCOUNT = null; // public fields (+ secret_state only in-memory right after creation)

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
      const reason = check_username(name); // null = ok, else reason string
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
      const acct = JSON.parse(build_registration(name, 32, 32));

      // Publish ONLY the public registration body to the relay.
      const resp = await fetch("/v1/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(acct.register_request),
      });
      if (resp.status === 409) throw new Error("That username is already taken — try another.");
      if (resp.status === 429) throw new Error("The relay is busy (rate limit). Give it a moment and retry.");
      if (!resp.ok) throw new Error("Registration failed (" + resp.status + "). Please try again.");

      ACCOUNT = acct;
      await persistAccount(acct); // public fields in the clear; seed + prekey secrets encrypted at rest

      // Recovery screen.
      $("rec-username").textContent = "@" + name;
      $("rec-seed").textContent = acct.secret_state.seed_hex;
      show("recovery");
    } catch (e) {
      btn.innerHTML = original;
      btn.disabled = false;
      const hint2 = $("username-hint");
      hint2.className = "hint bad";
      hint2.textContent = (e && e.message) || "Something went wrong.";
    }
  });
}

function wireRecovery() {
  $("rec-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("rec-seed").textContent); $("rec-copy").textContent = "Copied ✓"; }
    catch { $("rec-copy").textContent = "Select & copy manually"; }
  });
  $("rec-done").addEventListener("click", () => enterApp());
}

// ---------- app ----------
function enterApp() {
  const a = ACCOUNT;
  $("whoami").hidden = false;
  $("whoami-name").textContent = "@" + a.username;
  $("me-name").textContent = a.username;
  $("me-avatar").textContent = (a.username[0] || "?").toUpperCase();
  $("me-fpr").textContent = short(a.identity_ed_hex, 10);
  $("me-mailbox").textContent = short(a.mailbox, 10);
  show("app");
}

function wireApp() {
  $("me-seed-btn").addEventListener("click", async () => {
    let seed = ACCOUNT.secret_state?.seed_hex;          // present right after creation
    if (!seed) seed = (await decryptSecret())?.seed_hex; // decrypt on demand on a return visit
    if (!seed) { alert("Couldn’t unlock the recovery seed on this device."); return; }
    alert("Recovery seed for @" + ACCOUNT.username + ":\n\n" + seed + "\n\nKeep this private and safe.");
  });

  const doLookup = async () => {
    const name = $("lookup").value.trim().toLowerCase();
    const box = $("peer-result");
    if (!name) return;
    box.classList.remove("hidden");
    box.innerHTML = '<span class="spin"></span> <span class="muted small">Looking up @' + esc(name) +"…</span>";
    try {
      const resp = await fetch("/v1/directory/" + encodeURIComponent(name));
      if (resp.status === 404) {
        box.innerHTML = '<span class="badge missing">not found</span> <span class="small muted">@' + esc(name) +" isn’t registered on this relay.</span>";
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
      const sn = compute_safety_number(ACCOUNT.identity_ed_hex, ACCOUNT.identity_dh_hex, peerEd, peerDh);
      const self = name === ACCOUNT.username;
      box.innerHTML =
        '<span class="badge found">found</span> <b>@' + esc(name) +"</b>" +
        '<div class="kv" style="margin-top:10px">Their identity key<br><span class="mono">' + short(peerEd, 10) + "</span></div>" +
        (self
          ? '<div class="note" style="margin-top:12px"><span class="ico">🪞</span><span>That’s you.</span></div>'
          : '<div class="kv" style="margin-top:10px">Safety number (compare in person / on a call)<br><span class="mono" style="font-size:13px">' + sn + "</span></div>");
    } catch (e) {
      box.innerHTML = '<span class="small muted">Lookup failed. ' + ((e && e.message) || "") + "</span>";
    }
  };
  $("lookup-btn").addEventListener("click", doLookup);
  $("lookup").addEventListener("keydown", (e) => { if (e.key === "Enter") doLookup(); });
}

// ---------- boot ----------
(async function main() {
  show("loading");
  await init(); // load the wasm module
  wireOnboarding();
  wireRecovery();
  wireApp();

  ACCOUNT = await dbGet("pub");
  // One-time migration: an earlier build stored the whole account (incl. plaintext
  // secrets) under "me". Re-encrypt it and drop the plaintext record.
  if (!ACCOUNT) {
    const legacy = await dbGet("me");
    if (legacy && legacy.username) {
      await persistAccount(legacy);
      await dbDel("me");
      ACCOUNT = await dbGet("pub");
    }
  }
  if (ACCOUNT && ACCOUNT.username) enterApp();
  else show("onboard");
})();
