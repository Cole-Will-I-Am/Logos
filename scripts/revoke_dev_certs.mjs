// Revoke stale cloud-managed "Apple Development" certificates before archiving.
//
// Each CI run on a fresh macOS runner mints a new Development cert during
// `xcodebuild archive` (automatic signing + -allowProvisioningUpdates). They
// accumulate until the account hits "maximum number of certificates" and the
// archive fails. This clears Development certs first so the run can mint a fresh
// one. It ONLY touches DEVELOPMENT-type certs — Distribution/TestFlight certs are
// never affected — and it never fails the build (best-effort cleanup).
//
// Uses the App Store Connect API key already provided as CI secrets:
//   ASC_KEY_ID, ASC_ISSUER_ID, ASC_KEY_P8_BASE64
import crypto from "node:crypto";

const apiBase = "https://api.appstoreconnect.apple.com/v1";

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function makeToken() {
  const keyId = process.env.ASC_KEY_ID;
  const issuerId = process.env.ASC_ISSUER_ID;
  const privateKey = Buffer.from(process.env.ASC_KEY_P8_BASE64 || "", "base64").toString("utf8");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", kid: keyId, typ: "JWT" };
  const payload = { iss: issuerId, iat: now, exp: now + 19 * 60, aud: "appstoreconnect-v1" };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = crypto.sign("sha256", Buffer.from(signingInput), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${signingInput}.${base64url(signature)}`;
}

async function api(token, method, path) {
  const r = await fetch(`${apiBase}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  const text = await r.text();
  const body = text ? JSON.parse(text) : {};
  if (!r.ok) throw new Error(`${method} ${path} -> ${r.status}: ${JSON.stringify(body.errors || body)}`);
  return body;
}

async function main() {
  if (!process.env.ASC_KEY_ID || !process.env.ASC_ISSUER_ID || !process.env.ASC_KEY_P8_BASE64) {
    console.log("ASC secrets not present — skipping cert cleanup.");
    return;
  }
  const token = makeToken();
  const certs = (await api(token, "GET", "/certificates?limit=200")).data || [];
  const dev = certs.filter((c) => /DEVELOPMENT/i.test(c.attributes?.certificateType || ""));
  const distribution = certs.length - dev.length;
  console.log(`Certificates: ${certs.length} total — ${dev.length} development, ${distribution} other (kept).`);

  let revoked = 0;
  for (const c of dev) {
    try {
      await api(token, "DELETE", `/certificates/${c.id}`);
      revoked++;
      console.log(`  revoked DEVELOPMENT "${c.attributes?.displayName}" (${c.id})`);
    } catch (e) {
      console.log(`  could not revoke ${c.id}: ${e.message}`);
    }
  }
  console.log(`Revoked ${revoked} development cert(s). The archive will mint a fresh one.`);
}

// Best-effort: never fail the build on cleanup problems.
main().catch((e) => {
  console.log(`Cert cleanup skipped (non-fatal): ${e.message}`);
  process.exit(0);
});
