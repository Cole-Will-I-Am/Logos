// Logos web — Cloudflare Worker.
//
// 1) Serves the static web client (./public: index.html, app.js, styles.css, the
//    wasm + bindings, brand assets).
// 2) Proxies the Logos relay API same-origin: /v1/* -> https://relay.manticthink.com/v1/*.
//    This keeps the browser talking only to its own origin (no CORS) and means the
//    relay (which iOS uses unchanged) needs no modification.
//
// The relay is a dumb store-and-forward of sealed blobs; all E2EE happens in the
// browser via WebAssembly, so this proxy never sees plaintext.

const RELAY = "https://relay.manticthink.com";

// Strict CSP. Keys live in the browser (see app.js), so an XSS would be
// catastrophic — lock the origin down. `wasm-unsafe-eval` is required for
// WebAssembly.instantiate; `style-src 'unsafe-inline'` covers the small inline
// style attributes the app sets (there is no inline <script>, so scripts stay strict).
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
].join("; ");

const SECURITY_HEADERS = {
  "content-security-policy": CSP,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/v1/")) {
      const target = RELAY + url.pathname + url.search;
      const method = request.method.toUpperCase();
      const init = {
        method,
        headers: { "content-type": request.headers.get("content-type") || "application/json" },
        body: method === "GET" || method === "HEAD" ? undefined : await request.arrayBuffer(),
      };
      let resp;
      try {
        resp = await fetch(target, init);
      } catch (e) {
        return new Response(JSON.stringify({ error: "relay unreachable" }), {
          status: 502,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        });
      }
      const headers = new Headers(resp.headers);
      headers.set("cache-control", "no-store");
      return new Response(resp.body, { status: resp.status, headers });
    }

    // Static site (single page — any non-asset path falls back to index.html).
    if (env.ASSETS) {
      const resp = await env.ASSETS.fetch(request);
      const headers = new Headers(resp.headers);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
      return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
    }
    return new Response("Logos web", { status: 200, headers: { "content-type": "text/plain", ...SECURITY_HEADERS } });
  },
};
