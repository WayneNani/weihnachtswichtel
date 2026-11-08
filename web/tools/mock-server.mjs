// Mock server for UI development (Node standard library only).
// Serves the mock build (dist-mock/) and an in-memory implementation of docs/api.md.
//
//   npm run dev:mock                       → http://localhost:8080
//   PORT=9000 MOCK_COLLISION=0.3 npm run dev:mock
//
// MOCK_COLLISION: probability (0…1) that a finished step 1 counts as a collision (new round).
// MOCK_PUSH=0: never contact push services (default: send payload-less VAPID pushes after opt-in,
// incl. the anonymous wish-change hints of Spec §16.3).
import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";
import { createSign, generateKeyPairSync } from "node:crypto";
import { MockServer } from "../dist-mock-server/core.mjs";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".webmanifest": "application/manifest+json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".wasm": "application/wasm",
  ".ico": "image/x-icon",
};

const SECURITY_HEADERS = {
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

const b64u = (buf) => Buffer.from(buf).toString("base64url");

function vapidKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  return { raw: new Uint8Array(raw), privateKey };
}

function vapidJwt(privateKey, audience) {
  const header = b64u(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = b64u(JSON.stringify({ aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "mailto:mock@localhost" }));
  const signer = createSign("SHA256");
  signer.update(`${header}.${claims}`);
  const sig = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${header}.${claims}.${b64u(sig)}`;
}

export async function startMockServer({ root = "dist-mock", port = 8080, host = "127.0.0.1" } = {}) {
  const rootDir = resolve(root);
  const vapid = vapidKeys();
  const pushEnabled = process.env.MOCK_PUSH !== "0";
  // Payload-less VAPID push. Only the host is logged, never the endpoint (Spec §16.3: a hint
  // endpoint is not stored, not even in the log).
  const sendPush = (endpoint, what) => {
    if (!pushEnabled) return;
    const url = new URL(endpoint);
    const jwt = vapidJwt(vapid.privateKey, url.origin);
    fetch(endpoint, {
      method: "POST",
      headers: { TTL: "3600", Authorization: `vapid t=${jwt}, k=${b64u(vapid.raw)}`, "Content-Length": "0" },
      signal: AbortSignal.timeout(10_000),
    })
      .then((r) => console.log(`[mock] ${what} → ${url.host}: ${r.status}`))
      .catch((e) => console.log(`[mock] ${what} failed: ${e.message}`));
  };
  const server = new MockServer({
    collisionRate: Number(process.env.MOCK_COLLISION ?? 0.1),
    vapidPublicKey: vapid.raw,
    log: (m) => console.log(`[mock] ${m}`),
    onPush: (sub) => sendPush(sub.endpoint, "push"),
    onNotify: (endpoint) => sendPush(endpoint, "wish hint"),
  });
  setInterval(() => server.tick(), 2000).unref();

  const http = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);

    // Server-Sent Events.
    const sse = /^\/api\/groups\/([^/]+)\/events$/.exec(url.pathname);
    if (sse && req.method === "GET") {
      if (!server.hasGroup(sse[1])) {
        res.writeHead(404, { "content-type": "application/json" }).end('{"error":"not_found","message":"no such group"}');
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      res.write(": connected\n\n");
      const unsubscribe = server.subscribe(sse[1], (ev) => res.write(`event: update\ndata: ${JSON.stringify(ev)}\n\n`));
      const ping = setInterval(() => res.write(": ping\n\n"), 25_000);
      req.on("close", () => {
        clearInterval(ping);
        unsubscribe();
      });
      return;
    }

    if (url.pathname.startsWith("/api/")) {
      const chunks = [];
      let size = 0;
      for await (const c of req) {
        size += c.length;
        if (size > 3_000_000) {
          res.writeHead(413).end();
          return;
        }
        chunks.push(c);
      }
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
      // Simulated network latency.
      await new Promise((r) => setTimeout(r, 80 + Math.random() * 120));
      const out = server.handle({ method: req.method ?? "GET", path: url.pathname + url.search, headers, body: new Uint8Array(Buffer.concat(chunks)) });
      res.writeHead(out.status, out.headers);
      res.end(Buffer.from(out.body));
      return;
    }

    // Static files with SPA fallback (all non-file paths → index.html).
    let file = normalize(join(rootDir, decodeURIComponent(url.pathname)));
    if (!file.startsWith(rootDir)) {
      res.writeHead(403).end();
      return;
    }
    if (!existsSync(file) || statSync(file).isDirectory()) file = join(rootDir, "index.html");
    res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    createReadStream(file).pipe(res);
  });

  await new Promise((r) => http.listen(port, host, r));
  console.log(`\n🎁 Mock-Server läuft: http://localhost:${port}/  (Strg+C beendet)\n`);
  return http;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await startMockServer({ root: process.argv[2] ?? "dist-mock", port: Number(process.env.PORT ?? 8080) });
}
