import assert from "node:assert/strict";
import { test } from "node:test";
import { b64uDecode, b64uDecodeLen, b64uEncode, truncateUtf8, utf8Len } from "../lib/bytes";
import { buildFragment, groupLink, parseFragment, parseRoute } from "../lib/fragment";
import { sha256 } from "../lib/sha256";
import { utf8 } from "../lib/bytes";

const K = new Uint8Array(32).fill(1);
const A = new Uint8Array(32).fill(2);
const S = new Uint8Array(32).fill(3);
const GID = b64uEncode(new Uint8Array(16).fill(9));

test("base64url roundtrip for all lengths", () => {
  for (let len = 0; len < 70; len++) {
    const b = new Uint8Array(len).map((_, i) => (i * 37 + len) & 255);
    const s = b64uEncode(b);
    assert.ok(!s.includes("=") && !s.includes("+") && !s.includes("/"));
    assert.deepEqual(b64uDecode(s), b);
  }
  assert.equal(b64uEncode(new Uint8Array(16).fill(7)), "BwcHBwcHBwcHBwcHBwcHBw"); // same as wichtel-api test
});

test("base64url rejects padding, foreign chars, non-canonical tails", () => {
  assert.throws(() => b64uDecode("AAAA="));
  assert.throws(() => b64uDecode("AA+A"));
  assert.throws(() => b64uDecode("A"));
  assert.throws(() => b64uDecode("AB")); // trailing bits set
  assert.equal(b64uDecodeLen("AQ", 2), null);
  assert.deepEqual(b64uDecodeLen("AQ", 1), new Uint8Array([1]));
});

test("sha256 known answers", () => {
  assert.equal(b64uEncode(sha256(new Uint8Array(0))), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
  assert.equal(b64uEncode(sha256(utf8("abc"))), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  // multi-block input (> 55 bytes)
  const long = utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  assert.equal(b64uEncode(sha256(long)), "JI1qYdIGOLjlwCaTDD5gOaM85Flk_yFn9uzt1BnbBsE");
  assert.deepEqual(sha256(utf8("ab"), utf8("c")), sha256(utf8("abc")));
});

test("parseFragment: invite, admin, personal", () => {
  const inv = parseFragment(`#k=${b64uEncode(K)}`);
  assert.ok(inv.ok);
  if (inv.ok) {
    assert.deepEqual(inv.secrets.k, K);
    assert.equal(inv.secrets.a, undefined);
    assert.equal(inv.secrets.s, undefined);
  }
  const adm = parseFragment(`k=${b64uEncode(K)}&a=${b64uEncode(A)}`);
  assert.ok(adm.ok && adm.secrets.a && adm.secrets.a[0] === 2);
  const per = parseFragment(`#k=${b64uEncode(K)}&s=${b64uEncode(S)}`);
  assert.ok(per.ok && per.secrets.s && per.secrets.s[0] === 3);
  // order does not matter, unknown keys are ignored
  const mixed = parseFragment(`#s=${b64uEncode(S)}&x=1&k=${b64uEncode(K)}`);
  assert.ok(mixed.ok && mixed.secrets.s);
});

test("parseFragment: errors", () => {
  assert.deepEqual(parseFragment(""), { ok: false, error: "missing_key" });
  assert.deepEqual(parseFragment("#"), { ok: false, error: "missing_key" });
  assert.deepEqual(parseFragment(`#s=${b64uEncode(S)}`), { ok: false, error: "missing_key" });
  assert.deepEqual(parseFragment("#k=abc"), { ok: false, error: "invalid" }); // wrong length
  assert.deepEqual(parseFragment(`#k=${b64uEncode(K)}&k=${b64uEncode(K)}`), { ok: false, error: "invalid" });
  assert.deepEqual(parseFragment(`#k=${b64uEncode(K)}&a=`), { ok: false, error: "invalid" });
  assert.deepEqual(parseFragment(`#k=${b64uEncode(K)}=`), { ok: false, error: "invalid" });
  // truncated copy-paste (one char missing)
  assert.deepEqual(parseFragment(`#k=${b64uEncode(K).slice(0, -1)}`), { ok: false, error: "invalid" });
});

test("buildFragment ⇄ parseFragment", () => {
  const f = buildFragment({ k: K, a: A, s: S });
  assert.equal(f, `#k=${b64uEncode(K)}&a=${b64uEncode(A)}&s=${b64uEncode(S)}`);
  const p = parseFragment(f);
  assert.ok(p.ok);
  if (p.ok) assert.deepEqual([p.secrets.k, p.secrets.a, p.secrets.s], [K, A, S]);
});

test("parseRoute", () => {
  assert.deepEqual(parseRoute("/", ""), { page: "home" });
  assert.deepEqual(parseRoute("/neu", ""), { page: "create" });
  assert.deepEqual(parseRoute("/foo", ""), { page: "not_found" });
  assert.deepEqual(parseRoute("/g/short", ""), { page: "not_found" });
  const r = parseRoute(`/g/${GID}`, `#k=${b64uEncode(K)}`);
  assert.equal(r.page, "group");
  if (r.page === "group") {
    assert.equal(r.gidB64, GID);
    assert.equal(r.gid.length, 16);
    assert.ok(r.fragment.ok);
  }
  const noKey = parseRoute(`/g/${GID}/`, "");
  assert.ok(noKey.page === "group" && !noKey.fragment.ok);
});

test("groupLink never leaks the admin secret into invite/personal links", () => {
  const all = { k: K, a: A, s: S };
  const inv = groupLink("https://x.test", GID, "invite", all);
  const per = groupLink("https://x.test", GID, "personal", all);
  const adm = groupLink("https://x.test", GID, "admin", all);
  assert.equal(inv, `https://x.test/g/${GID}#k=${b64uEncode(K)}`);
  assert.ok(!per.includes("&a=") && per.includes("&s="));
  assert.ok(adm.includes("&a=") && !adm.includes("&s="));
});

test("truncateUtf8 keeps code points intact", () => {
  assert.equal(truncateUtf8("äöü", 4), "äö");
  assert.equal(truncateUtf8("🎁🎁", 5), "🎁");
  assert.equal(utf8Len(truncateUtf8("x".repeat(100), 64)), 64);
});
