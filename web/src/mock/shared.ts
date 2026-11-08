/**
 * Deterministic helpers shared by the mock WASM module and the mock server, so that both
 * agree on attempt validity, permutations and signatures. NOT cryptographically meaningful.
 */
import { concat, u32be, utf8 } from "../lib/bytes";
import { sha256 } from "../lib/sha256";

export const T = 16;

const l = (s: string) => utf8(s);

/** Copy of crates/wichtel-core/data/wortliste.txt (for realistic-looking mock fingerprints). */
export const WORDS = (
  "Abend Adler Ahorn Anker Apfel Arche Atlas Bach Backe Ball Banane Bank Bart Bauer Baum Becher Beere Berg Besen Biber " +
  "Birne Blatt Blume Bogen Boot Brief Brille Brot Brunnen Buch Burg Butter Dach Dackel Dampf Daumen Decke Delfin Diamant " +
  "Dorf Drache Dose Dudelsack Echo Efeu Eiche Eimer Eis Elch Engel Ente Erbse Esel Eule Fackel Faden Falke Farn Feder Fee " +
  "Feld Fenster Fichte Fisch Flagge Flasche Floh Flocke Fluss Fohlen Forelle Frosch Fuchs Gabel Gans Garten Geige Gipfel " +
  "Giraffe Glocke Gold Gurke Hafen Hagel Hahn Hammer Hase Haus Hecht Hefe Held Helm Hering Himmel Hirsch Honig Horn Hund " +
  "Hut Igel Insel Jacke Jaguar Joghurt Kaffee Kakao Kamel Kamin Kanne Kapelle Karte Kasper Katze Kerze Kiefer Kirsche " +
  "Kiste Klee Knopf Koala Koch Koffer Komet Krone Kugel Kuchen Lachs Lampe Laterne Laus Leiter Lerche Licht Linde Lineal " +
  "Locke Loewe Luchs Mantel Marder Maus Meer Melone Mond Moewe Muschel Nadel Nebel Nelke Nest Netz Nuss Oase Ofen Ohr " +
  "Olive Onkel Orgel Otter Paket Palme Panda Papier Pfanne Pferd Pilz Pinsel Pirat Planet Pudel Puppe Quelle Rabe Rakete " +
  "Rasen Raupe Regen Reh Rentier Riese Ring Robbe Rose Rubin Sahne Salz Sand Schaf Schal Schiff Schlitten Schnee Schnecke " +
  "Schwan Seife Sonne Spatz Spiegel Stern Stiefel Storch Strand Stroh Tanne Tasse Taube Teller Tiger Tisch Tomate Topf " +
  "Turm Uhr Ufer Vase Vogel Vulkan Waage Wal Wald Walnuss Wanne Wecker Welle Wiese Wind Winter Wolf Wolke Wurm Zange " +
  "Zebra Zelt Ziege Zimt Zitrone Zucker Zug Zwerg Zwiebel Anemone Biene Dattel Eisbaer Flamingo Gecko Hummel Kakadu Lama " +
  "Marzipan Nashorn Orange Pinguin Rodel Socke Trompete"
).split(" ");

/** About 88 % of attempts are "valid" (no collision in S_t), like the real protocol. */
export function mockAttemptValid(gid: Uint8Array, round: number, t: number): boolean {
  return sha256(l("mock/attempt"), gid, u32be(round), new Uint8Array([t]))[0]! < 225;
}

/** Uniform permutation of 0…n-1 for attempt t (Fisher–Yates from a hash stream). */
export function mockSigma(gid: Uint8Array, round: number, t: number, n: number): number[] {
  const a = Array.from({ length: n }, (_, i) => i);
  let block = sha256(l("mock/sigma"), gid, u32be(round), new Uint8Array([t]));
  let ctr = 0;
  let pos = 0;
  const next = (): number => {
    if (pos + 4 > block.length) {
      ctr++;
      block = sha256(l("mock/sigma"), gid, u32be(round), new Uint8Array([t]), u32be(ctr));
      pos = 0;
    }
    const v = ((block[pos]! << 24) | (block[pos + 1]! << 16) | (block[pos + 2]! << 8) | block[pos + 3]!) >>> 0;
    pos += 4;
    return v;
  };
  for (let k = n - 1; k >= 1; k--) {
    const m = k + 1;
    const limit = Math.floor(0x100000000 / m) * m;
    let u = next();
    while (u >= limit) u = next();
    const j = u % m;
    const tmp = a[k]!;
    a[k] = a[j]!;
    a[j] = tmp;
  }
  return a;
}

/** Mock "signature": 64 bytes derived from the public key and the message hash. */
export function mockSign(ipk: Uint8Array, msgHash: Uint8Array): Uint8Array {
  return concat(sha256(l("mock/sig/a"), ipk, msgHash), sha256(l("mock/sig/b"), ipk, msgHash));
}

export function lp(x: Uint8Array): Uint8Array {
  return concat(u32be(x.length), x);
}

/** Spec §5 join message hash. */
export function joinMessage(gid: Uint8Array, ipk: Uint8Array, idh: Uint8Array, authHash: Uint8Array, encName: Uint8Array, encWish: Uint8Array): Uint8Array {
  return sha256(l("wichtel/v1/join"), gid, ipk, idh, authHash, lp(encName), lp(encWish));
}

/** Spec §12 upload message hash. */
export function uploadMessage(kind: 1 | 2 | 3, gid: Uint8Array, round: number, pid: Uint8Array, body: Uint8Array): Uint8Array {
  return sha256(l("wichtel/v1/upload"), new Uint8Array([kind]), gid, u32be(round), pid, sha256(body));
}

export { authHash, pidFromIpk } from "../lib/hashes";

export function adminHash(as: Uint8Array): Uint8Array {
  return sha256(l("wichtel/v1/admin-hash"), as);
}
