# Weihnachtswichtel

Wichteln im Browser – ohne Installation, ohne Konto, datensparsam. Ein Spielleiter teilt einen
Link, alle tragen sich ein, und eine gemeinsame kryptographische Verlosung sorgt dafür, dass jeder
nur erfährt, wen er beschenkt. **Weder Spielleiter noch Server kennen die Zuordnung.**

Dokumentation:

| Datei | Inhalt |
|---|---|
| `docs/01-konzept.md` | Konzept (v5) |
| `docs/02-review.md` | Kritisches Review und Entscheidungen |
| `docs/03-umsetzungsplan.md` | Umsetzungsplan mit parallelen Agents |
| `docs/04-protokoll-spec.md` | **normative** Protokoll-Spezifikation |
| `docs/api.md` | HTTP-API |
| `docs/analysis/` | Leck-Analysen zur Auslosung |

## Struktur

```
crates/wichtel-core     Protokoll & Krypto (kein I/O), nativ + wasm32
crates/wichtel-api      DTOs der HTTP-API
crates/wichtel-wasm     wasm-bindgen-Hülle für den Browser
crates/wichtel-server   axum-Server, Turso (lokal), Ablauf-Job, Web-Push
web/                    TypeScript-UI (Preact, esbuild)
```

## Bauen

Voraussetzungen: Rust (stable) mit Target `wasm32-unknown-unknown`, `wasm-bindgen-cli` in der
Version aus `Cargo.lock` (0.2.130), Node.js 22.

```bash
cargo check --workspace
cargo test -p wichtel-core
cargo check -p wichtel-core -p wichtel-wasm --target wasm32-unknown-unknown
cd web && npm ci && npm run typecheck && npm run build
cargo run -p wichtel-server        # http://127.0.0.1:8080/api/health
```

## WASM bauen

```bash
scripts/build-wasm.sh          # → web/src/wasm-pkg/ (gitignored), wasm-bindgen --target web
node scripts/test-wasm.mjs     # Testvektoren, Fehlercodes, Protokolldurchlauf n=4, Laufzeiten
```

`build-wasm.sh` baut `crates/wichtel-wasm` mit
`cargo build --target wasm32-unknown-unknown --profile wasm-release -p wichtel-wasm` und erzeugt
daraus mit `wasm-bindgen --target web` das Paket (`wichtel_wasm.js`, `.d.ts`, `_bg.wasm`). Die
Version von `wasm-bindgen-cli` muss exakt der aus `Cargo.lock` entsprechen (0.2.130); das Skript
prüft das. `CARGO_TARGET_DIR` wird berücksichtigt. `wasm-opt` wird nicht benötigt.

In der UI wird das Modul einmal initialisiert (`await init()` bzw. `initSync({ module })` im Web
Worker) und erfüllt dann `WichtelWasm` aus `web/src/wasm-api.ts`. Fehler werfen ein `Error` mit
`name = "WichtelError"` und stabilem `code` (Typ `WichtelErrorCode` in der `.d.ts`), z. B.
`DECRYPTION_FAILED`, `REVEAL_COUNT`, `STATE_MISMATCH`.

`test-wasm.mjs` (nur Node-22-Standardbibliothek) bindet die gebaute `.wasm` zusätzlich mit
`wasm-bindgen --target nodejs` in ein Temp-Verzeichnis, prüft
`crates/wichtel-core/tests/vectors/v1.json`, Signaturen gegen `node:crypto` (Ed25519), alle
Fehlercodes und spielt mehrere komplette Verlosungen mit n = 4 über einen In-Memory-Briefkasten
durch. Variablen: `WICHTEL_WASM` (andere `.wasm`), `BENCH_RUNS` (Wiederholungen, Standard 3).

**Profil `wasm-release`** (`Cargo.toml`): `lto = true`, `codegen-units = 1`, `panic = "abort"`,
`opt-level = 2`. `strip` bleibt aus, damit wasm-bindgen die `target_features`-Sektion sieht; den
Namens- und Producer-Abschnitt entfernt wasm-bindgen. Messung (Node 22, x86-64, Median):

| opt-level | `_bg.wasm` | gzip -9 | Rollen-Vektor n=20 | n=30 | Enthüllungs-Upload (≈16 HPKE-Seal) | `openResult` n=30 |
|---|---|---|---|---|---|---|
| `"z"` | 172 KB | 67 KB | 422 ms | 1410 ms | 12,7 ms | 14,9 ms |
| `"s"` | 257 KB | 72 KB | 200 ms | 687 ms | 10,8 ms | 12,7 ms |
| **`2`** | 289 KB | 84 KB | **39 ms** | **126 ms** | 9,4 ms | 10,3 ms |
| `3` | 306 KB | 89 KB | 39 ms | 129 ms | 9,6 ms | 10,3 ms |

Ein HPKE-Seal kostet in jeder Variante unter 1 ms; den Ausschlag gibt der ChaCha20-lastige
Rollen-Vektor (n=30: 2,4 MB, 29 Paarmasken). `2` ist dort 5× schneller als `"s"` bei +12 KB gzip
– vernachlässigbar neben dem 2,4-MB-Upload.

## Last-Regeln für parallele Agents

Siehe `docs/03-umsetzungsplan.md` §1. Kurzfassung:

```bash
export CARGO_TARGET_DIR=/home/user/wichtel-target   # gemeinsam für alle Worktrees
export CARGO_BUILD_JOBS=2
nice -n 10 cargo test -p <eigenes-crate> -- --test-threads=2
```

Höchstens zwei Agents kompilieren gleichzeitig Rust; kein `--release`, kein `--workspace` außer
durch den Orchestrator; keine neuen Abhängigkeiten ohne Absprache.
