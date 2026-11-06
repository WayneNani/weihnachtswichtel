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
| `deploy/README.md` | Betrieb: Container, Caddy, Umgebungsvariablen, Backups, Updates |

## Schnellstart

Lokal (Rust stable, Node.js 22):

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked   # exakt die Version aus Cargo.lock
scripts/build-all.sh                                        # WASM → web/dist → wichtel-server
cargo run -p wichtel-server                                 # http://127.0.0.1:8080
```

Mit Docker (baut alles im Container, Daten im Volume `/data`):

```bash
docker build -t wichtel .
docker run --rm -p 127.0.0.1:8080:8080 -v wichtel-data:/data wichtel
```

Nur die UI ohne Rust (Mock-Server, keine echte Kryptographie): `cd web && npm ci && npm run dev:mock`.

## Betrieb

Siehe **`deploy/README.md`**: Container (`Dockerfile`, non-root, Healthcheck auf `/api/health`),
Reverse Proxy mit TLS und ohne Access-Logs (`deploy/Caddyfile`), alle `WICHTEL_*`-Variablen,
VAPID-Schlüssel, Volume, Backups (besser keine – gelöschte Runden leben sonst darin weiter) und
Updates. Vor dem öffentlichen Betrieb `web/public/impressum.html` und
`web/public/datenschutz.html` ausfüllen (Vorlagen mit Platzhaltern) und neu bauen. Das
Release-Binary (`scripts/build-all.sh --release`, gestrippt, inkl. UI und WASM) ist ≈ 22 MiB groß.

## Sicherheitsmodell in 5 Sätzen

1. Titel, Namen, Wunschzettel und Hinweise werden im Browser verschlüsselt, der Schlüssel steht
   nur im URL-Fragment; der Server speichert Chiffretexte, Public Keys, Hashes, Zeitstempel und
   den Verlosungstermin, keine IP-Adressen.
2. Die Zuordnung entsteht in einem gemeinsamen Protokoll der Browser (anonyme Rollen per DC-Netz,
   Enthüllung per HPKE): Jeder erfährt nur seinen eigenen Beschenkten, weder Server noch
   Spielleiter erfahren die Zuordnung – unter der Annahme eines *ehrlichen, aber neugierigen*
   Servers.
3. Ein **aktiv bösartiger Server** (oder wer ihn übernimmt) kann manipuliertes JavaScript/WASM
   ausliefern und damit alles mitlesen – eine Grenze jeder Browser-E2E-Anwendung; deshalb darf der
   **Spielleiter nicht der Betreiber** des Servers sein.
4. Beitreten kann jeder mit dem Einladungslink, auch mehrfach: Mit genug **Sybils** (Fake-
   Teilnehmern, n − 2 reichen) ist die Anonymität weg, das verhindert keine Kryptographie – die
   Teilnehmerliste muss vor dem Start von Menschen geprüft werden.
5. In **kleinen Gruppen** verrät schon das eigene Ergebnis durch Abzählen viel (bei n = 4 lässt
   sich oft einiges ausschließen, deshalb n ≥ 4 und ein Hinweis bis n = 5), und Metadaten wie
   Teilnehmerzahl, Zeitpunkte und – bei eingeschalteten Benachrichtigungen – der Push-Dienst des
   Browserherstellers bleiben sichtbar; ein Störer kann die Verlosung blockieren, aber nichts
   herausfinden.

Details: `docs/01-konzept.md` §3 und §6.7, `docs/02-review.md`.

## Tests

| Befehl | Prüft |
|---|---|
| `cargo test -p <crate>` | Kern (Testvektoren, Protokoll-Simulation, Leck- und Verteilungstests), API-DTOs, Server (HTTP-API und Protokoll gegen echte Turso-Datei, Push) |
| `cd web && npm run typecheck && npm test` | TypeScript-Typen; Protokoll-Treiber, Link-Fragment und QR-Code gegen Mock |
| `node scripts/test-wasm.mjs` | gebautes WASM: Testvektoren, Fehlercodes, Verlosungen n = 4, Laufzeiten |
| `node scripts/smoke.mjs` | echter Server + echtes WASM, 4 Clients über HTTP (auch gegen das Release-Binary: `WICHTEL_SERVER=…/release/wichtel-server`) |
| `scripts/e2e.sh` | Browser-E2E mit Playwright/Chromium (siehe unten), ≈ 1,5 min |

Die CI (`.github/workflows/ci.yml`) führt alles davon aus: `rust` (fmt, clippy, Tests je Crate),
`web` (Typecheck, Tests, Build), `build` (wasm32-Check, `build-all.sh`, `test-wasm.mjs`,
`smoke.mjs`) und `e2e` als eigenen Job. Die Werkzeuge (wasm32-Target, `wasm-bindgen-cli` in der
Version aus `Cargo.lock` als vorkompiliertes Binary, Node 22) richtet
`.github/actions/setup-build` ein; Cargo und npm werden gecacht.

## Struktur

```
crates/wichtel-core     Protokoll & Krypto (kein I/O), nativ + wasm32
crates/wichtel-api      DTOs der HTTP-API
crates/wichtel-wasm     wasm-bindgen-Hülle für den Browser
crates/wichtel-server   axum-Server, Turso (lokal), Ablauf-Job, Web-Push
web/                    TypeScript-UI (Preact, esbuild); web/public: statische Seiten (Impressum, Datenschutz)
deploy/                 Betrieb: Caddyfile-Beispiel, Doku (Dockerfile im Wurzelverzeichnis)
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

scripts/build-all.sh           # build-wasm.sh → npm run build (web/dist) → cargo build -p wichtel-server
node scripts/smoke.mjs         # echter Server + echtes WASM, 4 simulierte Clients über HTTP
```

`smoke.mjs` bündelt die Protokoll-Bausteine der UI (`web/src/api`, `protocol/`, `ui/join.tsx`,
`wasm.ts`) mit esbuild für Node (`__MOCK__ = false`), startet `wichtel-server` mit temporärer
Datenbank auf einem freien Port, prüft die ausgelieferten Dateien (`/pkg/*.wasm` als
`application/wasm`, kein Mock-Code) und spielt Anlegen, Beitreten, Start, beide Schritte und das
Ergebnis durch: jeder hat genau einen Beschenkten, niemand sich selbst. `SMOKE_N=8` für mehr
Teilnehmer, `SMOKE_KEEP=1` behält Temp-Verzeichnis und DB.

In der UI bildet `web/src/wasm.ts` die wasm-bindgen-Exporte auf `WichtelWasm` ab (Seite und
Web Worker laden je eine eigene Instanz); `web/src/wasm-errors.ts` ordnet die Fehlercodes den
Zuständen des Protokoll-Treibers zu (Teilnehmerliste passt nicht ⇒ Störung, unbrauchbarer
Zwischenstand ⇒ neu berechnen, sonst erneuter Versuch) und liefert deutsche Fehlertexte.

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

## Browser-E2E-Tests

```bash
scripts/build-all.sh && scripts/e2e.sh    # = node --test --test-concurrency=1 'tests/e2e/*.test.mjs'
```

Node-Skripte (`node:test` + vorinstallierte `playwright`-Library, Chromium; kein `@playwright/test`).
Jede Datei startet den Debug-Server mit temporärer DB auf freiem Port (Web-Push nur an
`push.invalid` erlaubt, kein Abo) und **einen** Browser; jeder Teilnehmer ist ein eigener
Browser-Kontext (= eigenes Gerät). Szenarien: Live-Modus n=4 (`01`, inkl. Datensparsamkeit: DB-Dateien
roh durchsucht, alle Requests auf Fragment-Geheimnisse, Klartexte und fremde Hosts geprüft),
Asynchron-Modus n=5 mit neuem Kontext pro Besuch (`02`), Verlosungstermin mit Countdown und
automatischem Start (`03`, legt den Termin zuletzt per API auf den nächsten Minuten-Tick des
Server-Jobs, ≈ 1 min), Austritt/Entfernen nach dem Ergebnis ⇒ Neuverlosung Nr. 2 und 3 (`04`),
Kernseiten auf 390×844 ohne horizontales Scrollen (`05`). Laufzeit ≈ 1,5 min. Screenshots nur bei
Fehlschlag in `tests/e2e/artifacts/`. Variablen: `WICHTEL_SERVER`, `E2E_HEADED=1`, `E2E_SLOWMO`,
`E2E_KEEP=1` (Temp-Verzeichnis behalten), `E2E_DEBUG=1` (Browser-Konsolenfehler ausgeben).

## Last-Regeln für parallele Agents

Siehe `docs/03-umsetzungsplan.md` §1. Kurzfassung:

```bash
export CARGO_TARGET_DIR=/home/user/wichtel-target   # gemeinsam für alle Worktrees
export CARGO_BUILD_JOBS=2
nice -n 10 cargo test -p <eigenes-crate> -- --test-threads=2
```

Höchstens zwei Agents kompilieren gleichzeitig Rust; kein `--release`, kein `--workspace` außer
durch den Orchestrator; keine neuen Abhängigkeiten ohne Absprache.
