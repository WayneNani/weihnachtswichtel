# Weihnachtswichtel – Umsetzungsplan mit parallelen Subagents

Stand: 2026-11-06 · Grundlage: `01-konzept.md` inkl. der Änderungen aus `02-review.md`

## 1. Leitplanken für die Maschinenlast

Referenzmaschine: 4 Kerne, 15 GB RAM, keine Swap. Rust-Builds sind der Hauptlastfaktor
(ein kalter Build mit axum + Krypto-Crates + wasm-bindgen: mehrere Minuten, 1–3 GB im `target/`).

**Regeln, die jeder Subagent im Prompt mitbekommt:**

1. **Höchstens 2 Agents kompilieren gleichzeitig Rust.** Ein dritter paralleler Agent darf nur
   Nicht-Rust-Arbeit machen (TypeScript/esbuild, Doku, read-only Review).
2. **Gemeinsames Build-Verzeichnis**: `CARGO_TARGET_DIR=<repo>/../wichtel-target` für alle
   Worktrees. Abhängigkeiten werden so nur **einmal** gebaut; Cargo serialisiert parallele Builds
   über einen Datei-Lock – das wirkt zusätzlich als natürliche Drossel.
3. **`CARGO_BUILD_JOBS=2`** und `nice -n 10` für jeden `cargo`-Aufruf ⇒ max. 4 Compiler-Jobs gesamt.
4. **Nur das eigene Crate bauen/testen**: `cargo check -p <crate>`, `cargo test -p <crate> -- --test-threads=2`.
   Kein `--workspace`, kein `--release` (Release-Build nur einmal am Ende durch den Integrator).
5. **Keine neuen Abhängigkeiten** ohne Not: Alle Dependencies werden in Phase 0 zentral in
   `[workspace.dependencies]` festgelegt und `Cargo.lock` eingecheckt. Braucht ein Agent eine
   neue, meldet er das, statt sie selbst hinzuzufügen (vermeidet Lock-Konflikte und Neu-Builds).
6. **Schlanke Dev-Profile** in `Cargo.toml`:
   ```toml
   [profile.dev]
   debug = "line-tables-only"   # weniger Plattenplatz, schnelleres Linken
   [profile.dev.package."*"]
   debug = false
   ```
7. **Browser-Tests (Playwright/Chromium)** und **wasm-Release-Builds** laufen nur, wenn **kein**
   anderer Agent kompiliert (eigene, sequentielle Phase).
8. Kein `cargo install` von Zusatztools (cargo-watch, nextest, …) – `wasm-pack`/`wasm-bindgen-cli`
   einmalig in Phase 0, versioniert passend zu `wasm-bindgen` im Lockfile.

Ergebnis: Spitzenlast ≈ 4 Compiler-Prozesse + ein Node-Prozess; RAM-Bedarf < 8 GB.

## 2. Repository-Struktur (Ziel)

```
Cargo.toml                 # Workspace, zentrale Dependencies, Profile
crates/
  wichtel-core/            # Protokoll & Krypto (no I/O), native + wasm32
  wichtel-api/             # DTOs, gemeinsam für Server und WASM
  wichtel-wasm/            # wasm-bindgen-Hülle
  wichtel-server/          # axum, rusqlite, Ablauf-Job, statische Assets
web/                       # TypeScript-UI (Preact + esbuild), Ausgabe nach web/dist
docs/                      # Konzept, Review, Protokoll-Spezifikation, Plan
tests/e2e/                 # Playwright-Szenarien
```

## 3. Phasen und Agents

Legende: 🦀 = kompiliert Rust · 🟨 = Node/TS · 👁 = read-only

```
Phase 0  ──[A0 🦀 Fundament]───────────────────────────────►
Phase 1        ├─[A1 🦀 core]──────────────┐
                ├─[A2 🦀 server]────────────┤   (max. 2× 🦀 parallel)
                └─[A3 🟨 web-UI, Mocks]─────┤
Phase 2                                     ├─[A4 🦀 wasm + Verdrahtung]──┐
                                            └─[A5 👁 Krypto-Review core]──┤
Phase 3                                                                   ├─[A6 🦀/🟨 E2E + Fixes]
Phase 4                                                                   └─[A7 👁 Privacy-/Security-Review] → [A8 Fixes, Release-Build]
```

### Phase 0 – Fundament (1 Agent, sequentiell) 🦀

**A0 „Fundament“** – schafft den Rahmen, gegen den alle anderen parallel arbeiten:
- Workspace anlegen, alle Dependencies zentral pinnen, `Cargo.lock` erzeugen, Profile setzen.
- `docs/04-protokoll-spec.md`: das Protokoll aus Konzept §5–6 (mit Review-Korrekturen) als
  **normative** Spezifikation inkl. Byte-Layouts, KDF-Labels, Testvektoren-Format.
- `wichtel-api`: alle Request/Response-Typen + Zustandsautomat der Gruppe als `enum` (das ist der
  **Vertrag** zwischen A1, A2 und A3). Zusätzlich als `docs/api.md` bzw. JSON-Beispiele für A3.
- `wichtel-core`: nur öffentliche Signaturen (`todo!()`-Rümpfe) für Schlüsselableitung,
  DC-Vektor, Ergebnis-Parsing, Reveal-Bau, Reveal-Auswertung.
- Einmal `cargo build` (dev) für Warm-Cache; `wasm32-unknown-unknown`-Target + `wasm-bindgen-cli`
  installieren; `web/` mit `package.json` + esbuild initialisieren, `npm ci`.
- CI-Skizze (`.github/workflows/ci.yml`): fmt, clippy, test pro Crate, web build.

*Definition of Done:* `cargo check --workspace` grün, Spezifikation und API-Vertrag committed.

### Phase 1 – Parallele Kernarbeit (3 Agents, je eigener Worktree)

**A1 „core“** 🦀 — `crates/wichtel-core`
- Schlüsselableitung aus `seed`, Gruppenkontext `G`, AEAD für `GK`-Daten.
- DC-Netz: Pads, Vektor, Ergebnis-Parsing, Kollisions-/Störungserkennung.
- Kreisbildung, Reveal-Nachrichten (echt/Attrappe, Padding, HPKE, Signaturen), Auswertung.
- **Protokoll-Simulation** als Test: n ∈ {3, 4, 7, 20, 50} Clients + In-Memory-Briefkasten;
  Szenarien: Normalfall, Kollision, Störer (Jamming, Doppel-Claim, falsche Signatur), Abbrecher,
  Server-Equivocation (verschiedene Rosters). Property-Test: Ergebnis ist ein Kreis über alle.
- Statistik-Test (klein, `#[ignore]` per Default): Gleichverteilung der Kreise für n=4.
- Testvektoren-Datei für A4/A5.

**A2 „server“** 🦀 — `crates/wichtel-server`
- axum-Routen gemäß `wichtel-api`, Zustandsautomat, Auth (Hash-Vergleich in konstanter Zeit),
  Signaturprüfung der Uploads (nutzt nur die Verify-Funktion aus `core` – bis A1 fertig: Feature-Flag/Stub).
- `Store`-Trait + `SqliteStore` (rusqlite, WAL, Migrations als SQL-Dateien).
- XOR-Aggregation der DC-Vektoren, Freigabe erst bei Vollständigkeit, Vektoren danach löschen.
- SSE-Endpunkt, Größen- und Rate-Limits, Ablauf-/Lösch-Job.
- Logging ohne IPs; Security-Header (CSP, Referrer-Policy, …); Auslieferung von `web/dist` via rust-embed.
- Integrationstests mit `tower::ServiceExt::oneshot` + temporärer SQLite-Datei.

**A3 „web-UI“** 🟨 — `web/` (kompiliert **kein** Rust ⇒ zählt nicht zum Rust-Budget)
- Seiten: Runde anlegen, Einladung/Links/QR, Beitreten, Teilnehmerliste, Spielleiter-Ansicht,
  Fortschritt (Live/Asynchron), Ergebnis, Fehler-/Neustart-Zustände, „persönlichen Link sichern“-Dialog.
- Gegen ein **Mock-Interface** der WASM-Funktionen (TypeScript-Interface aus Phase 0) und einen
  Mock-Server (JSON-Fixtures) – damit unabhängig von A1/A2.
- Fragment-Parsing, `localStorage` mit try/catch, keine externen Ressourcen, mobile-first.

*Merge-Reihenfolge:* A1 → A2 (ersetzt Stub durch echte Verify-Funktion) → A3.
Jeder Agent rebased vor dem Merge auf den aktuellen Hauptzweig und lässt `cargo test -p <eigenes Crate>` laufen.

### Phase 2 – Verdrahtung + erstes Review (2 Agents)

**A4 „wasm + Verdrahtung“** 🦀 — `crates/wichtel-wasm`, `web/src/crypto.ts`
- wasm-bindgen-Exports für die core-API, `getrandom` mit JS-Backend, Größenoptimierung (`opt-level="z"`, `wasm-opt` falls vorhanden).
- Mocks in der UI durch echte WASM-Aufrufe ersetzen; Web Worker für die DC-Vektor-Berechnung (UI bleibt flüssig).
- Testvektoren aus A1 im Browser-Build gegenprüfen.

**A5 „Krypto-Review core“** 👁 (läuft parallel, da read-only – keine CPU-Last)
- Prüft `wichtel-core` gegen `04-protokoll-spec.md`: Domain-Separation, Nonce-Verwendung,
  Zeroize, Konstantzeit-Vergleiche, Längen-/Padding-Prüfungen, Fehlerpfade, die keine Positionen leaken.
- Liefert Findings als Liste; Fixes macht A1 bzw. der Integrator (nicht A5 selbst).

### Phase 3 – End-to-End (1 Agent, allein auf der Maschine) 🦀🟨

**A6 „E2E“**
- Release-Build des Servers, Playwright mit **max. 2 Worker**:
  Szenarien mit 4 und 8 Browser-Kontexten (Live-Modus), Asynchron-Modus mit Neuladen über
  persönliche Links, Spielleiter entfernt Abbrecher ⇒ Neustart, Kollision erzwingen (Test-Feature
  mit kleinem `m`).
- Prüft zusätzlich: Server-DB enthält nach der Runde keine Klartextnamen und nichts, woraus sich
  die Zuordnung ableiten ließe (Test liest die SQLite-Datei aus).
- Behebt gefundene Fehler direkt (kleine Fixes) oder meldet sie.

### Phase 4 – Härtung (sequentiell)

**A7 „Privacy-/Security-Review“** 👁 — ganzes Repo: Metadaten-Leaks (Zugriffsmuster, Größen,
Timing, Logs), Header/CSP, Rate-Limits, DSGVO-Texte (Datenschutzerklärung, Impressum-Platzhalter),
Abhängigkeiten (`cargo audit`, falls verfügbar, sonst manuelle Liste).

**A8 „Fixes + Release“** 🦀 — arbeitet A5/A7-Findings ab, Release-Build, Dockerfile (statisches
Binary, distroless), Caddy-Beispielkonfiguration, README mit Betriebsanleitung.

## 4. Orchestrierung

- Agents laufen im Hintergrund, jeweils mit `isolation: worktree` (Phase 1/2), damit sich die
  Arbeitsverzeichnisse nicht in die Quere kommen. Gemeinsames `CARGO_TARGET_DIR` (siehe §1).
- Der Orchestrator (Hauptsitzung) merged nach jeder Phase, lässt einmal
  `cargo test --workspace` mit `CARGO_BUILD_JOBS=4` laufen (nur er, nur dann) und startet die
  nächste Phase.
- Jeder Agent-Prompt enthält: Ziel, Pfade, Vertrag (Spec/API), Last-Regeln aus §1,
  Definition of Done, „nicht anfassen“-Liste (fremde Crates).

## 5. Grobe Aufwandsschätzung

| Phase | Agents | Rust-parallel | Dauer (Agent-Laufzeit, grob) |
|---|---|---|---|
| 0 Fundament | 1 | 1 | 30–45 min (inkl. kaltem Build) |
| 1 Kern | 3 | 2 | 1–2 h |
| 2 Verdrahtung/Review | 2 | 1 | 45–60 min |
| 3 E2E | 1 | 1 | 45–60 min |
| 4 Härtung | 1–2 | 1 | 45 min |

Gesamt etwa ein halber Tag Agent-Laufzeit; davon realistisch mehrere Iterationsschleifen bei
A1 (Protokoll) – dort steckt das eigentliche Risiko.

## 6. Risiken für den Plan

| Risiko | Gegenmaßnahme |
|---|---|
| API-Vertrag ändert sich während Phase 1 | Vertrag in Phase 0 festziehen; Änderungen nur über Orchestrator, alle Agents informieren |
| A2 braucht core-Funktionen vor A1-Merge | Verify-Funktionen zuerst in A1 fertigstellen und früh mergen (A1 liefert in zwei Stufen) |
| `Cargo.lock`-Konflikte | keine neuen Dependencies außer über Orchestrator |
| Plattenplatz (mehrere `target/`) | gemeinsames `CARGO_TARGET_DIR`, `debug = "line-tables-only"`, `cargo clean -p` bei Bedarf |
| Playwright + Build gleichzeitig ⇒ RAM | E2E-Phase exklusiv, `--workers=2`, `--trace off` |
