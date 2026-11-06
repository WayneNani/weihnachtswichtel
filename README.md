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

## Last-Regeln für parallele Agents

Siehe `docs/03-umsetzungsplan.md` §1. Kurzfassung:

```bash
export CARGO_TARGET_DIR=/home/user/wichtel-target   # gemeinsam für alle Worktrees
export CARGO_BUILD_JOBS=2
nice -n 10 cargo test -p <eigenes-crate> -- --test-threads=2
```

Höchstens zwei Agents kompilieren gleichzeitig Rust; kein `--release`, kein `--workspace` außer
durch den Orchestrator; keine neuen Abhängigkeiten ohne Absprache.
