# Weihnachtswichtel – Konzept

Stand: 2026-11-06 · Status: Entwurf v1

## 1. Ziel

Eine Web-Anwendung (Backend in Rust) für Wichtel-Runden, die

- **ohne Installation und ohne Konto** funktioniert (nur ein Link im Browser),
- **datensparsam** ist (der Server speichert so wenig wie möglich, Klarnamen nur verschlüsselt),
- einem **Spielleiter** erlaubt, eine Runde anzulegen, den Einladungslink zu teilen und den Zeitpunkt der Verlosung zu bestimmen,
- jedem Teilnehmer mitteilt, **wen er beschenkt**, ohne dass irgendjemand anderes das erfährt –
  **auch nicht der Spielleiter und auch nicht der Server-Betreiber**.

## 2. Die Kernfrage: Reicht Ende-zu-Ende-Verschlüsselung?

**Nein, nicht allein.** E2E-Verschlüsselung löst nur den *Transport*: Das Ergebnis wird für jeden
Teilnehmer so verschlüsselt, dass nur er es lesen kann. Das eigentliche Problem ist aber:
**Wer berechnet die Zuordnung?**

| Wer würfelt?                     | Wer kennt danach die Zuordnung?       |
|----------------------------------|---------------------------------------|
| Server                           | Server-Betreiber (und jeder mit DB-/RAM-Zugriff) |
| Browser des Spielleiters         | Spielleiter                           |
| Browser eines Teilnehmers        | dieser Teilnehmer                     |
| **Gemeinsames Protokoll aller**  | **niemand** (jeder nur seinen Teil)    |

Die Anforderung „auch der Spielleiter erfährt es nicht“ ist nur mit der letzten Zeile sauber
erfüllbar: Die Teilnehmer-Browser erzeugen die Zuordnung **gemeinsam** über ein kleines
kryptographisches Protokoll (Multi-Party-Computation im Kleinen). Der Server ist dabei nur ein
„dummer Briefkasten“, der verschlüsselte bzw. maskierte Daten weiterreicht.

## 3. Bedrohungsmodell

| Akteur | Annahme | Schutzziel |
|---|---|---|
| Spielleiter | neugierig, evtl. mit DB-Zugriff (z. B. selbst gehostet) | erfährt keine Zuordnung (außer seiner eigenen) |
| Server/Betreiber | *honest-but-curious*: liefert korrekten Code aus, liest aber DB, Logs, Traffic | erfährt keine Zuordnung, keine Klarnamen |
| Teilnehmer | neugierig, einzelne evtl. böswillig (stören) | erfährt nur den eigenen Beschenkten; Störungen werden **erkannt** (nicht zwingend zugeordnet) |
| Außenstehende | kennen den Link nicht | sehen nichts |

**Explizit nicht abgedeckt** (siehe Review): ein *aktiv bösartiger* Server, der manipuliertes
JavaScript/WASM ausliefert. Das ist eine grundsätzliche Grenze jeder Browser-E2E-Anwendung.

## 4. Nutzerfluss

1. **Runde anlegen** (Spielleiter): Titel, Budget, Datum, optional Hinweistext. Der Browser erzeugt
   einen Gruppenschlüssel `GK` und ein Admin-Geheimnis `AS`. Der Spielleiter erhält
   - einen **Einladungslink**: `https://host/g/<gid>#k=<GK>`
   - einen **Spielleiter-Link**: `https://host/g/<gid>#k=<GK>&a=<AS>` (privat aufbewahren)
2. **Beitreten** (jeder, auch der Spielleiter selbst): Link öffnen, Namen eingeben (optional:
   Wunschzettel/Hinweis). Der Browser erzeugt ein persönliches Geheimnis `seed` und zeigt einen
   **persönlichen Link** `…#k=<GK>&s=<seed>` an („als Lesezeichen speichern – damit siehst du später dein Ergebnis, auch auf einem anderen Gerät“).
3. **Teilnehmerliste prüfen**: Alle sehen die Liste der Namen. Der Spielleiter kann Einträge
   entfernen (Dubletten, Spaßvögel).
4. **Verlosung starten** (Spielleiter): Teilnehmerliste wird eingefroren. Ab jetzt läuft das
   Protokoll in Runden (Abschnitt 6). Zwei Modi:
   - **Live-Modus**: Alle haben den Link gleichzeitig offen (Weihnachtsfeier, Videocall). Das
     Protokoll läuft automatisch in wenigen Sekunden durch.
   - **Asynchron-Modus**: Jeder öffnet seinen persönlichen Link irgendwann; jeder Besuch erledigt
     automatisch den nächsten fälligen Schritt. Fortschritt ist für alle sichtbar
     („12 von 15 haben Schritt 2 erledigt“).
5. **Ergebnis**: Jeder sieht „Du beschenkst: **Anna**“ (+ deren optionalen Hinweis).
6. **Automatisches Löschen**: Alle Daten der Runde werden X Tage nach dem Wichteldatum gelöscht
   (Default 14, max. 60). Der Spielleiter kann jederzeit sofort löschen.

Warum der Gruppenschlüssel im **URL-Fragment** (`#…`)? Das Fragment wird vom Browser nie an den
Server geschickt. Damit kann der Server Namen, Titel und Wunschzettel nur als Chiffretext speichern.

## 5. Schlüssel und Identitäten

Alle Schlüssel werden im Browser erzeugt (CSPRNG via WebCrypto `getRandomValues`).

| Schlüssel | Herkunft | Zweck |
|---|---|---|
| `GK` (32 B) | Spielleiter, im Link-Fragment | AEAD-Verschlüsselung von Gruppen-Metadaten, Namen, Wunschzetteln |
| `AS` (32 B) | Spielleiter | Admin-Token; Server speichert nur `SHA-256(AS)` |
| `seed` (32 B) | Teilnehmer | via HKDF abgeleitet: Ed25519-Identität (`isk`/`IPK`), X25519-Identität (`idh`/`IDH`), Auth-Token (Server speichert nur Hash) |
| Pseudonym (pro Protokollrunde) | Teilnehmer, frisch zufällig | Ed25519 (`psk`/`PPK`) + X25519 (`pdh`/`PDH`); anonym, nicht mit Identität verknüpfbar |

Gruppenkontext für alle Signaturen/KDFs:
`G = SHA-256("wichtel-v1" ‖ gid ‖ round ‖ sortierte Liste (pid, IPK, IDH))`
– damit sind alle Nachrichten an genau diese Teilnehmerliste und Runde gebunden. Zeigt der Server
verschiedenen Teilnehmern verschiedene Listen, bricht das Protokoll ab (statt still zu leaken).
Zusätzlich zeigt die UI einen kurzen **Gruppen-Fingerabdruck** (z. B. 4 Emojis aus `G`), den man
im Live-Modus vergleichen kann.

## 6. Das Verlosungsprotokoll

Idee in einem Satz: *Jeder veröffentlicht **anonym** ein Pseudonym; die zufällige Reihenfolge der
Pseudonyme bildet einen Kreis (jeder beschenkt den nächsten); danach verrät jeder **nur seinem
Schenker** – ohne zu wissen, wer das ist – wer hinter dem nächsten Pseudonym steckt.*

### 6.1 Schritt 1 – Anonyme Pseudonyme (DC-Netz)

Anonymes Veröffentlichen ohne vertrauenswürdige Partei gelingt mit einem **DC-Netz**
(„Dining Cryptographers“), das alle Teilnehmer **parallel** in **einem** Durchgang ausführen:

- Jedes Paar `(i, j)` hat einen gemeinsamen Schlüssel `k_ij = HKDF(X25519(idh_i, IDH_j), "dcnet" ‖ G)`
  – ohne Interaktion berechenbar, da alle öffentlichen Schlüssel beim Beitritt hinterlegt wurden.
- Es gibt `m = max(64, 16·n²)` Slots à 72 Byte.
  Slot-Inhalt: `PPK (32) ‖ PDH (32) ‖ SHA-256(G ‖ PPK ‖ PDH)[0..8]`.
- Teilnehmer `i` wählt zufällig einen Slot `s_i` und berechnet den Vektor
  `V_i = ⊕_{j≠i} ChaCha20(k_ij)[0 .. 72·m]  ⊕  (Pseudonym an Position s_i)`.
- Der Server sammelt alle `n` Vektoren und veröffentlicht erst dann `R = ⊕_i V_i`.
  Die paarweisen Masken heben sich auf; in `R` stehen alle Pseudonyme – **ohne Absender**.
- Jeder Client prüft: genau `n` Slots mit gültiger Prüfsumme **und** das eigene Pseudonym steht an
  der eigenen Stelle. Sonst (Kollision zweier Slots, ~3 % Wahrscheinlichkeit, oder Störung):
  automatisch neue Protokollrunde `round+1`.

Der Server sieht nur zufällig aussehende Vektoren gleicher Länge. Um einen Absender zu
de-anonymisieren, bräuchte man **alle** paarweisen Schlüssel dieses Teilnehmers, also die
Mitwirkung aller anderen.

### 6.2 Der Kreis

Die gültigen Slots, aufsteigend sortiert, ergeben Positionen `0 … n-1`.
**Position `k` beschenkt Position `(k+1) mod n`.** Da die Slots zufällig gewählt wurden, ist das ein
gleichverteilt zufälliger Kreis über alle Teilnehmer – damit ist Selbstbeschenkung ausgeschlossen
und es entstehen auch keine 2er-Pärchen („A beschenkt B, B beschenkt A“).

Jeder kennt nun seine eigene Position, aber nur Pseudonyme der anderen.

### 6.3 Schritt 2 – Enthüllung an den (unbekannten) Schenker

Teilnehmer `i` auf Position `k` kennt das Pseudonym seines Schenkers (`k-1`), aber nicht dessen
Identität. Damit der Server aus dem Upload-Muster nichts lernt, schickt **jeder an jede Position**
genau eine Nachricht gleicher Länge:

- an Position `k-1` (eigener Schenker): **echte Nachricht**
  `0x01 ‖ pid_i ‖ Sig_isk_i(G ‖ "claim" ‖ k ‖ PPK_k) ‖ Sig_psk_k(G ‖ "claim" ‖ pid_i) ‖ optionale private Notiz`
- an alle anderen Positionen: **Attrappe** `0x00 ‖ Padding`
- alle Klartexte werden auf feste Länge `L = 1024 B` aufgefüllt und per **HPKE** (RFC 9180,
  X25519-HKDF-SHA256 / ChaCha20-Poly1305) an `PDH_p` verschlüsselt; Info = `G ‖ "reveal" ‖ p`.

Der Server veröffentlicht die `n²` Chiffretexte erst, wenn alle hochgeladen haben. **Jeder Client
lädt alle herunter** (kein positionsabhängiges Zugriffsmuster!) und entschlüsselt lokal die `n`, die
an seine Position adressiert sind. Erwartet wird **genau eine** echte Nachricht mit zwei gültigen
Signaturen – die belegen: „Identität `pid_j` besitzt das Pseudonym auf Position `k+1`“.

Ergebnis: „Du beschenkst `name(pid_j)`“ (Name entschlüsselt mit `GK`) + optionale private Notiz
(z. B. Lieferadresse, die so nur der Schenker sieht).

Abweichungen (0 oder ≥ 2 echte Nachrichten, ungültige Signatur) ⇒ Client meldet „Störung“, die
Runde wird neu gestartet.

### 6.4 Rundenzahl & Besuche

| Phase | Wer | Voraussetzung |
|---|---|---|
| Beitritt | jeder | – |
| DC-Netz-Upload | jeder | Spielleiter hat gestartet |
| Enthüllungs-Upload | jeder | alle DC-Uploads da |
| Ergebnis abrufen | jeder | alle Enthüllungen da |

Im **Live-Modus** läuft das in Sekunden ab (Clients pollen bzw. lauschen per Server-Sent Events).
Im **Asynchron-Modus** braucht jeder bis zu 4 Besuche; jeder Besuch erledigt automatisch alles
Mögliche. Erscheint ein Teilnehmer nicht, kann der Spielleiter ihn entfernen ⇒ neue Runde mit den
verbleibenden.

### 6.5 Was lernt wer?

- **Server/Spielleiter**: Teilnehmerzahl, öffentliche Schlüssel, Zeitpunkte, Fortschritt.
  Keine Namen im Klartext (nur mit `GK` – der Spielleiter kennt `GK`, also die Namen, aber nicht
  die Zuordnung). Keine Zuordnung.
- **Teilnehmer**: den eigenen Beschenkten. Dass der Schenker *nicht* der eigene Beschenkte ist
  (Kreisstruktur, bei n ≥ 4 sonst nichts).
- **Koalition aus k Teilnehmern + Server**: ihre eigenen Zuordnungen; die übrigen bleiben
  anonym, solange mindestens 2 ehrliche Teilnehmer übrig sind.

## 7. Architektur & Technik

```
┌────────────────────────── Browser ──────────────────────────┐
│  UI (TypeScript, Preact, esbuild)                           │
│     │                                                        │
│  wichtel-wasm  (wasm-bindgen-Hülle)                          │
│     │                                                        │
│  wichtel-core  (Rust: Schlüssel, DC-Netz, HPKE, Protokoll)   │
└──────────────┬──────────────────────────────────────────────┘
               │ HTTPS/JSON + SSE (nur Chiffretexte, Hashes, Public Keys)
┌──────────────▼──────────────────────────────────────────────┐
│  wichtel-server (Rust: axum, tokio, rusqlite)               │
│   - Zustandsautomat pro Runde, Größen-/Rate-Limits          │
│   - liefert statische Assets (rust-embed) aus               │
│   - Hintergrund-Job: Ablauf & Löschung                       │
└──────────────┬──────────────────────────────────────────────┘
               │
          SQLite-Datei (WAL)
```

**Ein einziges Binary** + eine SQLite-Datei. Deployment z. B. hinter Caddy (TLS) auf einem kleinen
VPS oder Container.

### 7.1 Crates

| Crate | Inhalt | Abhängigkeiten (Auswahl) |
|---|---|---|
| `wichtel-core` | reine Logik, kein I/O, `native` + `wasm32` | `x25519-dalek`, `ed25519-dalek`, `hpke`, `chacha20`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize`, `rand_core`, `serde` |
| `wichtel-api` | gemeinsame DTOs (Request/Response-Typen) | `serde`, `base64` |
| `wichtel-wasm` | JS-Bindings für `core` | `wasm-bindgen`, `getrandom` (Feature `js`/`wasm_js`) |
| `wichtel-server` | HTTP-API, Persistenz, Ablauf | `axum`, `tokio`, `rusqlite` (bundled), `tower-http`, `rust-embed`, `tracing` |

Der Kern ist ohne Server testbar: Ein **Simulations-Test** spielt das ganze Protokoll mit n
In-Process-Clients und einem In-Memory-„Briefkasten“ durch – inkl. Kollisionen, Störern und
abbrechenden Teilnehmern.

### 7.2 HTTP-API (Entwurf)

| Methode & Pfad | Auth | Zweck |
|---|---|---|
| `POST /api/groups` | – | Gruppe anlegen (`admin_hash`, `enc_meta`) |
| `GET /api/groups/{gid}` | – | Zustand, `enc_meta`, Teilnehmerliste (pid, Public Keys, `enc_name`), Fortschritt |
| `DELETE /api/groups/{gid}` | Admin | sofort löschen |
| `POST /api/groups/{gid}/participants` | – | beitreten (`IPK`, `IDH`, `auth_hash`, `enc_name`, `enc_wish`) |
| `DELETE /api/groups/{gid}/participants/{pid}` | Admin oder selbst | entfernen / austreten (nur vor Start bzw. löst Neustart aus) |
| `POST /api/groups/{gid}/start` | Admin | Liste einfrieren, Runde 1 starten |
| `PUT /api/groups/{gid}/rounds/{r}/dcnet` | Teilnehmer | Vektor `V_i` (signiert) |
| `GET /api/groups/{gid}/rounds/{r}/dcnet` | – | `R`, erst wenn vollständig |
| `PUT /api/groups/{gid}/rounds/{r}/reveal` | Teilnehmer | `n` Chiffretexte (signiert) |
| `GET /api/groups/{gid}/rounds/{r}/reveal` | – | alle `n²` Chiffretexte, erst wenn vollständig |
| `POST /api/groups/{gid}/rounds/{r}/abort` | Teilnehmer | Störung melden ⇒ Runde `r+1` |
| `GET /api/groups/{gid}/events` | – | SSE: Zustandsänderungen (für Live-Modus) |

Auth per `Authorization: Bearer <token>`; Server vergleicht Hashes in konstanter Zeit.
Hochgeladene Protokollnachrichten sind zusätzlich mit `isk` signiert.

### 7.3 Datenmodell (SQLite)

```sql
groups(gid TEXT PK, admin_hash BLOB, enc_meta BLOB, state TEXT, round INT,
       roster_hash BLOB, created_at INT, expires_at INT)
participants(gid, pid, ipk BLOB, idh BLOB, auth_hash BLOB, enc_name BLOB,
             enc_wish BLOB, joined_at INT, PRIMARY KEY(gid, pid))
dcnet_uploads(gid, round, pid, vector BLOB)          -- wird nach Berechnung von R gelöscht
dcnet_results(gid, round, result BLOB)
reveal_uploads(gid, round, pid, ciphertexts BLOB)
```

Größen: n = 20 ⇒ `m = 6400` Slots ⇒ 460 KB pro DC-Vektor, Enthüllung 20 × 1,1 KB pro Teilnehmer.
Obergrenze: **n ≤ 50** (DC-Vektor ≈ 2,9 MB).

### 7.4 Datensparsamkeit

- Keine Konten, keine E-Mail-Adressen, keine Cookies (nur `localStorage` für den eigenen `seed`,
  technisch notwendig ⇒ kein Consent-Banner nötig).
- Namen, Titel, Wunschzettel nur als Chiffretext (Schlüssel im URL-Fragment).
- Keine IP-Adressen in Logs (Tracing ohne Peer-Adresse; Reverse-Proxy-Logs ebenfalls aus/anonymisiert).
- Keine externen Ressourcen (Fonts, CDN, Analytics). Strikte CSP, `Referrer-Policy: no-referrer`.
- Automatische Löschung nach Ablauf; DC-Vektoren sofort nach Berechnung von `R`.
- Rate-Limits und Größenlimits gegen Missbrauch als anonymer Speicher.

## 8. Turso als Datenbank?

**Einschätzung: für dieses Projekt nicht nötig – einfache SQLite-Datei bevorzugen.**

Turso ist ein gehosteter, SQLite-kompatibler Dienst (libSQL bzw. die neue Rust-Neuimplementierung
„Turso Database“) mit Edge-Replikas und großzügigem Free-Tier. Das ist attraktiv, wenn man
*serverless* (ohne persistente Platte) oder global verteilt deployt.

| | SQLite-Datei (rusqlite) | Turso (gehostet) |
|---|---|---|
| Datensparsamkeit / DSGVO | Daten bleiben auf eigenem Server | weiterer Auftragsverarbeiter (US-Firma), AV-Vertrag, Drittlandtransfer prüfen |
| Betrieb | eine Datei, Backup = Datei kopieren | Account, Token, Netzwerk-Abhängigkeit |
| Latenz | lokal (µs) | Netzwerk-Roundtrip (ms), außer Embedded Replica |
| Skalierung | ein Server reicht für zehntausende Runden | horizontal, Edge – hier nicht gebraucht |
| Rust-Ökosystem | `rusqlite` sehr ausgereift | im Umbruch: `libsql`-Crate vs. neuer `turso`-Crate |
| Build-Last | moderat | `libsql` zieht viele Abhängigkeiten |

Datenvolumen pro Runde: wenige MB, nur kurz. Lastprofil: Spitzen im Dezember, sonst nahezu null.
Das ist ein Paradebeispiel für „ein Binary + eine SQLite-Datei“.

**Empfehlung:** Persistenz hinter einem kleinen Repository-Trait kapseln (`Store`). Start mit
`rusqlite`. Falls später serverless gehostet werden soll, kann ein `TursoStore` ergänzt werden,
ohne den Rest anzufassen. Da alle sensiblen Inhalte ohnehin Ende-zu-Ende-verschlüsselt sind, wäre
Turso datenschutzrechtlich zwar vertretbar, bringt aber keinen Nutzen, der den zusätzlichen
Dienstleister rechtfertigt.

## 9. Funktionsumfang

**v1 (MVP)**
- Runde anlegen, Einladungs-/Spielleiter-/persönlicher Link (inkl. QR-Code)
- Beitreten, Liste sehen, Spielleiter entfernt Teilnehmer
- Verlosung (Live + Asynchron), automatische Neustarts bei Kollision/Störung
- Ergebnisanzeige, private Notiz an den Schenker
- Wunschzettel (für die Gruppe sichtbar, mit `GK` verschlüsselt)
- Automatisches Löschen, Sofort-Löschen

**v2 (später)**
- Ausschlüsse („Paare beschenken sich nicht“) – siehe Review
- Anonymer Rückkanal (Beschenkter ↔ Schenker, z. B. Kleidergröße)
- Mehrsprachigkeit
