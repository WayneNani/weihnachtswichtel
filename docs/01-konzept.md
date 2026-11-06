# Weihnachtswichtel – Konzept

Stand: 2026-11-06 · Status: Entwurf v2 (überarbeitet nach Review, siehe `02-review.md`)

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
| Spielleiter | neugierig, evtl. mit DB-Lesezugriff, aber **nicht** Betreiber des Servers | erfährt keine Zuordnung (außer seiner eigenen) |
| Server/Betreiber | *honest-but-curious*: liefert korrekten Code aus, liest aber DB, Logs, Traffic | erfährt keine Zuordnung, keine Klarnamen |
| Teilnehmer | neugierig, einzelne evtl. böswillig (stören, neu würfeln wollen) | erfährt nur den eigenen Beschenkten; Störungen werden erkannt **und dem Störer zugeordnet**; niemand kann gezielt neu würfeln lassen |
| Außenstehende | kennen den Link nicht | sehen nichts |

**Explizit nicht abgedeckt** (siehe Review): ein *aktiv bösartiger* Server, der manipuliertes
JavaScript/WASM ausliefert. Das ist eine grundsätzliche Grenze jeder Browser-E2E-Anwendung.
Daraus folgt: Hostet der Spielleiter den Server selbst, schützt das Protokoll **nicht** vor ihm.

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
4. **Fingerabdruck vergleichen**: Jeder sieht einen Gruppen-Fingerabdruck (6 Wörter) und postet
   bzw. vergleicht ihn im Gruppenchat. Stimmt er bei allen überein, sehen alle dieselbe Liste.
5. **Verlosung starten** (Spielleiter): Teilnehmerliste wird eingefroren. Ab jetzt läuft das
   Protokoll in Runden (Abschnitt 6). Zwei Modi:
   - **Live-Modus**: Alle haben den Link gleichzeitig offen (Weihnachtsfeier, Videocall). Das
     Protokoll läuft automatisch in wenigen Sekunden durch.
   - **Asynchron-Modus**: Jeder öffnet seinen persönlichen Link irgendwann; jeder Besuch erledigt
     automatisch den nächsten fälligen Schritt. Fortschritt ist für alle sichtbar
     („12 von 15 haben Schritt 2 erledigt“).
6. **Ergebnis**: Jeder sieht „Du beschenkst: **Anna**“ (+ deren optionalen Hinweis).
7. **Automatisches Löschen**: Alle Daten der Runde werden X Tage nach dem Wichteldatum gelöscht
   (Default 14, max. 60). Der Spielleiter kann jederzeit sofort löschen.

Warum der Gruppenschlüssel im **URL-Fragment** (`#…`)? Das Fragment wird vom Browser nie an den
Server geschickt. Damit kann der Server Namen, Titel und Wunschzettel nur als Chiffretext speichern.

## 5. Schlüssel und Identitäten

Alle Schlüssel werden im Browser erzeugt (CSPRNG via WebCrypto `getRandomValues`). Alles
Rundenspezifische wird **deterministisch aus dem `seed` abgeleitet**, damit der persönliche Link
auf jedem Gerät und in jeder Phase genügt.

| Schlüssel | Herkunft | Zweck |
|---|---|---|
| `GK` (32 B) | Spielleiter, im Link-Fragment | AEAD für Gruppen-Metadaten, Namen, Wunschzettel |
| `AS` (32 B) | Spielleiter | Admin-Token; Server speichert nur `SHA-256(AS)` |
| `seed` (32 B) | Teilnehmer | Wurzel aller persönlichen Schlüssel (HKDF mit getrennten Labels) |
| `isk`/`IPK` | `HKDF(seed, "id-sig")` | Ed25519: signiert Beitritt und Uploads gegenüber dem Server |
| `idh`/`IDH` | `HKDF(seed, "id-dh")` | X25519: Identität gegenüber dem Schenker (HPKE-Auth) |
| `tok` | `HKDF(seed, "auth")` | Bearer-Token; Server speichert nur `SHA-256(tok)` |
| `e_r`/`E_r` | `HKDF(seed, "dc-eph" ‖ gid ‖ r)` | X25519 je Protokollrunde r: DC-Netz-Paarschlüssel; wird im Störfall **offengelegt** |
| `x_r` | `HKDF(seed, "slot" ‖ gid ‖ r)` | Slot-Wahl je Runde; beim Beitritt nur als Commitment `H(x_r)` hinterlegt |
| `pdh_r`/`PDH_r` | `HKDF(seed, "pseudo" ‖ gid ‖ r)` | X25519-Pseudonym je Runde |

Beim **Beitritt** lädt der Client hoch: `IPK`, `IDH`, `H(tok)`, `enc_name`, `enc_wish` sowie für
die Runden `r = 1…R_max` (z. B. 8) die Paare `(E_r, H(x_r))` – alles mit `isk` signiert.
`enc_name`/`enc_wish` werden mit AAD `gid ‖ pid ‖ IPK ‖ IDH` verschlüsselt, damit niemand Namen
zwischen Teilnehmern vertauschen kann. Alle Public Keys werden auf kleine Ordnung geprüft.

Gruppenkontext für alle Signaturen/KDFs einer Runde:
`G_r = SHA-256("wichtel-v2" ‖ gid ‖ r ‖ sortierte Liste (pid, IPK, IDH, E_r, H(x_r), H(enc_name)))`.
Zeigt der Server verschiedenen Teilnehmern verschiedene Listen, passen die Masken nicht zusammen
und das Protokoll bricht ab. Zusätzlich zeigt die UI einen **Gruppen-Fingerabdruck** aus `G_r`
(≥ 64 Bit, z. B. 6 Wörter). Er muss vor dem Start **im Gruppenchat verglichen** werden – auch im
Asynchron-Modus (Schutz gegen „jeder sieht eine eigene Welt aus Fake-Teilnehmern“).

## 6. Das Verlosungsprotokoll

Idee in einem Satz: *Jeder veröffentlicht **anonym** ein Pseudonym; die zufällige Reihenfolge der
Pseudonyme bildet einen Kreis (jeder beschenkt den nächsten); danach verrät sich jeder **nur seinem
Schenker** – ohne zu wissen, wer das ist.*

### 6.1 Schritt 1 – Anonyme Pseudonyme (DC-Netz)

Anonymes Veröffentlichen ohne vertrauenswürdige Partei gelingt mit einem **DC-Netz**
(„Dining Cryptographers“), das alle Teilnehmer **parallel** in **einem** Durchgang ausführen:

- Jedes Paar `(i, j)` hat einen gemeinsamen Schlüssel
  `k_ij = HKDF(X25519(e_r,i, E_r,j), "dcnet" ‖ G_r ‖ min(E_i,E_j) ‖ max(E_i,E_j))`
  – ohne Interaktion berechenbar, da alle `E_r` beim Beitritt hinterlegt wurden.
- Es gibt `m = max(64, 16·n²)` Slots à **40 Byte**: `PDH_r (32) ‖ SHA-256(G_r ‖ PDH_r)[0..8]`.
- Der Slot `s_i` wird aus `x_r` per Rejection-Sampling (ohne Modulo-Bias) bestimmt. Weil `H(x_r)`
  schon beim Beitritt festgelegt wurde, kann niemand seinen Slot nachträglich wählen – auch nicht,
  wer mit DB-Zugriff die Vektoren der anderen vorab sieht (*Rushing*).
- `V_i = ⊕_{j≠i} ChaCha20(k_ij)[0 .. 40·m]  ⊕  (Pseudonym an Position s_i)`.
- Der Server sammelt alle `n` Vektoren und veröffentlicht erst dann `R = ⊕_i V_i`.
  Die paarweisen Masken heben sich auf; in `R` stehen alle Pseudonyme – **ohne Absender**.
- Jeder Client prüft: genau `n` gültige Slots **und** das eigene Pseudonym an der eigenen Stelle.

**Störfall im DC-Netz (Blame-Verfahren):** Ist die Prüfung nicht erfüllt (Kollision, ~3 %, oder
Störer), legen **alle** `e_r` und `x_r` dieser Runde offen. Damit kann jeder jeden Vektor `V_i`
nachrechnen: Entweder es war eine ehrliche Kollision (zwei korrekte Vektoren, gleicher Slot) ⇒
Runde `r+1`; oder ein Teilnehmer hat einen falschen Vektor geschickt ⇒ er ist **namentlich
überführt** und der Spielleiter entfernt ihn. Die offengelegten Werte sind rundenspezifisch; die
verworfene Runde verrät nichts über künftige Runden.

### 6.2 Der Kreis

Die gültigen Slots, aufsteigend sortiert, ergeben Positionen `0 … n-1`.
**Position `k` beschenkt Position `(k+1) mod n`.** Das ergibt einen gleichverteilt zufälligen Kreis
über alle Teilnehmer: keine Selbstbeschenkung, keine 2er-Pärchen.

Jeder kennt nun seine eigene Position; die Reihenfolge der Pseudonyme ist für alle sichtbar.

### 6.3 Schritt 2 – Enthüllung an den (unbekannten) Schenker

Teilnehmer `i` auf Position `k` lädt **genau einen** Chiffretext hoch, verschlüsselt an das Pseudonym
seines Schenkers `PDH_{k-1}`:

- **HPKE** (RFC 9180) im **Auth-Modus**, X25519-HKDF-SHA256 / ChaCha20-Poly1305, Absenderschlüssel
  `idh_i` ⇒ der Schenker weiß sicher: „das kommt von Identität `pid_i`“.
- Klartext: `pid_i ‖ MAC_{X25519(pdh_k, PDH_{k-1})}(G_r ‖ "claim" ‖ pid_i) ‖ optionale private Notiz`,
  aufgefüllt auf feste Länge `L = 512 B`. Der MAC beweist: „Identität `pid_i` besitzt das
  Pseudonym auf Position `k`“.
- `info = G_r ‖ "reveal"`.

HPKE mit DHKEM ist **key-private**: Am Chiffretext ist nicht erkennbar, an welchen Schlüssel er
gerichtet ist. Der Server sieht also n gleich große Uploads von n Personen – sonst nichts. Erst wenn
alle hochgeladen haben, gibt er sie frei. **Jeder Client lädt alle n herunter** und probiert sie
durch. Erwartet wird **genau einer**, der sich entschlüsseln lässt und dessen MAC stimmt.

Ergebnis: „Du beschenkst `name(pid_j)`“ (Name entschlüsselt mit `GK`) + optionale private Notiz
(z. B. Lieferadresse, die so nur der Schenker sieht). Weil MAC statt Signatur verwendet wird, kann
der Schenker das Ergebnis **niemandem beweisen** (Abstreitbarkeit).

**Störfall in der Enthüllung:** Es gibt **keinen** automatischen Neustart mehr – sonst könnte jeder,
der sein Ergebnis kennt, so lange „Störung“ melden, bis es ihm passt. Wer 0 oder ≥ 2 gültige
Nachrichten erhält, kann eine **Beschwerde mit Beweis** einreichen: Er legt `pdh_r` seiner Position
offen. Jeder kann dann alle n Chiffretexte daraufhin prüfen und sieht, welcher Uploader falsch
gehandelt hat – oder dass die Beschwerde unbegründet war. Beides ist namentlich zuordenbar.
Neustarts löst nur der Spielleiter aus, sichtbar für alle und mitgezählt („Runde 3“).

### 6.4 Rundenzahl & Besuche

| Phase | Wer | Voraussetzung |
|---|---|---|
| Beitritt (inkl. Commitments) | jeder | – |
| DC-Netz-Upload | jeder | Spielleiter hat gestartet |
| Enthüllungs-Upload | jeder | alle DC-Uploads da und gültig |
| Ergebnis abrufen | jeder | alle Enthüllungen da |
| *(nur im Störfall)* Offenlegung | jeder | Prüfung fehlgeschlagen |

Im **Live-Modus** läuft das in Sekunden ab (Server-Sent Events). Im **Asynchron-Modus** braucht
jeder bis zu 4 Besuche; jeder Besuch erledigt automatisch alles Mögliche.

**Abbrecher:** Fehlt ein Upload von `X`, kann der Spielleiter `X` entfernen. Statt neu zu starten,
legen die übrigen ihre Paarmasken `k_iX` offen (nur die mit `X` – das gefährdet niemanden), und der
Server rechnet `X` aus `R` heraus. Die Runde läuft mit n−1 weiter. Wer sich so selbst entfernt, um
die Reihenfolge zu beeinflussen, ist danach nicht mehr dabei.

### 6.5 Was lernt wer?

- **Server/Spielleiter** (passiv): Teilnehmerzahl, öffentliche Schlüssel, Zeitpunkte, Fortschritt.
  Keine Zuordnung. Der Spielleiter kennt `GK` und damit die Namen – der Server allein nicht.
- **Teilnehmer**: den eigenen Beschenkten; dass sein Schenker nicht sein Beschenkter ist.
- **Koalitionen**: Die Reihenfolge der Pseudonyme ist öffentlich. Zwei Verbündete kennen deshalb
  ihren Abstand im Kreis. Sitzt B zwei Plätze hinter A, wissen beide zusammen, wer B beschenkt
  (A kennt seinen Beschenkten, und genau dieser beschenkt B). Bei zufälligem Kreis passiert das mit
  Wahrscheinlichkeit ≈ 2/(n−1), bei n = 10 also ≈ 22 %. Allgemein lernt eine Koalition die Kanten
  zwischen ihren Mitgliedern und deren direkten Nachbarn – nicht mehr. Erzwingen können sie eine
  bestimmte Lage nicht (Slot-Commitments, keine freien Neustarts).
- **n = 3**: Jeder kennt die komplette Zuordnung (gilt für *jedes* Verfahren). Deshalb **n ≥ 4**.
- **Grenze**: Ein *aktiv* bösartiger Server kann manipulierten Code ausliefern (siehe Review A1).
  Der Schutz vor dem Spielleiter gilt nur, wenn der Spielleiter **nicht** zugleich Betreiber ist.

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
| `POST /api/groups/{gid}/participants` | – | beitreten (`IPK`, `IDH`, `auth_hash`, `enc_name`, `enc_wish`, `(E_r, H(x_r))` für r = 1…R_max) |
| `DELETE /api/groups/{gid}/participants/{pid}` | Admin oder selbst | entfernen / austreten (nur vor Start bzw. löst Neustart aus) |
| `POST /api/groups/{gid}/start` | Admin | Liste einfrieren, Runde 1 starten |
| `PUT /api/groups/{gid}/rounds/{r}/dcnet` | Teilnehmer | Vektor `V_i` (signiert) |
| `GET /api/groups/{gid}/rounds/{r}/dcnet` | – | `R`, erst wenn vollständig |
| `PUT /api/groups/{gid}/rounds/{r}/blame` | Teilnehmer | Offenlegung `e_r`, `x_r` (nur im DC-Störfall) bzw. Maskenkorrektur `k_iX` (bei Abbrecher X) |
| `PUT /api/groups/{gid}/rounds/{r}/reveal` | Teilnehmer | **ein** Chiffretext (signiert) |
| `GET /api/groups/{gid}/rounds/{r}/reveal` | – | alle `n` Chiffretexte, erst wenn vollständig |
| `POST /api/groups/{gid}/rounds/{r}/complaint` | Teilnehmer | Beschwerde mit Beweis (`pdh_r`); kein Freitext, keine Position |
| `POST /api/groups/{gid}/rounds/{r}/restart` | Admin | Neustart (sichtbar, gezählt) |
| `GET /api/groups/{gid}/events` | – | SSE: Zustandsänderungen (für Live-Modus) |

Auth per `Authorization: Bearer <token>`; Server vergleicht Hashes in konstanter Zeit.
Hochgeladene Protokollnachrichten sind zusätzlich mit `isk` signiert.

### 7.3 Datenmodell (SQLite)

```sql
groups(gid TEXT PK, admin_hash BLOB, enc_meta BLOB, state TEXT, round INT,
       roster_hash BLOB, created_at INT, expires_at INT)
participants(gid, pid, ipk BLOB, idh BLOB, auth_hash BLOB, enc_name BLOB,
             enc_wish BLOB, joined_at INT, PRIMARY KEY(gid, pid))
round_commitments(gid, pid, round, eph_pub BLOB, slot_commit BLOB)
blame_disclosures(gid, round, pid, payload BLOB)
dcnet_uploads(gid, round, pid, vector BLOB)          -- wird nach Berechnung von R gelöscht
dcnet_results(gid, round, result BLOB)
reveal_uploads(gid, round, pid, ciphertext BLOB)
complaints(gid, round, pid, proof BLOB)
```

Größen: n = 20 ⇒ `m = 6400` Slots à 40 B ⇒ 256 KB pro DC-Vektor; Enthüllung 1 × ~0,6 KB pro
Teilnehmer. Obergrenze **n ≤ 50** (DC-Vektor ≈ 1,6 MB, ~80 MB Keystream je Client – im Web Worker
unter einer Sekunde); empfohlen ≤ 30.
SQLite mit `PRAGMA secure_delete = ON` und regelmäßigem WAL-Checkpoint, damit gelöschte Vektoren
nicht in Freelist/WAL weiterleben.

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
