# Weihnachtswichtel – Konzept

Stand: 2026-11-06 · Status: Entwurf v4 (nach Review und Rückmeldungen: lokales Turso, kein Störerschutz, freie Auslosung mit verborgenen gegenseitigen Paaren – siehe `02-review.md` §G)

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
| Teilnehmer | neugierig; Sabotage wird nicht erwartet | erfährt nur den eigenen Beschenkten; niemand kann gezielt neu würfeln lassen. Ein Störer kann die Verlosung blockieren, aber nichts herausfinden (bewusst akzeptiert) |
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
| `idh`/`IDH` | `HKDF(seed, "id-dh")` | X25519: DC-Netz-Paarschlüssel und Identität gegenüber dem Schenker (HPKE-Auth) |
| `tok` | `HKDF(seed, "auth")` | Bearer-Token; Server speichert nur `SHA-256(tok)` |
| `rp_r`/`RP_r` | `HKDF(seed, "recv" ‖ G_r)` | X25519: anonyme **Beschenkten-Rolle** je Protokollrunde r |
| `gp_{r,t}`/`GP_{r,t}` | `HKDF(seed, "give" ‖ G_r ‖ t)` | X25519: anonyme **Schenker-Rolle** je Runde r und Versuch t = 1…T |
| `x_r` | `HKDF(seed, "slot" ‖ G_r)` | Zufallsquelle für die Slot-Wahl je Runde |

Beim **Beitritt** lädt der Client hoch: `IPK`, `IDH`, `H(tok)`, `enc_name`, `enc_wish` – mit `isk`
signiert. `enc_name`/`enc_wish` werden mit AAD `gid ‖ pid ‖ IPK ‖ IDH` verschlüsselt, damit niemand
Namen zwischen Teilnehmern vertauschen kann. Public Keys werden auf kleine Ordnung geprüft.

Gruppenkontext für alle Signaturen/KDFs einer Runde:
`G_r = SHA-256("wichtel-v3" ‖ gid ‖ r ‖ sortierte Liste (pid, IPK, IDH, H(enc_name)))`.
Zeigt der Server verschiedenen Teilnehmern verschiedene Listen, passen die Masken nicht zusammen
und das Protokoll bricht ab. Zusätzlich zeigt die UI einen **Gruppen-Fingerabdruck** aus `G_r`
(≥ 64 Bit, z. B. 6 Wörter). Er wird vor dem Start **im Gruppenchat verglichen** – auch im
Asynchron-Modus (Schutz gegen „jeder sieht eine eigene Welt aus Fake-Teilnehmern“).

## 6. Das Verlosungsprotokoll

Die Idee: Jeder Teilnehmer hat **zwei voneinander unabhängige anonyme Rollen**, eine
*Beschenkten-Rolle* und eine *Schenker-Rolle*. Niemand außer ihm selbst weiß, dass beide Rollen zu
derselben Person gehören. Zwischen den Rollen wird **offen** gelost; weil niemand die Rollen den
Personen zuordnen kann, verrät die offene Auslosung nichts. Zum Schluss verrät sich jeder **nur
seinem Schenker**, ohne zu wissen, wer das ist.

Ergebnis: eine gleichverteilt zufällige Zuordnung, in der sich **niemand selbst zieht**,
**gegenseitiges Beschenken möglich** ist und **niemand erkennen kann**, ob er in einem
gegenseitigen Paar ist.

### 6.1 Schritt 1 – Anonyme Rollen (DC-Netz, ein Upload)

Anonymes Veröffentlichen ohne vertrauenswürdige Partei gelingt mit einem **DC-Netz**
(„Dining Cryptographers“), das alle Teilnehmer **parallel** in **einem** Durchgang ausführen:

- Jedes Paar `(i, j)` hat einen gemeinsamen Schlüssel
  `k_ij = HKDF(X25519(idh_i, IDH_j), "dcnet" ‖ G_r ‖ min(IDH_i,IDH_j) ‖ max(IDH_i,IDH_j))`
  – ohne Interaktion berechenbar, da alle `IDH` beim Beitritt hinterlegt wurden. Durch `G_r` (enthält
  die Rundennummer) sind die Masken jeder Runde neu.
- Der Vektor besteht aus **1 + T Bereichen** (T = 16):
  - **Bereich E** (Beschenkten-Rollen): `m_E = 16·n²` Slots à 40 B:
    `RP (32) ‖ SHA-256(G_r ‖ RP)[0..8]`. Eine Rolle pro Teilnehmer, gilt für alle Versuche.
  - **Bereiche S_1 … S_T** (Schenker-Rollen, **pro Versuch frisch**): je `m_S = 4·n²` Slots à 32 B:
    `GP_t`. Gültig ist ein Versuch, wenn genau n Slots belegt sind.
- Jeder wählt pro Bereich einen Slot (aus `seed`-abgeleitetem Zufall, Rejection-Sampling ohne
  Modulo-Bias) und schreibt dort seinen Schlüssel hinein. Den Vektor maskiert er mit
  `⊕_{j≠i} ChaCha20(k_ij)` und lädt ihn hoch.
- Der Server XORt die Vektoren **beim Eintreffen** auf (er speichert nur die laufende Summe) und
  veröffentlicht das Ergebnis `R`, wenn alle hochgeladen haben. Die Masken heben sich auf; in `R`
  stehen alle Rollen-Schlüssel – **ohne Absender**.
- Sortiert ergeben die Slots anonyme Positionen: Beschenkten-Positionen `0…n-1` aus E und, für
  jeden gültigen Versuch t, Schenker-Positionen `0…n-1` aus S_t.

Kollidieren zwei Teilnehmer in Bereich E (~3 %), ist die ganze Runde ungültig; alle Clients gehen
automatisch zu Runde `r+1` über. Eine Kollision in einem S_t macht nur diesen Versuch ungültig.
Beides passiert, **bevor** irgendjemand ein Ergebnis kennt.

### 6.2 Die Auslosung (offen, mit T Versuchen)

Aus `R` wird eine gemeinsame Zufallszahl abgeleitet: `ρ = SHA-256("sigma" ‖ G_r ‖ R)`. Für jeden
Versuch t berechnet jeder Client dieselbe **gleichverteilte Permutation**
`σ_t = FisherYates(ChaCha20(ρ ‖ t))`: Schenker-Position p in Versuch t beschenkt
Beschenkten-Position `σ_t(p)`.

Ob sich in Versuch t jemand selbst zieht, weiß nur der Betroffene selbst. Das wird im nächsten
Schritt **anonym** abgefragt. Gewählt wird der **erste** gültige Versuch `t*`, in dem sich niemand
selbst zieht. Pro Versuch klappt das mit ≈ 32 % (≈ 37 % kein Selbstzug × ≈ 88 % keine Kollision).
Dass alle 16 Versuche scheitern, kommt in ≈ 0,2 % der Fälle vor; dann folgt automatisch Runde `r+1`.

**Warum frische Schenker-Rollen pro Versuch?** Würde man dieselben Rollen mehrfach auslosen,
verriete jeder gescheiterte Versuch („hier hat sich jemand selbst gezogen“) etwas über die
Verbindung der Rollen. Das ließ sich in einer Simulation bei 4 Personen in ~8 % der Fälle bis zur
Gewissheit ausnutzen. Mit frischen Schenker-Rollen sind gescheiterte Versuche statistisch
unabhängig vom gewählten Versuch. Eine exakte Auszählung für n = 4 und 5 bestätigt: Was ein
Teilnehmer über „sind wir ein gegenseitiges Paar?“ weiß, entspricht genau der allgemeinen
Grundwahrscheinlichkeit, mehr nicht.

### 6.3 Schritt 2 – Selbstzug-Abfrage und Enthüllung (ein Upload)

Teilnehmer `i` mit Beschenkten-Position `e_i` und Schenker-Positionen `p_{i,t}` lädt in **einem**
Upload hoch:

1. **Anonyme Selbstzug-Meldung**: ein zweites, kleines DC-Netz mit T Slots à 16 B. In Slot t
   schreibt `i` 16 Zufallsbytes, wenn `σ_t(p_{i,t}) = e_i` (er würde sich selbst ziehen), sonst
   nichts. Nach dem XOR aller Beiträge ist Slot t genau dann ≠ 0, wenn sich in Versuch t
   *irgendwer* selbst zieht – aber niemand erfährt, wer.
2. **Je Versuch eine Enthüllung** (T Chiffretexte): an den Schenker-Schlüssel
   `GP_t` der Position `σ_t⁻¹(e_i)`, per **HPKE** (RFC 9180) im **Auth-Modus** (X25519-HKDF-SHA256 /
   ChaCha20-Poly1305) mit Absenderschlüssel `idh_i`. Klartext:
   `pid_i ‖ MAC_{X25519(rp_i, GP)}(G_r ‖ t ‖ "claim" ‖ pid_i) ‖ optionale private Notiz`, aufgefüllt
   auf `L = 512 B`. Für ungültige Versuche: Zufallsbytes gleicher Länge.

Der Server berechnet, sobald alle hochgeladen haben, das XOR der Selbstzug-Meldungen, bestimmt `t*`
und **gibt nur die n Enthüllungen von Versuch `t*` frei**. Alle anderen löscht er.

HPKE mit DHKEM ist **key-private**: Am Chiffretext ist nicht erkennbar, an welchen Schlüssel er
gerichtet ist. **Jeder Client lädt alle n Enthüllungen herunter** (kein positionsabhängiges
Zugriffsmuster) und probiert sie mit seinem `gp_{t*}` durch. Genau eine lässt sich öffnen, und
ihr MAC stimmt. Ergebnis: „Du beschenkst `name(pid_j)`“ + optionale private Notiz (z. B.
Lieferadresse). Weil MAC statt Signatur verwendet wird, kann der Schenker das Ergebnis **niemandem
beweisen** (Abstreitbarkeit).

Erhält jemand 0 oder ≥ 2 gültige Enthüllungen (Fehler oder Störer), zeigt die UI einen Fehler. Eine
Neuverlosung kann **nur der Spielleiter** auslösen, sichtbar für alle („Verlosung Nr. 2“).

### 6.4 Neu auslosen – nur bei Austritt

Es gibt **kein** „Neu würfeln“ auf Wunsch. Eine neue Verlosung gibt es nur, wenn sich die
Teilnehmerliste ändert:

| Wann verlässt jemand die Gruppe? | Folge |
|---|---|
| vor dem Start | einfach austreten bzw. vom Spielleiter entfernt werden |
| während der Verlosung (noch kein Ergebnis) | Person wird entfernt, Verlosung startet neu – unbedenklich, niemand kennt etwas |
| nach der Verlosung | Spielleiter entfernt die Person ⇒ **komplett neue Verlosung** für alle; die UI warnt vorher („Alle bekommen eine neue Person zugelost“) |

Automatische Folgerunden (Kollision in Bereich E, alle T Versuche gescheitert) zählen nicht als
Neu-Auslosen, weil zu dem Zeitpunkt noch niemand ein Ergebnis kennt.

### 6.5 Besuche

| Phase | Wer | Voraussetzung |
|---|---|---|
| Beitritt | jeder | – |
| DC-Netz-Upload (Rollen) | jeder | Spielleiter hat gestartet |
| Selbstzug-Meldung + Enthüllungen | jeder | alle Rollen-Uploads da |
| Ergebnis abrufen | jeder | alle Enthüllungen da |

Im **Live-Modus** läuft das in Sekunden ab (Server-Sent Events). Im **Asynchron-Modus** braucht
jeder bis zu 4 Besuche; jeder Besuch erledigt automatisch alles Mögliche. In ≈ 3 % der Fälle
(Kollision in Bereich E) kommt ein Durchgang hinzu. Fehlt jemand dauerhaft, entfernt ihn der
Spielleiter (siehe 6.4).

### 6.6 Was lernt wer?

- **Server/Spielleiter** (passiv): Teilnehmerzahl, öffentliche Schlüssel, Zeitpunkte, Fortschritt,
  welcher Versuch gewählt wurde. Keine Zuordnung. Der Spielleiter kennt `GK` und damit die Namen –
  der Server allein nicht.
- **Teilnehmer**: nur den eigenen Beschenkten. **Niemand erfährt seinen Schenker – auch nicht in
  einem gegenseitigen Paar.** Was bleibt, ist die allgemein bekannte Grundwahrscheinlichkeit
  (z. B. bei 10 Personen beschenkt der eigene Beschenkte einen mit ≈ 10 % zurück).
- **Koalitionen**: Verbündete kennen ihre eigenen Kanten. Weil die Rollen anderer nicht mit
  Personen verknüpfbar sind, lernen sie darüber hinaus nur, was sich aus der Zählung ergibt (siehe
  n = 4 unten).
- **Kleine Gruppen**: Bei n = 3 kennt jeder die komplette Zuordnung, bei n = 4 lässt sich mit dem
  eigenen Ergebnis oft viel ausschließen. Das gilt für **jedes** Verfahren. Deshalb **n ≥ 4** und
  ein Hinweis bei n ≤ 5.
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
│  wichtel-server (Rust: axum, tokio, turso – lokal)          │
│   - Zustandsautomat pro Runde, Größen-/Rate-Limits          │
│   - liefert statische Assets (rust-embed) aus               │
│   - Hintergrund-Job: Ablauf & Löschung                       │
└──────────────┬──────────────────────────────────────────────┘
               │
   SQLite-kompatible Datei (Turso, lokal, kein Cloud-Dienst)
```

**Ein einziges Binary** + eine Datenbankdatei. Deployment z. B. hinter Caddy (TLS) auf einem kleinen
VPS oder Container.

### 7.1 Crates

| Crate | Inhalt | Abhängigkeiten (Auswahl) |
|---|---|---|
| `wichtel-core` | reine Logik, kein I/O, `native` + `wasm32` | `x25519-dalek`, `ed25519-dalek`, `hpke`, `chacha20`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize`, `rand_core`, `serde` |
| `wichtel-api` | gemeinsame DTOs (Request/Response-Typen) | `serde`, `base64` |
| `wichtel-wasm` | JS-Bindings für `core` | `wasm-bindgen`, `getrandom` (Feature `js`/`wasm_js`) |
| `wichtel-server` | HTTP-API, Persistenz, Ablauf | `axum`, `tokio`, `turso` (lokal, `default-features = false`), `tower-http`, `rust-embed`, `tracing` |

Der Kern ist ohne Server testbar: Ein **Simulations-Test** spielt das ganze Protokoll mit n
In-Process-Clients und einem In-Memory-„Briefkasten“ durch – inkl. Kollisionen, Austritten,
Server-Equivocation und einem statistischen Test auf Gleichverteilung der Zuordnung.

### 7.2 HTTP-API (Entwurf)

| Methode & Pfad | Auth | Zweck |
|---|---|---|
| `POST /api/groups` | – | Gruppe anlegen (`admin_hash`, `enc_meta`) |
| `GET /api/groups/{gid}` | – | Zustand, `enc_meta`, Teilnehmerliste (pid, Public Keys, `enc_name`), Fortschritt |
| `DELETE /api/groups/{gid}` | Admin | sofort löschen |
| `POST /api/groups/{gid}/participants` | – | beitreten (`IPK`, `IDH`, `auth_hash`, `enc_name`, `enc_wish` |
| `DELETE /api/groups/{gid}/participants/{pid}` | Admin oder selbst | entfernen / austreten (nur vor Start bzw. löst Neustart aus) |
| `POST /api/groups/{gid}/start` | Admin | Liste einfrieren, Runde 1 starten |
| `PUT /api/groups/{gid}/rounds/{r}/dcnet` | Teilnehmer | Rollen-Vektor `V_i` (signiert) |
| `GET /api/groups/{gid}/rounds/{r}/dcnet` | – | `R`, erst wenn vollständig |
| `PUT /api/groups/{gid}/rounds/{r}/reveal` | Teilnehmer | Selbstzug-Meldung (T × 16 B, maskiert) + T Chiffretexte (signiert) |
| `GET /api/groups/{gid}/rounds/{r}/reveal` | – | `t*` und die `n` Chiffretexte von Versuch `t*`, erst wenn vollständig |
| `POST /api/groups/{gid}/rounds/{r}/next` | Teilnehmer | „Kollision in Bereich E“ ⇒ Runde `r+1` (nur vor Freigabe der Enthüllungen; ohne Inhalt; Server prüft selbst nach) |
| `POST /api/groups/{gid}/restart` | Admin | neue Verlosung (nach Austritt oder Fehler; sichtbar, gezählt) |
| `GET /api/groups/{gid}/events` | – | SSE: Zustandsänderungen (für Live-Modus) |

Auth per `Authorization: Bearer <token>`; Server vergleicht Hashes in konstanter Zeit.
Hochgeladene Protokollnachrichten sind zusätzlich mit `isk` signiert.

### 7.3 Datenmodell (Turso lokal, SQLite-Dialekt)

```sql
groups(gid TEXT PK, admin_hash BLOB, enc_meta BLOB, state TEXT, round INT,
       roster_hash BLOB, created_at INT, expires_at INT)
participants(gid, pid, ipk BLOB, idh BLOB, auth_hash BLOB, enc_name BLOB,
             enc_wish BLOB, joined_at INT, PRIMARY KEY(gid, pid))
dcnet_rounds(gid, round, aggregate BLOB, submitted TEXT)  -- laufendes XOR + wer schon hochgeladen hat
selfdraw_rounds(gid, round, aggregate BLOB, submitted TEXT)
reveal_uploads(gid, round, pid, attempt INT, ciphertext BLOB) -- nach Bestimmung von t* nur t* behalten
```

Größen (T = 16): n = 20 ⇒ Rollen-Vektor ≈ 1,1 MB (Bereich E 256 KB + 16 × 51 KB), Enthüllungen
≈ 10 KB pro Teilnehmer. Obergrenze **n ≤ 30** (Rollen-Vektor ≈ 2,4 MB hoch und ≈ 2,4 MB `R`
herunter; ~70 MB Keystream je Client – im Web Worker etwa eine Sekunde). Server-Speicher pro
Runde: nur das laufende XOR, also eine Vektorgröße unabhängig von n.
Gelöschte Daten (verworfene Enthüllungen, abgelaufene Gruppen) dürfen nicht in Freelist/WAL weiterleben: `PRAGMA secure_delete = ON` +
WAL-Checkpoint. **In Phase 0 prüfen, ob Turso das unterstützt**; sonst nach Löschungen periodisch
`VACUUM`.

### 7.4 Datensparsamkeit

- Keine Konten, keine E-Mail-Adressen, keine Cookies (nur `localStorage` für den eigenen `seed`,
  technisch notwendig ⇒ kein Consent-Banner nötig).
- Namen, Titel, Wunschzettel nur als Chiffretext (Schlüssel im URL-Fragment).
- Keine IP-Adressen in Logs (Tracing ohne Peer-Adresse; Reverse-Proxy-Logs ebenfalls aus/anonymisiert).
- Keine externen Ressourcen (Fonts, CDN, Analytics). Strikte CSP, `Referrer-Policy: no-referrer`.
- Automatische Löschung nach Ablauf; einzelne DC-Vektoren werden nie gespeichert (laufendes XOR),
  Enthüllungen nicht gewählter Versuche sofort gelöscht.
- Rate-Limits und Größenlimits gegen Missbrauch als anonymer Speicher.

## 8. Datenbank: Turso, lokal eingebettet

**Entscheidung: Turso als eingebettete, lokale Datenbank – kein Turso-Cloud-Dienst.**

„Turso“ meint zweierlei:
- **Turso Database**: eine Neuimplementierung von SQLite in Rust. SQL-Dialekt und Dateiformat sind
  SQLite-kompatibel, sie läuft als Bibliothek im eigenen Prozess und schreibt in eine lokale Datei.
  Das nehmen wir.
- **Turso Cloud**: gehosteter Dienst mit Account, Token, Replikas. Das nehmen wir **nicht**, denn das
  wäre ein zusätzlicher Auftragsverarbeiter und widerspricht der Datensparsamkeit.

„Drop-in“ gilt auf Ebene von SQL und Dateiformat: Die Datei lässt sich z. B. mit dem
`sqlite3`-Kommandozeilenwerkzeug untersuchen. Im Rust-Code ist es keine Eins-zu-eins-Ersetzung für
`rusqlite`: Der Crate `turso` hat eine eigene, asynchrone API (passt gut zu axum/tokio).

| | Bewertung |
|---|---|
| Crate | `turso` 0.8.x (Stand 2026-11; 0.9 im Vorab-Release), MIT-Lizenz |
| Build-Last | reines Rust, kein C-Compiler nötig; mit `default-features = false` ohne `mimalloc`/Volltextsuche ⇒ schlanker Build |
| Datensparsamkeit | Daten bleiben auf dem eigenen Server |
| Reife | **vor 1.0** ⇒ API-Änderungen und Lücken möglich (z. B. einzelne PRAGMAs) |

**Absicherung gegen das Reife-Risiko:**
- Persistenz hinter einem kleinen `Store`-Trait. Fällt Turso an einer Stelle durch, ist ein
  `rusqlite`-Backend mit denselben SQL-Migrationen schnell ergänzt.
- Version exakt pinnen und Upgrades bewusst einspielen.
- Phase 0 prüft vorab die benötigten Features: WAL, Transaktionen, BLOBs, `secure_delete` bzw.
  `VACUUM`, gleichzeitige Leser.
- Integrationstests laufen gegen eine echte Turso-Datei.

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
