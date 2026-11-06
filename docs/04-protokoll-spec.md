# Weihnachtswichtel – Protokoll-Spezifikation (normativ)

Stand: 2026-11-06 · Version: `wichtel/v1` · Grundlage: Konzept v5 (`01-konzept.md`)

Diese Spezifikation ist **normativ**: `wichtel-core` (Rust, nativ und WASM) und alle Tests richten
sich danach. Bei Widerspruch zum Konzept gilt diese Datei; Abweichungen vom Konzept sind in §13
aufgeführt. Die Schlüsselwörter MUSS/DARF NICHT/SOLL sind im Sinne von RFC 2119 zu lesen.

## 1. Notation und Kodierung

| Symbol | Bedeutung |
|---|---|
| `a ‖ b` | Konkatenation von Bytefolgen |
| `u8(x)`, `u16(x)`, `u32(x)` | vorzeichenlose Ganzzahl, **Big-Endian**, 1/2/4 Byte |
| `lp(x)` | `u32(len(x)) ‖ x` (längenpräfixiert) |
| `"…"` | ASCII-Bytes ohne Terminator |
| `H(x)` | SHA-256, 32 Byte |
| `HKDF(salt, ikm, info, L)` | HKDF-SHA256 (RFC 5869), Extract + Expand |
| `Expand(prk, info, L)` | HKDF-Expand-SHA256 |
| `HMAC(k, m)` | HMAC-SHA256, 32 Byte |
| `X25519(sk, pk)` | RFC 7748; **MUSS** abgelehnt werden, wenn das Ergebnis 32 Null-Bytes ist (nicht beitragend) |
| `ChaCha20(k, nonce)` | ChaCha20-Schlüsselstrom nach RFC 8439 (32-Byte-Schlüssel, 12-Byte-Nonce, Zähler ab 0) |
| `Z(n)` | n Null-Bytes |

- Alle Labels beginnen mit `"wichtel/v1/"` (Domain-Separation, Versionierung).
- In JSON werden Binärfelder als **Base64url ohne Padding** (RFC 4648 §5) kodiert.
- Zeitpunkte in der API: Unix-Sekunden (UTC) als JSON-Zahl.
- Indizes (Slots, Positionen, Versuche) sind **0-basiert**, außer der Versuchsnummer `t ∈ 1…16`
  und der Runde `r ≥ 1`.

## 2. Konstanten

| Name | Wert | Bedeutung |
|---|---|---|
| `N_MIN` | 4 | Mindestteilnehmerzahl für den Start |
| `N_MAX` | 30 | Höchstteilnehmerzahl |
| `T` | 16 | Zahl der Auslosungsversuche pro Runde |
| `m_E(n)` | `16·n²` | Slots im Bereich E |
| `m_S(n)` | `4·n²` | Slots je Bereich S_t |
| `SLOT_E` | 40 | Bytes je E-Slot |
| `SLOT_S` | 32 | Bytes je S-Slot |
| `L_V(n)` | `40·m_E + T·32·m_S = 2688·n²` | Länge des Rollen-Vektors (n = 30: 2 419 200 B) |
| `SLOT_SD` | 16 | Bytes je Selbstzug-Slot |
| `L_SD` | `T·16 = 256` | Länge des Selbstzug-Vektors |
| `L_PT` | 512 | Klartextlänge einer Enthüllung |
| `L_CT` | `32 + 512 + 16 = 560` | Länge einer Enthüllung (HPKE `enc ‖ ct`) |
| `NAME_MAX` | 64 | max. Bytes (UTF-8) eines Namens |
| `WISH_MAX` | 1000 | max. Bytes (UTF-8) eines Wunschzettels |
| `META_MAX` | 2000 | max. Bytes der Gruppen-Metadaten (JSON) |
| `NOTE_MAX` | 461 | max. Bytes der privaten Notiz (`512 − 1 − 16 − 32 − 2`) |

## 3. Bezeichner und Geheimnisse

| Wert | Länge | Erzeugung |
|---|---|---|
| `gid` | 16 B | Server, CSPRNG; in URLs Base64url (22 Zeichen) |
| `GK` | 32 B | Browser des Spielleiters, CSPRNG; nur im URL-Fragment |
| `AS` | 32 B | Browser des Spielleiters, CSPRNG; nur im URL-Fragment des Spielleiter-Links |
| `seed` | 32 B | Browser des Teilnehmers, CSPRNG; nur lokal und im persönlichen Link |
| `pid` | 16 B | `H("wichtel/v1/pid" ‖ gid ‖ IPK)[0..16]` – vom Server nachgeprüft |

URL-Fragmente: `#k=<GK>` (Einladung), `#k=<GK>&a=<AS>` (Spielleiter), `#k=<GK>&s=<seed>`
(persönlich), jeweils Base64url ohne Padding.

`admin_hash = H("wichtel/v1/admin-hash" ‖ AS)`.

## 4. Schlüsselableitung

```
prk  = HKDF-Extract(salt = "wichtel/v1/seed", ikm = seed)

isk  = Ed25519-SigningKey(Expand(prk, "wichtel/v1/id-sig" ‖ gid, 32))     IPK = Public(isk)
idh  = X25519-StaticSecret(Expand(prk, "wichtel/v1/id-dh" ‖ gid, 32))      IDH = X25519(idh, 9)
tok  = Expand(prk, "wichtel/v1/auth" ‖ gid, 32)
auth_hash = H("wichtel/v1/auth-hash" ‖ tok)
```

Rundenspezifisch (benötigt `G_r`, §5):

```
rp_r       = X25519-StaticSecret(Expand(prk, "wichtel/v1/recv" ‖ G_r, 32))           RP_r
gp_{r,t}   = X25519-StaticSecret(Expand(prk, "wichtel/v1/give" ‖ G_r ‖ u8(t), 32))   GP_{r,t}   (t = 1…16)
slotkey_r  = Expand(prk, "wichtel/v1/slot" ‖ G_r, 32)
sd_{r,t}   = Expand(prk, "wichtel/v1/selfdraw" ‖ G_r ‖ u8(t), 16)
rngkey_{r} = Expand(prk, "wichtel/v1/reveal-rng" ‖ G_r, 32)
```

X25519-Schlüssel werden von der Bibliothek beim Gebrauch geklemmt (clamping); die
abgeleiteten 32 Byte werden unverändert als Secret übernommen.

`tok` wird als `Authorization: Bearer <base64url(tok)>` gesendet; der Server speichert nur
`auth_hash` und vergleicht in konstanter Zeit.

## 5. Teilnehmerliste und Gruppenkontext

Beitritt: Der Client sendet `IPK, IDH, auth_hash, enc_name, enc_wish` und
`join_sig = Ed25519-Sign(isk, H("wichtel/v1/join" ‖ gid ‖ IPK ‖ IDH ‖ auth_hash ‖ lp(enc_name) ‖ lp(enc_wish)))`.
Der Server MUSS prüfen: Signatur gültig, `IDH` ist **kanonisch kodiert** (Bit 255 = 0 und
`u < p = 2^255 − 19`, als Little-Endian-Zahl) und kein Punkt kleiner Ordnung (X25519 mit einem
festen Testschlüssel ist beitragend), `pid` **und `IDH`** noch nicht in der Gruppe vorhanden,
Größenlimits (`wichtel_core::keys::validate_idh` + Duplikatprüfung). Clients lehnen eine
Teilnehmerliste mit ungültigem oder doppeltem `IDH` bzw. doppelter `pid` ab (`Roster::new`).

Die **Roster-Reihenfolge** ist aufsteigend nach `pid` (Bytevergleich). Ein Roster-Eintrag ist
`entry_i = pid_i ‖ IPK_i ‖ IDH_i ‖ H(enc_name_i)` (112 Byte).

```
G_r = H("wichtel/v1/G" ‖ gid ‖ u32(r) ‖ u32(n) ‖ entry_0 ‖ … ‖ entry_{n-1})
```

`r` ist die **Protokollrunde** (global pro Gruppe, beginnt bei 1, steigt bei jeder Kollisions-,
Fehlversuchs- oder Neuverlosungsrunde). Der Wunschzettel ist nicht Teil von `G_r` (er ist per AAD
an `pid` gebunden und nach dem Start unveränderlich).

### Fingerabdruck

```
fp = H("wichtel/v1/fp" ‖ gid ‖ u32(n) ‖ entry_0 ‖ … ‖ entry_{n-1})
```

Angezeigt werden die ersten **8 Bytes** von `fp` als **8 Wörter** aus der festen Liste
`crates/wichtel-core/data/wortliste.txt` (256 deutsche Nomen, ASCII, Zeile k = Wort für Byte k),
Trennzeichen Leerzeichen. 8 × 8 Bit = 64 Bit. Der Fingerabdruck ist unabhängig von `r` und ändert
sich nur, wenn sich die Teilnehmerliste ändert.

## 6. Verschlüsselte Gruppendaten (GK)

```
K_gk = HKDF(salt = "wichtel/v1/gk", ikm = GK, info = "wichtel/v1/gk-aead", 32)
seal(aad, data): nonce ← CSPRNG(12);  ct = ChaCha20-Poly1305(K_gk, nonce, pad(data), aad)
                 Ausgabe: nonce ‖ ct   (inkl. 16-Byte-Tag)
pad(data) = u16(len(data)) ‖ data ‖ Z(k)   mit k minimal, sodass Gesamtlänge ≡ 0 (mod 32)
```

| Datum | AAD | Inhalt | Limit |
|---|---|---|---|
| `enc_meta` | `"wichtel/v1/meta" ‖ Z(16)` ¹ | UTF-8-JSON `{"title","budget","event_date","description"}` | `META_MAX` |
| `enc_name` | `"wichtel/v1/name" ‖ gid ‖ pid ‖ IPK ‖ IDH` | UTF-8 | `NAME_MAX` |
| `enc_wish` | `"wichtel/v1/wish" ‖ gid ‖ pid ‖ IPK ‖ IDH` | UTF-8 (darf leer sein) | `WISH_MAX` |

¹ Die `gid` vergibt der Server erst in der Antwort auf `POST /api/groups`, `enc_meta` steht aber
schon im Request. Deshalb wird an Stelle der `gid` ein fester Nullwert `Z(16)` verwendet. Das
schwächt nichts: `GK` ist pro Gruppe frisch und zufällig, ein vom Server untergeschobenes
`enc_meta` einer anderen Gruppe ließe sich mit diesem `GK` nicht öffnen.

Beim Öffnen MUSS `pad` geprüft werden; akzeptiert wird nur die **kanonische (minimale)** Form:
`len(data) ≤ Limit`, Gesamtlänge genau `2 + len(data)` auf ein Vielfaches von 32 aufgerundet,
Füllbytes = 0. Ein Eintrag, dessen Name
sich nicht öffnen lässt, wird in der UI als „⚠ ungültiger Eintrag“ angezeigt; der Client DARF in
einer Gruppe mit ungültigen Einträgen **nicht** an der Verlosung teilnehmen.

## 7. Schritt 1 – Rollen-Vektor (DC-Netz)

### 7.1 Paarschlüssel und Masken

Für jedes Paar `i ≠ j`:

```
dh_ij      = X25519(idh_i, IDH_j)                        (nicht beitragend ⇒ Fehler)
lo, hi     = min(IDH_i, IDH_j), max(IDH_i, IDH_j)        (Bytevergleich)
k^roles_ij = HKDF(salt = G_r, ikm = dh_ij, info = "wichtel/v1/dc-roles" ‖ lo ‖ hi, 32)
k^sd_ij    = HKDF(salt = G_r, ikm = dh_ij, info = "wichtel/v1/dc-selfdraw" ‖ ρ ‖ lo ‖ hi, 32)
P^roles_ij = ChaCha20(k^roles_ij, Z(12))[0 .. L_V]
P^sd_ij    = ChaCha20(k^sd_ij, Z(12))[0 .. L_SD]
```

`ρ` (§8) hängt von `R` ab. Die Selbstzug-Masken sind damit an das veröffentlichte Aggregat
gebunden: Zeigt ein Server verschiedenen Clients verschiedene `R` (Equivocation), entstehen
verschiedene Masken statt eines Two-Time-Pads auf `SD`.

### 7.2 Slot-Wahl

`U = ChaCha20(slotkey_r, Z(12))` wird als Strom von `u32`-Werten (Big-Endian, je 4 Byte) gelesen.

```
uniform(m):  limit = floor(2^32 / m) · m
             wiederhole: u = nächstes u32 aus U;  falls u < limit: return u mod m
```

Reihenfolge der Ziehungen: zuerst `s_E = uniform(m_E)`, dann `s_t = uniform(m_S)` für t = 1…16.

### 7.3 Layout und Inhalt

```
Offset 0:                     Bereich E,  m_E Slots à 40 B
Offset 40·m_E + (t−1)·32·m_S: Bereich S_t, m_S Slots à 32 B      (t = 1…16)
```

Nachricht `M_i` (Länge `L_V`, sonst Nullen):
- E-Slot `s_E`: `RP_r ‖ H("wichtel/v1/slot-check" ‖ G_r ‖ RP_r)[0..8]`
- S_t-Slot `s_t`: `GP_{r,t}`

Upload: `V_i = M_i ⊕ (⊕_{j≠i} P^roles_ij)`.

### 7.4 Aggregation und Auswertung

Der Server berechnet `R = ⊕_i V_i` (laufend, beim Eintreffen) und veröffentlicht `R` erst, wenn
alle `n` Vektoren vorliegen.

Auswertung (von Server **und** jedem Client identisch durchgeführt):

- **E-Gültigkeit:** Ein E-Slot ist *belegt*, wenn er nicht `Z(40)` ist. E ist gültig genau dann,
  wenn genau `n` Slots belegt sind **und** für jeden belegten Slot die 8 Prüfbytes zu den ersten
  32 Bytes passen. Ungültiges E ⇒ **Kollisionsrunde** (§10).
- **E-Positionen:** belegte E-Slots aufsteigend nach Slot-Index ⇒ Positionen `0…n−1`; `RP[e]` ist
  der Schlüssel an Position `e`.
- **Versuch t gültig** genau dann, wenn in S_t genau `n` Slots ≠ `Z(32)` sind. Die belegten Slots
  aufsteigend ergeben Schenker-Positionen `0…n−1` mit Schlüsseln `GP_t[p]`.
- **Eigene Prüfung (nur Client):** Das eigene `RP_r` MUSS an Slot `s_E` stehen; in jedem gültigen
  Versuch MUSS das eigene `GP_{r,t}` an Slot `s_t` stehen. Sonst: Zustand „Störung“, keine weitere
  Teilnahme in dieser Runde (§11).

Eigene Positionen: `e_i` = Position von `s_E` in E; `p_{i,t}` = Position von `s_t` in S_t.

## 8. Auslosung

```
ρ   = H("wichtel/v1/rho" ‖ G_r ‖ R)
key = H("wichtel/v1/sigma" ‖ ρ)
σ_t: Strom W_t = ChaCha20(key, Z(11) ‖ u8(t)) als u32-Folge (Big-Endian)
     a = [0, 1, …, n−1]
     für k = n−1 abwärts bis 1:  j = uniform_{W_t}(k+1);  tausche a[k], a[j]
     σ_t(p) = a[p]
```

`uniform_W(m)` wie in §7.2, aber aus `W_t`. Bedeutung: **Schenker-Position p beschenkt
E-Position σ_t(p).** σ_t ist eine gleichverteilte Permutation (keine Fixpunktfreiheit erzwungen;
die wird über §9.1 hergestellt).

Selbstzug von `i` in Versuch `t`: `σ_t(p_{i,t}) = e_i`.

## 9. Schritt 2 – Selbstzug-Meldung und Enthüllungen

### 9.1 Selbstzug-Vektor

Nachricht `D_i` (256 B, sonst Nullen): für jeden gültigen Versuch `t`, in dem `i` sich selbst zieht,
steht in Slot `t−1` der Wert `sd_{r,t}`.
Upload: `SD_i = D_i ⊕ (⊕_{j≠i} P^sd_ij)`. Aggregat: `SD = ⊕_i SD_i`.

**Wahl von t\*:** kleinstes `t ∈ 1…16` mit „Versuch t gültig“ **und** Slot `t−1` von `SD` = `Z(16)`.
Gibt es keins ⇒ **Fehlversuchsrunde** (§10). Server und Clients berechnen `t*` unabhängig; ein
Client MUSS abbrechen, wenn der Server ein anderes `t*` meldet.

### 9.2 Enthüllungen

Alle Zufallswerte sind deterministisch (identische Wiederholung nach Neuladen):

```
padkey   = Expand(rngkey_r, "wichtel/v1/reveal-pad" ‖ ρ, 32)
pad      = ChaCha20(padkey, Z(12))          (reiner ChaCha20-Schlüsselstrom, Zähler ab 0)
eph_ikm  = Expand(rngkey_r, "wichtel/v1/reveal-eph" ‖ u8(t) ‖ ρ ‖ pkR ‖ H(pt), 32)
```

- Der Strom `pad` liefert **nur Platzhalter**, je 560 Bytes, in der Reihenfolge t = 1…16;
  gültige, erfolgreich versiegelte Versuche verbrauchen nichts aus `pad`.
- Das HPKE-Ephemeral eines gültigen Versuchs ist `DeriveKeyPair(eph_ikm)` (RFC 9180 §7.1.3, d. h.
  `GenerateKeyPair` mit `eph_ikm` als Zufall). Weil `eph_ikm` vom Klartext `pt` abhängt, führen
  zwei Aufrufe mit unterschiedlicher Notiz (zweites Gerät, Wiederholung mit geänderter Notiz) nie
  zu AEAD-Nonce-Wiederverwendung.

Für jeden Versuch `t = 1…16`:

- **Ungültiger Versuch:** `C_{i,t}` = nächste 560 Bytes aus `pad`.
- **Gültiger Versuch:** Schenker-Position `g = σ_t⁻¹(e_i)`, Zielschlüssel `pkR = GP_t[g]`.
  - `mac_key = HKDF(salt = G_r, ikm = X25519(rp_r, pkR), info = "wichtel/v1/claim-mac" ‖ u8(t), 32)`
  - `mac = HMAC(mac_key, "wichtel/v1/claim" ‖ G_r ‖ ρ ‖ u8(t) ‖ pid_i ‖ RP_r ‖ pkR)`
  - Klartext (genau 512 B):

    | Offset | Länge | Feld |
    |---|---|---|
    | 0 | 1 | Version = `0x01` |
    | 1 | 16 | `pid_i` |
    | 17 | 32 | `mac` |
    | 49 | 2 | `u16(len(note))` |
    | 51 | len | `note` (UTF-8, ≤ 461 B, darf leer sein) |
    | 51+len | Rest | Null-Bytes |

  - HPKE (RFC 9180), **Mode Auth (0x02)**, Suite `DHKEM(X25519, HKDF-SHA256)` (0x0020),
    `HKDF-SHA256` (0x0001), `ChaCha20Poly1305` (0x0003);
    `skS = idh_i`, `pkR`, `info = "wichtel/v1/reveal" ‖ G_r ‖ ρ ‖ u8(t)`, `aad = ""`,
    Single-Shot-Seal, Ephemeral aus `eph_ikm` (s. o.).
  - `C_{i,t} = enc (32) ‖ ct (528)`.
  - Ist `X25519(rp_r, pkR)` nicht beitragend oder schlägt die Kapselung fehl (z. B. `pkR` kleiner
    Ordnung), wird `C_{i,t}` wie bei einem ungültigen Versuch mit den nächsten 560 Bytes aus
    `pad` gefüllt.

Upload Schritt 2: `SD_i ‖ C_{i,1} ‖ … ‖ C_{i,16}` (256 + 16·560 = 9216 B), signiert (§12).

### 9.3 Freigabe und Auswertung

Sobald alle `n` Uploads vorliegen, berechnet der Server `SD` und `t*`, veröffentlicht `SD`, `t*`
und **nur** die `n` Enthüllungen `(pid_j, C_{j,t*})`. Alle übrigen `C_{j,t}` MUSS er löschen.

Client `i` (Schenker-Position `p = p_{i,t*}`, erwarteter Beschenkter `e = σ_{t*}(p)`):
für jede freigegebene `(pid_j, C)`: HPKE-Open (Mode Auth, `skR = gp_{r,t*}`, `pkS = IDH_j`, gleiche
`info` inkl. `ρ`). Erfolgreich ⇒ Klartext prüfen: Version = 1, `pid` = `pid_j`, `len(note) ≤ 461`, Füllbytes = 0,
`mac` gegen `X25519(gp_{r,t*}, RP[e])` mit `pkR = GP_{r,t*}` und `RP[e]` neu berechnen (Vergleich in
konstanter Zeit). **Genau eine** Enthüllung MUSS alle Prüfungen bestehen; das Ergebnis ist
`(pid_j, note)`. Sonst Zustand „Störung“ (§11).

## 10. Zustandsautomat der Gruppe

```
                 join/leave/schedule
               ┌──────────────┐
               ▼              │
           ┌────────┐─────────┘
 create ──►│  Open  │──start (Admin) oder draw_at erreicht, N_MIN ≤ n ≤ N_MAX──┐
           └────────┘                                                          │
               ▲  draw_at erreicht, n < N_MIN ⇒ bleibt Open, schedule_missed    │
               │                                                                ▼
               │ n < N_MIN nach Austritt              ┌──────────────────────────────┐
               └──────────────────────────────────────│ Drawing { r, phase: Roles }  │◄─┐
                                                      └──────────────────────────────┘  │
                                         alle n Rollen-Vektoren da                      │
                                          ├─ E ungültig ⇒ r+1 (Kollisionsrunde) ─────────┤
                                          ▼                                              │
                                      ┌──────────────────────────────┐                   │
                                      │ Drawing { r, phase: Reveal } │                   │
                                      └──────────────────────────────┘                   │
                                         alle n Uploads da                               │
                                          ├─ kein t* ⇒ r+1 (Fehlversuchsrunde) ──────────┤
                                          ▼                                              │
                                      ┌──────────────────┐                               │
                                      │ Done { r, t* }   │── Austritt / Restart (Admin) ─┘
                                      └──────────────────┘     ⇒ r+1, draw_no+1
```

- `draw_no` (Verlosung Nr.) zählt nur Starts und Neuverlosungen (Admin-Restart, Austritt nach
  Start), **nicht** Kollisions- und Fehlversuchsrunden.
- Beitreten, Wunschzettel ändern und Termin setzen sind **nur in `Open`** erlaubt.
- Austritt/Entfernen in `Drawing` oder `Done` ⇒ Roster ändert sich, sofort `Drawing{r+1, Roles}`
  mit `draw_no+1` (bzw. `Open`, falls danach `n < N_MIN`).
- `restart` (Admin) aus `Drawing` oder `Done` ⇒ `Drawing{r+1, Roles}`, `draw_no+1`.
- Ein Upload für eine andere als die aktuelle `(r, phase)` MUSS mit `409 Conflict` abgelehnt
  werden; ein zweiter Upload desselben Teilnehmers für dieselbe `(r, phase)` ebenfalls (`409`,
  erster Upload gilt).
- Verlosungstermin `draw_at`: Ein Hintergrundjob prüft minütlich; ist `draw_at ≤ jetzt` und der
  Zustand `Open`, wird gestartet bzw. `schedule_missed = true` gesetzt und `draw_at` gelöscht.
- Ablauf: `expires_at = event_date + 14 Tage` (max. 60 Tage nach Erstellung, ohne Event-Datum
  7 Tage nach letzter Aktivität), danach Löschen aller Daten der Gruppe.

## 11. Fehlerfälle (Client)

| Fall | Erkennung | Verhalten |
|---|---|---|
| Kollision in E | §7.4 | automatisch, Server wechselt zu `r+1` |
| kein gültiges `t*` | §9.1 | automatisch, Server wechselt zu `r+1` |
| eigenes RP/GP fehlt bei gültigem Bereich | §7.4 | „Störung“ anzeigen, Spielleiter kann neu starten |
| Server-`t*` ≠ eigenes `t*` | §9.1 | Abbruch, „Störung“ |
| ≠ 1 gültige Enthüllung | §9.3 | „Störung“ |
| Roster-Abweichung (Equivocation) | Masken heben sich nicht auf ⇒ E ungültig in jeder Runde | nach 3 Kollisionsrunden in Folge: Hinweis „Fingerabdruck vergleichen“ |
| nicht beitragender DH | §1 | Teilnahme verweigern, Hinweis |
| ungültiger Namens-Eintrag | §6 | Teilnahme verweigern |

Kein Fehlerfall darf zu einer Nachricht an den Server führen, die die eigene Position verrät.

## 12. Upload-Signaturen

```
upload_sig = Ed25519-Sign(isk, H("wichtel/v1/upload" ‖ u8(kind) ‖ gid ‖ u32(r) ‖ pid ‖ H(body)))
kind: 1 = Rollen-Vektor, 2 = Selbstzug + Enthüllungen
```

Der Server MUSS Signatur, Länge (`L_V(n)` bzw. 9216) und Bearer-Token prüfen.

`ρ` ist bewusst **nicht** Teil der Signatur: Die Upload-Signatur prüft nur der Server selbst, sie
schützt also nicht gegen einen equivozierenden Server. Die Bindung an `R` erfolgt dort, wo sie
wirkt: in den Selbstzug-Masken (§7.1), in HPKE-`info` und im Claim-MAC (§9.2).

## 13. Abweichungen vom Konzept v5

| Konzept | Spezifikation | Grund |
|---|---|---|
| Fingerabdruck „6 Wörter“, ≥ 64 Bit | **8 Wörter** à 8 Bit aus 256er-Liste | 6 Wörter à 8 Bit wären nur 48 Bit |
| Endpunkt `…/rounds/{r}/next` (Client meldet Kollision) | entfällt; **Server erkennt Kollision selbst** (§7.4) | Auswertung ist deterministisch und öffentlich; weniger Endpunkte, kein Missbrauch |
| HPKE-Ephemeral zufällig | **deterministisch aus `seed`, `ρ`, `pkR` und dem Klartext** (§9.2) | identische Wiederholung nach Neuladen, reproduzierbare Testvektoren; keine Nonce-Wiederverwendung bei geänderter Notiz |
| `pid` vom Server vergeben | `pid = H(… ‖ IPK)[0..16]` | Client kennt `pid` ohne Server, Server kann keine IDs vertauschen |
| Neuverlosung bei Austritt nur nach Ergebnis | auch in `Drawing` sofortige Neuverlosung | einheitliche Regel |

## 14. Persistenz (Ergebnis des Turso-Spikes)

Ergebnis des Turso-Spikes (`crates/wichtel-server/tests/turso_spike.rs`, Crate `turso` 0.8.3,
`default-features = false`):

| Merkmal | Ergebnis |
|---|---|
| WAL | ✅ Standard (`journal_mode = wal`) |
| Transaktionen (`BEGIN`/`COMMIT`/`ROLLBACK`) | ✅ |
| BLOB 2,5 MB schreiben/lesen | ✅ |
| parallele Leser (4 Verbindungen, tokio multi-thread) | ✅ |
| `PRAGMA secure_delete` | ❌ **nicht unterstützt** (wird stillschweigend ignoriert) |
| `VACUUM` | ⚠ nur mit `Builder::experimental_vacuum(true)`; dann ✅ und **keine Datenreste** mehr in Datei/WAL |
| Überschreiben mit `zeroblob` vor dem Löschen | ❌ hilft nicht (Copy-on-Write, alte Seiten bleiben als Freelist erhalten) |
| `PRAGMA wal_checkpoint(TRUNCATE)` | ✅, solange kein anderes Statement derselben Verbindung offen ist |

**Festlegung für den Server:**
- Datenbank mit `experimental_vacuum(true)` öffnen.
- Nach jedem Löschvorgang mit sensiblen Daten (verworfene Enthüllungen, Kollisions-/Fehlversuchs-
  runden, abgelaufene Gruppen) wird ein **`VACUUM` + `wal_checkpoint(TRUNCATE)`** eingeplant
  (gebündelt, höchstens alle 5 Minuten, im Hintergrund-Job). Bis dahin können gelöschte Bytes noch
  in der Datei stehen. Das ist akzeptabel, weil diese Daten ohnehin nur Chiffretexte bzw. maskierte
  Vektoren sind.
- Die Rollen-Aggregation wird **nur im RAM** (oder als ein einziger, überschriebener BLOB pro Runde)
  gehalten; einzelne `V_i` werden nie geschrieben.
- Risiko: `VACUUM` ist in Turso als experimentell markiert. Fallback ohne Codeänderung außerhalb
  von `Store`: `rusqlite` (bundled) mit `PRAGMA secure_delete = ON`. Der Spike-Test prüft die
  Eigenschaft „kein Datenrest nach VACUUM“ bei jedem Testlauf, damit ein Turso-Update sie nicht
  unbemerkt bricht.

## 15. Testvektoren-Format

Datei `crates/wichtel-core/tests/vectors/v1.json`, erzeugt von einem Test in `wichtel-core`
(deterministisch, da alle Zufallswerte aus festen Seeds stammen). Große Werte werden als SHA-256
angegeben.

```json
{
  "version": "wichtel/v1",
  "gid": "<b64url 16 B>",
  "gk": "<b64url 32 B>",
  "round": 1,
  "participants": [
    {
      "seed": "<b64url 32 B>",
      "pid": "<b64url 16 B>",
      "ipk": "<b64url 32 B>",
      "idh": "<b64url 32 B>",
      "auth_hash": "<b64url 32 B>",
      "name": "Anna",
      "enc_name_nonce": "<b64url 12 B>",
      "enc_name": "<b64url>",
      "roles_vector_sha256": "<b64url 32 B>",
      "reveal_upload_sha256": "<b64url 32 B>",
      "e": 3,
      "p": [0, 5, 1, …],
      "recipient_pid": "<b64url 16 B>"
    }
  ],
  "fingerprint": ["Tanne", "Stern", "…"],
  "g_r": "<b64url 32 B>",
  "r_sha256": "<b64url 32 B>",
  "rho": "<b64url 32 B>",
  "attempt_valid": [true, false, …],
  "sigma": [[2, 0, 3, 1], …],
  "selfdraw_aggregate": "<b64url 256 B>",
  "t_star": 2
}
```

`enc_name_nonce` ist im Testvektor fest vorgegeben (Produktivcode zieht sie aus dem CSPRNG);
dafür bietet `wichtel-core` eine Funktion mit expliziter Nonce.
