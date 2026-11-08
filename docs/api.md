# Weihnachtswichtel – HTTP-API

Vertrag zwischen Server (`wichtel-server`), Browser-Client (`web/`) und Tests. Die Rust-Typen
stehen in `crates/wichtel-api/src/lib.rs`; Protokollinhalte in `docs/04-protokoll-spec.md`.

## Konventionen

- Basis-Pfad `/api`. JSON in UTF-8. Binärfelder in JSON: **Base64url ohne Padding**.
- `gid`, `pid` in Pfaden: Base64url ohne Padding (22 Zeichen).
- Große Protokolldaten (Rollen-Vektor, `R`, Schritt-2-Upload) als **rohe Bytes**
  (`Content-Type: application/octet-stream`). Die Upload-Signatur steht dann im Header
  `X-Wichtel-Signature` (Base64url, 64 B, Spec §12).
- Zeitpunkte: Unix-Sekunden (UTC).
- Authentifizierung: `Authorization: Bearer <base64url>`
  - **Admin**: `AS` (Server vergleicht `H("wichtel/v1/admin-hash" ‖ AS)` mit `admin_hash`)
  - **Teilnehmer**: `tok` (Server vergleicht `H("wichtel/v1/auth-hash" ‖ tok)` mit `auth_hash`
    des Teilnehmers `pid` aus dem Pfad bzw. – bei Uploads – aus dem Token ermittelt)
- Fehler: HTTP-Status + `{"error": "<code>", "message": "…"}`; Codes: `bad_request`,
  `unauthorized`, `not_found`, `conflict`, `payload_too_large`, `too_many_requests`,
  `group_full`, `too_few_participants`, `internal`.
- Keine Cookies. Antworten mit `Cache-Control: no-store`.

## Endpunkte

| Methode & Pfad | Auth | Body → Antwort |
|---|---|---|
| `POST /api/groups` | – | `CreateGroupRequest` → `201 CreateGroupResponse` |
| `GET /api/groups/{gid}` | – | → `GroupView` |
| `DELETE /api/groups/{gid}` | Admin | → `204` (sofort alle Daten löschen) |
| `PUT /api/groups/{gid}/schedule` | Admin | `ScheduleRequest` → `204` (nur `open`) |
| `POST /api/groups/{gid}/start` | Admin | – → `204` (nur `open`, 4 ≤ n ≤ 30) |
| `POST /api/groups/{gid}/restart` | Admin | – → `204` (nur `drawing`/`done`; neue Verlosung) |
| `POST /api/groups/{gid}/participants` | – | `JoinRequest` → `201 JoinResponse` (nur `open`, n < 30) |
| `PUT /api/groups/{gid}/participants/{pid}` | Teilnehmer | `UpdateParticipantRequest` (gleiche Schlüssel, neue `enc_wish`/`join_sig`; `enc_name` nur in `open` änderbar; optional `notify_endpoint`, nur in `done`) → `204` (Spec §16) |
| `PUT /api/groups/{gid}/draws/{d}/contact` | Teilnehmer | Bytes `K_i` (816 B) + Signatur-Header (kind 3) → `204` (nur `done`, aktuelles `draw_no`; ersetzt) |
| `GET /api/groups/{gid}/draws/{d}/contacts` | – | → Bytes `K_a ‖ K_b ‖ …` (sortiert nach Hash, ohne pids) |
| `DELETE /api/groups/{gid}/participants/{pid}` | Admin oder Teilnehmer selbst | → `204`; in `drawing`/`done` ⇒ Neuverlosung (Spec §10) |
| `PUT /api/groups/{gid}/rounds/{r}/roles` | Teilnehmer | Bytes `V_i` (`2688·n²` B) + Signatur-Header → `204` |
| `GET /api/groups/{gid}/rounds/{r}/roles` | – | → Bytes `R`; `409`, solange unvollständig |
| `PUT /api/groups/{gid}/rounds/{r}/reveal` | Teilnehmer | Bytes `SD_i ‖ C_{i,1..16}` (9216 B) + Signatur-Header → `204` |
| `GET /api/groups/{gid}/rounds/{r}/reveal` | – | → `RevealRelease`; `409`, solange unvollständig |
| `GET /api/groups/{gid}/events` | – | SSE, Ereignis `update` mit `UpdateEvent` |
| `GET /api/push/vapid-key` | – | → `VapidKeyResponse` |
| `PUT /api/groups/{gid}/participants/{pid}/push` | Teilnehmer | `PushSubscriptionRequest` → `204` |
| `DELETE /api/groups/{gid}/participants/{pid}/push` | Teilnehmer | → `204` |
| `GET /api/health` | – | → `ok` |

Uploads für eine andere `(r, phase)` als die aktuelle sowie doppelte Uploads ⇒ `409 conflict`.

## Beispiele

### Gruppe anlegen

```http
POST /api/groups
Content-Type: application/json

{
  "admin_hash": "q2Jv3l0b0hP8m0bqk1y3iY9o7dN0eZ3nXb2kQe7aG1U",
  "enc_meta": "AAECAwQFBgcICQoLzS0Wf…",
  "delete_after": 1767225600,
  "draw_at": 1764619200
}
```

```json
{ "gid": "3q2-7wAAAAAAAAAAAAAAAA" }
```

### Gruppe abrufen

```json
{
  "gid": "3q2-7wAAAAAAAAAAAAAAAA",
  "state": "drawing",
  "round": 2,
  "phase": "reveal",
  "draw_no": 1,
  "enc_meta": "AAECAwQFBgcICQoLzS0Wf…",
  "draw_at": null,
  "schedule_missed": false,
  "delete_after": 1767225600,
  "created_at": 1762459200,
  "participants": [
    {
      "pid": "AQEBAQEBAQEBAQEBAQEBAQ",
      "ipk": "…32 B…",
      "idh": "…32 B…",
      "enc_name": "…",
      "enc_wish": "…"
    }
  ],
  "progress": {
    "round": 2,
    "phase": "reveal",
    "submitted": ["AQEBAQEBAQEBAQEBAQEBAQ"]
  }
}
```

Weitere Zustände: `{"state": "open", …}`, `{"state": "done", "round": 2, "t_star": 3, …}`.

Teilnehmer tragen bewusst keinen Beitrittszeitpunkt: Er würde die Beitrittsreihenfolge hinter
der nach `pid` sortierten Liste verraten.

### Beitreten

```http
POST /api/groups/3q2-7wAAAAAAAAAAAAAAAA/participants
Content-Type: application/json

{
  "ipk": "…", "idh": "…", "auth_hash": "…",
  "enc_name": "…", "enc_wish": "…",
  "join_sig": "…64 B…"
}
```

```json
{ "pid": "AQEBAQEBAQEBAQEBAQEBAQ" }
```

### Wunschzettel ändern (Spec §16.1, §16.3)

```http
PUT /api/groups/3q2-7wAAAAAAAAAAAAAAAA/participants/AQEBAQEBAQEBAQEBAQEBAQ
Authorization: Bearer <base64url(tok)>
Content-Type: application/json

{
  "ipk": "…", "idh": "…", "auth_hash": "…",
  "enc_name": "…unverändert…", "enc_wish": "…neu…",
  "join_sig": "…64 B…",
  "notify_endpoint": "https://fcm.googleapis.com/fcm/send/def…"
}
```

→ `204`. In `drawing`/`done` muss `enc_name` byte-identisch zum gespeicherten sein, sonst `409`.
Die Änderung erzeugt nur ein SSE-Ereignis (offene Seiten laden neu), **keinen** Gruppen-Push.
`notify_endpoint` (optional) ist der Push-Endpoint des eigenen Schenkers aus dessen Kontakt: Nur in
`done` sendet der Server **einen** leeren VAPID-Push dorthin, höchstens einmal pro Teilnehmer in
10 Minuten, und speichert/loggt den Endpoint nicht. Ist er ungültig (kein HTTPS, Host nicht in
`WICHTEL_PUSH_HOSTS`, > 700 B), außerhalb von `done` oder über dem Limit, entfällt der Hinweis
**still**; der Wunschzettel wird trotzdem gespeichert (`204`).

### Kontakt hochladen und abrufen (Spec §16.2)

```http
PUT /api/groups/3q2-7wAAAAAAAAAAAAAAAA/draws/1/contact
Authorization: Bearer <base64url(tok)>
X-Wichtel-Signature: <base64url(upload_sig, kind 3, r = Runde von done)>
Content-Type: application/octet-stream

<816 Bytes K_i>
```

→ `204`; ersetzt einen früheren Kontakt desselben Teilnehmers. Nur in `done` mit aktuellem
`draw_no` (sonst `409`).

```http
GET /api/groups/3q2-7wAAAAAAAAAAAAAAAA/draws/1/contacts
```

→ `200`, `application/octet-stream`: `K_a ‖ K_b ‖ …` (je 816 B), sortiert nach `SHA-256(K)`,
ohne `pid`s. Bei einer Neuverlosung, beim Austritt nach dem Start und beim Löschen der Gruppe
werden alle Kontakte gelöscht.

### Termin setzen

```http
PUT /api/groups/3q2-7wAAAAAAAAAAAAAAAA/schedule
Authorization: Bearer <base64url(AS)>
Content-Type: application/json

{ "draw_at": 1764619200 }
```

### Rollen-Vektor hochladen

```http
PUT /api/groups/3q2-7wAAAAAAAAAAAAAAAA/rounds/2/roles
Authorization: Bearer <base64url(tok)>
X-Wichtel-Signature: <base64url(upload_sig)>
Content-Type: application/octet-stream

<2688·n² Bytes>
```

### Enthüllungen abrufen

```json
{
  "round": 2,
  "selfdraw_aggregate": "…256 B…",
  "t_star": 3,
  "reveals": [
    { "pid": "AQEBAQEBAQEBAQEBAQEBAQ", "ciphertext": "…560 B…" }
  ]
}
```

### Server-Sent Events

```
event: update
data: {"state":"drawing","round":2,"phase":"roles","draw_no":1,"submitted_count":7,"participant_count":12}
```

### Push-Abo

```http
PUT /api/groups/3q2-7wAAAAAAAAAAAAAAAA/participants/AQEBAQEBAQEBAQEBAQEBAQ/push
Authorization: Bearer <base64url(tok)>
Content-Type: application/json

{
  "endpoint": "https://fcm.googleapis.com/fcm/send/abc…",
  "p256dh": "…65 B…",
  "auth": "…16 B…"
}
```

Der Server sendet Pushes **ohne Inhalt** (leerer Body, `TTL: 3600`, VAPID-JWT ES256 im
`Authorization: vapid t=…, k=…`-Header) an alle Abonnenten einer Gruppe, wenn sich der Zustand
ändert, 10 Minuten vor `draw_at` und zu `draw_at`. Antwort 404/410 ⇒ Abo löschen.

## Limits

| Was | Grenze |
|---|---|
| JSON-Body | 16 KB |
| `enc_meta` | ≤ 2048 B |
| `enc_name` | ≤ 128 B |
| `enc_wish` | ≤ 1100 B |
| Rollen-Vektor | genau `2688·n²` B (≤ 2,42 MB) |
| Schritt-2-Upload | genau 9216 B |
| Kontakt | genau 816 B |
| Uploads (Rollen, Schritt 2, Kontakt) | Token, Zustand, Runde und `Content-Length` werden **vor** dem Lesen des Bodys geprüft (`401`/`409`/`413`/`400`); höchstens die erwartete Länge wird gelesen |
| Gruppen-Erstellung | Rate-Limit pro IPv4-Adresse bzw. IPv6-/48 (nur im RAM), 10/h; zusätzlich global 500/h |
| Beitritte | 120/h pro IP (IPv6: /64) |
| `GET …/roles`, `GET …/reveal`, `GET …/contacts` | 300/h pro IP (IPv6: /64), gemeinsam |
| SSE-Verbindungen | 100 pro Gruppe, 40 pro IP (IPv6: /64), 2000 insgesamt (`429`) |
| Gleichzeitige Anfragen | 256; darüber `503` mit `Retry-After: 5` |
| Zeitlimits | 120 s pro Anfrage (`408`), 30 s Pause im Request-Body (`400`) |
| Leere Gruppen | ohne Teilnehmer nach 24 h ohne Aktivität gelöscht; mit < 4 Teilnehmern und ohne Termin nach 7 Tagen |
| Push | höchstens ein Push pro Gruppe und Minute; Änderungen dazwischen werden zu einem Push zusammengefasst |
| Push-Endpoint | HTTPS-URL, ≤ 1024 Zeichen, Host aus `WICHTEL_PUSH_HOSTS` (keine Platzhalter) |
| `notify_endpoint` | wie Push-Endpoint, aber ≤ 700 B; höchstens 1 Hinweis pro Teilnehmer und 10 min (nur im RAM) |

## Abweichung vom Konzept §7.2

Pfad `…/rounds/{r}/dcnet` heißt hier `…/rounds/{r}/roles`. `…/rounds/{r}/next` entfällt (Server
erkennt Kollisionen selbst, Spec §13). Neu: `PUT …/participants/{pid}` (Name vor dem Start,
Wunschzettel jederzeit ändern) sowie `…/draws/{d}/contact(s)` (Spec §16).
