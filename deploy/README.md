# Betrieb

Weihnachtswichtel ist **ein Binary** (`wichtel-server`, Web-UI und WASM eingebettet) plus **eine
Datenbankdatei** (Turso, lokal, SQLite-Format). Empfohlen: Container hinter Caddy (TLS).

| Datei | Inhalt |
|---|---|
| `../Dockerfile` | Multi-Stage-Build, Laufzeit-Image `debian:trixie-slim`, non-root (UID 10001), Volume `/data` |
| `Caddyfile` | Reverse Proxy mit TLS, HSTS, Kompression, **ohne Access-Logs** |

Vor dem öffentlichen Betrieb: **Impressum und Datenschutzerklärung** ausfüllen
(`web/public/impressum.html`, `web/public/datenschutz.html`, beide sind Vorlagen mit Platzhaltern
in eckigen Klammern) und danach neu bauen – die Seiten werden in das Binary eingebettet.

## Start mit Docker

```bash
docker build -t wichtel .
docker volume create wichtel-data
docker run -d --name wichtel --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v wichtel-data:/data \
  -e WICHTEL_PUBLIC_URL=https://wichteln.example.org \
  -e WICHTEL_VAPID_SUBJECT=mailto:betrieb@example.org \
  -e WICHTEL_TRUST_PROXY=1 \
  wichtel
```

Caddy läuft dann auf dem Host mit `deploy/Caddyfile` (Domain und E-Mail ersetzen) und spricht
`127.0.0.1:8080` an. Läuft Caddy selbst im Container, beide in ein gemeinsames Docker-Netz legen,
den Port **nicht** veröffentlichen und im Caddyfile `reverse_proxy wichtel:8080` eintragen.

Das Image setzt `STOPSIGNAL SIGINT` (der Server fährt auf Ctrl-C/SIGINT geordnet herunter) und hat
einen Healthcheck auf `GET /api/health` (Antwort `ok`), der ohne zusätzliche Werkzeuge auskommt.

Ohne Docker: `scripts/build-all.sh --release`, das Binary aus `$CARGO_TARGET_DIR/release/` kopieren
und z. B. als systemd-Dienst mit eigenem Benutzer und denselben Umgebungsvariablen starten
(`KillSignal=SIGINT`).

## Umgebungsvariablen

Aus `crates/wichtel-server/src/config.rs`:

| Variable | Standard (Binary) | Im Image | Bedeutung |
|---|---|---|---|
| `WICHTEL_ADDR` | `127.0.0.1:8080` | `0.0.0.0:8080` | Listen-Adresse |
| `WICHTEL_PORT` | – | – | überschreibt nur den Port von `WICHTEL_ADDR` |
| `WICHTEL_DB` | `wichtel.db` | `/data/wichtel.db` | Datenbankdatei (daneben `-wal`) |
| `WICHTEL_PUBLIC_URL` | `http://127.0.0.1:8080` | – | öffentliche Basis-URL; Fallback für den VAPID-Subject. **Setzen.** |
| `WICHTEL_VAPID_SUBJECT` | = `WICHTEL_PUBLIC_URL` | – | VAPID-`sub` (`mailto:…` oder `https://…`); Kontakt für die Push-Dienste |
| `WICHTEL_TRUST_PROXY` | `false` | – | `1`/`true`/`yes`/`on`: Client-IP für Rate-Limits aus dem **letzten** `X-Forwarded-For`-Eintrag |
| `WICHTEL_MAX_GROUPS` | `10000` | – | globale Obergrenze gespeicherter Runden |
| `WICHTEL_PUSH_HOSTS` | `fcm.googleapis.com, push.services.mozilla.com, push.apple.com, notify.windows.com` | – | erlaubte Push-Dienste (Host-Suffixe, kommagetrennt); `*` = jeder öffentliche Host |
| `RUST_LOG` | `info,turso=warn,turso_core=warn` | ebenso | Log-Level (`tracing`-Filter) |

Fest eingebaut (nicht konfigurierbar): 10 neue Runden und 120 Beitritte pro IP und Stunde
(IPv6 je /64), höchstens 100 SSE-Verbindungen je Runde, `VACUUM` nach Löschungen höchstens alle
5 Minuten.

**`WICHTEL_TRUST_PROXY`** nur setzen, wenn der Server ausschließlich über den Proxy erreichbar ist
(Bindung an `127.0.0.1` bzw. internes Netz) und der Proxy `X-Forwarded-For` selbst setzt – Caddy tut
das standardmäßig und verwirft vom Client mitgeschickte Werte. Ohne die Variable sieht der Server
nur die IP des Proxys, alle Nutzer teilen sich dann ein Rate-Limit. Mit der Variable, aber direkt
erreichbarem Server, kann jeder die Rate-Limits mit einem gefälschten Header umgehen.

## Logs

Der Server protokolliert weder IP-Adressen noch User-Agents noch Pfadparameter: nur Methode,
Routen-Muster, Status, Dauer und ein 4-Byte-Hash der Gruppen-ID (Anfragen auf `debug`, Serverfehler
auf `warn`). Rate-Limit-Zähler pro IP liegen nur im RAM und verfallen nach einer Stunde.

Der Reverse Proxy muss dazu passen: Im `Caddyfile` gibt es **keine Access-Logs**; die
Handler-Fehlerlogs von Caddy (enthalten die Client-IP) sind ausgeschlossen. Andere Proxys
(nginx: `access_log off;`) entsprechend konfigurieren. Auch Logs des Hosters/Load-Balancers prüfen.

## VAPID-Schlüssel (Web-Push)

Nichts zu tun: Der Server erzeugt beim ersten Start ein P-256-Schlüsselpaar und speichert es in
der Datenbank (Tabelle `server_keys`). Den öffentlichen Schlüssel holt sich der Browser über
`GET /api/push/vapid-key`. Pushes sind leer (ohne Inhalt) und gehen nur an Abonnenten mit Opt-in.

- Geht die Datenbank verloren, entsteht beim nächsten Start ein neuer Schlüssel. Das schadet
  nicht: Die alten Push-Abos lagen in derselben Datenbank und sind ohnehin weg.
- Schlüssel wechseln: Server stoppen, `DELETE FROM server_keys WHERE name = 'vapid_p256_v1';` und
  `DELETE FROM push_subscriptions;` (z. B. mit `sqlite3`), starten. Teilnehmer müssen
  Benachrichtigungen dann neu einschalten.
- Der Server braucht für Web-Push ausgehendes HTTPS zu den Push-Diensten (`WICHTEL_PUSH_HOSTS`).
  Fehlt das, funktioniert alles andere weiter.

## Volume und Datenbank

Im Image liegt alles Persistente unter `/data` (Verzeichnis `0700`, gehört UID 10001):
`wichtel.db`, `wichtel.db-wal` und der VAPID-Schlüssel darin. Bind-Mounts müssen für UID 10001
beschreibbar sein (`chown 10001:10001 <verzeichnis>`).

Die Datenbank enthält nur Chiffretexte, Public Keys, Hashes, Zeitstempel und den
Verlosungstermin im Klartext – trotzdem gehört sie nicht in fremde Hände (Metadaten: wann wie viele
Leute in welcher Runde waren). Speicherbedarf: pro laufender Runde höchstens etwa eine
Rollen-Vektorgröße (n = 30: ≈ 2,4 MB) zusätzlich zu den kleinen Datensätzen.

Löschung passiert automatisch (minütlicher Job): Runden zum `delete_after`-Zeitpunkt (die UI setzt
Wichteldatum + 14 Tage, der Server kappt bei Anlage + 60 Tage), ungenutzte offene Runden ohne Termin
mit weniger als 4 Teilnehmern nach 7 Tagen ohne Aktivität, und sofort, wenn der Spielleiter löscht.
Danach `VACUUM` + WAL-Checkpoint, damit Gelöschtes nicht in freien Seiten weiterlebt.

## Backups

**Am besten keine.** Die Daten sind kurzlebig (höchstens 60 Tage) und ohne die Schlüssel aus den
Links der Teilnehmer wertlos; ein Verlust kostet schlimmstenfalls eine neue Verlosung. Jedes Backup
hebelt dagegen die Löschung aus: **Eine gelöschte Runde lebt in jedem Backup weiter**, das vor der
Löschung entstanden ist.

Wenn doch (z. B. weil der Host Volumes automatisch sichert):

- Aufbewahrung kurz halten (wenige Tage) und in der Datenschutzerklärung nennen.
- Konsistent sichern: Container stoppen, `wichtel.db` und `wichtel.db-wal` gemeinsam kopieren,
  starten. Eine Kopie der laufenden Datei kann inkonsistent sein.
- Snapshot-Backups des Hosters/der VM erfassen das Volume ebenfalls – dort die Aufbewahrung prüfen.

## Updates

```bash
git pull
docker build -t wichtel .
docker stop wichtel && docker rm wichtel
docker run -d --name wichtel … wichtel      # gleiche Optionen wie oben
```

Datenbankmigrationen laufen beim Start automatisch (`schema_migrations`). Laufende Verlosungen
überstehen einen Neustart: Der Zustand liegt in der Datenbank, Clients verbinden sich neu (SSE) und
setzen fort. Ein Update während einer laufenden Verlosung ist trotzdem unnötig riskant, wenn sich
das Protokoll geändert hat – Release-Hinweise lesen, im Zweifel nach den Feiertagen aktualisieren.

Basis-Images (`rust`, `node`, `debian`) regelmäßig neu ziehen (`docker build --pull`), damit
Sicherheitsupdates von Debian (`ca-certificates`, glibc) ankommen.

## Checkliste vor dem Start

- [ ] Domain zeigt auf den Host, Ports 80/443 offen, `deploy/Caddyfile` angepasst.
- [ ] `WICHTEL_PUBLIC_URL` und `WICHTEL_VAPID_SUBJECT` gesetzt, `WICHTEL_TRUST_PROXY=1` nur hinter dem Proxy.
- [ ] Port 8080 nicht öffentlich erreichbar.
- [ ] Keine Access-Logs mit IP (Proxy, Load-Balancer, Hoster).
- [ ] Impressum und Datenschutzerklärung ausgefüllt, Image neu gebaut.
- [ ] Backup-Strategie entschieden (siehe oben) und in der Datenschutzerklärung beschrieben.
- [ ] **Betreiber ist nicht Spielleiter** einer Runde auf diesem Server (siehe README,
  Sicherheitsmodell).
