# Weihnachtswichtel – Kritisches Review des Konzepts

Stand: 2026-11-06 · Gegenstand: `01-konzept.md` (v1)

Bewertung: 🔴 kritisch · 🟠 hoch · 🟡 mittel · 🟢 niedrig. Jede Feststellung hat eine Entscheidung,
die in Spezifikation (`04-protokoll-spec.md`, Phase 0) und Plan übernommen wird.

## A. Grundsätzliche Grenzen

### A1 🔴 Der Server liefert den Code aus
Jede Browser-E2E-Anwendung vertraut dem Server, der das JavaScript/WASM ausliefert. Ein aktiv
bösartiger Betreiber (oder ein Spielleiter, der selbst hostet) kann für *eine* Runde manipulierten
Code ausliefern, der Seeds oder Ergebnisse abgreift. Das Protokoll schützt also gegen
**neugierige** Betreiber und DB-Lecks, nicht gegen **aktive** Angreifer auf dem Server.

*Entscheidung:* Ehrlich kommunizieren („Schutz gegen Mitlesen, nicht gegen einen manipulierten
Server“). Mitigationen: Open Source + reproduzierbarer Build; Hash des ausgelieferten Bundles in
der UI und im README veröffentlichen; Frontend optional separat statisch hosten (z. B. GitHub
Pages), sodass Code-Hoster und Daten-Server verschiedene Parteien sind. Für Selbsthoster: Hinweis,
dass dann der Spielleiter technisch *könnte* – Teilnehmer sollten einen neutral gehosteten Server
nutzen.

### A2 🟠 Eigenes Krypto-Protokoll
Das Protokoll ist aus Standardbausteinen (X25519, Ed25519, HPKE, ChaCha20) zusammengesetzt, aber
die Komposition ist neu und unauditiert. Fehler hier sind leise.

*Entscheidung:* Normative Spezifikation mit Byte-Layouts vor der Implementierung; Simulationstests
inkl. Angreifer-Szenarien; separater read-only Krypto-Review-Agent; Testvektoren. Vor einem
„öffentlichen“ Betrieb idealerweise ein externes Review.

## B. Protokoll

### B1 🟠 Teilnehmerliste muss von Menschen geprüft werden (Sybils)
Der Spielleiter (oder jeder mit dem Einladungslink) kann Fake-Teilnehmer anlegen. Mit n−2
Sybils ist die Anonymität weg. Kryptographie kann das nicht verhindern.

*Entscheidung:* Vor dem Start sieht jeder die Liste; beim Start zeigt die UI „Bist du sicher, dass
du alle kennst?“. Teilnehmerzahl und Fingerabdruck prominent. Optional: Einladungslink deaktivieren,
sobald alle drin sind.

### B2 🟡 Kreisstruktur und kleine Gruppen
Ein einzelner Kreis ist nur eine Teilmenge aller fixpunktfreien Permutationen. Folgen: keine
2er-Pärchen (gewollt), aber bei **n = 3 kennt jeder die komplette Zuordnung** (A→B ⇒ B→C ⇒ C→A).
Das gilt für n = 3 bei *jedem* Verfahren, da es nur zwei fixpunktfreie Permutationen gibt.

*Entscheidung:* Minimum **n = 4**, bei n = 4 Hinweis anzeigen. Kreis beibehalten.

### B3 🟡 Kollisionen und Störer im DC-Netz
~3 % Kollisionswahrscheinlichkeit pro Runde; ein böswilliger Teilnehmer kann jede Runde stören
(Jamming) und ist nicht identifizierbar. Im Asynchron-Modus kostet jeder Neustart allen einen
weiteren Besuch.

*Entscheidung:* Für Freundes-/Kollegenkreise akzeptabel. Kollisionen: `m` so wählen, dass
P(Kollision) ≤ 3 %; Neustart läuft im Live-Modus automatisch. Nach 3 gestörten Runden zeigt die UI
„Jemand stört die Verlosung“ und empfiehlt einen Live-Termin. Kein Identifizierungsmechanismus in v1.

### B4 🟡 Abbrecher blockieren alle
Ein einziger Teilnehmer, der seinen Upload nicht macht, blockiert die Runde (das DC-Netz braucht
alle Vektoren).

*Entscheidung:* Fortschrittsanzeige („wartet auf: Max, Lisa“ – das ist unkritisch, sagt nichts über
die Zuordnung). Spielleiter kann Wartende entfernen ⇒ neue Runde. Empfehlung in der UI: Verlosung
erst starten, wenn alle „bereit“ markiert haben; Live-Modus bevorzugen.

### B5 🟡 Ausschlüsse (Paare) passen nicht ins Grundprotokoll
Der beliebte Wunsch „Partner sollen sich nicht ziehen“ ist mit einem blinden Kreis nicht
direkt möglich: niemand darf prüfen, ohne etwas zu lernen.

*Entscheidung:* v2. Machbar über eine anonyme „Veto“-Runde (zweites, kleines DC-Netz: jeder Schenker
setzt bei verbotener Zuordnung ein Zufallsbit ⇒ ≠ 0 ⇒ neu losen). Leakt nur „irgendwer hatte einen
Konflikt“. Kostet einen weiteren Besuch.

## C. Produkt & UX

### C1 🟠 Schlüsselverlust = Ergebnis verloren
Wer `localStorage` löscht, im privaten Fenster war oder das Gerät wechselt, kann ohne persönlichen
Link sein Ergebnis nie wieder sehen – und niemand kann es ihm sagen (gewollt!).

*Entscheidung:* Persönlicher Link wird nach dem Beitritt **erzwungen** gesichert (Kopieren-Button,
QR-Code, „Ich habe den Link gespeichert“-Checkbox). Geht er *vor* dem Start verloren: austreten und
neu beitreten. Geht er *nach* dem Start verloren: Spielleiter kann eine Neuverlosung auslösen.

### C2 🟡 Bis zu 4 Besuche im Asynchron-Modus
Ohne E-Mail/Push muss jeder selbst wiederkommen.

*Entscheidung:* Live-Modus als Standard empfehlen. Im Asynchron-Modus: Status-Texte, die zum
Teilen in der Gruppen-Chat einladen („Bitte alle nochmal den eigenen Link öffnen“). Jeder Besuch
erledigt automatisch alles Mögliche. Web-Push bewusst nicht (Datensparsamkeit).

### C3 🟢 Datenmengen auf dem Handy
n = 50 ⇒ ~2,9 MB DC-Vektor up, ~2,9 MB Ergebnis down, ~2,7 MB Reveal down. Unkritisch im WLAN,
spürbar im Mobilfunk. Berechnung im Web Worker.

*Entscheidung:* Limit n ≤ 50; Fortschrittsbalken.

### C4 🟢 Links in Messengern
Messenger erzeugen Vorschauen über die URL **ohne** Fragment ⇒ unkritisch. Der persönliche Link
darf aber nicht in die Gruppe gepostet werden.

*Entscheidung:* Deutlicher Hinweis am persönlichen Link; persönlicher Link optisch anders
(„🔒 nur für dich“).

## D. Betrieb & Datenschutz

### D1 🟡 Metadaten
Server kennt IPs (TCP), Zeitpunkte, User-Agents. Zuordnung lässt sich daraus nicht ableiten
(alle Uploads/Downloads haben gleiche Größe und gleiches Muster), aber Teilnahme schon.

*Entscheidung:* Keine IP-Logs (App und Reverse-Proxy), keine User-Agent-Speicherung, Zugriffsmuster
positionsunabhängig halten – das wird in E2E-Tests geprüft.

### D2 🟡 Missbrauch als anonymer Speicher / DoS
Ohne Konten kann jeder Gruppen anlegen und MB-weise Daten hochladen.

*Entscheidung:* Größenlimits pro Feld, Rate-Limit pro IP **nur im RAM** (nicht persistiert),
Ablauf ungenutzter Gruppen nach 7 Tagen, globale Speicherobergrenze.

### D3 🟢 Turso
Siehe Konzept §8: Mehrwert gering, zusätzlicher Auftragsverarbeiter. Entscheidung: SQLite hinter
`Store`-Trait.

### D4 🟢 Rechtliches
Kein Cookie-Banner nötig (`localStorage` für den Schlüssel ist technisch erforderlich), aber
Datenschutzerklärung und Impressum (bei öffentlichem Betrieb) einplanen.

## E. Alternativen, die verworfen wurden

| Alternative | Warum nicht |
|---|---|
| Server lost aus und vergisst sofort | Erfüllt „Betreiber weiß es nicht“ nur per Versprechen; Spielleiter-als-Hoster könnte mitlesen. Wäre aber deutlich einfacher – als „Schnellmodus“ denkbar, bewusst **nicht** im MVP, um keine zwei Sicherheitsniveaus zu erklären. |
| Sequentieller Mixnet-Shuffle (jeder mischt nacheinander) | Gleiche Garantien, aber n Besuche *nacheinander* statt parallel – im Asynchron-Modus untauglich. |
| Volles MPC-Framework | Viel zu schwergewichtig für den Browser und das Problem. |
| Rust-Frontend-Framework (Leptos/Yew) | Möglich, aber deutlich höhere Build-Last und WASM-Größe; die UI ist schlicht genug für TS. Rust bleibt dort, wo es zählt: Krypto-Kern und Server. |
