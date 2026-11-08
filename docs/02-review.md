# Weihnachtswichtel – Kritisches Review des Konzepts

Stand: 2026-11-06 · Gegenstand: `01-konzept.md` (v1; Ergebnis eingearbeitet in v2)

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

### B2 🟡 Kreisstruktur und kleine Gruppen *(überholt: kein Kreis mehr, siehe G3)*
Ein einzelner Kreis ist nur eine Teilmenge aller fixpunktfreien Permutationen. Folgen: keine
2er-Pärchen (gewollt), aber bei **n = 3 kennt jeder die komplette Zuordnung** (A→B ⇒ B→C ⇒ C→A).
Das gilt für n = 3 bei *jedem* Verfahren, da es nur zwei fixpunktfreie Permutationen gibt.

*Entscheidung:* Minimum **n = 4**, bei n ≤ 5 Hinweis anzeigen. Kreis beibehalten. Zur
Koalitions-Problematik der öffentlichen Reihenfolge siehe F4.

### B3 🟡 Kollisionen und Störer im DC-Netz *(Störerschutz entfällt, siehe G2)*
~3 % Kollisionswahrscheinlichkeit pro Runde; in v1 konnte ein böswilliger Teilnehmer jede Runde
unerkannt stören (Jamming). Im Asynchron-Modus kostet jeder Neustart allen einen weiteren Besuch.

*Entscheidung (v2):* Blame-Verfahren mit rundenspezifischen, vorab committeten Schlüsseln (siehe
F2) – Störer werden namentlich überführt. Ehrliche Kollisionen bleiben bei ~3 % und kosten einen
zusätzlichen Besuch; im Live-Modus merkt man davon nichts.

### B4 🟡 Abbrecher blockieren alle
Ein einziger Teilnehmer, der seinen Upload nicht macht, blockiert die Runde (das DC-Netz braucht
alle Vektoren).

*Entscheidung:* Fortschrittsanzeige („wartet auf: Max, Lisa“ – das ist unkritisch, sagt nichts über
die Zuordnung). Spielleiter kann Wartende entfernen ⇒ in v2 werden sie herausgerechnet statt neu zu starten (F8). Empfehlung in der UI: Verlosung
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
Link sein Ergebnis nie wieder sehen – und niemand kann es ihm sagen (gewollt!). Mit dem Link geht
es dagegen auf jedem Gerät, weil in v2 alle Rundenschlüssel aus dem `seed` abgeleitet werden (F7).

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

### D3 🟢 Turso *(überholt, siehe G1)*
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

## F. Unabhängiges Zweit-Review (Protokoll)

Ein zweiter Reviewer hat das Konzept v1 ohne Kenntnis dieses Reviews geprüft. Seine Funde und die
Entscheidungen dazu (alle in Konzept v2 umgesetzt, sofern nicht anders vermerkt):

| # | Fund | Schwere | Entscheidung |
|---|---|---|---|
| F1 | **Neu würfeln nach Sicht aufs Ergebnis**: Der ungeprüfte `abort` erlaubte jedem, der seinen Beschenkten kennt, so lange neu losen zu lassen, bis es passt. | 🔴 | Kein automatischer Neustart nach der Enthüllung. Beschwerden nur **mit Beweis** (Offenlegung des Rundenpseudonyms ⇒ Störer oder falscher Beschwerdeführer wird sichtbar). Neustart nur durch Spielleiter, sichtbar und gezählt. |
| F2 | **Störungen im DC-Netz nicht zuordenbar** ⇒ risikoloses Stören, gezieltes Neuwürfeln mit Komplizen. | 🟠 | Paarschlüssel aus rundenspezifischen Ephemeral-Keys, beim Beitritt hinterlegt. Im Störfall legen alle offen ⇒ jeder Vektor ist nachprüfbar. |
| F3 | **Rushing**: Wer DB-Zugriff hat, sieht die Vektoren der anderen vor dem eigenen Upload und kann seinen Slot passend wählen. | 🟠 | Slot-Wahl aus beim Beitritt committetem `x_r` ⇒ keine freie Wahl mehr. Kostet keinen zusätzlichen Besuch (statt Commit-then-Reveal pro Runde). |
| F4 | **Koalitionsaussage falsch**: Die Pseudonym-Reihenfolge ist öffentlich; zwei Verbündete im Abstand 2 erfahren, wer den zweiten beschenkt (≈ 2/(n−1), bei n = 10 ≈ 22 %). | 🟠 | Aussage in §6.5 korrigiert. Akzeptiertes Restrisiko: es braucht eine Absprache und betrifft nur Nachbarn der Verbündeten. Vollständig verbergen ginge nur mit einem sequentiellen Shuffle (n Besuche nacheinander) – nicht praktikabel. |
| F5 | **Selbst hostender Spielleiter** widerspricht dem Bedrohungsmodell; außerdem Partitionsangriff (jeder sieht eigene Fake-Welt), im Asynchron-Modus unbemerkt. | 🔴 | Bedrohungsmodell präzisiert (Spielleiter ≠ Betreiber). Fingerabdruck ≥ 64 Bit, **Vergleich im Gruppenchat vor dem Start Pflicht** (UI-Schritt). Reproduzierbare Builds, Bundle-Hash veröffentlichen (vgl. A1). |
| F6 | **Namen nicht an Schlüssel gebunden** ⇒ wer in die DB schreibt, kann Namen vertauschen. | 🟠 | AEAD mit AAD `gid‖pid‖IPK‖IDH`, `H(enc_name)` fließt in `G_r` ein. |
| F7 | **Pseudonyme zufällig statt abgeleitet** ⇒ persönlicher Link reicht nicht, Gerätewechsel zwischen Phasen bricht alles. | 🟠 | Alle Rundenschlüssel per HKDF aus `seed`. |
| F8 | **Asynchron-Modus**: ein Abwesender blockiert alle; jeder Neustart kostet Besuche. | 🟡 | Abbrecher werden herausgerechnet (übrige legen nur ihre Masken mit dem Abbrecher offen) statt Neustart. Live-Modus als Standard. Vorab-Upload für mehrere Runden **nicht** übernommen (3× Datenmenge für ~3 % Fälle). |
| F9 | **Größen** bei n = 50 grenzwertig für Mobilgeräte. | 🟡 | Slot von 72 B auf 40 B (nur `PDH` + Prüfsumme), Empfehlung n ≤ 30, Hartgrenze 50. Bit-Reservierungsrunde nicht übernommen (zusätzlicher Besuch). |
| F10 | **Enthüllung zu kompliziert**: n² Attrappen unnötig, da HPKE/DHKEM key-private ist; Ed25519-Signaturen machen das Ergebnis übertragbar beweisbar. | 🟡 | Übernommen: **ein** Chiffretext pro Teilnehmer, HPKE-Auth mit `idh` + DH-MAC für das Pseudonym ⇒ einfacher, kleiner, abstreitbar. |
| F11 | **Abbruchnachrichten** dürfen keinen Grund/keine Position enthalten. | 🟡 | Beschwerden haben ein festes Format ohne Freitext; Offenlegung nur über das Beweisverfahren. |
| F12 | **Schlüsselvalidierung**: Low-Order-Punkte, Modulo-Bias bei Slot-Wahl. | 🟢 | Prüfung auf beitragende DH-Ergebnisse, beide Public Keys in HKDF-Info, Rejection-Sampling. |
| F13 | **Datenreste**: gelöschte Vektoren in WAL/Freelist/Backups; `seed` im Browserverlauf/Lesezeichen-Sync. | 🟢 | `PRAGMA secure_delete`, WAL-Checkpoint, keine Backups der Live-DB; Hinweis in der UI. |

**Fazit beider Reviews:** Der Ansatz (DC-Netz ⇒ anonymer Kreis ⇒ Enthüllung an den Schenker) trägt.
Die kritischen Punkte lagen im Fehlerfall-Handling (F1–F3) und in der Ehrlichkeit des
Bedrohungsmodells (A1/F5). Beides ist in v2 adressiert. Restrisiken, die bewusst akzeptiert werden:
aktiv bösartiger Server (A1), Sybils ohne menschliche Prüfung (B1), Nachbarschafts-Wissen von
Koalitionen (F4), ~3 % Kollisionsrunden.

## G. Entscheidungen nach Rückmeldung (Konzept v3)

### G1 Datenbank: Turso lokal
Turso wird als **eingebettete lokale Datenbank** (Crate `turso`, reines Rust) genutzt, nicht als
Cloud-Dienst. Damit entfällt das Datenschutz-Argument aus D3. Neues Restrisiko: Der Crate ist noch
**vor 1.0**. Gegenmaßnahmen: `Store`-Trait, exakt gepinnte Version, Feature-Check in Phase 0
(insbesondere `secure_delete`/`VACUUM`, vgl. F13), Integrationstests gegen echte Datei.

### G2 Kein Schutz gegen Störer
Ein Teilnehmer, der absichtlich kaputte Daten schickt, wird **nicht** abgewehrt oder überführt.
Begründung: In Wichtelrunden unter Bekannten unwahrscheinlich, und der Schutz kostet viel
Komplexität. Störer können die Verlosung **blockieren**, aber **nichts herausfinden**.

Damit entfallen aus Abschnitt F: Blame-Verfahren (F2), Slot-Commitments gegen Rushing (F3),
Beschwerden mit Beweis (F1-Teil, F11), Masken-Korrektur für Abbrecher (F8-Teil).

**F1 bleibt trotzdem gelöst**, und zwar einfacher: Teilnehmer können überhaupt keinen Neustart
auslösen, sobald Ergebnisse freigegeben sind. Automatische Folgerunden gibt es nur bei Kollisionen
*vor* jeder Freigabe. Eine neue Verlosung startet nur der Spielleiter, und zwar wenn jemand austritt
oder ein technischer Fehler auftritt. Das ist für alle sichtbar und wird mitgezählt.

Restrisiko: siehe G3 (Beeinflussung von `ρ` durch den letzten Uploader).

### G3 Freie Auslosung, gegenseitige Paare unsichtbar
Gewünscht ist jede fixpunktfreie Zuordnung, also auch gegenseitiges Beschenken. **Niemand soll
erkennen können, dass er in einem gegenseitigen Paar ist.**

**Verworfener Zwischenstand (v3):** eine anonyme Position pro Person, dazu eine öffentliche
fixpunktfreie Permutation σ. Problem: Wer A beschenkt und von A beschenkt wird, sieht das direkt an
σ. Das trifft pro Verlosung in ≈ 33–45 % der Fälle mindestens ein Paar.

**Lösung (v4):** Jeder hat **zwei unverknüpfbare anonyme Rollen**, eine als Beschenkter und eine als
Schenker. Zwischen den Rollen wird offen mit einer gleichverteilten Permutation gelost. Selbstzüge
erkennt nur der Betroffene; sie werden über ein kleines zweites DC-Netz **anonym** gemeldet, und
der erste Versuch ohne Selbstzug gilt. Damit ist das Ergebnis eine gleichverteilte fixpunktfreie
Zuordnung.

**Gefundene und behobene Falle:** Verwendet man in allen Versuchen dieselben Schenker-Rollen,
verraten die gescheiterten Versuche etwas über die Verknüpfung der Rollen. Eine Simulation zeigte:
Bei n = 4 kann ein Teilnehmer in ~8 % der Verlosungen **sicher** auf ein gegenseitiges Paar
schließen, bei n = 5 in ~2 %. Deshalb bekommt jeder Versuch **frische Schenker-Rollen**. Eine
exakte Auszählung (n = 4, 5) bestätigt dann: Das Wissen eines Teilnehmers über „gegenseitig?“
entspricht immer genau der Grundwahrscheinlichkeit (n = 4: 33 %, n = 5: 18 %, n = 10: 10 %).

**Preis:** größere Uploads (T = 16 Versuche ⇒ n = 20: ≈ 1,1 MB statt 256 KB; n = 30: ≈ 2,4 MB).
Deshalb Obergrenze **n ≤ 30**. Die Zahl der Besuche bleibt gleich, weil Selbstzug-Meldung und
Enthüllung in einem Upload zusammengefasst sind.

**Nebeneffekt:** Das Koalitionsproblem aus F4 (Verbündete kennen ihren Abstand im Kreis) entfällt.
Weil die Rollen anderer nicht mit Personen verknüpfbar sind, lernen Verbündete nur ihre eigenen
Kanten.

Restrisiko: Ein Spielleiter mit DB-Lesezugriff, der mit einem Teilnehmer zusammenarbeitet, kann als
Letzter hochladen und `ρ` durch Ausprobieren beeinflussen. Er kann damit aber keine bestimmte Person
ansteuern, weil die Rollen anonym sind. Akzeptiert.

Unverändert: **n ≥ 4**, Hinweis bei n ≤ 5 (kleine Gruppen verraten durch reines Abzählen viel – bei
jedem Verfahren).

### G4 Neu auslosen nur bei Austritt
Austritt nach der Verlosung ⇒ **komplette Neuverlosung** für alle, mit Warnung vorab. Eine
„Reparatur“ (nur der Schenker des Ausgetretenen bekommt einen neuen Beschenkten) ist mit
gegenseitigem Beschenken nicht immer möglich: Waren X und Y ein Paar, würde Y sich selbst ziehen.
Deshalb ist die Neuverlosung die einfache und immer korrekte Lösung.

### G5 Verlosungstermin und Web-Push (aus C2)
Der **Verlosungstermin** (Konzept 6.6) entschärft das größte UX-Problem, das Warten auf den
Langsamsten (B4, C2), ohne zusätzliche Daten: Der Termin selbst ist unkritisch und liegt im
Klartext auf dem Server.

**Web-Push** (Konzept 7.4) wird entgegen der ursprünglichen Entscheidung in C2 aufgenommen, aber
nur abgesichert:
- nur nach Opt-in,
- Push **ohne Inhalt**, damit der Push-Dienst keinen Text sieht,
- Pushes immer an alle Abonnenten einer Gruppe gleichzeitig, damit das Muster nichts verrät,
- Abos werden mit der Gruppe gelöscht, ungültige sofort.

Restrisiken:
- Der Push-Dienst des Browserherstellers ist ein **Dritter**: Er sieht Server-IP, Zeitpunkt und
  den pseudonymen Endpoint. Das muss in der Datenschutzerklärung stehen.
- Auf **iOS** funktioniert Push nur, wenn die Seite zum Home-Bildschirm hinzugefügt wurde. Die UI
  erklärt das, die App funktioniert auch ohne.
- Der Server braucht ausgehende HTTPS-Verbindungen. In Tests wird der Push-Dienst durch einen
  lokalen Mock ersetzt.

### G6 Wunschzettel nach der Verlosung, Hinweis nur an den Schenker
Gewünscht: Wunschzettel jederzeit änderbar, und **nur** der Schenker wird benachrichtigt. Der Server
kennt die Zuordnung nicht und kann deshalb nicht gezielt pushen.

**Lösung (Spec §16):** Nach dem Ergebnis lädt **jeder** einen versiegelten „Kontakt“ für sein
Wichtelkind hoch: HPKE von der eigenen Schenker-Rolle an den Identitätsschlüssel des Wichtelkinds,
Inhalt = Endpoint eines **eigenen, anonymen** Push-Abos (oder leer). Der Server liefert alle
Kontakte ohne Zuordnung aus; nur das Wichtelkind kann seinen öffnen und prüft dabei, dass er von
seinem Schenker stammt. Beim Ändern des Wunschzettels gibt der Client diesen Endpoint mit, der
Server pusht inhaltslos dorthin und speichert ihn nicht.

Verworfen:
- **Push an alle**, Service Worker zeigt nur beim Schenker etwas an: Browser verlangen bei jedem
  Push eine sichtbare Benachrichtigung (Safari kündigt sonst das Abo), also bekämen alle eine.
- **Schenker meldet ein Abo unter seiner Rolle direkt beim Server an:** Der Server könnte das über
  Endpoint, IP und Zeitpunkt mit der Identität verknüpfen.

Restrisiken:
- **Timing:** Öffnet der Schenker sofort nach dem Hinweis die App, könnte ein neugieriger Betreiber
  den Abruf zeitlich mit dem Push verbinden. Der Service Worker lädt beim Empfang bewusst nichts.
- **Wichtelkind kennt die anonyme Push-Adresse des Schenkers.** Daraus allein ist er nicht
  identifizierbar; ein Wichtelkind kann seinem Schenker höchstens Hinweise schicken, begrenzt auf
  einen pro 10 Minuten.

