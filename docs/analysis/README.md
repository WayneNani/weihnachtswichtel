# Leck-Analysen zur Auslosung

Kleine Python-Skripte (nur Standardbibliothek), mit denen die Designentscheidung in
`../02-review.md` §G3 überprüft wurde. Gefragt wird jeweils: Wie sicher kann ein Teilnehmer A aus
allen öffentlichen Daten und seinem eigenen Ergebnis schließen, dass sein Beschenkter auch sein
Schenker ist (gegenseitiges Paar)? Ausgegeben wird die Verteilung von As Einschätzung.

| Skript | Variante | Ergebnis |
|---|---|---|
| `leak_shared_giver_roles.py` | dieselben Schenker-Rollen in allen Versuchen | **Leck**: bei n = 4 in ~8 % der Läufe Gewissheit (P ≈ 1,0) |
| `leak_check.py` | frische Schenker-Rollen pro Versuch (Konzept v4) | **kein Leck**: As Einschätzung ist immer genau die Grundwahrscheinlichkeit (n = 4: 0,33; n = 5: 0,18) |

Aufruf: `python3 leak_check.py` (n = 4 und 5, einige Minuten Laufzeit).
