/** Read-only views: fingerprint, participant list, draw progress, result, disturbances. */
import { useEffect, useState } from "preact/hooks";
import { N_MAX, N_MIN, type GroupMeta, type GroupView } from "../api/types";
import { loadWishSeen, markWishSeen, wishUpdated } from "../lib/wishseen";
import type { DisturbanceReason, DriverStatus } from "../protocol/driver";
import type { Member } from "../protocol/roster";
import { copyText, formatDate, Notice, plural } from "./common";
import type { LiveMode } from "./controller";

export function Fingerprint({ words, prominent }: { words: string[]; prominent: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <section class={`card fingerprint${prominent ? "" : " subtle"}`} aria-labelledby="fp-title">
      <h2 id="fp-title">Fingerabdruck der Teilnehmerliste</h2>
      <ol class="fp-words" aria-label="Fingerabdruck, 8 Wörter">
        {words.map((w, i) => (
          <li key={i}>{w}</li>
        ))}
      </ol>
      {prominent ? (
        <p>
          <strong>Vergleicht diese 8 Wörter im Gruppenchat</strong>, bevor die Verlosung startet. Sehen alle dieselben
          Wörter, sehen auch alle dieselbe Teilnehmerliste – niemandem wird eine falsche Liste untergeschoben. Kommt
          noch jemand dazu, ändern sich die Wörter.
        </p>
      ) : (
        <p class="hint">Diese Wörter müssen bei allen gleich sein.</p>
      )}
      <button
        type="button"
        class="btn"
        onClick={async () => {
          setCopied(await copyText(`Fingerabdruck: ${words.join(" ")}`));
          setTimeout(() => setCopied(false), 2500);
        }}
      >
        {copied ? "✓ Kopiert" : "Wörter kopieren"}
      </button>
    </section>
  );
}

export function RosterList(props: {
  members: Member[];
  myPid: string | null;
  view: GroupView;
  onRemove?: (m: Member) => void;
}) {
  const { members, myPid, view } = props;
  const submitted = new Set(view.state === "drawing" && view.progress ? view.progress.submitted : []);
  const n = members.length;
  return (
    <section class="card" aria-labelledby="roster-title">
      <h2 id="roster-title">
        Teilnehmer <span class="count">({n})</span>
      </h2>
      {n === 0 && <p class="hint">Noch niemand dabei.</p>}
      <ul class="roster">
        {members.map((m) => (
          <li key={m.pidB64} class={m.valid ? "" : "invalid"}>
            <div class="roster-head">
              <span class="roster-name">
                {m.valid ? m.name : "⚠ ungültiger Eintrag"}
                {m.pidB64 === myPid && <span class="tag tag-green">du</span>}
                {m.valid && m.duplicate && (
                  <span class="tag tag-red" title="Mehrere Einträge heißen gleich – fragt nach, wer wer ist.">
                    ⚠ Name doppelt
                  </span>
                )}
              </span>
              {view.state === "drawing" && (
                <span class={`roster-state ${submitted.has(m.pidB64) ? "ok" : "wait"}`}>
                  {submitted.has(m.pidB64) ? "✓ erledigt" : "⏳ offen"}
                </span>
              )}
              {props.onRemove && (
                <button type="button" class="btn-link danger" onClick={() => props.onRemove!(m)} aria-label={`${m.name ?? "Eintrag"} entfernen`}>
                  entfernen
                </button>
              )}
            </div>
            {m.valid && m.wish && (
              <details class="wish">
                <summary>Wunschzettel</summary>
                <p class="pre">{m.wish}</p>
              </details>
            )}
            {m.valid && m.wish === null && <p class="hint">Wunschzettel nicht lesbar.</p>}
          </li>
        ))}
      </ul>
      {view.state === "open" && n < N_MIN && (
        <p class="hint">
          Noch {plural(N_MIN - n, "Person", "Personen")} nötig – die Verlosung braucht mindestens {N_MIN} Teilnehmer.
        </p>
      )}
      {view.state === "open" && n >= N_MIN && n <= 5 && (
        <p class="hint">
          Kleine Runde: Bei {n} Personen lässt sich aus dem eigenen Ergebnis manchmal einiges über die anderen
          erraten. Das gilt für jedes Wichtelverfahren.
        </p>
      )}
      {n >= N_MAX && view.state === "open" && <p class="hint">Die Runde ist voll ({N_MAX} Personen).</p>}
    </section>
  );
}

function LiveBadge({ live }: { live: LiveMode }) {
  if (live === "sse") return <span class="live live-on">● Live</span>;
  if (live === "poll") return <span class="live">Aktualisiert alle paar Sekunden</span>;
  return <span class="live">Verbinde …</span>;
}

export function DrawProgress(props: {
  view: Extract<GroupView, { state: "drawing" }>;
  members: Member[];
  myPid: string | null;
  isMember: boolean;
  driver: DriverStatus | null;
  busy: string | null;
  live: LiveMode;
  manyCollisions: boolean;
  firstRound: number | null;
}) {
  const { view, members } = props;
  const submitted = new Set(view.progress?.submitted ?? []);
  const n = members.length;
  const done = members.filter((m) => submitted.has(m.pidB64)).length;
  const missing = members.filter((m) => !submitted.has(m.pidB64)).map((m) => m.name ?? "⚠ ungültiger Eintrag");
  const step = view.phase === "roles" ? 1 : 2;
  const mine = props.myPid ? submitted.has(props.myPid) : false;
  return (
    <section class="card status-card" aria-live="polite">
      <div class="status-head">
        <h2>
          Verlosung läuft{view.draw_no > 1 && <span class="tag tag-red">Verlosung Nr. {view.draw_no}</span>}
        </h2>
        <LiveBadge live={props.live} />
      </div>
      <ol class="stepper" aria-label="Fortschritt">
        <li class={step === 1 ? "current" : "done"}>Rollen</li>
        <li class={step === 2 ? "current" : ""}>Prüfen</li>
        <li>Ergebnis</li>
      </ol>
      <p>
        Schritt {step} von 2: <strong>{done} von {n}</strong> haben ihren Teil erledigt.
      </p>
      <progress max={n} value={done} aria-label={`${done} von ${n} erledigt`} />
      {missing.length > 0 && (
        <p class="missing">
          Es fehlen noch: <strong>{missing.join(", ")}</strong>
        </p>
      )}
      {props.isMember && (
        <div class="my-step">
          {props.busy ? (
            <p class="working">
              <span class="spinner" aria-hidden="true" /> {props.busy}
            </p>
          ) : mine ? (
            <p>✓ Dein Teil ist erledigt. Sobald alle so weit sind, geht es automatisch weiter.</p>
          ) : props.driver?.kind === "retry" ? (
            <p>Dein Schritt wird gleich erneut versucht …</p>
          ) : (
            <p>Dein Browser erledigt deinen Schritt automatisch.</p>
          )}
        </div>
      )}
      <p class="hint">
        Du musst nicht warten: Du kannst die Seite schließen und später deinen persönlichen Link öffnen – dein Browser
        erledigt dann automatisch den nächsten Schritt.
      </p>
      {props.firstRound !== null && view.round > props.firstRound && !props.manyCollisions && (
        <p class="hint">Automatische Wiederholung (Runde {view.round}) – das passiert gelegentlich und ist normal.</p>
      )}
      {props.manyCollisions && (
        <Notice kind="warn" title="Ungewöhnlich viele Wiederholungen">
          Bitte vergleicht noch einmal den Fingerabdruck im Gruppenchat. Weicht er bei jemandem ab, sieht nicht jede
          Person dieselbe Teilnehmerliste.
        </Notice>
      )}
    </section>
  );
}

const DISTURBANCE_TEXT: Record<DisturbanceReason, string> = {
  own_role_missing: "Deine anonyme Rolle ist im Ergebnis von Schritt 1 nicht aufgetaucht.",
  evaluation_mismatch: "Das Ergebnis von Schritt 1 ist für deinen Browser ungültig, der Server hat aber weitergemacht.",
  t_star_mismatch: "Der Server meldet einen anderen Auslosungsversuch, als dein Browser berechnet hat.",
  open_failed: "Für dich ließ sich nicht genau eine gültige Enthüllung öffnen.",
  roster_mismatch: "Die Teilnehmerliste vom Server passt nicht zu deinem Schlüssel oder ist fehlerhaft.",
};

export function DisturbanceCard({ reason, drawNo }: { reason: DisturbanceReason; drawNo: number }) {
  return (
    <section class="card">
      <Notice kind="error" title="Die Verlosung ist gestört">
        <p>{DISTURBANCE_TEXT[reason]}</p>
        <p>
          Das kann an einem technischen Fehler liegen oder daran, dass jemand die Verlosung stört. Niemand hat dabei
          etwas über die Zuordnung erfahren. Bitte gib dem Spielleiter Bescheid – er kann eine neue Verlosung starten
          (dann Verlosung Nr. {drawNo + 1}).
        </p>
      </Notice>
    </section>
  );
}

export function ResultCard(props: {
  gidB64: string;
  recipient: Member | null;
  note: string;
  meta: GroupMeta;
  drawNo: number;
}) {
  const [revealed, setRevealed] = useState(false);
  /** The wish list changed since it was last seen (shown until the card is covered again). */
  const [updated, setUpdated] = useState(false);
  const name = props.recipient?.name ?? "⚠ unbekannt";
  const wish = props.recipient?.wish ?? null;
  // Before revealing: only a hint without any name (someone might look over the shoulder).
  const pendingUpdate = !revealed && wish !== null && wishUpdated(loadWishSeen(props.gidB64), props.drawNo, wish);

  // Revealed ⇒ the current wish list counts as seen; a live change while revealed is marked too.
  useEffect(() => {
    if (!revealed || wish === null) return;
    if (wishUpdated(loadWishSeen(props.gidB64), props.drawNo, wish)) setUpdated(true);
    markWishSeen(props.gidB64, props.drawNo, wish);
  }, [revealed, wish, props.drawNo, props.gidB64]);

  const updatedTag = updated && (
    <span class="tag tag-gold" data-testid="wish-updated">
      aktualisiert
    </span>
  );
  return (
    <section class="card result-card" aria-labelledby="res-title">
      <h2 id="res-title">Dein Ergebnis</h2>
      {props.drawNo > 1 && (
        <Notice kind="warn">
          Das ist <strong>Verlosung Nr. {props.drawNo}</strong>. Ergebnisse früherer Verlosungen gelten nicht mehr.
        </Notice>
      )}
      {!revealed ? (
        <div class="reveal-gate">
          {pendingUpdate && (
            <p class="wish-update-hint" role="status">
              <span class="tag tag-gold">aktualisiert</span> Dein Wichtelkind hat seinen Wunschzettel geändert.
            </p>
          )}
          <p>Schau, dass niemand mitliest – dann:</p>
          <button type="button" class="btn btn-primary btn-big" onClick={() => setRevealed(true)}>
            Aufdecken
          </button>
        </div>
      ) : (
        <>
          <div class="gift">
            <svg class="gift-bow" width="112" height="62" viewBox="0 0 112 62" fill="none" aria-hidden="true">
                <path d="M56 34 C 40 6, 6 2, 8 22 C 10 40, 38 40, 56 34 Z" fill="#b3242e" stroke="#7e1520" stroke-width="2" />
                <path d="M56 34 C 72 6, 106 2, 104 22 C 102 40, 74 40, 56 34 Z" fill="#b3242e" stroke="#7e1520" stroke-width="2" />
                <path d="M50 36 L 40 60 L 50 54 L 56 62 L 56 36 Z" fill="#9e1b22" />
                <path d="M62 36 L 72 60 L 62 54 L 56 62 L 56 36 Z" fill="#9e1b22" />
                <circle cx="56" cy="33" r="8" fill="#d9b85c" stroke="#8c6b1e" stroke-width="2" />
              </svg>
            <div class="gift-label">
              <p class="result-line">Du beschenkst</p>
              <strong class="result-name">{name}</strong>
              {(props.meta.budget || props.meta.event_date) && (
                <span class="result-sub">
                  {[props.meta.budget && `Budget: ${props.meta.budget}`, props.meta.event_date && formatDate(props.meta.event_date)]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
              )}
            </div>
          </div>
          {wish ? (
            <div class={`result-block${updated ? " wish-updated" : ""}`}>
              <h3>
                Wunschzettel von {name}
                {updatedTag}
              </h3>
              {updated && <p class="hint">Seit du zuletzt nachgesehen hast, wurde der Wunschzettel geändert.</p>}
              <p class="pre">{wish}</p>
            </div>
          ) : (
            <p class="hint">
              {name} hat keinen Wunschzettel hinterlegt.
              {updatedTag}
            </p>
          )}
          {props.note && (
            <div class="result-block private">
              <h3>Private Nachricht von {name} an dich</h3>
              <p class="pre">{props.note}</p>
            </div>
          )}
          <p class="hint">Psst: Das Ergebnis siehst nur du. Auch der Spielleiter kennt es nicht.</p>
          <button
            type="button"
            class="btn"
            onClick={() => {
              setRevealed(false);
              setUpdated(false);
            }}
          >
            Wieder verdecken
          </button>
        </>
      )}
    </section>
  );
}
