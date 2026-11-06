/** Spielleiter view: links, schedule, start, restart, delete. */
import type { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { N_MAX, N_MIN, type GroupMeta, type GroupView } from "../api/types";
import { groupLink } from "../lib/fragment";
import { forgetGroupOnDevice } from "../forget";
import { navigate } from "./app";
import { CopyField, errorText, formatDate, formatDateTime, fromLocalInput, Notice, toLocalInput } from "./common";
import type { GroupController } from "./controller";

/** Button with an inline "are you sure?" step (keyboard- and screenreader-friendly). */
export function ConfirmButton(props: {
  label: string;
  confirmLabel: string;
  danger?: boolean;
  disabled?: boolean;
  onConfirm(): Promise<void> | void;
  children?: ComponentChildren;
}) {
  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);
  if (!asking)
    return (
      <button type="button" class={`btn${props.danger ? " btn-danger" : " btn-primary"}`} disabled={props.disabled} onClick={() => setAsking(true)}>
        {props.label}
      </button>
    );
  return (
    <div class="confirm-box" role="group" aria-label={props.label}>
      {props.children}
      <div class="button-row">
        <button
          type="button"
          class={`btn${props.danger ? " btn-danger" : " btn-primary"}`}
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await props.onConfirm();
            } finally {
              setBusy(false);
              setAsking(false);
            }
          }}
        >
          {props.confirmLabel}
        </button>
        <button type="button" class="btn" onClick={() => setAsking(false)}>
          Abbrechen
        </button>
      </div>
    </div>
  );
}

export function AdminPanel({ ctrl, view, meta, adminSecret }: { ctrl: GroupController; view: GroupView; meta: GroupMeta; adminSecret: Uint8Array }) {
  const [error, setError] = useState<string | null>(null);
  const [drawAt, setDrawAt] = useState(view.draw_at ? toLocalInput(view.draw_at) : "");
  const [saved, setSaved] = useState(false);
  const n = view.participants.length;
  const invite = groupLink(location.origin, ctrl.gidB64, "invite", ctrl.currentSecrets);

  const run = async (f: () => Promise<void>) => {
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(errorText(e));
    } finally {
      await ctrl.refresh();
    }
  };

  const saveSchedule = (value: number | null) =>
    run(async () => {
      if (value !== null) {
        const now = Math.floor(Date.now() / 1000);
        if (value <= now + 60) throw new Error("Der Termin muss in der Zukunft liegen.");
        if (meta.event_date) {
          const [y, m, d] = meta.event_date.split("-").map(Number) as [number, number, number];
          if (value > new Date(y, m - 1, d, 23, 59).getTime() / 1000) throw new Error("Der Termin muss vor dem Wichteldatum liegen.");
        }
      }
      await ctrl.api.setSchedule(ctrl.gidB64, adminSecret, value);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
      if (value === null) setDrawAt("");
    });

  return (
    <section class="card admin" aria-labelledby="admin-title">
      <h2 id="admin-title">🎅 Spielleitung</h2>
      <p class="hint">
        Nur du siehst diesen Bereich (dank des Spielleiter-Links). Du siehst nicht, wer wen beschenkt.
      </p>

      <CopyField label="Einladungslink für die Gruppe" value={invite} qr share />

      {view.state === "open" && (
        <div class="admin-block">
          <h3>Verlosungstermin</h3>
          {view.schedule_missed && (
            <Notice kind="warn" title="Termin verpasst">
              Zum Termin waren weniger als {N_MIN} Personen dabei. Setz einen neuen Termin oder starte später von Hand.
            </Notice>
          )}
          <p>{view.draw_at ? <>Aktuell: <strong>{formatDateTime(view.draw_at)}</strong></> : "Kein Termin gesetzt."}</p>
          <div class="field">
            <label for="admin-drawat">{view.draw_at ? "Termin ändern" : "Termin setzen"}</label>
            <input id="admin-drawat" type="datetime-local" value={drawAt} onInput={(e) => setDrawAt(e.currentTarget.value)} />
          </div>
          <div class="button-row">
            <button
              type="button"
              class="btn btn-primary"
              disabled={!drawAt}
              onClick={() => {
                const v = fromLocalInput(drawAt);
                if (v === null) setError("Ungültiger Termin.");
                else void saveSchedule(v);
              }}
            >
              {saved ? "✓ Gespeichert" : "Termin speichern"}
            </button>
            {view.draw_at && (
              <button type="button" class="btn" onClick={() => void saveSchedule(null)}>
                Termin entfernen
              </button>
            )}
          </div>
          {meta.event_date && <p class="hint">Wichteldatum: {formatDate(meta.event_date)}</p>}
        </div>
      )}

      {view.state === "open" && (
        <div class="admin-block">
          <h3>Jetzt starten</h3>
          {n < N_MIN ? (
            <p class="hint">Zum Starten braucht es mindestens {N_MIN} Teilnehmer (aktuell {n}).</p>
          ) : n > N_MAX ? (
            <p class="hint">Zu viele Teilnehmer (höchstens {N_MAX}).</p>
          ) : (
            <ConfirmButton label="Verlosung jetzt starten" confirmLabel="Ja, jetzt starten" onConfirm={() => run(() => ctrl.api.start(ctrl.gidB64, adminSecret))}>
              <p>
                Danach kann niemand mehr beitreten. Habt ihr den <strong>Fingerabdruck</strong> im Gruppenchat
                verglichen und sind alle {n} dabei, die mitmachen wollen?
              </p>
            </ConfirmButton>
          )}
        </div>
      )}

      {view.state !== "open" && (
        <div class="admin-block">
          <h3>Neue Verlosung</h3>
          <p class="hint">
            Nur nötig, wenn die Verlosung gestört ist oder jemand ausgestiegen ist. Für ein „Nochmal würfeln“ auf Wunsch
            gibt es das bewusst nicht.
          </p>
          <ConfirmButton label="Neue Verlosung starten" confirmLabel="Ja, alle neu auslosen" danger onConfirm={() => run(() => ctrl.api.restart(ctrl.gidB64, adminSecret))}>
            <Notice kind="warn" title="Alle bekommen eine neue Person zugelost">
              {view.state === "done"
                ? "Die bisherigen Ergebnisse werden ungültig. Wer schon ein Geschenk besorgt hat, muss eventuell umplanen."
                : "Die laufende Verlosung wird abgebrochen und beginnt von vorn."}{" "}
              Alle sehen „Verlosung Nr. {view.draw_no + 1}“.
            </Notice>
          </ConfirmButton>
        </div>
      )}

      <div class="admin-block">
        <h3>Runde löschen</h3>
        <ConfirmButton
          label="Runde endgültig löschen"
          confirmLabel="Ja, alles löschen"
          danger
          onConfirm={() =>
            run(async () => {
              await ctrl.api.deleteGroup(ctrl.gidB64, adminSecret);
              // The server deleted the subscriptions with the group; clean up this device.
              void forgetGroupOnDevice(ctrl.gidB64, { kv: ctrl.kv });
              navigate("/");
            })
          }
        >
          <p>Alle Daten dieser Runde werden sofort vom Server gelöscht – auch die Ergebnisse. Das lässt sich nicht rückgängig machen.</p>
        </ConfirmButton>
      </div>

      {error && <Notice kind="error">{error}</Notice>}
    </section>
  );
}
