import { useState } from "preact/hooks";
import { META_MAX, type GroupMeta } from "../api/types";
import { b64uEncode, utf8Len } from "../lib/bytes";
import { groupLink, type Secrets } from "../lib/fragment";
import { saveGroup } from "../lib/storage";
import { sealMeta } from "../protocol/roster";
import { navigate, useServices } from "./app";
import { CopyField, errorText, formatDate, formatDateTime, fromLocalInput, Notice } from "./common";

const DAY = 86400;

function todayIso(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** End of the event day (local) as Unix seconds. */
function endOfDay(iso: string): number {
  const [y, m, d] = iso.split("-").map(Number) as [number, number, number];
  return Math.floor(new Date(y, m - 1, d, 23, 59, 59).getTime() / 1000);
}

interface Created {
  gid: string;
  secrets: Secrets;
  meta: GroupMeta;
  drawAt: number | null;
}

export function CreatePage() {
  const { api, wasm } = useServices();
  const [title, setTitle] = useState("");
  const [budget, setBudget] = useState("");
  const [eventDate, setEventDate] = useState("");
  const [drawAt, setDrawAt] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<Created | null>(null);

  if (created) return <CreatedView created={created} />;

  const submit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    const now = Math.floor(Date.now() / 1000);
    if (!title.trim()) return setError("Bitte gib einen Titel ein.");
    if (!eventDate) return setError("Bitte wähle das Wichteldatum.");
    const eventEnd = endOfDay(eventDate);
    if (eventEnd < now) return setError("Das Wichteldatum liegt in der Vergangenheit.");
    let drawAtUnix: number | null = null;
    if (drawAt) {
      drawAtUnix = fromLocalInput(drawAt);
      if (drawAtUnix === null) return setError("Der Verlosungstermin ist ungültig.");
      if (drawAtUnix <= now + 60) return setError("Der Verlosungstermin muss in der Zukunft liegen.");
      if (drawAtUnix > eventEnd) return setError("Der Verlosungstermin muss vor dem Wichteldatum liegen.");
    }
    const meta: GroupMeta = {
      title: title.trim(),
      budget: budget.trim(),
      event_date: eventDate,
      description: description.trim(),
    };
    if (utf8Len(JSON.stringify(meta)) > META_MAX) return setError("Titel und Hinweis sind zusammen zu lang.");
    setBusy(true);
    try {
      const k = wasm.generateSecret();
      const a = wasm.generateSecret();
      const res = await api.createGroup({
        admin_hash: b64uEncode(wasm.adminHash(a)),
        enc_meta: b64uEncode(sealMeta(wasm, k, meta)),
        delete_after: eventEnd + 14 * DAY,
        draw_at: drawAtUnix,
      });
      saveGroup(res.gid, { k: b64uEncode(k), a: b64uEncode(a), title: meta.title });
      setCreated({ gid: res.gid, secrets: { k, a }, meta, drawAt: drawAtUnix });
      window.scrollTo(0, 0);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="card">
      <h1>Neue Wichtelrunde</h1>
      <p class="hint">
        Alles außer dem Verlosungstermin wird in deinem Browser verschlüsselt. Der Server sieht weder Titel noch Namen.
      </p>
      <form onSubmit={submit} class="form" noValidate>
        <div class="field">
          <label for="title">Titel *</label>
          <input id="title" required maxLength={80} value={title} onInput={(e) => setTitle(e.currentTarget.value)} placeholder="z. B. Wichteln Familie Berger" />
        </div>
        <div class="field-row">
          <div class="field">
            <label for="budget">Budget</label>
            <input id="budget" maxLength={40} value={budget} onInput={(e) => setBudget(e.currentTarget.value)} placeholder="z. B. 20 €" />
          </div>
          <div class="field">
            <label for="event">Wichteldatum *</label>
            <input id="event" type="date" required min={todayIso()} value={eventDate} onInput={(e) => setEventDate(e.currentTarget.value)} />
          </div>
        </div>
        <div class="field">
          <label for="drawat">Verlosungstermin (optional)</label>
          <input id="drawat" type="datetime-local" value={drawAt} onInput={(e) => setDrawAt(e.currentTarget.value)} aria-describedby="drawat-hint" />
          <p id="drawat-hint" class="hint">
            Zum Termin startet die Verlosung automatisch – am besten, wenn viele online sind (z. B. beim Familienessen).
            Du kannst auch später starten oder den Termin ändern.
          </p>
        </div>
        <div class="field">
          <label for="desc">Hinweis für alle (optional)</label>
          <textarea id="desc" rows={3} maxLength={1200} value={description} onInput={(e) => setDescription(e.currentTarget.value)} placeholder="z. B. Bescherung am 24. nach dem Essen" />
        </div>
        {error && <Notice kind="error">{error}</Notice>}
        <button type="submit" class="btn btn-primary btn-big" disabled={busy}>
          {busy ? "Wird angelegt …" : "Runde anlegen"}
        </button>
      </form>
      <p class="hint">
        Alle Daten werden 14 Tage nach dem Wichteldatum automatisch gelöscht (spätestens 60 Tage nach dem Anlegen).
      </p>
    </section>
  );
}

function CreatedView({ created }: { created: Created }) {
  const origin = location.origin;
  const invite = groupLink(origin, created.gid, "invite", created.secrets);
  const admin = groupLink(origin, created.gid, "admin", created.secrets);
  const [adminSaved, setAdminSaved] = useState(false);
  return (
    <section class="card">
      <h1>🎄 Deine Runde ist angelegt</h1>
      <p>
        <strong>{created.meta.title}</strong>
        {created.meta.event_date && <> · {formatDate(created.meta.event_date)}</>}
        {created.drawAt && <> · Verlosung {formatDateTime(created.drawAt)}</>}
      </p>

      <h2>1. Einladungslink für die Gruppe</h2>
      <p>Diesen Link postest du in den Gruppenchat. Damit kann jede und jeder mitmachen.</p>
      <CopyField label="Einladungslink" value={invite} qr share />

      <h2>2. Dein Spielleiter-Link (privat!)</h2>
      <Notice kind="warn" title="Nur für dich">
        Mit diesem Link kannst du Teilnehmer entfernen, den Termin ändern, die Verlosung starten und die Runde löschen.
        Teile ihn mit niemandem. Er verrät dir nicht, wer wen beschenkt.
      </Notice>
      <CopyField label="Spielleiter-Link" value={admin} qr secret onCopied={() => setAdminSaved(true)} />
      <label class="check">
        <input type="checkbox" checked={adminSaved} onChange={(e) => setAdminSaved(e.currentTarget.checked)} />
        Ich habe den Spielleiter-Link gespeichert (z. B. als Lesezeichen oder in einer Notiz).
      </label>

      <h2>3. Selbst mitmachen</h2>
      <p>Als Spielleiter machst du ganz normal mit: Auf der nächsten Seite trägst du dich wie alle anderen ein.</p>
      <button type="button" class="btn btn-primary btn-big" disabled={!adminSaved} onClick={() => navigate(admin.slice(origin.length))}>
        Weiter zur Runde
      </button>
      {!adminSaved && <p class="hint">Bitte bestätige zuerst, dass du den Spielleiter-Link gespeichert hast.</p>}
    </section>
  );
}
