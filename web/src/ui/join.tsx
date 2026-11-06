/** Joining, editing one's entry, private note, leaving – and the forced "save your link" dialog. */
import { useState } from "preact/hooks";
import { ApiError } from "../api/client";
import { NAME_MAX, NOTE_MAX, WISH_MAX, type JoinRequest } from "../api/types";
import { b64uEncode, utf8, utf8Len } from "../lib/bytes";
import { authHash } from "../lib/hashes";
import { loadGroup, saveGroup } from "../lib/storage";
import { cleanName } from "../protocol/roster";
import type { ParticipantKeysHandle, WichtelWasm } from "../wasm-api";
import { CopyField, errorText, Modal, Notice } from "./common";
import type { GroupController } from "./controller";

export function buildJoinRequest(wasm: WichtelWasm, gk: Uint8Array, gid: Uint8Array, keys: ParticipantKeysHandle, name: string, wish: string): JoinRequest {
  const encName = wasm.gkSeal(gk, "name", gid, utf8(name), keys.pid, keys.ipk, keys.idh);
  const encWish = wasm.gkSeal(gk, "wish", gid, utf8(wish), keys.pid, keys.ipk, keys.idh);
  return {
    ipk: b64uEncode(keys.ipk),
    idh: b64uEncode(keys.idh),
    auth_hash: b64uEncode(authHash(keys.authToken)),
    enc_name: b64uEncode(encName),
    enc_wish: b64uEncode(encWish),
    join_sig: b64uEncode(keys.signJoin(encName, encWish)),
  };
}

function validate(name: string, wish: string): string | null {
  if (!cleanName(name)) return "Bitte gib deinen Namen ein.";
  if (utf8Len(cleanName(name)) > NAME_MAX) return "Der Name ist zu lang.";
  if (utf8Len(wish) > WISH_MAX) return `Der Wunschzettel ist zu lang (höchstens ${WISH_MAX} Bytes).`;
  return null;
}

function NameWishFields(props: { name: string; wish: string; setName(v: string): void; setWish(v: string): void }) {
  const wishBytes = utf8Len(props.wish);
  return (
    <>
      <div class="field">
        <label for="jname">Dein Name *</label>
        <input id="jname" required autoComplete="given-name" value={props.name} onInput={(e) => props.setName(e.currentTarget.value)} placeholder="So kennt dich die Gruppe" />
      </div>
      <div class="field">
        <label for="jwish">Wunschzettel (optional, für alle sichtbar)</label>
        <textarea id="jwish" rows={4} value={props.wish} onInput={(e) => props.setWish(e.currentTarget.value)} placeholder="z. B. Bücher, Tee, bitte keine Süßigkeiten" aria-describedby="jwish-count" />
        <p id="jwish-count" class={`hint counter${wishBytes > WISH_MAX ? " over" : ""}`}>
          {wishBytes} / {WISH_MAX}
        </p>
      </div>
    </>
  );
}

/** Join form. `existingSeed` re-joins with a known seed (e.g. after being removed while open). */
export function JoinForm({ ctrl, onJoined, existingSeed }: { ctrl: GroupController; onJoined(seed: Uint8Array): void; existingSeed?: Uint8Array }) {
  const [name, setName] = useState("");
  const [wish, setWish] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const full = (ctrl.snapshot.view?.participants.length ?? 0) >= 30;

  const submit = async (e: Event) => {
    e.preventDefault();
    const v = validate(name, wish);
    if (v) return setError(v);
    setError(null);
    setBusy(true);
    const { wasm, api } = ctrl;
    const seed = existingSeed ?? wasm.generateSecret();
    // Remember the seed *before* the request: a retry then yields the same pid.
    saveGroup(ctrl.gidB64, { k: b64uEncode(ctrl.currentSecrets.k), s: b64uEncode(seed), linkSaved: false });
    const keys = wasm.deriveKeys(seed, ctrl.gid);
    try {
      const req = buildJoinRequest(wasm, ctrl.currentSecrets.k, ctrl.gid, keys, cleanName(name), wish);
      try {
        const res = await api.join(ctrl.gidB64, req);
        if (res.pid !== b64uEncode(keys.pid)) throw new Error("Der Server hat eine unerwartete Teilnehmer-ID gemeldet.");
      } catch (err) {
        // Already joined with this seed (e.g. lost response) ⇒ fine.
        if (!(err instanceof ApiError && err.code === "conflict")) throw err;
        const view = await api.getGroup(ctrl.gidB64);
        if (!view.participants.some((p) => p.pid === b64uEncode(keys.pid))) throw err;
      }
      saveGroup(ctrl.gidB64, { pid: b64uEncode(keys.pid) });
      onJoined(seed);
    } catch (err) {
      setError(errorText(err));
    } finally {
      keys.free();
      setBusy(false);
    }
  };

  if (full) return <Notice kind="warn" title="Die Runde ist voll">Es können höchstens 30 Personen mitmachen.</Notice>;

  return (
    <form class="form" onSubmit={submit} noValidate>
      <NameWishFields name={name} wish={wish} setName={setName} setWish={setWish} />
      {error && <Notice kind="error">{error}</Notice>}
      <button type="submit" class="btn btn-primary btn-big" disabled={busy}>
        {busy ? "Wird eingetragen …" : "Mitmachen"}
      </button>
    </form>
  );
}

export function EditEntry({ ctrl, name: initialName, wish: initialWish, onDone }: { ctrl: GroupController; name: string; wish: string; onDone(): void }) {
  const [name, setName] = useState(initialName);
  const [wish, setWish] = useState(initialWish);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const keys = ctrl.keysHandle;
  if (!keys) return null;
  const submit = async (e: Event) => {
    e.preventDefault();
    const v = validate(name, wish);
    if (v) return setError(v);
    setBusy(true);
    try {
      const req = buildJoinRequest(ctrl.wasm, ctrl.currentSecrets.k, ctrl.gid, keys, cleanName(name), wish);
      await ctrl.api.updateParticipant(ctrl.gidB64, b64uEncode(keys.pid), keys.authToken, req);
      await ctrl.refresh();
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form class="form" onSubmit={submit} noValidate>
      <NameWishFields name={name} wish={wish} setName={setName} setWish={setWish} />
      {error && <Notice kind="error">{error}</Notice>}
      <div class="button-row">
        <button type="submit" class="btn btn-primary" disabled={busy}>
          Speichern
        </button>
        <button type="button" class="btn" onClick={onDone}>
          Abbrechen
        </button>
      </div>
    </form>
  );
}

/** Private note for the Schenker – kept on this device, sent encrypted in step 2 only. */
export function NoteField({ gidB64, locked }: { gidB64: string; locked: boolean }) {
  const [note, setNote] = useState(() => loadGroup(gidB64)?.note ?? "");
  const [saved, setSaved] = useState(false);
  const bytes = utf8Len(note);
  return (
    <details class="note-box">
      <summary>Private Nachricht an deinen Schenker {note ? "✓" : "(optional)"}</summary>
      <p class="hint">
        Nur die Person, die dich beschenkt, sieht diese Nachricht nach der Verlosung – z. B. eine Lieferadresse oder
        deine Kleidergröße. Sie bleibt bis dahin nur auf diesem Gerät.
      </p>
      <label for="note" class="sr-only">
        Private Nachricht
      </label>
      <textarea
        id="note"
        rows={3}
        value={note}
        disabled={locked}
        onInput={(e) => {
          setNote(e.currentTarget.value);
          setSaved(false);
        }}
        aria-describedby="note-count"
      />
      <p id="note-count" class={`hint counter${bytes > NOTE_MAX ? " over" : ""}`}>
        {bytes} / {NOTE_MAX}
      </p>
      {locked ? (
        <p class="hint">Die Nachricht ist bereits verschickt und kann nicht mehr geändert werden.</p>
      ) : (
        <button
          type="button"
          class="btn"
          disabled={bytes > NOTE_MAX}
          onClick={() => {
            saveGroup(gidB64, { note });
            setSaved(true);
          }}
        >
          {saved ? "✓ Gespeichert" : "Nachricht speichern"}
        </button>
      )}
    </details>
  );
}

/** Forced dialog after joining: the personal link must be saved (copy/QR + checkbox). */
export function SaveLinkDialog({ open, link, forced, onClose }: { open: boolean; link: string; forced: boolean; onClose(): void }) {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Modal open={open} title="Speichere deinen persönlichen Link" dismissable={!forced} onClose={onClose}>
      <p>
        Mit diesem Link siehst du später, <strong>wen du beschenkst</strong> – auch auf einem anderen Gerät. Ohne ihn
        geht das nur auf diesem Gerät in diesem Browser.
      </p>
      <Notice kind="warn" title="Nicht in die Gruppe posten!">
        Dieser Link gehört nur dir. Wer ihn hat, kann dein Ergebnis sehen. Kopiere ihn von hier in eine private Notiz,
        als Lesezeichen oder schick ihn dir selbst.
      </Notice>
      <CopyField label="Dein persönlicher Link" value={link} qr share secret onCopied={() => setCopied(true)} />
      <label class="check">
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.currentTarget.checked)} />
        Ich habe meinen persönlichen Link gespeichert.
      </label>
      {forced && !copied && <p class="hint">Bitte zuerst „Kopieren“, „Teilen“ oder den QR-Code nutzen, dann bestätigen.</p>}
      <div class="button-row">
        <button type="button" class="btn btn-primary" disabled={!confirmed || (forced && !copied)} onClick={onClose}>
          Weiter
        </button>
      </div>
    </Modal>
  );
}
