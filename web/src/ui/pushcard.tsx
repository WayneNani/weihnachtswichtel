/** Opt-in for Web-Push (default off), incl. iOS "Zum Home-Bildschirm" hint. */
import { useState } from "preact/hooks";
import { loadGroup } from "../lib/storage";
import { disablePush, enablePush, isIos, pushSupport } from "../push";
import { Notice } from "./common";
import type { GroupController } from "./controller";

export function PushCard({ ctrl, personalLink, title }: { ctrl: GroupController; personalLink: string; title: string }) {
  const [enabled, setEnabled] = useState(() => loadGroup(ctrl.gidB64)?.push === true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);
  const support = pushSupport();
  const keys = ctrl.keysHandle;
  const pid = ctrl.snapshot.myPid;
  if (!keys || !pid) return null;

  const turnOn = async () => {
    setBusy(true);
    setError(null);
    try {
      await enablePush({ api: ctrl.api, gidB64: ctrl.gidB64, pidB64: pid, token: keys.authToken, personalLink, title });
      setEnabled(true);
      setAsking(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Einschalten hat nicht geklappt.");
    } finally {
      setBusy(false);
    }
  };

  const turnOff = async () => {
    setBusy(true);
    setError(null);
    try {
      await disablePush({ api: ctrl.api, gidB64: ctrl.gidB64, pidB64: pid, token: keys.authToken });
      setEnabled(false);
    } catch {
      setError("Abmelden beim Server hat nicht geklappt – lokal ist es ausgeschaltet.");
      setEnabled(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="card subtle" aria-labelledby="push-title">
      <h2 id="push-title">🔔 Benachrichtigungen</h2>
      {enabled ? (
        <>
          <p>Eingeschaltet: Du bekommst einen Hinweis, wenn es in dieser Runde etwas Neues gibt.</p>
          <button type="button" class="btn" disabled={busy} onClick={turnOff}>
            Ausschalten
          </button>
        </>
      ) : support === "ios_homescreen" ? (
        <p>
          Auf iPhone und iPad gibt es Benachrichtigungen nur, wenn du diese Seite zum Home-Bildschirm hinzufügst:
          Tippe auf <strong>Teilen</strong> <span aria-hidden="true">⎋</span> und dann auf{" "}
          <strong>„Zum Home-Bildschirm“</strong>. Öffne die Runde danach über das neue Symbol. Ohne diesen Schritt
          funktioniert alles genauso – nur ohne Benachrichtigung.
        </p>
      ) : support === "unsupported" || support === "insecure" ? (
        <p class="hint">Dein Browser unterstützt keine Benachrichtigungen. Alles andere funktioniert trotzdem.</p>
      ) : support === "denied" ? (
        <p class="hint">Benachrichtigungen sind für diese Seite im Browser blockiert. Du kannst das in den Website-Einstellungen ändern.</p>
      ) : !asking ? (
        <>
          <p>Möchtest du Bescheid bekommen, wenn du wieder dran bist oder dein Ergebnis da ist? Standardmäßig ist das aus.</p>
          <button type="button" class="btn" onClick={() => setAsking(true)}>
            Benachrichtigen, wenn ich dran bin …
          </button>
        </>
      ) : (
        <div class="confirm-box">
          <p>So funktioniert es:</p>
          <ul>
            <li>
              Dein Browser meldet sich beim Push-Dienst seines Herstellers an (z. B. Google, Mozilla oder Apple). Der
              sieht nur, dass unser Server deinen Browser weckt – keinen Namen, keinen Text.
            </li>
            <li>Die Nachricht lautet immer gleich: „🎁 Wichteln: Es gibt Neuigkeiten in deiner Runde“.</li>
            <li>Du kannst es jederzeit wieder ausschalten. Mit der Runde wird auch das Abo gelöscht.</li>
          </ul>
          <div class="button-row">
            <button type="button" class="btn btn-primary" disabled={busy} onClick={turnOn}>
              {busy ? "Wird eingeschaltet …" : "Einschalten"}
            </button>
            <button type="button" class="btn" onClick={() => setAsking(false)}>
              Lieber nicht
            </button>
          </div>
        </div>
      )}
      {error && <Notice kind="error">{error}</Notice>}
      {isIos() && enabled && <p class="hint">Tipp: Lass die Web-App auf dem Home-Bildschirm, sonst kommen keine Hinweise an.</p>}
    </section>
  );
}
