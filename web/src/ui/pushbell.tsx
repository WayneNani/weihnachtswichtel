/**
 * Web-Push opt-in as a bell in the top bar (default off), incl. iOS "Zum Home-Bildschirm" hint.
 *
 * The bell is rendered by the group page but lives in the top bar slot `#topbar-actions`
 * (own render root, see `TopbarSlot`). Until the participant has opened it once, it shows a
 * label and a dot so that nobody has to scroll down to find the setting.
 */
import { render, type ComponentChildren } from "preact";
import { useLayoutEffect, useRef, useState } from "preact/hooks";
import { loadGroup, saveGroup } from "../lib/storage";
import { disablePush, enablePush, isIos, pushSupport, type PushSupport } from "../push";
import { Notice } from "./common";
import type { GroupController } from "./controller";

export const TOPBAR_SLOT_ID = "topbar-actions";

/** Renders `children` into the top bar slot (a separate Preact root) while mounted. */
export function TopbarSlot({ children }: { children: ComponentChildren }) {
  useLayoutEffect(() => {
    const slot = document.getElementById(TOPBAR_SLOT_ID);
    if (slot) render(<>{children}</>, slot);
  });
  useLayoutEffect(
    () => () => {
      const slot = document.getElementById(TOPBAR_SLOT_ID);
      if (slot) render(null, slot);
    },
    [],
  );
  return null;
}

export type BellLook = {
  /** Bell visible at all (hidden where push cannot work anyway). */
  visible: boolean;
  variant: "on" | "off" | "blocked";
  /** Short text next to the icon (only while it still needs attention). */
  label: string | null;
  /** Attention dot. */
  dot: boolean;
  /** Accessible name of the button. */
  ariaLabel: string;
};

/** Pure presentation logic of the bell (unit-tested). */
export function bellLook(input: { support: PushSupport; enabled: boolean; prompted: boolean }): BellLook {
  const { support, enabled, prompted } = input;
  if (enabled) return { visible: true, variant: "on", label: null, dot: false, ariaLabel: "Benachrichtigungen: eingeschaltet" };
  if (support === "unsupported" || support === "insecure") {
    return { visible: false, variant: "blocked", label: null, dot: false, ariaLabel: "Benachrichtigungen nicht verfügbar" };
  }
  if (support === "denied") {
    return { visible: true, variant: "blocked", label: null, dot: false, ariaLabel: "Benachrichtigungen: im Browser blockiert" };
  }
  const attention = !prompted;
  return {
    visible: true,
    variant: "off",
    label: attention ? "Benachrichtigen?" : null,
    dot: attention,
    ariaLabel: attention ? "Benachrichtigungen einschalten?" : "Benachrichtigungen: ausgeschaltet",
  };
}

function BellIcon({ off }: { off: boolean }) {
  return (
    <svg class="bell-icon" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <path
        d="M12 3a6 6 0 0 0-6 6v3.6l-1.7 2.9A1 1 0 0 0 5.2 17h13.6a1 1 0 0 0 .9-1.5L18 12.6V9a6 6 0 0 0-6-6Z"
        fill="none"
        stroke="currentColor"
        stroke-width="1.8"
        stroke-linejoin="round"
      />
      <path d="M9.5 19.5a2.5 2.5 0 0 0 5 0" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
      {off && <path d="M4 4l16 16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />}
    </svg>
  );
}

export function PushBell({ ctrl, personalLink, title }: { ctrl: GroupController; personalLink: string; title: string }) {
  const gid = ctrl.gidB64;
  const [enabled, setEnabled] = useState(() => loadGroup(gid)?.push === true);
  const [prompted, setPrompted] = useState(() => loadGroup(gid)?.pushPrompted === true);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const support = pushSupport();
  const keys = ctrl.keysHandle;
  const pid = ctrl.snapshot.myPid;
  const look = bellLook({ support, enabled, prompted });

  const close = (refocus: boolean) => {
    setOpen(false);
    setAsking(false);
    if (refocus) buttonRef.current?.focus();
  };

  // Layout effect: the listeners must exist as soon as the panel is visible (a quick Escape
  // right after opening would otherwise get lost).
  useLayoutEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close(true);
    };
    const onPointer = (e: PointerEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) close(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    panelRef.current?.querySelector<HTMLElement>("button")?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
    };
  }, [open]);

  if (!keys || !pid || !look.visible) return null;

  const toggle = () => {
    if (open) return close(true);
    setOpen(true);
    setError(null);
    if (!prompted) {
      setPrompted(true);
      saveGroup(gid, { pushPrompted: true });
    }
  };

  const turnOn = async () => {
    setBusy(true);
    setError(null);
    try {
      await enablePush({ api: ctrl.api, gidB64: gid, pidB64: pid, token: keys.authToken, personalLink, title });
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
      await disablePush({ api: ctrl.api, gidB64: gid, pidB64: pid, token: keys.authToken });
      setEnabled(false);
    } catch {
      setError("Abmelden beim Server hat nicht geklappt – lokal ist es ausgeschaltet.");
      setEnabled(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="bell-wrap" ref={wrapRef}>
      <button
        ref={buttonRef}
        type="button"
        class={`bell-button bell-${look.variant}${look.label ? " bell-attention" : ""}`}
        aria-label={look.ariaLabel}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls="bell-panel"
        data-testid="push-bell"
        onClick={toggle}
      >
        {/* Struck through only when declined or blocked – the invitation shows a plain bell. */}
        <BellIcon off={look.variant === "blocked" || (look.variant === "off" && !look.label)} />
        {look.label && <span class="bell-label">{look.label}</span>}
        {look.dot && <span class="bell-dot" aria-hidden="true" />}
      </button>
      {open && (
        <div id="bell-panel" class="bell-panel" role="dialog" aria-labelledby="bell-title" ref={panelRef}>
          <div class="bell-panel-head">
            <h2 id="bell-title">Benachrichtigungen</h2>
            <button type="button" class="btn-link bell-close" aria-label="Schließen" onClick={() => close(true)}>
              ✕
            </button>
          </div>
          {enabled ? (
            <>
              <p>Eingeschaltet: Du bekommst einen Hinweis, wenn es in dieser Runde etwas Neues gibt.</p>
              {isIos() && <p class="hint">Tipp: Lass die Web-App auf dem Home-Bildschirm, sonst kommen keine Hinweise an.</p>}
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
          ) : support === "denied" ? (
            <p class="hint">
              Benachrichtigungen sind für diese Seite im Browser blockiert. Du kannst das in den Website-Einstellungen
              ändern.
            </p>
          ) : !asking ? (
            <>
              <p>
                Bekomm Bescheid, wenn du wieder dran bist oder dein Ergebnis da ist – dann musst du nicht ständig
                nachschauen. Standardmäßig ist das aus.
              </p>
              <div class="button-row">
                <button type="button" class="btn btn-primary" onClick={() => setAsking(true)}>
                  Ja, benachrichtigen …
                </button>
                <button type="button" class="btn" onClick={() => close(true)}>
                  Nein danke
                </button>
              </div>
            </>
          ) : (
            <div class="confirm-box">
              <p>So funktioniert es:</p>
              <ul>
                <li>
                  Dein Browser meldet sich beim Push-Dienst seines Herstellers an (z. B. Google, Mozilla oder Apple).
                  Der sieht nur, dass unser Server deinen Browser weckt – keinen Namen, keinen Text.
                </li>
                <li>Die Nachricht lautet immer gleich: „🎁 Wichteln: Es gibt Neuigkeiten in deiner Runde“.</li>
                <li>Du kannst es jederzeit hier oben wieder ausschalten. Mit der Runde wird auch das Abo gelöscht.</li>
              </ul>
              <div class="button-row">
                <button type="button" class="btn btn-primary" disabled={busy} onClick={turnOn}>
                  {busy ? "Wird eingeschaltet …" : "Einschalten"}
                </button>
                <button type="button" class="btn" onClick={() => close(true)}>
                  Lieber nicht
                </button>
              </div>
            </div>
          )}
          {error && <Notice kind="error">{error}</Notice>}
        </div>
      )}
    </div>
  );
}
