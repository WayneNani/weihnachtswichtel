/** Small shared UI pieces: copy field, QR code, countdown, dialog, formatting. */
import type { ComponentChildren } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { utf8 } from "../lib/bytes";
import { encodeQr, qrPath } from "../lib/qr";
import { wasmErrorText, wichtelErrorCode } from "../wasm-errors";

// ------------------------------------------------------------ formatting

const dateFmt = new Intl.DateTimeFormat("de-DE", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat("de-DE", {
  weekday: "short",
  day: "numeric",
  month: "long",
  hour: "2-digit",
  minute: "2-digit",
});

export function formatDate(isoDate: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(isoDate);
  if (!m) return isoDate;
  return dateFmt.format(new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
}

export function formatDateTime(unix: number): string {
  return `${dateTimeFmt.format(new Date(unix * 1000))} Uhr`;
}

/** `<input type="datetime-local">` value ⇄ Unix seconds (local time zone). */
export function toLocalInput(unix: number): string {
  const d = new Date(unix * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function fromLocalInput(value: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]));
  return Math.floor(d.getTime() / 1000);
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

// ------------------------------------------------------------ copy + QR

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers / non-secure contexts.
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

export function QrCode({ text, label }: { text: string; label: string }) {
  const svg = useMemo(() => {
    try {
      const qr = encodeQr(utf8(text), "M");
      return { d: qrPath(qr, 4), size: qr.size + 8 };
    } catch {
      return null;
    }
  }, [text]);
  if (!svg) return <p class="hint">QR-Code nicht möglich.</p>;
  return (
    <svg class="qr" viewBox={`0 0 ${svg.size} ${svg.size}`} role="img" aria-label={label} shape-rendering="crispEdges">
      <rect width={svg.size} height={svg.size} fill="#fff" />
      <path d={svg.d} fill="#000" />
    </svg>
  );
}

export function CopyField(props: {
  label: string;
  value: string;
  onCopied?: () => void;
  qr?: boolean;
  share?: boolean;
  secret?: boolean;
}) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");
  const [showQr, setShowQr] = useState(false);
  const id = useMemo(() => `cf-${Math.random().toString(36).slice(2)}`, []);
  const canShare = props.share && typeof navigator !== "undefined" && typeof navigator.share === "function";
  const copy = async () => {
    const ok = await copyText(props.value);
    setState(ok ? "ok" : "fail");
    if (ok) props.onCopied?.();
    setTimeout(() => setState("idle"), 2500);
  };
  return (
    <div class={`copy-field${props.secret ? " secret" : ""}`}>
      <label for={id}>{props.label}</label>
      <div class="copy-row">
        <input id={id} type="text" readOnly value={props.value} onFocus={(e) => (e.currentTarget as HTMLInputElement).select()} spellcheck={false} />
        <button type="button" class="btn" onClick={copy}>
          {state === "ok" ? "✓ Kopiert" : "Kopieren"}
        </button>
      </div>
      <div class="copy-actions">
        {props.qr && (
          <button type="button" class="btn-link" aria-expanded={showQr} onClick={() => setShowQr(!showQr)}>
            {showQr ? "QR-Code ausblenden" : "QR-Code zeigen"}
          </button>
        )}
        {canShare && (
          <button
            type="button"
            class="btn-link"
            onClick={() => {
              navigator.share({ url: props.value }).then(() => props.onCopied?.(), () => undefined);
            }}
          >
            Teilen …
          </button>
        )}
      </div>
      <span class="sr-only" aria-live="polite">
        {state === "ok" ? "In die Zwischenablage kopiert" : state === "fail" ? "Kopieren nicht möglich – bitte manuell markieren" : ""}
      </span>
      {state === "fail" && <p class="hint">Kopieren ging nicht – bitte den Link markieren und manuell kopieren.</p>}
      {showQr && props.qr && (
        <div class="qr-wrap">
          <QrCode text={props.value} label={`QR-Code: ${props.label}`} />
          {props.onCopied && (
            <button type="button" class="btn-link" onClick={() => props.onCopied?.()}>
              Ich habe den QR-Code abfotografiert
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------ countdown

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function countdownText(seconds: number): string {
  if (seconds <= 0) return "jetzt";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d >= 2) return `${d} Tage, ${h} Std.`;
  if (d === 1) return `1 Tag, ${h} Std.`;
  const p = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${p(m)}:${p(s)} Std.` : `${p(m)}:${p(s)} Min.`;
}

export function Countdown({ at }: { at: number }) {
  const now = useNow(1000);
  const left = Math.max(0, Math.round(at - now / 1000));
  return (
    <div class="countdown" role="timer" aria-live="off">
      <span class="countdown-label">Verlosung</span>
      <strong class="countdown-value">{left > 0 ? `in ${countdownText(left)}` : "startet gleich …"}</strong>
      <span class="countdown-at">{formatDateTime(at)}</span>
    </div>
  );
}

// ------------------------------------------------------------ dialog

/** Modal dialog on top of `<dialog>`; `dismissable=false` blocks Esc. */
export function Modal(props: { open: boolean; title: string; onClose?: () => void; dismissable?: boolean; children: ComponentChildren }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (props.open && !d.open) {
      try {
        d.showModal();
      } catch {
        d.setAttribute("open", "");
      }
    } else if (!props.open && d.open) d.close();
  }, [props.open]);
  return (
    <dialog
      ref={ref}
      class="modal"
      aria-labelledby="modal-title"
      onCancel={(e) => {
        if (props.dismissable === false) e.preventDefault();
        else props.onClose?.();
      }}
    >
      <h2 id="modal-title">{props.title}</h2>
      {props.children}
    </dialog>
  );
}

export function Notice(props: { kind?: "info" | "warn" | "error" | "ok"; title?: string; children: ComponentChildren }) {
  const kind = props.kind ?? "info";
  return (
    <div class={`notice notice-${kind}`} role={kind === "error" ? "alert" : undefined}>
      {props.title && <strong class="notice-title">{props.title}</strong>}
      <div>{props.children}</div>
    </div>
  );
}

export function errorText(e: unknown): string {
  const wasmCode = wichtelErrorCode(e);
  if (wasmCode) return wasmErrorText(wasmCode);
  if (e && typeof e === "object" && "code" in e) {
    const code = (e as { code: string }).code;
    switch (code) {
      case "network":
        return "Keine Verbindung zum Server. Bitte versuche es gleich noch einmal.";
      case "group_full":
        return "Die Runde ist voll (höchstens 30 Teilnehmer).";
      case "too_few_participants":
        return "Es sind noch zu wenige Teilnehmer (mindestens 4).";
      case "conflict":
        return "Das geht im aktuellen Zustand der Runde nicht (mehr). Die Seite wurde aktualisiert.";
      case "unauthorized":
        return "Keine Berechtigung – ist der Link vollständig?";
      case "not_found":
        return "Diese Runde gibt es nicht (mehr).";
      case "too_many_requests":
        return "Zu viele Anfragen. Bitte warte kurz.";
      case "payload_too_large":
        return "Der Text ist zu lang.";
    }
  }
  return e instanceof Error ? e.message : "Unbekannter Fehler";
}
