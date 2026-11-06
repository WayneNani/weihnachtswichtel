/**
 * Developer tools, only rendered in the mock build (`npm run dev:mock`): add test participants
 * ("Bots") that run the real protocol driver against the mock server, simulate a disturbance.
 */
import { useEffect, useRef, useState } from "preact/hooks";
import { b64uDecodeLen, b64uEncode } from "../lib/bytes";
import { loadExtra, saveExtra } from "../lib/storage";
import { computeRolesInline, ProtocolDriver } from "../protocol/driver";
import { useServices } from "./app";
import { errorText } from "./common";
import type { GroupController, Snapshot } from "./controller";
import { buildJoinRequest } from "./join";

interface Bot {
  seed: string;
  name: string;
}

const NAMES = ["Anna", "Ben", "Clara", "Deniz", "Emil", "Frieda", "Gül", "Hannes", "Ida", "Jonas", "Kim", "Lea", "Mats", "Nora", "Ole", "Pia"];
const WISHES = ["Bücher und Tee", "Wollsocken 🧦", "", "Etwas Selbstgemachtes", "Schokolade, gern dunkel", "Ein gutes Rätsel"];

function readFlag(name: string): boolean {
  try {
    return localStorage.getItem(name) === "1";
  } catch {
    return false;
  }
}
function writeFlag(name: string, v: boolean): void {
  try {
    if (v) localStorage.setItem(name, "1");
    else localStorage.removeItem(name);
  } catch {
    /* ignore */
  }
}

export function MockTools({ ctrl, snap }: { ctrl: GroupController; snap: Snapshot }) {
  const services = useServices();
  const [bots, setBots] = useState<Bot[]>(() => loadExtra<Bot[]>(ctrl.gidB64, "bots") ?? []);
  const [auto, setAuto] = useState(() => !readFlag("wichtel:mock:manual"));
  const [disturb, setDisturb] = useState(() => readFlag("wichtel:mock:disturb"));
  const [msg, setMsg] = useState<string | null>(null);
  const drivers = useRef(new Map<string, ProtocolDriver>());

  const addBots = async (count: number) => {
    setMsg(null);
    const next = [...bots];
    try {
      for (let i = 0; i < count; i++) {
        const name = NAMES[(next.length + (snap.view?.participants.length ?? 0)) % NAMES.length]!;
        const seed = services.wasm.generateSecret();
        const keys = services.wasm.deriveKeys(seed, ctrl.gid);
        try {
          const req = buildJoinRequest(services.wasm, ctrl.currentSecrets.k, ctrl.gid, keys, name, WISHES[next.length % WISHES.length]!);
          await services.api.join(ctrl.gidB64, req);
        } finally {
          keys.free();
        }
        next.push({ seed: b64uEncode(seed), name });
      }
    } catch (e) {
      setMsg(errorText(e));
    }
    setBots(next);
    saveExtra(ctrl.gidB64, "bots", next);
    await ctrl.refresh();
  };

  // Bots run their protocol steps whenever the view changes.
  useEffect(() => {
    const view = snap.view;
    const roster = snap.roster;
    if (!auto || !view || !roster || view.state === "open") return;
    let cancelled = false;
    const timers: ReturnType<typeof setTimeout>[] = [];
    bots.forEach((bot, i) => {
      const seed = b64uDecodeLen(bot.seed, 32);
      if (!seed) return;
      let d = drivers.current.get(bot.seed);
      if (!d) {
        const keys = services.wasm.deriveKeys(seed, ctrl.gid);
        d = new ProtocolDriver(
          { wasm: services.wasm, api: services.api, kv: services.kv, computeRoles: computeRolesInline(services.wasm) },
          { gidB64: ctrl.gidB64, gid: ctrl.gid, seed, keys, note: () => `Lieferadresse: Tannenweg ${i + 1}, 12345 Schneedorf` },
        );
        drivers.current.set(bot.seed, d);
      }
      const driver = d;
      timers.push(
        setTimeout(async () => {
          if (cancelled) return;
          const st = await driver.step(view, roster.entries, roster.allValid);
          if (st.kind === "uploaded") void ctrl.refresh();
        }, 400 + Math.random() * 1600),
      );
    });
    return () => {
      cancelled = true;
      timers.forEach(clearTimeout);
    };
  }, [snap.view, auto, bots]);

  return (
    <section class="card mock-tools" aria-labelledby="mock-title">
      <h2 id="mock-title">🧪 Mock-Werkzeuge</h2>
      <p class="hint">Nur im Mock-Build sichtbar. Test-Teilnehmer laufen in diesem Tab mit dem echten Protokoll-Treiber gegen den Mock-Server.</p>
      <div class="button-row">
        <button type="button" class="btn" disabled={snap.view?.state !== "open"} onClick={() => addBots(1)}>
          + 1 Test-Teilnehmer
        </button>
        <button type="button" class="btn" disabled={snap.view?.state !== "open"} onClick={() => addBots(3)}>
          + 3 Test-Teilnehmer
        </button>
      </div>
      <label class="check">
        <input
          type="checkbox"
          checked={auto}
          onChange={(e) => {
            setAuto(e.currentTarget.checked);
            writeFlag("wichtel:mock:manual", !e.currentTarget.checked);
          }}
        />
        Test-Teilnehmer erledigen ihre Schritte automatisch ({bots.length})
      </label>
      <label class="check">
        <input
          type="checkbox"
          checked={disturb}
          onChange={(e) => {
            setDisturb(e.currentTarget.checked);
            writeFlag("wichtel:mock:disturb", e.currentTarget.checked);
          }}
        />
        Störung beim Öffnen des Ergebnisses simulieren
      </label>
      {msg && <p class="hint">{msg}</p>}
    </section>
  );
}
