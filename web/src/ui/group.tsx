/** Group page `/g/<gid>#k=…[&a=…][&s=…]`. */
import { useEffect, useMemo, useState } from "preact/hooks";
import { N_MAX } from "../api/types";
import { b64uEncode } from "../lib/bytes";
import { addressBarFragment, groupLink, type Route, type Secrets } from "../lib/fragment";
import { loadGroup, mergeSecrets, saveGroup, seedPersisted, storageAvailable } from "../lib/storage";
import { forgetDriverState } from "../protocol/driver";
import { forgetPush } from "../push";
import { useServices } from "./app";
import { Countdown, errorText, formatDate, Notice } from "./common";
import { GroupController, type Snapshot } from "./controller";
import { AdminPanel, ConfirmButton } from "./admin";
import { EditEntry, JoinForm, NoteField, SaveLinkDialog } from "./join";
import { MockTools } from "./mocktools";
import { PushBell, TopbarSlot } from "./pushbell";
import { DisturbanceCard, DrawProgress, Fingerprint, ResultCard, RosterList } from "./status";

type GroupRoute = Extract<Route, { page: "group" }>;

export function GroupPage({ route }: { route: GroupRoute }) {
  if (!route.fragment.ok) {
    return (
      <section class="card">
        <h1>Link unvollständig</h1>
        <Notice kind="error">
          {route.fragment.error === "missing_key"
            ? "Diesem Link fehlt der Teil nach dem „#“. Darin steckt der Schlüssel der Runde – ohne ihn kann niemand die Namen lesen. Bitte kopiere den Link noch einmal vollständig."
            : "Der Link ist beschädigt. Bitte kopiere ihn noch einmal vollständig."}
        </Notice>
      </section>
    );
  }
  return <GroupPageInner route={route} secretsFromUrl={route.fragment.secrets} />;
}

/** Replaces the current history entry (no navigation, no new entry). */
function setAddressBar(gidB64: string, secrets: Secrets, keepSeed: boolean): void {
  try {
    const url = `/g/${gidB64}${addressBarFragment(secrets, keepSeed)}`;
    if (location.pathname + location.hash !== url) history.replaceState(history.state, "", url);
  } catch {
    /* ignore */
  }
}

function useSnapshot(ctrl: GroupController): Snapshot {
  const [snap, setSnap] = useState(ctrl.snapshot);
  useEffect(() => ctrl.subscribe(setSnap), [ctrl]);
  return snap;
}

function GroupPageInner({ route, secretsFromUrl }: { route: GroupRoute; secretsFromUrl: NonNullable<Extract<GroupRoute["fragment"], { ok: true }>["secrets"]> }) {
  const services = useServices();
  const merged = useMemo(() => mergeSecrets(route.gidB64, secretsFromUrl), []);
  const ctrl = useMemo(
    () => new GroupController({ api: services.api, wasm: services.wasm, kv: services.kv, computeRoles: services.computeRoles }, route.gidB64, route.gid, merged.secrets),
    [],
  );
  const snap = useSnapshot(ctrl);
  const [saveDialog, setSaveDialog] = useState<"forced" | "info" | null>(null);
  const [editing, setEditing] = useState(false);
  const [leaveError, setLeaveError] = useState<string | null>(null);
  /** Left the group on this page (so the page does not ask for a personal link afterwards). */
  const [left, setLeft] = useState(false);

  useEffect(() => {
    // Remember what this device knows (never overwrite another stored seed with a different one).
    const rec = loadGroup(route.gidB64);
    const patch: Parameters<typeof saveGroup>[1] = { k: b64uEncode(merged.secrets.k) };
    if (secretsFromUrl.a) patch.a = b64uEncode(secretsFromUrl.a);
    if (secretsFromUrl.s && (!rec?.s || rec.k !== patch.k)) patch.s = b64uEncode(secretsFromUrl.s);
    saveGroup(route.gidB64, patch);
    // Personal link opened (e.g. on a new device): once the seed is stored here, reduce the
    // address bar to the invite/admin link so that sharing the URL never passes on the seed.
    if (secretsFromUrl.s && seedPersisted(route.gidB64, secretsFromUrl.k, secretsFromUrl.s)) {
      setAddressBar(route.gidB64, secretsFromUrl, false);
    }
    ctrl.start();
    return () => ctrl.stop();
  }, []);

  useEffect(() => {
    if (snap.isMember && snap.myPid && loadGroup(route.gidB64)?.linkSaved === false && !saveDialog) setSaveDialog("forced");
  }, [snap.isMember]);

  const secrets = ctrl.currentSecrets;
  const adminSecret = secrets.a ?? null;
  const personalLink = secrets.s ? groupLink(location.origin, route.gidB64, "personal", secrets) : null;
  const { view, meta, roster } = snap;

  const onJoined = async (seed: Uint8Array) => {
    ctrl.setSeed(seed);
    await ctrl.refresh();
    setSaveDialog("forced");
    // The personal link is only offered in the save dialog; the address bar shows the invite link
    // (a bookmark of it still leads back here with the seed stored on this device). Only if this
    // browser cannot store anything does the address bar keep the seed – it is the only way back.
    // The Spielleiter-Link stays as it is.
    if (!secretsFromUrl.a) {
      const keepSeed = !seedPersisted(route.gidB64, secrets.k, seed);
      setAddressBar(route.gidB64, { k: secrets.k, s: seed }, keepSeed);
    }
  };

  if (snap.loading && !view) {
    return (
      <section class="card">
        <p class="working">
          <span class="spinner" aria-hidden="true" /> Runde wird geladen …
        </p>
        {snap.problem && <Notice kind="warn">{snap.problem}</Notice>}
      </section>
    );
  }
  if (snap.notFound) {
    return (
      <section class="card">
        <h1>Diese Runde gibt es nicht (mehr)</h1>
        <p>Vielleicht wurde sie vom Spielleiter gelöscht oder nach dem Wichteln automatisch entfernt.</p>
      </section>
    );
  }
  if (snap.badKey || !view || !meta || !roster) {
    return (
      <section class="card">
        <h1>Link passt nicht</h1>
        <Notice kind="error">Mit diesem Link lässt sich die Runde nicht entschlüsseln. Bitte prüfe, ob du ihn vollständig kopiert hast.</Notice>
      </section>
    );
  }

  const n = view.participants.length;
  const me = roster.members.find((m) => m.pidB64 === snap.myPid) ?? null;
  const driver = snap.driver;
  const revealLocked =
    view.state === "done" ||
    (view.state === "drawing" && view.phase === "reveal" && !!snap.myPid && (view.progress?.submitted ?? []).includes(snap.myPid));
  const firstRound = loadGroup(route.gidB64)?.drawRound?.firstRound ?? null;

  const leave = async () => {
    const keys = ctrl.keysHandle;
    if (!keys || !snap.myPid) return;
    setLeaveError(null);
    try {
      await ctrl.api.removeParticipant(route.gidB64, snap.myPid, keys.authToken);
      saveGroup(route.gidB64, { s: undefined, pid: undefined, note: undefined, push: undefined, linkSaved: undefined });
      // The server dropped the push subscription with the participant; clean up this device.
      void forgetPush(route.gidB64);
      void forgetDriverState(ctrl.kv, route.gidB64);
      // A personal link in the address bar (no local storage) would now point to a stale seed.
      setAddressBar(route.gidB64, { k: secrets.k, a: secretsFromUrl.a }, false);
      ctrl.setSeed(null);
      setLeft(true);
      await ctrl.refresh();
    } catch (e) {
      setLeaveError(errorText(e));
    }
  };

  return (
    <>
      <section class="card group-head">
        <p class="group-eyebrow" aria-hidden="true">Wichtelrunde</p>
        <h1>{meta.title || "Wichtelrunde"}</h1>
        <ul class="meta-list">
          {meta.budget && (
            <li>
              <svg class="meta-icon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M17 6.5A7 7 0 1 0 17 17.5M4 10h9M4 14h9" />
              </svg>
              Budget: {meta.budget}
            </li>
          )}
          {meta.event_date && (
            <li>
              <svg class="meta-icon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3.5" y="5" width="17" height="15" rx="2" />
                <path d="M3.5 10h17M8 3v4M16 3v4" />
              </svg>
              {formatDate(meta.event_date)}
            </li>
          )}
          <li>
            <svg class="meta-icon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="9" cy="8" r="3.5" />
                <path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6 6 0 0 1 3.5 6" />
              </svg>
            {n} {n === 1 ? "Person" : "Personen"}
          </li>
        </ul>
        {meta.description && <p class="pre description">{meta.description}</p>}
        {view.state === "open" && view.draw_at && <Countdown at={view.draw_at} />}
        {view.state === "open" && view.schedule_missed && !adminSecret && (
          <Notice kind="warn" title="Termin verpasst">
            Zum Verlosungstermin waren zu wenige dabei (mindestens 4). Der Spielleiter setzt einen neuen Termin.
          </Notice>
        )}
        {snap.problem && <Notice kind="warn">{snap.problem}</Notice>}
        {!storageAvailable() && (
          <p class="hint">Dein Browser speichert für diese Seite nichts. Bewahre deinen persönlichen Link gut auf – nur damit kommst du zurück.</p>
        )}
      </section>

      {/* ---------- main status ---------- */}
      {n > N_MAX && (
        <Notice kind="error" title="Zu viele Teilnehmer">
          Diese Runde hat mehr als {N_MAX} Einträge. Die Verlosung ist so nicht möglich – der Spielleiter muss Einträge entfernen.
        </Notice>
      )}
      {!roster.allValid && (
        <Notice kind="error" title="Ungültiger Eintrag in der Liste">
          Mindestens ein Eintrag lässt sich nicht entschlüsseln. Solange er drin ist, nimmt dein Browser nicht an der
          Verlosung teil. Der Spielleiter sollte ihn entfernen.
        </Notice>
      )}

      {view.state === "open" && !snap.isMember && (
        <section class="card" aria-labelledby="join-title">
          <h2 id="join-title">{secrets.s ? "Du bist nicht (mehr) in der Liste" : "Mitmachen"}</h2>
          {left ? (
            <Notice kind="ok" title="Du bist ausgetreten">
              Solange die Verlosung nicht gestartet ist, kannst du dich hier wieder eintragen.
            </Notice>
          ) : secrets.s ? (
            <p>Dieses Gerät kennt dich, aber du stehst nicht in der Teilnehmerliste – vielleicht wurdest du entfernt. Du kannst dich erneut eintragen.</p>
          ) : (
            <p class="hint">
              Schon dabei, z. B. auf einem anderen Gerät? Dann öffne bitte deinen <strong>persönlichen Link</strong>{" "}
              statt dich noch einmal einzutragen.
            </p>
          )}
          <JoinForm ctrl={ctrl} onJoined={onJoined} existingSeed={secrets.s} />
        </section>
      )}

      {view.state === "open" && snap.isMember && me && (
        <section class="card" aria-labelledby="me-title">
          <h2 id="me-title">Du bist dabei 🎉</h2>
          {editing ? (
            <EditEntry ctrl={ctrl} name={me.name ?? ""} wish={me.wish ?? ""} onDone={() => setEditing(false)} />
          ) : (
            <>
              <p>
                Eingetragen als <strong>{me.name}</strong>.{" "}
                {view.draw_at ? "Die Verlosung startet zum Termin automatisch." : "Jetzt heißt es warten, bis der Spielleiter die Verlosung startet."}
              </p>
              <div class="button-row">
                <button type="button" class="btn" onClick={() => setEditing(true)}>
                  Name / Wunschzettel ändern
                </button>
                <button type="button" class="btn" onClick={() => setSaveDialog("info")}>
                  Persönlichen Link zeigen
                </button>
              </div>
            </>
          )}
          <NoteField gidB64={route.gidB64} locked={false} />
        </section>
      )}

      {view.state !== "open" && !snap.isMember && !adminSecret && (
        <section class="card">
          {left ? (
            <Notice kind="ok" title="Du bist ausgetreten">
              Du nimmst an dieser Verlosung nicht mehr teil. Für alle anderen wird neu ausgelost.
            </Notice>
          ) : secrets.s ? (
            <Notice kind="warn" title="Du bist nicht mehr dabei">
              Du stehst nicht in der Teilnehmerliste dieser Verlosung – vermutlich wurdest du entfernt.
            </Notice>
          ) : (
            <Notice kind="info" title={view.state === "done" ? "Die Verlosung ist abgeschlossen" : "Die Verlosung läuft bereits"}>
              Neue Teilnehmer können nicht mehr beitreten. Wenn du dabei bist, öffne bitte deinen{" "}
              <strong>persönlichen Link</strong> (den du beim Mitmachen gespeichert hast) – nur damit kann dieses Gerät dein Ergebnis
              anzeigen.
            </Notice>
          )}
        </section>
      )}

      {driver?.kind === "disturbance" && <DisturbanceCard reason={driver.reason} drawNo={view.draw_no} />}

      {view.state === "drawing" && driver?.kind !== "disturbance" && (
        <DrawProgress
          view={view}
          members={roster.members}
          myPid={snap.myPid}
          isMember={snap.isMember}
          driver={driver}
          busy={snap.busy}
          live={snap.live}
          manyCollisions={snap.manyCollisions}
          firstRound={firstRound}
        />
      )}

      {view.state === "done" && snap.isMember && driver?.kind === "result" && (
        <ResultCard
          recipient={roster.members.find((m) => m.pidB64 === driver.recipientPid) ?? null}
          note={driver.note}
          meta={meta}
          drawNo={view.draw_no}
        />
      )}
      {view.state === "done" && snap.isMember && driver?.kind !== "result" && driver?.kind !== "disturbance" && (
        <section class="card">
          <p class="working">
            <span class="spinner" aria-hidden="true" /> {snap.busy ?? "Dein Ergebnis wird geladen …"}
          </p>
        </section>
      )}
      {view.state === "done" && !snap.isMember && adminSecret && (
        <section class="card">
          <Notice kind="ok" title="Verlosung abgeschlossen">
            Alle können jetzt ihr Ergebnis über ihren persönlichen Link sehen. Als Spielleiter siehst du keine Zuordnung.
          </Notice>
        </section>
      )}

      {snap.isMember && view.state === "drawing" && (
        <section class="card subtle">
          <NoteField gidB64={route.gidB64} locked={revealLocked} />
        </section>
      )}

      {snap.fingerprint && n >= 2 && <Fingerprint words={snap.fingerprint} prominent={view.state === "open"} />}

      <RosterList
        members={roster.members}
        myPid={snap.myPid}
        view={view}
        onRemove={
          adminSecret
            ? (m) => {
                const warn =
                  view.state === "open"
                    ? `${m.name ?? "Diesen Eintrag"} wirklich entfernen?`
                    : `${m.name ?? "Diesen Eintrag"} entfernen? Achtung: Alle bekommen dann eine neue Person zugelost (Verlosung Nr. ${view.draw_no + 1}).`;
                if (!confirm(warn)) return;
                ctrl.api
                  .removeParticipant(route.gidB64, m.pidB64, adminSecret)
                  .catch((e: unknown) => alert(errorText(e)))
                  .finally(() => void ctrl.refresh());
              }
            : undefined
        }
      />

      {snap.isMember && personalLink && (
        <TopbarSlot>
          <PushBell ctrl={ctrl} personalLink={personalLink} title={meta.title} />
        </TopbarSlot>
      )}

      {snap.isMember && (
        <section class="card subtle">
          <h2>Aussteigen</h2>
          {view.state === "open" ? (
            <p class="hint">Solange die Verlosung nicht gestartet ist, kannst du einfach austreten.</p>
          ) : (
            <p class="hint">Wenn du jetzt austrittst, wird für alle anderen neu ausgelost.</p>
          )}
          <ConfirmButton label="Austreten" confirmLabel="Ja, austreten" danger onConfirm={leave}>
            {view.state === "open" ? (
              <p>Du wirst aus der Teilnehmerliste entfernt.</p>
            ) : (
              <Notice kind="warn" title="Alle bekommen eine neue Person zugelost">
                Die Verlosung startet für alle anderen neu (Verlosung Nr. {view.draw_no + 1}).
              </Notice>
            )}
          </ConfirmButton>
          {leaveError && <Notice kind="error">{leaveError}</Notice>}
          {view.state !== "open" && personalLink && (
            <button type="button" class="btn-link leave-link" onClick={() => setSaveDialog("info")}>
              Persönlichen Link zeigen
            </button>
          )}
        </section>
      )}

      {adminSecret && <AdminPanel ctrl={ctrl} view={view} meta={meta} adminSecret={adminSecret} />}

      {__MOCK__ && <MockTools ctrl={ctrl} snap={snap} />}

      {personalLink && (
        <SaveLinkDialog
          open={saveDialog !== null}
          link={personalLink}
          forced={saveDialog === "forced"}
          onClose={() => {
            if (saveDialog === "forced") saveGroup(route.gidB64, { linkSaved: true });
            setSaveDialog(null);
          }}
        />
      )}
    </>
  );
}
