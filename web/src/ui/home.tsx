import { useState } from "preact/hooks";
import { b64uDecodeLen } from "../lib/bytes";
import { buildFragment, SECRET_LEN, type Secrets } from "../lib/fragment";
import { forgetGroupOnDevice } from "../forget";
import { listGroups } from "../lib/storage";
import { navigate, useServices } from "./app";

/**
 * Link to a group stored on this device. The seed is never put into the address bar: the group
 * page takes it from local storage (see mergeSecrets).
 */
function localLink(gid: string, rec: { k: string; a?: string; s?: string }): string | null {
  const k = b64uDecodeLen(rec.k, SECRET_LEN);
  if (!k) return null;
  const s: Secrets = { k };
  const seed = rec.s ? b64uDecodeLen(rec.s, SECRET_LEN) : null;
  const admin = rec.a ? b64uDecodeLen(rec.a, SECRET_LEN) : null;
  if (admin && !seed) s.a = admin;
  return `/g/${gid}${buildFragment(s)}`;
}

export function HomePage() {
  const services = useServices();
  const [groups, setGroups] = useState(() => listGroups());
  return (
    <>
      <section class="hero">
        <svg class="hero-star" width="44" height="44" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M12 2l2.9 6.3 6.9.7-5.2 4.6 1.5 6.8L12 17l-6.1 3.4 1.5-6.8L2.2 9l6.9-.7Z" />
        </svg>
        <h1>Wichteln, ganz ohne Geheimnisverrat</h1>
        <p class="lead">
          Leg eine Runde an, teile den Einladungslink in eurem Gruppenchat – fertig. Kein Konto, keine App, keine
          E-Mail-Adresse. Und das Beste: <strong>Niemand außer dir erfährt, wen du beschenkst</strong> – auch nicht
          der Spielleiter und nicht der Server.
        </p>
        <button type="button" class="btn btn-primary btn-big" onClick={() => navigate("/neu")}>
          Neue Runde anlegen
        </button>
      </section>

      {groups.length > 0 && (
        <section class="card">
          <h2>Deine Runden auf diesem Gerät</h2>
          <ul class="group-list">
            {groups.map(({ gid, rec }) => {
              const link = localLink(gid, rec);
              return (
                <li key={gid}>
                  {link ? (
                    <a
                      href={link}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(link);
                      }}
                    >
                      {rec.title || "Wichtelrunde"}
                    </a>
                  ) : (
                    <span>{rec.title || "Wichtelrunde"}</span>
                  )}
                  <span class="tags">
                    {rec.a && <span class="tag">Spielleitung</span>}
                    {rec.s && <span class="tag tag-green">dabei</span>}
                  </span>
                  <button
                    type="button"
                    class="btn-link danger"
                    onClick={() => {
                      if (!confirm("Diese Runde von diesem Gerät entfernen? Ohne deinen persönlichen Link kommst du dann nicht mehr an dein Ergebnis.")) return;
                      // Removes the local record synchronously; push/IndexedDB cleanup continues in the background.
                      void forgetGroupOnDevice(gid, { kv: services.kv, api: services.api, wasm: services.wasm });
                      setGroups(listGroups());
                    }}
                  >
                    vergessen
                  </button>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      <section class="card">
        <h2>So funktioniert’s</h2>
        <ol class="steps">
          <li>
            <strong>Runde anlegen</strong> – Titel, Budget und Wichteldatum eintragen. Du bekommst einen
            Einladungslink für die Gruppe und einen privaten Spielleiter-Link.
          </li>
          <li>
            <strong>Mitmachen</strong> – Alle öffnen den Einladungslink, tragen ihren Namen und einen Wunschzettel
            ein und speichern ihren <em>persönlichen Link</em>.
          </li>
          <li>
            <strong>Fingerabdruck vergleichen</strong> – Alle sehen dieselben 8 Wörter? Dann sehen auch alle
            dieselbe Teilnehmerliste.
          </li>
          <li>
            <strong>Verlosung</strong> – Zum Termin oder per Knopfdruck. Eure Browser losen gemeinsam aus; jede und
            jeder sieht nur das eigene Ergebnis.
          </li>
        </ol>
      </section>

      <section class="card subtle">
        <h2>Datensparsam</h2>
        <ul>
          <li>Namen, Titel und Wunschzettel liegen nur verschlüsselt auf dem Server. Der Schlüssel steckt im Link hinter dem „#“ und wird nie übertragen.</li>
          <li>Keine Cookies, keine externen Schriften oder Skripte, keine Werbung.</li>
          <li>Alle Daten werden automatisch nach dem Wichteln gelöscht.</li>
        </ul>
      </section>
    </>
  );
}
