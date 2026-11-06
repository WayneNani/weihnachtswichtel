import { createContext } from "preact";
import { useContext, useEffect, useState } from "preact/hooks";
import type { Api } from "../api/client";
import { parseRoute, type Route } from "../lib/fragment";
import type { KvStore } from "../lib/idb";
import type { RolesJob, RolesJobResult } from "../protocol/driver";
import type { WichtelWasm } from "../wasm-api";
import { CreatePage } from "./create";
import { GroupPage } from "./group";
import { HomePage } from "./home";

export interface Services {
  api: Api;
  wasm: WichtelWasm;
  kv: KvStore;
  computeRoles(job: RolesJob): Promise<RolesJobResult>;
}

export const ServicesContext = createContext<Services | null>(null);

export function useServices(): Services {
  const s = useContext(ServicesContext);
  if (!s) throw new Error("services missing");
  return s;
}

/** Client-side navigation without a server round trip. */
export function navigate(url: string, replace = false): void {
  if (replace) history.replaceState(null, "", url);
  else history.pushState(null, "", url);
  window.dispatchEvent(new Event("wichtel:navigate"));
  window.scrollTo(0, 0);
}

function currentRoute(): Route {
  return parseRoute(location.pathname, location.hash);
}

export function App({ services }: { services: Services }) {
  const [route, setRoute] = useState<Route>(currentRoute);
  const [routeKey, setRouteKey] = useState(0);
  useEffect(() => {
    const update = () => {
      setRoute(currentRoute());
      setRouteKey((k) => k + 1);
    };
    window.addEventListener("popstate", update);
    window.addEventListener("hashchange", update);
    window.addEventListener("wichtel:navigate", update);
    return () => {
      window.removeEventListener("popstate", update);
      window.removeEventListener("hashchange", update);
      window.removeEventListener("wichtel:navigate", update);
    };
  }, []);

  useEffect(() => {
    document.title = route.page === "create" ? "Neue Runde – Wichteln" : "Wichteln";
  }, [route]);

  return (
    <ServicesContext.Provider value={services}>
      <header class="topbar">
        <a
          href="/"
          class="brand"
          onClick={(e) => {
            e.preventDefault();
            navigate("/");
          }}
        >
          <span aria-hidden="true">🎁</span> Wichteln
        </a>
        {__MOCK__ && <span class="mock-badge" title="Mock-Modus: keine echte Kryptographie">Mock</span>}
      </header>
      <main id="main">
        {route.page === "home" && <HomePage />}
        {route.page === "create" && <CreatePage />}
        {route.page === "group" && <GroupPage key={`${route.gidB64}:${routeKey}`} route={route} />}
        {route.page === "not_found" && (
          <section class="card">
            <h1>Seite nicht gefunden</h1>
            <p>
              Diese Adresse kennen wir nicht. Prüfe, ob der Link vollständig kopiert wurde, oder geh zur{" "}
              <a href="/">Startseite</a>.
            </p>
          </section>
        )}
      </main>
      <footer class="footer">
        <p>
          Ohne Konto, ohne Tracking. Wer wen beschenkt, wird in euren Browsern ausgelost – der Server erfährt es nicht.
        </p>
        <p class="footer-links">
          <a href="/impressum.html">Impressum</a> · <a href="/datenschutz.html">Datenschutz</a>
        </p>
      </footer>
    </ServicesContext.Provider>
  );
}
