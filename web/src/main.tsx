import { render } from "preact";
import { createApi } from "./api/client";
import { idbKv } from "./lib/idb";
import { createRolesComputer } from "./protocol/worker-client";
import { App, type Services } from "./ui/app";
import { loadWasm } from "./wasm";

const root = document.getElementById("app");

async function boot(): Promise<void> {
  if (!root) return;
  let wasm;
  try {
    wasm = await loadWasm();
  } catch {
    render(
      <main id="main">
        <section class="card">
          <h1>Das hat nicht geklappt</h1>
          <p>
            Die Verschlüsselungs-Komponente konnte nicht geladen werden. Bitte lade die Seite neu oder versuche es mit
            einem aktuellen Browser.
          </p>
        </section>
      </main>,
      root,
    );
    return;
  }
  const services: Services = {
    api: createApi(),
    wasm,
    kv: idbKv(),
    computeRoles: createRolesComputer(() => loadWasm()),
  };
  render(<App services={services} />, root);
}

void boot();
