import { render } from "preact";
import { mockWasm } from "./mock";

function App() {
  return (
    <main>
      <h1>Weihnachtswichtel</h1>
      <p>Gerüst (Phase 0) – {mockWasm.protocolVersion?.()}</p>
    </main>
  );
}

const root = document.getElementById("app");
if (root) render(<App />, root);
