// Build script: bundles web/src (no external resources, no CDN).
//
//   node build.mjs                    real build → dist/ (expects wasm-bindgen output in src/wasm-pkg/ → dist/pkg/)
//   node build.mjs --mock             mock build → dist-mock/ (mock WASM + in-memory mock server)
//   node build.mjs --mock --serve     mock build + start tools/mock-server.mjs on http://localhost:8080
//   node build.mjs --watch            rebuild on change (combinable with --mock/--serve)
//   node build.mjs --test             bundle src/test/*.test.ts → dist-test/ and run them with node:test
import * as esbuild from "esbuild";
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";

const args = new Set(process.argv.slice(2));
const watch = args.has("--watch");
const mock = args.has("--mock");
const serve = args.has("--serve");
const test = args.has("--test");

const common = {
  bundle: true,
  target: "es2022",
  logLevel: "info",
  legalComments: "none",
  jsx: "automatic",
  jsxImportSource: "preact",
};

if (test) {
  const dir = "dist-test";
  rmSync(dir, { recursive: true, force: true });
  const entries = readdirSync("src/test")
    .filter((f) => f.endsWith(".test.ts") || f.endsWith(".test.tsx"))
    .map((f) => `src/test/${f}`);
  await esbuild.build({
    ...common,
    entryPoints: entries,
    outdir: dir,
    outExtension: { ".js": ".mjs" },
    platform: "node",
    format: "esm",
    define: { __MOCK__: "true" },
    logLevel: "warning",
  });
  const files = readdirSync(dir).map((f) => `${dir}/${f}`);
  const res = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
  process.exit(res.status ?? 1);
}

const outdir = mock ? "dist-mock" : "dist";
rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });
cpSync("public", outdir, { recursive: true });
if (!mock && existsSync("src/wasm-pkg")) cpSync("src/wasm-pkg", `${outdir}/pkg`, { recursive: true });

const appOptions = {
  ...common,
  entryPoints: { app: "src/main.tsx", worker: "src/worker.ts" },
  outdir,
  format: "esm",
  platform: "browser",
  minify: !watch,
  sourcemap: watch ? "inline" : false,
  define: { __MOCK__: mock ? "true" : "false" },
  // The real WASM glue is loaded at runtime from /pkg/ and must not be bundled.
  external: ["/pkg/*"],
  loader: { ".wasm": "file" },
};

// The service worker is registered as a classic script (module SWs are not supported everywhere).
const swOptions = { ...appOptions, entryPoints: { sw: "src/sw.ts" }, format: "iife" };

// The mock server core (TypeScript) is bundled for Node; tools/mock-server.mjs wraps it in node:http.
const serverOptions = {
  ...common,
  entryPoints: { core: "src/mock/server.ts" },
  outdir: "dist-mock-server",
  outExtension: { ".js": ".mjs" },
  format: "esm",
  platform: "node",
  define: { __MOCK__: "true" },
};

if (mock) await esbuild.build(serverOptions);
if (watch) {
  for (const opts of [appOptions, swOptions]) await (await esbuild.context(opts)).watch();
} else {
  await esbuild.build(appOptions);
  await esbuild.build(swOptions);
}

if (serve) {
  const { startMockServer } = await import("./tools/mock-server.mjs");
  await startMockServer({ root: outdir, port: Number(process.env.PORT ?? 8080), host: process.env.HOST ?? "127.0.0.1" });
}
