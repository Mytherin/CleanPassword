// Builds the extension into extension/dist (load it at chrome://extensions
// with "Load unpacked"):
//
//   1. the Rust core as WebAssembly (cargo), with its JS glue (wasm-bindgen,
//      which must be the same version as the wasm-bindgen crate: 0.2.100;
//      `cargo install wasm-bindgen-cli --version 0.2.100`);
//   2. the TypeScript, bundled with esbuild;
//   3. the manifest, pages, styles and icons.
//
//   node build.mjs           # release build
//   node build.mjs --watch   # rebuild the TypeScript on change (not the core)

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const dist = join(here, "dist");
const watch = process.argv.includes("--watch");

function run(cmd, args, cwd = root) {
  execFileSync(cmd, args, { cwd, stdio: "inherit" });
}

// 1. The core.
run("cargo", ["build", "-p", "cleanpassword-wasm", "--target", "wasm32-unknown-unknown", "--release"]);
const coreOut = join(here, "src", "core");
rmSync(coreOut, { recursive: true, force: true });
run("wasm-bindgen", [
  join(root, "target", "wasm32-unknown-unknown", "release", "cleanpassword_wasm.wasm"),
  "--target", "web", "--out-dir", coreOut, "--out-name", "core",
]);

// 2. The scripts.
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
const common = { bundle: true, target: "chrome120", sourcemap: false, minify: false, keepNames: true, logLevel: "info", legalComments: "inline" };
const builds = [
  // The service worker is an ES module (it imports the core's glue).
  { entryPoints: { background: "src/background/index.ts" }, format: "esm" },
  // Content scripts can't be modules.
  { entryPoints: { content: "src/content/index.ts" }, format: "iife" },
  { entryPoints: { popup: "src/popup/popup.ts", menu: "src/menu/menu.ts", prompt: "src/prompt/prompt.ts", passkey: "src/passkey/passkey.ts" }, format: "iife" },
  // Passkeys: the page script (in the page's own world) and its bridge.
  { entryPoints: { "webauthn-page": "src/webauthn/page.ts", "webauthn-bridge": "src/webauthn/bridge.ts" }, format: "iife" },
  // The classifier alone, for tests that run it in pages.
  { entryPoints: { "test-classify": "src/content/test-entry.ts" }, format: "iife", outdir: join(here, "test", "build") },
];
const contexts = [];
for (const b of builds) {
  const opts = { ...common, outdir: dist, absWorkingDir: here, ...b };
  if (watch) {
    const ctx = await esbuild.context(opts);
    await ctx.watch();
    contexts.push(ctx);
  } else {
    await esbuild.build(opts);
  }
}

// 3. Everything else.
cpSync(join(here, "static"), dist, { recursive: true });
cpSync(join(coreOut, "core_bg.wasm"), join(dist, "core.wasm"));
if (!existsSync(join(dist, "icons"))) {
  run("node", [join(here, "tools", "icons.mjs"), join(dist, "icons")], here);
}
console.log(`Built ${dist}`);
