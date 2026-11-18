// Tests in a real Chrome (puppeteer-core with the installed Chrome; set
// CHROME to its path if it isn't found):
//
//   1. the classifier, on the fixture pages in fixtures.mjs;
//   2. the extension, end to end, against a fake S3 server: setting up a
//      vault, filling through the inline menu (into a field managed like
//      React's), a generated password on a sign-up form, the save prompt
//      after a sign-in, what ends up in S3, the locked menu, and refusing to
//      show the menu on a see-through page.
//
//   npm test     (builds first)

import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";
import { startFakeS3 } from "./fake-s3.mjs";
import { fixtures } from "./fixtures.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "  ok  " : "  FAIL"} ${name}${ok || !detail ? "" : `\n        ${detail}`}`);
  if (!ok) failures++;
}

const chrome = [
  process.env.CHROME,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].find((p) => p && existsSync(p));
if (!chrome) throw new Error("Chrome not found: set CHROME");

// ---- A web server for the pages ----------------------------------------------

const classifier = readFileSync(join(here, "build", "test-classify.js"), "utf8");
const pages = {
  // A login whose fields keep their value like React's controlled inputs:
  // the value set through the element is tracked, and only an input event
  // with a different native value counts as a change.
  "/login": `<!doctype html><title>Login</title><h1>Sign in</h1>
    <form action="/welcome" method="get"><input id="u" name="user" autocomplete="username" placeholder="Email">
    <input id="p" name="pass" type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>
    <script>
      window.state = {};
      for (const el of document.querySelectorAll("input")) {
        const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        let tracked = el.value;
        Object.defineProperty(el, "value", { configurable: true, get() { return desc.get.call(this); }, set(v) { tracked = String(v); desc.set.call(this, v); } });
        el.addEventListener("input", () => { const now = desc.get.call(el); if (now !== tracked) { tracked = now; state[el.id] = now; } });
      }
    </script>`,
  "/welcome": `<!doctype html><title>Welcome</title><p>Signed in.</p>`,
  "/signup": `<!doctype html><title>Sign up</title><h1>Create your account</h1>
    <form action="/welcome" method="get"><input id="email" type="email" autocomplete="username" placeholder="Email">
    <input id="np" type="password" autocomplete="new-password" placeholder="New password">
    <input id="cp" type="password" autocomplete="new-password" placeholder="Confirm password"><button type="submit">Create account</button></form>`,
  "/faded": `<!doctype html><title>Faded</title><style>html{opacity:.5}</style>
    <form><input id="u" autocomplete="username"><input id="p" type="password"><button>Sign in</button></form>`,
};
const web = createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname.startsWith("/fixture/")) {
    const f = fixtures[decodeURIComponent(url.pathname.slice(9))];
    res.writeHead(200, { "content-type": "text/html" });
    return res.end(`<!doctype html><meta charset="utf-8"><body>${f.html}</body>`);
  }
  const page = pages[url.pathname];
  res.writeHead(page ? 200 : 404, { "content-type": "text/html" });
  res.end(page ?? "not found");
});
await new Promise((r) => web.listen(0, "127.0.0.1", r));
const WEB = `http://127.0.0.1:${web.address().port}`;
const s3 = await startFakeS3();

// The built extension, allowed to reach the fake S3 server.
const ext = join(here, "dist-test");
rmSync(ext, { recursive: true, force: true });
cpSync(join(here, "..", "dist"), ext, { recursive: true });
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
manifest.host_permissions.push("http://127.0.0.1/*");
writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest, null, 2));

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  enableExtensions: [ext],
  args: ["--no-first-run", "--no-default-browser-check", "--window-size=1200,900"],
  defaultViewport: { width: 1200, height: 900 },
});

try {
  // ---- 1. The classifier --------------------------------------------------------
  console.log("Classifier");
  const page = await browser.newPage();
  for (const [name, f] of Object.entries(fixtures)) {
    await page.goto(`${WEB}/fixture/${encodeURIComponent(name)}`);
    if (f.toggle) {
      await page.evaluate(() => window.cleanpasswordScan?.());
      await page.addScriptTag({ content: classifier });
      await page.evaluate(() => window.cleanpasswordScan());
      await page.evaluate(() => window.toggle());
    } else {
      await page.addScriptTag({ content: classifier });
    }
    const got = await page.evaluate(() => window.cleanpasswordScan());
    const norm = (gs) => JSON.stringify(gs.map((g) => ({ kind: g.kind, roles: Object.fromEntries(Object.entries(g.roles).sort()) })));
    const ok = norm(got) === norm(f.expect);
    check(name, ok, `expected ${JSON.stringify(f.expect)}\n        got      ${JSON.stringify(got)}`);
  }
  await page.close();

  // ---- 2. The extension -----------------------------------------------------------
  console.log("Extension");
  const sw = await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().endsWith("/background.js"), { timeout: 10000 });
  const id = new URL(sw.url()).host;
  const popup = await browser.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);
  const ask = (type, args = {}) => popup.evaluate((m) => chrome.runtime.sendMessage(m), { type, ...args }).then((r) => r.value);

  // Setup.
  await popup.waitForSelector('input[placeholder="my-bucket"]');
  await popup.type('input[placeholder="my-bucket"]', "vault-bucket");
  await popup.click("details summary");
  await popup.type('input[placeholder^="https://"]', `http://127.0.0.1:${s3.port}`);
  await popup.type('input[placeholder="AKIA…"]', "AKIATEST");
  await popup.type('input[placeholder="Secret access key"]', "secret");
  await popup.click("button[type=submit]");
  await popup.waitForSelector('input[placeholder="Again"]', { timeout: 10000 });
  await popup.type('input[placeholder="Master password"]', "correct horse battery staple");
  await popup.type('input[placeholder="Again"]', "correct horse battery staple");
  await popup.click("button[type=submit]");
  await popup.waitForSelector("input.search", { timeout: 15000 });
  check("creates a vault in S3", s3.objects.has("vault-bucket/CleanPassword/vault.json"));

  const loginId = await ask("add", { data: { kind: "login", name: "Test site", username: "alice@example.com", password: "s3cret-Passw0rd", uris: [{ uri: WEB }], totp: "", notes: "", folder: "", favorite: false, fields: [] } });
  check("adds an item", typeof loginId === "string");

  // Filling through the inline menu.
  const tab = await browser.newPage();
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const menuFrame = await waitForFrame(tab, "menu.html");
  check("shows the inline menu on a sign-in field", !!menuFrame);
  if (menuFrame) {
    await menuFrame.waitForSelector(".row");
    const title = await menuFrame.$eval(".row .title", (e) => e.textContent);
    check("offers the matching login", title === "Test site", title);
    await sleep(700);
    await menuFrame.click(".row");
    await sleep(800);
    const values = await tab.evaluate(() => ({ u: document.getElementById("u").value, p: document.getElementById("p").value, state: window.state }));
    check("fills the user name and password", values.u === "alice@example.com" && values.p === "s3cret-Passw0rd", JSON.stringify(values));
    check("the page's framework sees the change", values.state.u === "alice@example.com" && values.state.p === "s3cret-Passw0rd", JSON.stringify(values.state));
  }

  // A click too soon after the menu appears does nothing.
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const early = await waitForFrame(tab, "menu.html");
  if (early) {
    await early.waitForSelector(".row");
    await early.click(".row");
    await sleep(500);
    check("ignores a click in the menu's first half second", (await tab.$eval("#u", (e) => e.value)) === "");
  }

  // A generated password on a sign-up form, saved right away.
  await tab.goto(`${WEB}/signup`);
  await sleep(500);
  await tab.type("#email", "bob@example.com");
  await tab.click("#np");
  const gen = await waitForFrame(tab, "menu.html");
  check("offers a strong password on a new-password field", !!gen);
  if (gen) {
    await gen.waitForSelector(".row.suggest");
    await sleep(700);
    await gen.click(".row.suggest");
    await sleep(800);
    const v = await tab.evaluate(() => [document.getElementById("np").value, document.getElementById("cp").value]);
    check("fills it into both password fields", v[0].length >= 16 && v[0] === v[1], JSON.stringify(v));
    const items = await ask("items");
    const saved = items.find((i) => i.password === v[0]);
    check("saves the generated password at once, with the user name", !!saved && saved.username === "bob@example.com", JSON.stringify(saved));
  }

  // Saving a login typed by hand.
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.type("#u", "carol@example.com");
  await tab.type("#p", "typed-by-hand-1");
  await tab.keyboard.press("Escape");
  await Promise.all([tab.waitForNavigation(), tab.click("button[type=submit]")]);
  const promptFrame = await waitForFrame(tab, "prompt.html", 8000);
  check("offers to save a new login after signing in", !!promptFrame);
  if (promptFrame) {
    await promptFrame.waitForSelector(".btn.primary");
    await sleep(700);
    await promptFrame.click(".btn.primary");
    await sleep(500);
    const items = await ask("items");
    check("saves it", items.some((i) => i.username === "carol@example.com" && i.password === "typed-by-hand-1"));
  }

  // What S3 holds.
  await ask("sync");
  const keys = [...s3.objects.keys()];
  const all = [...s3.objects.values()].map((o) => o.body.toString("latin1")).join("\n");
  check("uploads one object per item", keys.filter((k) => k.includes("/items/")).length >= 3, keys.join(", "));
  check("S3 never sees names, user names or passwords", !/alice|carol|s3cret|typed-by-hand|Test site|127\.0\.0\.1/.test(all));

  // Locked: the menu offers unlocking.
  await ask("lock");
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const locked = await waitForFrame(tab, "menu.html");
  if (locked) {
    await locked.waitForSelector(".row");
    check("a locked vault's menu offers to unlock", (await locked.$eval(".row .title", (e) => e.textContent)) === "Unlock CleanPassword");
  } else check("a locked vault's menu offers to unlock", false);
  const unlocked = await popup.evaluate((pw) => chrome.runtime.sendMessage({ type: "unlock", password: pw }), "wrong password!!");
  check("refuses a wrong master password", unlocked.ok === false && unlocked.name === "WrongPassword", JSON.stringify(unlocked));
  await ask("unlock", { password: "correct horse battery staple" });
  check("unlocks with the right one", (await ask("state")).state === "unlocked");

  // A see-through page gets no menu.
  await tab.goto(`${WEB}/faded`);
  await sleep(500);
  await tab.click("#u");
  check("no menu on a see-through page (clickjacking)", !(await waitForFrame(tab, "menu.html", 1500)));
} finally {
  await browser.close();
  web.close();
  s3.server.close();
  rmSync(ext, { recursive: true, force: true });
}

async function waitForFrame(page, name, timeout = 4000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const f = page.frames().find((fr) => fr.url().includes(`/${name}`));
    if (f) return f;
    await sleep(100);
  }
  return null;
}

console.log(failures ? `\n${failures} failed` : "\nAll passed");
process.exit(failures ? 1 : 0);
