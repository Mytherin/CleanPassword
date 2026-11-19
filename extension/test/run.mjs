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

import { createHash, verify as verifySignature } from "node:crypto";
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
  // A site using passkeys (on localhost: passkeys need https or localhost).
  "/passkey": `<!doctype html><title>Passkeys</title><h1>Sign in</h1>
    <form><input id="u" autocomplete="username webauthn" placeholder="Email"><input id="p" type="password"><button>Sign in</button></form>
    <script>
      const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
      const text = (b) => new TextDecoder().decode(b);
      window.results = {};
      window.register = async () => {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const c = await navigator.credentials.create({ publicKey: { rp: { name: "Passkey Test" }, user: { id: new TextEncoder().encode("user-1"), name: "pat@example.com", displayName: "Pat" },
          challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { residentKey: "required", userVerification: "required" } } });
        results.create = { id: c.id, rawId: b64(c.rawId), clientDataJSON: text(c.response.clientDataJSON), challenge: b64(challenge), publicKey: b64(c.response.getPublicKey()),
          alg: c.response.getPublicKeyAlgorithm(), authData: b64(c.response.getAuthenticatorData()), isCredential: c instanceof PublicKeyCredential, json: JSON.stringify(c.toJSON()) };
      };
      window.login = async (mediation) => {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const c = await navigator.credentials.get({ mediation, publicKey: { challenge, userVerification: "required" } });
        results.get = { id: c.id, clientDataJSON: text(c.response.clientDataJSON), challenge: b64(challenge), authData: b64(c.response.authenticatorData),
          signature: b64(c.response.signature), userHandle: text(c.response.userHandle) };
        return results.get;
      };
    </script>`,
  // A sign-in form in a modal dialog (everything outside it is inert).
  "/dialog": `<!doctype html><title>Dialog</title><p>Behind the dialog.</p>
    <dialog id="d"><form method="dialog"><input id="u" autocomplete="username"><input id="p" type="password"><button>Sign in</button></form></dialog>
    <script>document.getElementById("d").showModal();</script>`,
  // A page with a popover that stays open (a toast, a cookie banner).
  "/popover": `<!doctype html><title>Popover</title><div id="toast" popover="manual" style="inset:auto 8px 8px auto">Cookies!</div>
    <form><input id="u" autocomplete="username"><input id="p" type="password"><button>Sign in</button></form>
    <script>document.getElementById("toast").showPopover();</script>`,
  // A sign-in form inside a web component's closed shadow root.
  "/shadow": `<!doctype html><title>Shadow</title><login-box style="display:block;width:300px"></login-box>
    <script>customElements.define("login-box", class extends HTMLElement { constructor() { super();
      window.sr = this.attachShadow({ mode: "closed" });
      sr.innerHTML = '<form><input id="u" autocomplete="username" style="display:block;width:280px;height:30px"><input id="p" type="password" style="display:block;width:280px;height:30px"><button>Sign in</button></form>'; } });</script>`,
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

  // The same login saved twice more, under longer names: offered once.
  const dupIds = [];
  for (const name of ["Test site (copy)", "Test site, imported from Chrome"]) {
    dupIds.push(await ask("add", { data: { kind: "login", name, username: "alice@example.com", password: "s3cret-Passw0rd", uris: [{ uri: WEB }], totp: "", notes: "", folder: "", favorite: false, fields: [] } }));
  }
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const dupFrame = await waitForFrame(tab, "menu.html");
  if (dupFrame) {
    await dupFrame.waitForSelector(".row");
    const titles = await dupFrame.$$eval(".list .row .title", (r) => r.map((e) => e.textContent));
    check("offers the same login saved three times once, under its shortest name", titles.length === 1 && titles[0] === "Test site", JSON.stringify(titles));
  } else check("offers the same login saved three times once, under its shortest name", false);
  for (const id of dupIds) await ask("purge", { id });

  // Chrome stops the extension's worker while a menu is open: the menu
  // still fills (it doesn't say "expired").
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const kept = await waitForFrame(tab, "menu.html");
  if (kept) {
    await kept.waitForSelector(".row");
    const swTarget = browser.targets().find((t) => t.type() === "service_worker" && t.url().endsWith("/background.js"));
    const cdp = await browser.target().createCDPSession();
    await cdp.send("Target.closeTarget", { targetId: swTarget._targetId });
    await sleep(1000);
    const stopped = !browser.targets().some((t) => t.type() === "service_worker" && t.url().endsWith("/background.js"));
    await kept.click(".row");
    await sleep(1500);
    const v = await tab.evaluate(() => [document.getElementById("u").value, document.getElementById("p").value]);
    check("a menu still fills after Chrome restarts the extension's worker", stopped && v[0] === "alice@example.com" && v[1] === "s3cret-Passw0rd", JSON.stringify({ stopped, v }));
    await sleep(300);
    check("and the menu doesn't open again on the field just filled", !(await waitForFrame(tab, "menu.html", 500)));
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

    // Another sign-up in the same tab, the user name not typed yet: another
    // account, so bob's login keeps its password.
    await tab.goto(`${WEB}/signup`);
    await sleep(500);
    await tab.click("#np");
    const gen2 = await waitForFrame(tab, "menu.html");
    if (gen2) {
      await gen2.waitForSelector(".row.suggest");
      await sleep(700);
      await gen2.click(".row.suggest");
      await sleep(800);
      const v2 = await tab.$eval("#np", (e) => e.value);
      const after = await ask("items");
      const bob = after.find((i) => i.id === saved?.id);
      check("a second sign-up doesn't replace the first account's password", bob?.password === v[0] && after.some((i) => i.password === v2 && i.id !== saved?.id), JSON.stringify(bob));
    } else check("a second sign-up doesn't replace the first account's password", false, "no menu");
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
  check("keeps the vault in two objects", keys.length === 2 && keys.some((k) => k.endsWith("/vault.bin")) && keys.some((k) => k.endsWith("/vault.json")), keys.join(", "));
  check("S3 never sees names, user names or passwords", !/alice|carol|s3cret|typed-by-hand|Test site|127\.0\.0\.1/.test(all));

  // Passkeys: a site creates one (confirmed in CleanPassword's window), then
  // signs in with it, from the window and from the sign-in field's menu.
  const LOCAL = WEB.replace("127.0.0.1", "localhost");
  await tab.goto(`${LOCAL}/passkey`);
  await sleep(300);
  const registering = tab.evaluate(() => window.register().then(() => "done", (e) => `${e.name}: ${e.message}`));
  const saveWin = await passkeyWindow();
  check("asks in a window of its own to save a passkey", !!saveWin);
  if (saveWin) {
    await saveWin.waitForSelector(".btn.primary");
    await sleep(500);
    await saveWin.click(".btn.primary");
  }
  const registered = await registering;
  check("the site gets the new passkey", registered === "done", registered);
  const created = await tab.evaluate(() => window.results.create);
  if (created) {
    const client = JSON.parse(created.clientDataJSON);
    check("with the right client data", client.type === "webauthn.create" && client.challenge === created.challenge && client.origin === LOCAL, created.clientDataJSON);
    const authData = fromB64(created.authData);
    check("authenticator data for localhost, with flags and the key", authData.subarray(0, 32).equals(createHash("sha256").update("localhost").digest()) && authData[32] === 0x5d && created.alg === -7);
    check("as a real PublicKeyCredential", created.isCredential && created.id === created.rawId && JSON.parse(created.json).response.publicKeyAlgorithm === -7);
    const items = await ask("items");
    const saved = items.find((i) => (i.passkeys ?? []).length === 1);
    check("saved on a new login for the site", !!saved && saved.username === "pat@example.com" && saved.passkeys[0].rp_id === "localhost", JSON.stringify(saved?.passkeys?.[0]?.rp_id));

    // Signing in, from the window.
    const signing = tab.evaluate(() => window.login().then(() => "done", (e) => `${e.name}: ${e.message}`));
    const useWin = await passkeyWindow();
    check("asks in a window to sign in with it", !!useWin);
    if (useWin) {
      await useWin.waitForSelector(".list .row");
      await sleep(500);
      await useWin.click(".list .row");
    }
    check("signs in", (await signing) === "done");
    const got = await tab.evaluate(() => window.results.get);
    check("with a signature the site's public key verifies", !!got && verifyAssertion(got, created.publicKey, LOCAL));
    check("and the account's user handle", got?.userHandle === "user-1" && got?.id === created.id);

    // Signing in from the sign-in field (conditional mediation).
    await tab.goto(`${LOCAL}/passkey`);
    await sleep(300);
    await tab.evaluate(() => {
      window.conditional = window.login("conditional");
    });
    await sleep(300);
    await tab.click("#u");
    const menu = await waitForFrame(tab, "menu.html");
    if (menu) {
      await menu.waitForSelector(".row.passkey", { timeout: 4000 }).catch(() => null);
      await sleep(700);
      const row = await menu.$(".row.passkey");
      check("offers the passkey in the sign-in field's menu", !!row);
      if (row) await row.click();
      const viaMenu = await tab.evaluate(() => Promise.race([window.conditional, new Promise((r) => setTimeout(() => r(null), 4000))]));
      check("and signs in with it from there", !!viaMenu && verifyAssertion(viaMenu, created.publicKey, LOCAL));
    } else check("offers the passkey in the sign-in field's menu", false);

    // The page asks, is reloaded before an answer, and asks again: the
    // menu answers the page now showing (not the one before).
    await tab.goto(`${LOCAL}/passkey`);
    await sleep(300);
    await tab.evaluate(() => void window.login("conditional").catch(() => {}));
    await sleep(300);
    await tab.reload();
    await sleep(300);
    await tab.evaluate(() => {
      window.conditional = window.login("conditional");
    });
    await sleep(300);
    await tab.click("#u");
    const again = await waitForFrame(tab, "menu.html");
    const againRow = again && (await again.waitForSelector(".row.passkey", { timeout: 4000 }).catch(() => null));
    if (againRow) {
      await sleep(700);
      await againRow.click();
    }
    const afterReload = await tab.evaluate(() => Promise.race([window.conditional, new Promise((r) => setTimeout(() => r(null), 4000))]));
    check("signs in from the menu after the page was reloaded", !!afterReload && verifyAssertion(afterReload, created.publicKey, LOCAL));
  }

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

  // The menu works, and stays, on pages with a modal dialog or a popover of
  // their own, and for fields in a closed shadow root.
  const fillsFromMenu = async (name, path, focus, read) => {
    await tab.goto(`${WEB}${path}`);
    await sleep(500);
    await focus();
    const f = await waitForFrame(tab, "menu.html");
    if (!f) return check(name, false, "no menu");
    await f.waitForSelector(".row");
    // Longer than the overlay's guard took to give up on such pages.
    await sleep(2000);
    if (!tab.frames().includes(f)) return check(name, false, "the menu closed");
    let picked = false;
    for (const r of await f.$$(".list .row")) {
      if ((await r.$eval(".title", (e) => e.textContent)) !== "Test site") continue;
      await r.click();
      picked = true;
      break;
    }
    if (!picked) return check(name, false, "no Test site row");
    await sleep(800);
    const v = await tab.evaluate(read);
    check(name, v.u === "alice@example.com" && v.p === "s3cret-Passw0rd", JSON.stringify(v));
  };
  const byId = () => ({ u: document.getElementById("u").value, p: document.getElementById("p").value });
  await fillsFromMenu("fills a sign-in form in a modal dialog", "/dialog", () => tab.click("#u"), byId);
  await fillsFromMenu("fills on a page with a popover open", "/popover", () => tab.click("#u"), byId);
  await fillsFromMenu(
    "fills a sign-in form in a closed shadow root",
    "/shadow",
    async () => {
      const r = await tab.$eval("login-box", (e) => e.getBoundingClientRect().toJSON());
      await tab.mouse.click(r.x + 20, r.y + 15);
    },
    () => ({ u: window.sr.getElementById("u").value, p: window.sr.getElementById("p").value }),
  );

  // The page can't move the focus into the menu (to have a key press pick a
  // login it didn't choose).
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const posted = await waitForFrame(tab, "menu.html");
  if (posted) {
    await posted.waitForSelector(".row");
    await tab.evaluate(() => {
      for (let i = 0; i < frames.length; i++) frames[i].postMessage({ type: "focus-first" }, "*");
    });
    await sleep(300);
    check("ignores messages the page posts to the menu", !(await posted.evaluate(() => document.activeElement?.classList.contains("row"))));
  } else check("ignores messages the page posts to the menu", false, "no menu");

  // Many logins: typing filters them, and Enter fills the first one left.
  for (const n of [1, 2, 3]) {
    await ask("add", { data: { kind: "login", name: `Extra ${n}`, username: `extra${n}@example.com`, password: `extra-password-${n}`, uris: [{ uri: WEB }], totp: "", notes: "", folder: "", favorite: false, fields: [] } });
  }
  await tab.goto(`${WEB}/login`);
  await sleep(500);
  await tab.click("#u");
  const many = await waitForFrame(tab, "menu.html");
  if (many && (await many.waitForSelector("input.filter", { timeout: 4000 }).catch(() => null))) {
    await sleep(700);
    const focused = () => many.evaluate(() => `${document.activeElement?.className}:${document.querySelector("input.filter")?.value}`).catch((e) => String(e));
    const steps = [];
    await tab.keyboard.press("ArrowDown");
    await sleep(200);
    steps.push(await focused());
    await tab.keyboard.press("ArrowUp");
    await sleep(200);
    steps.push(await focused());
    await tab.keyboard.type("Extra 2");
    await sleep(200);
    steps.push(await focused());
    await tab.keyboard.press("Enter");
    await sleep(800);
    const v = await tab.evaluate(byId);
    check("Enter in the menu's filter fills the login left", v.u === "extra2@example.com" && v.p === "extra-password-2", JSON.stringify({ v, steps }));
  } else check("Enter in the menu's filter fills the login left", false, "no menu or no filter");

  // A see-through page gets no menu.
  await tab.goto(`${WEB}/faded`);
  await sleep(500);
  await tab.click("#u");
  check("no menu on a see-through page (clickjacking)", !(await waitForFrame(tab, "menu.html", 1500)));
  // Adding the vault in S3 to a browser: progress while it downloads.
  const countBefore = (await ask("items")).length;
  await ask("forget");
  await popup.bringToFront();
  await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.waitForSelector('input[placeholder="my-bucket"]');
  await popup.type('input[placeholder="my-bucket"]', "vault-bucket");
  await popup.click("details summary");
  await popup.type('input[placeholder^="https://"]', `http://127.0.0.1:${s3.port}`);
  await popup.type('input[placeholder="AKIA…"]', "AKIATEST");
  await popup.type('input[placeholder="Secret access key"]', "secret");
  await popup.click("button[type=submit]");
  await popup.waitForSelector('input[placeholder="Master password"]', { timeout: 10000 });
  await popup.evaluate(() => {
    window.seen = [];
    new MutationObserver(() => {
      const t = document.querySelector(".progress:not([hidden]) .small")?.textContent;
      if (t && window.seen.at(-1) !== t) window.seen.push(t);
    }).observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true });
  });
  await popup.type('input[placeholder="Master password"]', "correct horse battery staple");
  await popup.click("button[type=submit]");
  await popup.waitForSelector("input.search", { timeout: 20000 });
  const seen = await popup.evaluate(() => window.seen);
  check("shows progress while unlocking and downloading a vault", seen[0]?.startsWith("Unlocking") && seen.includes("Downloading your passwords…"), JSON.stringify(seen));
  const countAfter = (await ask("items")).length;
  check("and has every item once it's done", countAfter === countBefore, `${countAfter} of ${countBefore}`);
} finally {
  await browser.close();
  web.close();
  s3.server.close();
  rmSync(ext, { recursive: true, force: true });
}

/** The passkey window, once it opens. */
async function passkeyWindow() {
  const t = await browser.waitForTarget((t) => t.url().includes("/passkey.html"), { timeout: 8000 }).catch(() => null);
  return t ? await t.page() : null;
}

function fromB64(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Checks a sign-in's signature as a site would. */
function verifyAssertion(r, publicKey, origin) {
  const client = JSON.parse(r.clientDataJSON);
  if (client.type !== "webauthn.get" || client.challenge !== r.challenge || client.origin !== origin) return false;
  const signed = Buffer.concat([fromB64(r.authData), createHash("sha256").update(r.clientDataJSON).digest()]);
  return verifySignature("sha256", signed, { key: fromB64(publicKey), format: "der", type: "spki" }, fromB64(r.signature));
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
