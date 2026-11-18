// The popup (the toolbar button): setting up the vault, unlocking it, and
// everything done with it. All vault work happens in the service worker;
// this page asks it with messages.

import type { Credentials, Item, ItemData, Match, Recipe, S3Config, Settings, SyncReport } from "../shared/types";
import { ask, copy, CoreError, h, monogram } from "../shared/ui";

const app = document.getElementById("app")!;
if (new URLSearchParams(location.search).has("window")) document.body.classList.add("window");

interface State {
  state: "setup" | "locked" | "unlocked";
  info: { config: S3Config; vault_id: string; last_sync: string | null } | null;
  lastSync: { at: string; error: string | null; report: SyncReport | null };
  unsynced: boolean;
}

// ---- Plumbing ------------------------------------------------------------------------

function screen(title: string | Node, left: Node | null, right: Node[], ...body: (Node | null)[]): void {
  app.replaceChildren(
    h("header", {}, left, typeof title === "string" ? h("h1", {}, title) : title, ...right),
    h("div", { class: "content" }, ...body),
  );
}

function back(to: () => void): HTMLButtonElement {
  return h("button", { class: "icon", title: "Back", "aria-label": "Back", onclick: to }, "‹");
}

function errorBox(): HTMLDivElement {
  return h("div", { class: "error", role: "alert" });
}

async function run(err: HTMLElement, f: () => Promise<void>, button?: HTMLButtonElement): Promise<void> {
  err.textContent = "";
  if (button) button.disabled = true;
  try {
    await f();
  } catch (e) {
    err.textContent = e instanceof CoreError && e.kind === "WrongPassword" ? "That's not the master password." : (e as Error).message;
  } finally {
    if (button) button.disabled = false;
  }
}

function input(attrs: Record<string, string | boolean>): HTMLInputElement {
  return h("input", { autocomplete: "off", spellcheck: "false", ...attrs });
}

function strengthMeter(): { el: HTMLElement; update: (pw: string) => Promise<void> } {
  const bar = h("div", { style: "width:0" });
  const label = h("span", { class: "small muted" });
  const el = h("div", {}, h("div", { class: "meter" }, bar), label);
  return {
    el,
    update: async (pw: string) => {
      const s = await ask<{ bits: number; score: number }>("strength", { password: pw });
      const colors = ["#ff3b30", "#ff9500", "#ffcc00", "#34c759", "#30b158"];
      const words = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
      bar.style.width = `${(s.score + 1) * 20}%`;
      bar.style.background = colors[s.score];
      label.textContent = pw ? words[s.score] : "";
    },
  };
}

// ---- Start ------------------------------------------------------------------------------

async function start(): Promise<void> {
  const s = await ask<State>("state");
  if (s.state === "setup") return setup();
  if (s.state === "locked") return unlock(s);
  return home();
}

// ---- Setup ----------------------------------------------------------------------------------

function setup(prefill?: { config: S3Config; credentials: Credentials }): void {
  const bucket = input({ placeholder: "my-bucket", value: prefill?.config.bucket ?? "" });
  const region = input({ placeholder: "us-east-1", value: prefill?.config.region ?? "us-east-1" });
  const prefix = input({ placeholder: "CleanPassword", value: prefill?.config.prefix ?? "CleanPassword" });
  const endpoint = input({ placeholder: "https://… (only for R2, MinIO, …)", value: prefill?.config.endpoint ?? "" });
  const keyId = input({ placeholder: "AKIA…", value: prefill?.credentials.access_key_id ?? "" });
  const secret = input({ type: "password", placeholder: "Secret access key", value: prefill?.credentials.secret_access_key ?? "" });
  const err = errorBox();
  const go = h("button", { class: "btn primary", type: "submit" }, "Continue");
  const form = h("form", { class: "form" },
    h("label", {}, "Bucket", bucket),
    h("label", {}, "Region", region),
    h("label", {}, "Folder in the bucket", prefix),
    h("details", {}, h("summary", { class: "small muted" }, "S3-compatible service"), h("label", { style: "margin-top:8px" }, "Endpoint", endpoint)),
    h("label", {}, "Access key ID", keyId),
    h("label", {}, "Secret access key", secret),
    err,
    h("div", { style: "display:flex; justify-content:flex-end" }, go),
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      const config: S3Config = { bucket: bucket.value.trim(), region: region.value.trim(), prefix: prefix.value.trim(), endpoint: endpoint.value.trim() || null };
      const credentials: Credentials = { access_key_id: keyId.value.trim(), secret_access_key: secret.value.trim() };
      if (config.endpoint) {
        // Another service's address needs the browser's permission.
        const origin = new URL(config.endpoint).origin + "/*";
        if (!(await chrome.permissions.request({ origins: [origin] }))) throw new Error("CleanPassword needs permission to reach that address.");
      }
      const { exists } = await ask<{ exists: boolean }>("probe", { config, credentials });
      choosePassword(config, credentials, exists);
    }, go);
  });
  screen("CleanPassword", null, [],
    h("div", { class: "welcome" },
      h("h2", {}, "Your passwords, in your own S3 bucket"),
      h("p", { class: "muted" }, "Everything is encrypted on this device with your master password before it goes to S3. Use an IAM user that can only reach this bucket (see the README)."),
    ),
    form,
  );
}

function choosePassword(config: S3Config, credentials: Credentials, exists: boolean): void {
  const pw = input({ type: "password", autocomplete: "new-password", placeholder: "Master password" });
  const again = input({ type: "password", autocomplete: "new-password", placeholder: "Again" });
  const meter = strengthMeter();
  const err = errorBox();
  const go = h("button", { class: "btn primary", type: "submit" }, exists ? "Unlock" : "Create vault");
  pw.addEventListener("input", () => void meter.update(pw.value));
  const form = h("form", { class: "form" },
    exists
      ? h("p", { class: "muted" }, `There's a vault in ${config.bucket}/${config.prefix}. Enter its master password to use it here.`)
      : h("p", { class: "muted" }, "Choose a master password: at least 12 characters, ideally a few unrelated words. It can't be recovered if you forget it."),
    h("label", {}, "Master password", pw),
    exists ? null : meter.el,
    exists ? null : h("label", {}, "Confirm", again),
    err,
    h("div", { style: "display:flex; justify-content:flex-end" }, go),
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      if (!exists && pw.value !== again.value) throw new Error("The passwords don't match.");
      await ask(exists ? "join" : "create", { config, credentials, password: pw.value });
      await home();
    }, go);
  });
  screen(exists ? "Unlock vault" : "New vault", back(() => setup({ config, credentials })), [], form);
  pw.focus();
}

// ---- Unlock --------------------------------------------------------------------------------

function unlock(s: State): void {
  const pw = input({ type: "password", autocomplete: "current-password", placeholder: "Master password" });
  const err = errorBox();
  const go = h("button", { class: "btn primary", type: "submit" }, "Unlock");
  const form = h("form", { class: "form", style: "margin-top: 40px" },
    h("div", { style: "text-align:center; font-size:36px" }, "🔒"),
    h("p", { class: "muted", style: "text-align:center" }, s.info ? `${s.info.config.bucket}/${s.info.config.prefix}` : ""),
    pw, err,
    h("div", { style: "display:flex; justify-content:center" }, go),
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      await ask("unlock", { password: pw.value });
      await home();
    }, go);
  });
  screen("CleanPassword", null, [], form,
    h("div", { style: "text-align:center; padding: 20px" },
      h("button", { class: "link small", onclick: () => void forget() }, "Remove the vault from this browser…")),
  );
  pw.focus();
}

async function forget(): Promise<void> {
  if (!confirm("Remove the vault from this browser? It stays in S3 (unless changes here haven't synced yet), and you can add it again with the bucket's keys and the master password.")) return;
  await ask("forget");
  await start();
}

// ---- Home: suggestions for this page, and everything --------------------------------------

let query = "";

async function home(): Promise<void> {
  const search = input({ class: "search", type: "search", placeholder: "Search", value: query });
  const list = h("div", {});
  const status = h("div", { class: "status" });
  const right = [
    h("button", { class: "icon", title: "New item", "aria-label": "New item", onclick: () => edit(null) }, "+"),
    h("button", { class: "icon", title: "Generator", "aria-label": "Password generator", onclick: () => void generator() }, "⚄"),
    h("button", { class: "icon", title: "Settings", "aria-label": "Settings", onclick: () => void settingsView() }, "⚙"),
    h("button", { class: "icon", title: "Lock", "aria-label": "Lock", onclick: async () => (await ask("lock"), await start()) }, "🔒"),
  ];
  screen(search, null, right, list);
  app.append(status);
  const draw = async () => {
    query = search.value;
    const [tab, items] = await Promise.all([
      ask<{ host: string; matches: Match[]; pending: { kind: string; username: string } | null }>("tab-matches"),
      ask<Item[]>(query ? "search" : "items", { query }),
    ]);
    const nodes: Node[] = [];
    if (tab.pending && !query) {
      nodes.push(h("div", { class: "warn", style: "margin: 4px" },
        `${tab.pending.kind === "update" ? "Update" : "Save"} the password for ${tab.host}${tab.pending.username ? ` (${tab.pending.username})` : ""}? `,
        h("button", { class: "link", onclick: async () => (await ask("tab-answer-prompt", { answer: "save" }), draw()) }, tab.pending.kind === "update" ? "Update" : "Save"),
        " · ",
        h("button", { class: "link", onclick: async () => (await ask("tab-answer-prompt", { answer: "dismiss" }), draw()) }, "Not now"),
      ));
    }
    if (tab.matches.length && !query) {
      nodes.push(h("div", { class: "section" }, `For ${tab.host}`));
      for (const m of tab.matches) nodes.push(matchRow(m));
    }
    const favorites = items.filter((i) => i.favorite);
    if (favorites.length && !query) {
      nodes.push(h("div", { class: "section" }, "Favorites"));
      for (const i of favorites) nodes.push(itemRow(i));
    }
    nodes.push(h("div", { class: "section" }, query ? `${items.length} found` : `All items (${items.length})`));
    for (const i of items) nodes.push(itemRow(i));
    if (!items.length && !query) nodes.push(h("p", { class: "muted", style: "padding: 0 12px" }, "No items yet. Add one with +, or import from Bitwarden in Settings."));
    list.replaceChildren(...nodes);
  };
  search.addEventListener("input", () => void draw());
  await draw();
  await drawStatus(status);
  search.focus();
}

async function drawStatus(el: HTMLElement): Promise<void> {
  const s = await ask<State>("state");
  const when = s.lastSync.at ? new Date(s.lastSync.at).toLocaleTimeString() : "never";
  el.replaceChildren(
    h("span", {}, s.lastSync.error ? `⚠ ${s.lastSync.error}` : `Synced ${when}${s.unsynced ? " · changes waiting" : ""}`),
    h("button", { class: "link small", onclick: async () => {
      el.firstChild!.textContent = "Syncing…";
      await ask("sync");
      await drawStatus(el);
    } }, "Sync now"),
  );
}

function matchRow(m: Match): HTMLElement {
  const fill = h("button", { class: "btn small fill", onclick: async (e: Event) => {
    e.stopPropagation();
    const r = await ask<{ error: string | null }>("tab-fill", { id: m.id });
    if (r.error) alert(r.error);
    else window.close();
  } }, "Fill");
  return h("div", { class: "row", role: "button", tabindex: "0", onclick: () => void detail(m.id) },
    monogram(m.name), h("span", { class: "text" }, h("div", { class: "title" }, m.name), h("div", { class: "sub" }, m.username || "No user name")), fill);
}

function itemRow(i: Item): HTMLElement {
  const sub = i.kind === "note" ? "Secure note" : i.username || hostOf(i.uris[0]?.uri) || "";
  return h("button", { class: "row", onclick: () => void detail(i.id) },
    monogram(i.name), h("span", { class: "text" }, h("div", { class: "title" }, i.name), h("div", { class: "sub" }, sub)),
    i.folder ? h("span", { class: "pill" }, i.folder) : null);
}

function hostOf(u: string | undefined): string {
  if (!u) return "";
  try {
    return new URL(u.includes("://") ? u : `https://${u}`).hostname;
  } catch {
    return u;
  }
}

// ---- An item ------------------------------------------------------------------------------

function copyButton(text: () => string, label = "Copy"): HTMLButtonElement {
  const b = h("button", { class: "btn small" }, label);
  b.addEventListener("click", async () => {
    await copy(text());
    b.textContent = "Copied";
    setTimeout(() => (b.textContent = label), 1200);
  });
  return b;
}

function field(k: string, v: Node | string, ...buttons: Node[]): HTMLElement {
  return h("div", { class: "field" }, h("div", { class: "grow" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v)), ...buttons);
}

function secretField(k: string, value: string): HTMLElement {
  const v = h("span", { class: "secret" }, "••••••••••");
  let shown = false;
  const reveal = h("button", { class: "btn small" }, "Show");
  reveal.addEventListener("click", () => {
    shown = !shown;
    v.textContent = shown ? value : "••••••••••";
    reveal.textContent = shown ? "Hide" : "Show";
  });
  return field(k, v, reveal, copyButton(() => value));
}

async function detail(id: string): Promise<void> {
  const i = await ask<Item | null>("get", { id });
  if (!i) return home();
  const cards: Node[] = [];
  const main: Node[] = [];
  if (i.username) main.push(field("User name", i.username, copyButton(() => i.username)));
  if (i.password) main.push(secretField("Password", i.password));
  let timer: ReturnType<typeof setInterval> | undefined;
  if (i.totp) {
    const code = h("span", { class: "secret totp" });
    const left = h("span", { class: "small muted" });
    let current = "";
    const tick = async () => {
      try {
        const c = await ask<{ code: string; remaining: number }>("totp", { id });
        current = c.code;
        code.textContent = c.code.length === 6 ? `${c.code.slice(0, 3)} ${c.code.slice(3)}` : c.code;
        left.textContent = ` ${c.remaining}s`;
      } catch {
        code.textContent = "Invalid secret";
      }
    };
    await tick();
    timer = setInterval(() => void tick(), 1000);
    main.push(field("One-time code", h("span", {}, code, left), copyButton(() => current)));
  }
  if (main.length) cards.push(h("div", { class: "card" }, ...main));
  if (i.uris.length) {
    cards.push(h("div", { class: "card" }, ...i.uris.map((u) =>
      field("Website", u.uri, h("button", { class: "btn small", onclick: () => chrome.tabs.create({ url: u.uri.includes("://") ? u.uri : `https://${u.uri}` }) }, "Open")))));
  }
  if (i.fields.length) cards.push(h("div", { class: "card" }, ...i.fields.map((f) => (f.hidden ? secretField(f.name, f.value) : field(f.name, f.value, copyButton(() => f.value))))));
  if (i.notes) cards.push(h("div", { class: "card" }, field("Notes", h("div", { style: "white-space:pre-wrap" }, i.notes))));
  if (i.history.length) {
    cards.push(h("details", { class: "card", style: "padding: 8px 12px" },
      h("summary", { class: "small muted" }, `Password history (${i.history.length})`),
      ...i.history.map((p) => field(new Date(p.retired).toLocaleString(), h("span", { class: "secret" }, p.password), copyButton(() => p.password)))));
  }
  const leave = (to: () => void) => () => {
    clearInterval(timer);
    to();
  };
  cards.push(h("p", { class: "small muted", style: "padding: 0 12px" }, `Modified ${new Date(i.modified).toLocaleString()}${i.folder ? ` · ${i.folder}` : ""}`));
  screen(h("div", { style: "display:flex; gap:8px; align-items:center; flex:1; min-width:0" }, monogram(i.name), h("h1", {}, i.name)),
    back(leave(() => void home())),
    [
      h("button", { class: "btn small", onclick: leave(() => edit(i)) }, "Edit"),
    ],
    ...cards,
    h("div", { class: "actions" },
      h("button", { class: "btn danger", onclick: async () => {
        if (!confirm(`Move “${i.name}” to the trash?`)) return;
        clearInterval(timer);
        await ask("delete", { id });
        await home();
      } }, "Delete"),
    ),
  );
}

// ---- Editing --------------------------------------------------------------------------------

function edit(item: Item | null): void {
  const d: ItemData = item
    ? { kind: item.kind, name: item.name, username: item.username, password: item.password, uris: item.uris, totp: item.totp, notes: item.notes, folder: item.folder, favorite: item.favorite, fields: item.fields }
    : { kind: "login", name: "", username: "", password: "", uris: [], totp: "", notes: "", folder: "", favorite: false, fields: [] };
  const kind = h("select", {}, h("option", { value: "login" }, "Login"), h("option", { value: "note" }, "Secure note"));
  kind.value = d.kind;
  const name = input({ value: d.name, placeholder: "Name" });
  const username = input({ value: d.username, placeholder: "User name or email" });
  const password = input({ value: d.password, type: "password", autocomplete: "new-password", placeholder: "Password" });
  const meter = strengthMeter();
  password.addEventListener("input", () => void meter.update(password.value));
  void meter.update(d.password);
  const reveal = h("button", { class: "btn small", type: "button", onclick: () => (password.type = password.type === "password" ? "text" : "password") }, "👁");
  const gen = h("button", { class: "btn small", type: "button", title: "Generate", onclick: async () => {
    const s = await ask<Settings>("settings");
    password.value = await ask<string>("generate", { recipe: s.recipe });
    password.type = "text";
    void meter.update(password.value);
  } }, "Generate");
  const uris = h("div", { style: "display:flex; flex-direction:column; gap:6px" });
  const addUri = (v = "") => {
    const i = input({ value: v, placeholder: "https://example.com" });
    const row = h("div", { class: "inline" }, i, h("button", { class: "btn small", type: "button", onclick: () => row.remove() }, "−"));
    uris.append(row);
  };
  d.uris.forEach((u) => addUri(u.uri));
  if (!d.uris.length) addUri("");
  const uriMatch = new Map(d.uris.map((u) => [u.uri, u.match]));
  const totp = input({ value: d.totp, placeholder: "otpauth://… or the secret" });
  const folder = input({ value: d.folder, placeholder: "Folder", list: "folders" });
  const folders = h("datalist", { id: "folders" });
  void ask<string[]>("folders").then((fs) => folders.replaceChildren(...fs.map((f) => h("option", { value: f }))));
  const favorite = h("input", { type: "checkbox", checked: d.favorite });
  const notes = h("textarea", {}, d.notes);
  const err = errorBox();
  const save = h("button", { class: "btn primary", type: "submit" }, "Save");
  const loginOnly = [h("label", {}, "User name", username), h("label", {}, "Password", h("div", { class: "inline" }, password, reveal, gen), meter.el), h("label", {}, "Websites", uris, h("button", { class: "link small", type: "button", style: "align-self:flex-start", onclick: () => addUri() }, "Add website")), h("label", {}, "One-time code (TOTP)", totp)];
  const sync = () => loginOnly.forEach((n) => (n.style.display = kind.value === "login" ? "" : "none"));
  kind.addEventListener("change", sync);
  sync();
  const form = h("form", { class: "form" },
    h("label", {}, "Kind", kind), h("label", {}, "Name", name), ...loginOnly,
    h("label", {}, "Folder", folder, folders), h("label", { class: "check" }, favorite, "Favorite"), h("label", {}, "Notes", notes),
    err, h("div", { style: "display:flex; justify-content:flex-end; gap:8px" }, save),
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      const data: ItemData = {
        ...d,
        kind: kind.value as ItemData["kind"],
        name: name.value,
        username: username.value,
        password: password.value,
        uris: Array.from(uris.querySelectorAll("input")).map((i) => i.value.trim()).filter(Boolean).map((uri) => ({ uri, match: uriMatch.get(uri) ?? null })),
        totp: totp.value.trim(),
        folder: folder.value,
        favorite: favorite.checked,
        notes: notes.value,
      };
      if (item) {
        await ask("update", { id: item.id, data });
        await detail(item.id);
      } else {
        const id = await ask<string>("add", { data });
        await detail(id);
      }
    }, save);
  });
  screen(item ? "Edit" : "New item", back(() => (item ? void detail(item.id) : void home())), [], form);
  name.focus();
}

// ---- Generator ---------------------------------------------------------------------------------

async function generator(): Promise<void> {
  const st = await ask<Settings>("settings");
  let recipe: Recipe = st.recipe;
  const out = h("div", { class: "generated secret" });
  const options = h("div", { class: "form" });
  const kinds: [Recipe["kind"], string][] = [["apple", "Apple-style"], ["random", "Random"], ["passphrase", "Words"]];
  const seg = h("div", { class: "seg" });
  const regenerate = async () => {
    out.textContent = await ask<string>("generate", { recipe });
    await ask("set-settings", { settings: { recipe } });
  };
  const drawOptions = () => {
    seg.replaceChildren(...kinds.map(([k, label]) => h("button", { class: recipe.kind === k ? "on" : "", onclick: () => {
      recipe = k === "apple" ? { kind: "apple" } : k === "random" ? { kind: "random", length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: false } : { kind: "passphrase", words: 5, separator: "-", capitalize: false, number: true };
      drawOptions();
      void regenerate();
    } }, label)));
    const r = recipe;
    const nodes: Node[] = [];
    const check = (label: string, key: string) => {
      const c = h("input", { type: "checkbox", checked: (r as unknown as Record<string, boolean>)[key] });
      c.addEventListener("change", () => {
        (recipe as unknown as Record<string, boolean>)[key] = c.checked;
        void regenerate();
      });
      return h("label", { class: "check" }, c, label);
    };
    if (r.kind === "random") {
      const len = input({ type: "range", min: "8", max: "64", value: String(r.length) });
      const lenLabel = h("span", {}, `Length ${r.length}`);
      len.addEventListener("input", () => {
        r.length = Number(len.value);
        lenLabel.textContent = `Length ${r.length}`;
        void regenerate();
      });
      nodes.push(h("label", {}, lenLabel, len), check("a–z", "lowercase"), check("A–Z", "uppercase"), check("0–9", "digits"), check("!@#$…", "symbols"), check("Avoid look-alikes (l, 1, O, 0)", "avoid_ambiguous"));
    } else if (r.kind === "passphrase") {
      const words = input({ type: "range", min: "3", max: "10", value: String(r.words) });
      const wl = h("span", {}, `${r.words} words`);
      words.addEventListener("input", () => {
        r.words = Number(words.value);
        wl.textContent = `${r.words} words`;
        void regenerate();
      });
      nodes.push(h("label", {}, wl, words), check("Capitalize", "capitalize"), check("Add a number", "number"));
    } else {
      nodes.push(h("p", { class: "muted small" }, "Like Safari's: three groups of six letters with one capital and one digit. Easy to type, about 71 bits, accepted almost everywhere."));
    }
    options.replaceChildren(seg, ...nodes);
  };
  drawOptions();
  await regenerate();
  screen("Generator", back(() => void home()), [], h("div", { class: "card" }, out), h("div", { class: "actions" },
    h("button", { class: "btn", onclick: () => void regenerate() }, "Regenerate"), copyButton(() => out.textContent ?? "")), options);
}

// ---- Settings ---------------------------------------------------------------------------------

async function settingsView(): Promise<void> {
  const st = await ask<Settings>("settings");
  const acct = await ask<{ config: S3Config; accessKeyId: string; lastSync: string | null }>("account");
  const save = (patch: Partial<Settings>) => void ask("set-settings", { settings: patch });
  const lockMin = h("select", {}, ...[1, 5, 15, 30, 60, 240, 0].map((m) => h("option", { value: String(m) }, m === 0 ? "When the browser closes" : `After ${m} minutes`)));
  lockMin.value = String(st.autoLockMinutes);
  lockMin.addEventListener("change", () => save({ autoLockMinutes: Number(lockMin.value) }));
  const toggle = (label: string, key: keyof Settings) => {
    const c = h("input", { type: "checkbox", checked: !!st[key] });
    c.addEventListener("change", () => save({ [key]: c.checked } as Partial<Settings>));
    return h("label", { class: "check" }, c, label);
  };
  const exceptions = st.neverSave.length + st.menuOff.length;
  screen("Settings", back(() => void home()), [],
    h("div", { class: "section" }, "Vault"),
    h("div", { class: "card" },
      field("S3", `${acct.config.bucket}/${acct.config.prefix} (${acct.config.region})${acct.config.endpoint ? ` · ${acct.config.endpoint}` : ""}`),
      field("Access key", acct.accessKeyId, h("button", { class: "btn small", onclick: () => changeKeys() }, "Change")),
    ),
    h("div", { class: "section" }, "Security"),
    h("div", { class: "form" }, h("label", {}, "Lock automatically", lockMin), toggle("Lock when the computer locks", "lockOnIdle")),
    h("div", { class: "card" },
      h("button", { class: "row", onclick: () => void audit() }, h("span", { class: "text" }, h("div", { class: "title" }, "Security recommendations"), h("div", { class: "sub" }, "Weak and reused passwords"))),
      h("button", { class: "row", onclick: () => changePassword() }, h("span", { class: "text" }, h("div", { class: "title" }, "Change master password"))),
    ),
    h("div", { class: "section" }, "Autofill"),
    h("div", { class: "form" }, toggle("Show suggestions in sign-in fields", "inlineMenu"), toggle("Offer to save passwords", "offerToSave"),
      exceptions ? h("button", { class: "link small", style: "align-self:flex-start", onclick: () => { save({ neverSave: [], menuOff: [] }); void settingsView(); } }, `Forget ${exceptions} site exception(s)`) : null),
    h("div", { class: "section" }, "Data"),
    h("div", { class: "card" },
      h("button", { class: "row", onclick: () => importView() }, h("span", { class: "text" }, h("div", { class: "title" }, "Import"), h("div", { class: "sub" }, "From Bitwarden (JSON or CSV), Chrome, Safari, Firefox, 1Password, LastPass"))),
      h("button", { class: "row", onclick: () => void exportVault() }, h("span", { class: "text" }, h("div", { class: "title" }, "Export"), h("div", { class: "sub" }, "As unencrypted Bitwarden JSON"))),
      h("button", { class: "row", onclick: () => void trashView() }, h("span", { class: "text" }, h("div", { class: "title" }, "Recently deleted"))),
    ),
    h("div", { class: "actions", style: "margin-top: 12px" }, h("button", { class: "btn danger", onclick: () => void forget() }, "Remove vault from this browser")),
  );
}

function changeKeys(): void {
  const keyId = input({ placeholder: "Access key ID" });
  const secret = input({ type: "password", placeholder: "Secret access key" });
  const err = errorBox();
  const go = h("button", { class: "btn primary", type: "submit" }, "Save");
  const form = h("form", { class: "form" }, h("label", {}, "Access key ID", keyId), h("label", {}, "Secret access key", secret), err, h("div", { style: "display:flex; justify-content:flex-end" }, go));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      await ask("set-credentials", { credentials: { access_key_id: keyId.value.trim(), secret_access_key: secret.value.trim() } });
      const r = await ask<{ error: string | null }>("sync");
      if (r.error) throw new Error(r.error);
      await settingsView();
    }, go);
  });
  screen("AWS access key", back(() => void settingsView()), [], form);
}

function changePassword(): void {
  const current = input({ type: "password", autocomplete: "current-password" });
  const pw = input({ type: "password", autocomplete: "new-password" });
  const again = input({ type: "password", autocomplete: "new-password" });
  const meter = strengthMeter();
  pw.addEventListener("input", () => void meter.update(pw.value));
  const err = errorBox();
  const go = h("button", { class: "btn primary", type: "submit" }, "Change");
  const form = h("form", { class: "form" },
    h("label", {}, "Current master password", current), h("label", {}, "New master password", pw), meter.el, h("label", {}, "Confirm", again),
    h("p", { class: "small muted" }, "Other devices will need the new password from their next sync on."), err,
    h("div", { style: "display:flex; justify-content:flex-end" }, go));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      if (pw.value !== again.value) throw new Error("The new passwords don't match.");
      await ask("change-password", { current: current.value, password: pw.value });
      await ask("sync");
      await settingsView();
    }, go);
  });
  screen("Master password", back(() => void settingsView()), [], form);
}

async function audit(): Promise<void> {
  const entries = await ask<{ id: string; name: string; weak: boolean; reused: number }[]>("audit");
  screen("Security recommendations", back(() => void settingsView()), [],
    entries.length
      ? h("div", {}, ...entries.map((e) => h("button", { class: "row", onclick: () => void detail(e.id) }, monogram(e.name),
        h("span", { class: "text" }, h("div", { class: "title" }, e.name), h("div", { class: "sub" }, [e.reused ? `Reused on ${e.reused} other item(s)` : "", e.weak ? "Weak" : ""].filter(Boolean).join(" · "))))))
      : h("p", { class: "muted", style: "padding: 12px" }, "No weak or reused passwords. 👍"));
}

async function trashView(): Promise<void> {
  const items = await ask<Item[]>("trash");
  screen("Recently deleted", back(() => void settingsView()), [],
    h("p", { class: "small muted", style: "padding: 0 12px" }, "Items are deleted for good after 30 days."),
    ...items.map((i) => h("div", { class: "row" }, monogram(i.name), h("span", { class: "text" }, h("div", { class: "title" }, i.name), h("div", { class: "sub" }, i.username)),
      h("button", { class: "btn small", onclick: async () => (await ask("restore", { id: i.id }), trashView()) }, "Recover"),
      h("button", { class: "btn small danger", onclick: async () => {
        if (confirm(`Delete “${i.name}” for good, on every device?`)) {
          await ask("purge", { id: i.id });
          await trashView();
        }
      } }, "Delete"))));
}

function importView(): void {
  const file = h("input", { type: "file", accept: ".json,.csv,text/csv,application/json" });
  const pw = input({ type: "password", placeholder: "The export's password" });
  const pwLabel = h("label", { style: "display:none" }, "This export is password-protected", pw);
  const err = errorBox();
  const result = h("div", {});
  const go = h("button", { class: "btn primary", type: "submit" }, "Import");
  let text = "";
  file.addEventListener("change", async () => {
    text = (await file.files?.[0]?.text()) ?? "";
    pwLabel.style.display = (await ask<boolean>("import-needs-password", { text })) ? "" : "none";
  });
  const form = h("form", { class: "form" },
    h("p", { class: "small muted" }, "In Bitwarden: Tools → Export vault, as .json. Choosing “Password protected” keeps the file encrypted; CleanPassword decrypts it here. Delete unencrypted exports once imported."),
    file, pwLabel, err, result, h("div", { style: "display:flex; justify-content:flex-end" }, go));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void run(err, async () => {
      if (!text) throw new Error("Choose the export file.");
      const r = await ask<{ added: number; skipped: number; warnings: string[] }>("import", { text, password: pw.value });
      text = "";
      result.replaceChildren(h("p", {}, `Imported ${r.added} item(s)${r.skipped ? `; ${r.skipped} were already here` : ""}.`), ...r.warnings.map((w) => h("p", { class: "warn" }, w)));
      void ask("sync");
    }, go);
  });
  screen("Import", back(() => void settingsView()), [], form);
}

async function exportVault(): Promise<void> {
  if (!confirm("The export holds every password unencrypted. Keep it safe and delete it when you're done. Export?")) return;
  const json = await ask<string>("export");
  const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
  const a = h("a", { href: url, download: `cleanpassword-export-${new Date().toISOString().slice(0, 10)}.json` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

start().catch((e: Error) => {
  app.replaceChildren(h("div", { class: "form" }, h("div", { class: "error" }, e.message)));
});
