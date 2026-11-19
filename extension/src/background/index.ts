// The service worker: the only place the vault is ever decrypted.
//
// - The vault (the Rust core, as WebAssembly) is unlocked here. While
//   unlocked, its key is kept in chrome.storage.session (memory only, not
//   readable by content scripts) so the worker can restart without asking
//   for the master password again; locking removes it.
// - Extension pages (the popup, the inline menu and the save prompt) talk to
//   it with messages. Content scripts in web pages get only what they need:
//   a menu token, and the values for one fill, after the user picked a login
//   in the menu (an extension-origin iframe the page can't see into or click).
// - Which site a frame belongs to always comes from Chrome (sender.origin,
//   sender.url, webNavigation), never from the page.

import init, * as core from "../core/core.js";
import type { Credentials, FillValues, FormKind, Item, ItemData, Match, MenuState, PasskeyChoice, PasskeyState, PromptState, Recipe, Role, S3Config, Settings, Submission, SyncReport } from "../shared/types";
import { DEFAULT_SETTINGS } from "../shared/types";

const EXT_ORIGIN = new URL(chrome.runtime.getURL("")).origin;

// ---- The core ------------------------------------------------------------------

let ready: Promise<unknown> | null = null;
function loadCore(): Promise<unknown> {
  ready ??= init({ module_or_path: chrome.runtime.getURL("core.wasm") });
  return ready;
}

let session: core.Session | null = null;
let restoring: Promise<void> | null = null;

/** Runs `f` after any running sync (the core refuses calls during one). */
let queue: Promise<unknown> = Promise.resolve();
function exclusive<T>(f: () => Promise<T> | T): Promise<T> {
  const p = queue.then(f, f);
  queue = p.catch(() => {});
  return p;
}

async function restore(): Promise<void> {
  await loadCore();
  if (session) return;
  restoring ??= (async () => {
    const { key } = await chrome.storage.session.get("key");
    const { vault } = await chrome.storage.local.get("vault");
    if (typeof key === "string" && typeof vault === "string") {
      try {
        session = core.Session.unlockWithKey(vault, key);
      } catch {
        await chrome.storage.session.remove("key");
      }
    }
  })().finally(() => (restoring = null));
  await restoring;
}

async function settings(): Promise<Settings> {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(settings ?? {}) };
}

/** Chrome's own password manager: off while CleanPassword replaces it, or
 *  back to the user's choice in Chrome. Chrome itself undoes this when the
 *  extension is disabled or removed. */
async function applyReplaceChrome(): Promise<void> {
  const pw = chrome.privacy?.services?.passwordSavingEnabled;
  if (!pw) return;
  try {
    if ((await settings()).replaceChrome) await pw.set({ value: false });
    else await pw.clear({});
  } catch {}
}

async function becameUnlocked(s: core.Session): Promise<void> {
  session?.free();
  session = s;
  await chrome.storage.session.set({ key: s.keyB64() });
  await persist();
  touch();
  chrome.alarms.create("sync", { periodInMinutes: 5 });
  scheduleSync(0);
}

async function lock(): Promise<void> {
  await exclusive(async () => {
    if (session) {
      try {
        await chrome.storage.local.set({ vault: session.save() });
      } catch {}
      session.free();
      session = null;
    }
    await chrome.storage.session.remove("key");
    chrome.alarms.clear("sync");
    chrome.alarms.clear("autolock");
    tabLogins.clear();
    pendingSaves.clear();
    stepUsernames.clear();
    generatedIn.clear();
    // Menus opened before don't work after a later unlock.
    menus.clear();
    saveMenus();
  });
}

async function persist(): Promise<void> {
  if (session) await chrome.storage.local.set({ vault: session.save() });
}

/** Restarts the auto-lock timer. */
async function touch(): Promise<void> {
  const s = await settings();
  if (s.autoLockMinutes > 0) chrome.alarms.create("autolock", { delayInMinutes: s.autoLockMinutes });
  else chrome.alarms.clear("autolock");
}

// ---- S3 ----------------------------------------------------------------------

interface CoreRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body: Uint8Array;
}

const S3_TIMEOUT_MS = 30_000;

/** The core's transport: fetch, without following redirects or cookies. */
async function s3fetch(req: CoreRequest) {
  const resp = await fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
    redirect: "manual",
    credentials: "omit",
    cache: "no-store",
    // A stalled connection mustn't hold the queue (and with it locking) for
    // good: a sync is the only thing that waits on the network.
    signal: AbortSignal.timeout(S3_TIMEOUT_MS),
  });
  const headers: [string, string][] = [];
  resp.headers.forEach((v, k) => headers.push([k, v]));
  // A redirect (wrong region) comes back opaque, as status 0.
  const status = resp.type === "opaqueredirect" ? 301 : resp.status;
  return { status, headers, body: new Uint8Array(await resp.arrayBuffer()) };
}

let syncTimer: ReturnType<typeof setTimeout> | undefined;
let lastSync: { at: string; error: string | null; report: SyncReport | null } = { at: "", error: null, report: null };

function scheduleSync(delay = 2000): void {
  clearTimeout(syncTimer);
  syncTimer = setTimeout(() => void syncNow(), delay);
}

async function syncNow(): Promise<typeof lastSync> {
  return exclusive(async () => {
    if (!session) return lastSync;
    try {
      // How the download goes, for the popup (on joining a vault, it's
      // every item).
      const progress = (done: number, total: number) => void chrome.runtime.sendMessage({ type: "sync-progress", done, total }).catch(() => {});
      const report = (await session.sync(s3fetch, progress)) as SyncReport;
      lastSync = { at: new Date().toISOString(), error: null, report };
      await persist();
    } catch (e) {
      lastSync = { at: new Date().toISOString(), error: String((e as Error).message ?? e), report: null };
      await persist();
    }
    return lastSync;
  });
}

// ---- Pages and frames ------------------------------------------------------------

function originOf(url: string | undefined): string {
  try {
    return url ? new URL(url).origin : "";
  } catch {
    return "";
  }
}

function hostOf(url: string | undefined): string {
  try {
    return url ? new URL(url).hostname : "";
  } catch {
    return "";
  }
}

/** A web page's frame, as Chrome identifies it. */
interface FrameRef {
  tabId: number;
  frameId: number;
  documentId?: string;
  url: string;
  origin: string;
}

function frameOf(sender: chrome.runtime.MessageSender): FrameRef | null {
  if (!sender.tab?.id || sender.frameId === undefined || !sender.url) return null;
  const origin = sender.origin ?? originOf(sender.url);
  if (!/^https?:/.test(origin)) return null;
  return { tabId: sender.tab.id, frameId: sender.frameId, documentId: (sender as { documentId?: string }).documentId, url: sender.url, origin };
}

/** The top page's URL if the frame is embedded from another site, else null. */
async function embeddingPage(f: FrameRef): Promise<string | null> {
  if (f.frameId === 0) return null;
  const top = await chrome.webNavigation.getFrame({ tabId: f.tabId, frameId: 0 }).catch(() => null);
  if (!top?.url) return "an unknown page";
  const a = core.registrableDomain(hostOf(f.url));
  const b = core.registrableDomain(hostOf(top.url));
  return a === b ? null : hostOf(top.url);
}

/** Whether the frame still shows the same site (it may have navigated). */
async function stillThere(f: FrameRef): Promise<boolean> {
  const now = await chrome.webNavigation.getFrame({ tabId: f.tabId, frameId: f.frameId }).catch(() => null);
  return !!now?.url && originOf(now.url) === f.origin;
}

async function sendToFrame(f: FrameRef, msg: unknown): Promise<unknown> {
  const opts: chrome.tabs.MessageSendOptions = f.documentId ? { documentId: f.documentId } : { frameId: f.frameId };
  return chrome.tabs.sendMessage(f.tabId, msg, opts).catch(() => null);
}

// ---- Sign-ins in progress ---------------------------------------------------------

/** The login used in a tab, for the next steps of a sign-in (password after
 *  user name, then a one-time code). Memory only; 10 minutes. */
const tabLogins = new Map<number, { domain: string; itemId: string; at: number }>();

function tabLogin(tabId: number, url: string): string | null {
  const t = tabLogins.get(tabId);
  if (!t || Date.now() - t.at > 10 * 60_000 || t.domain !== core.registrableDomain(hostOf(url))) return null;
  return t.itemId;
}

/** Inline menus open in web pages, by token. */
interface MenuCtx {
  frame: FrameRef;
  role: Role;
  kind: FormKind;
  groupId: string;
  embeddedIn: string | null;
  suggestion: string | null;
  created: number;
}
const menus = new Map<string, MenuCtx>();
// Kept in session storage too: Chrome stops this worker after half a minute
// of quiet, and a menu still open on the page would then click to "expired".
const menusReady = chrome.storage.session
  .get("menus")
  .then(({ menus: saved }) => {
    for (const [k, v] of Object.entries((saved ?? {}) as Record<string, MenuCtx>)) if (!menus.has(k)) menus.set(k, v);
  })
  .catch(() => {});
function saveMenus(): void {
  void chrome.storage.session.set({ menus: Object.fromEntries(menus) }).catch(() => {});
}

/** The same login saved more than once (same user name, password and code),
 *  once: under the name used here before, or else the shortest, in the place
 *  of the best match. */
function unique(s: core.Session, matches: Match[], preferredId: string | null): Match[] {
  const byLogin = new Map<string, Match>();
  for (const m of matches) {
    const item = s.get(m.id) as Item | undefined;
    const key = item ? JSON.stringify([m.username.trim().toLowerCase(), item.password, item.totp]) : m.id;
    const prev = byLogin.get(key);
    if (!prev) byLogin.set(key, m);
    else if (prev.id !== preferredId && (m.id === preferredId || m.name.length < prev.name.length)) byLogin.set(key, { ...m, quality: prev.quality });
  }
  return [...byLogin.values()];
}

function token(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// ---- Filling ---------------------------------------------------------------------

/** Fills an item into a frame's group, after checking the item belongs to
 *  the frame's site (and the frame is still on it). */
async function fillItem(frame: FrameRef, groupId: string, kind: FormKind, itemId: string, allowAnySite = false): Promise<string | null> {
  if (!session) return "locked";
  const item = session.get(itemId) as Item | undefined;
  if (!item) return "no such item";
  const matched = (session.matches(frame.url) as Match[]).some((m) => m.id === itemId);
  if (!matched && !allowAnySite) return "this login isn't for this site";
  if (!(await stillThere(frame))) return "the page changed";
  const values: FillValues = {};
  if (kind === "otp") {
    if (!item.totp) return "no one-time code for this login";
    values.totp = (core.totpCode(item.totp) as { code: string }).code;
  } else {
    values.username = item.username;
    // Never a saved password into a new-password field.
    if (kind !== "signup" && kind !== "reset-password") values.password = item.password;
  }
  const r = (await sendToFrame(frame, { type: "fill", groupId, values })) as { ok?: boolean } | null;
  if (!r?.ok) return "couldn't fill";
  tabLogins.set(frame.tabId, { domain: core.registrableDomain(hostOf(frame.url)), itemId, at: Date.now() });
  if (!matched) {
    // Picked for another site: remember this one too (as Apple Passwords does).
    session.update(itemId, { ...item, uris: [...item.uris, { uri: frame.origin }] } as ItemData);
    await persist();
    scheduleSync();
  }
  touch();
  return null;
}

/** Fills a generated password into a sign-up or change-password form, and
 *  saves it right away so it can't be lost if the page fails. */
async function fillGenerated(frame: FrameRef, groupId: string, kind: FormKind, password: string): Promise<string | null> {
  if (!session) return "locked";
  if (!(await stillThere(frame))) return "the page changed";
  const r = (await sendToFrame(frame, { type: "fill", groupId, values: { newPassword: password } })) as { ok?: boolean; username?: string } | null;
  if (!r?.ok) return "couldn't fill";
  const domain = core.registrableDomain(hostOf(frame.url));
  const existing = tabLogin(frame.tabId, frame.url);
  const prev = existing ? (session.get(existing) as Item | undefined) : undefined;
  // Only a password change replaces the password of the login used here
  // (without a user name in the form, it's that login's). A sign-up form
  // is another account, unless it names this one's user.
  const changing = kind === "change-password" || kind === "reset-password";
  const sameUser = !!r.username && !!prev && prev.username.toLowerCase() === r.username.toLowerCase();
  let id: string;
  if (prev && (sameUser || (changing && !r.username))) {
    // A password change for the login used here: update it (the old
    // password goes into its history).
    session.update(prev.id, { ...prev, password } as ItemData);
    id = prev.id;
  } else {
    id = session.add({ kind: "login", name: domain, username: r.username ?? "", password, uris: [{ uri: frame.origin }], totp: "", notes: "", folder: "", favorite: false, fields: [] });
  }
  tabLogins.set(frame.tabId, { domain, itemId: id, at: Date.now() });
  generatedIn.set(frame.tabId, { itemId: id, password, at: Date.now() });
  await persist();
  scheduleSync();
  return null;
}

/** Passwords generated and saved in a tab, so their submission doesn't ask
 *  to save them again (only fills in the user name). */
const generatedIn = new Map<number, { itemId: string; password: string; at: number }>();

// ---- Saving what was typed ------------------------------------------------------

interface PendingSave {
  token: string;
  kind: "save" | "update";
  itemId: string | null;
  url: string;
  username: string;
  password: string;
  at: number;
}
const pendingSaves = new Map<number, PendingSave>();
/** How long a save is offered after the sign-in. */
const PROMPT_TTL_MS = 2 * 60_000;

/** The save waiting in a tab, if it's recent enough. */
function pendingSave(tabId: number | undefined): PendingSave | undefined {
  if (tabId === undefined) return undefined;
  const p = pendingSaves.get(tabId);
  if (p && Date.now() - p.at > PROMPT_TTL_MS) {
    pendingSaves.delete(tabId);
    void chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
    return undefined;
  }
  return p;
}
/** User names entered at the first step of a sign-in, by tab. */
const stepUsernames = new Map<number, { domain: string; username: string; at: number }>();

async function submitted(frame: FrameRef, s: Submission): Promise<void> {
  const cfg = await settings();
  if (!session || !cfg.offerToSave || cfg.neverSave.includes(frame.origin)) return;
  const domain = core.registrableDomain(hostOf(frame.url));
  // Step one of a multi-step sign-in: remember the user name for step two.
  if (!s.password && !s.newPassword) {
    if (s.username) stepUsernames.set(frame.tabId, { domain, username: s.username, at: Date.now() });
    return;
  }
  const password = s.newPassword || s.password;
  // Empty, or a site's mask ("••••"): nothing to save.
  if (password.length < 2 || /^(\W)\1+$/.test(password)) return;
  const step = stepUsernames.get(frame.tabId);
  const username = s.username || (step && step.domain === domain && Date.now() - step.at < 10 * 60_000 ? step.username : "");

  const gen = generatedIn.get(frame.tabId);
  if (gen && gen.password === password && Date.now() - gen.at < 30 * 60_000) {
    const item = session.get(gen.itemId) as Item | undefined;
    if (item && username && !item.username) {
      session.update(item.id, { ...item, username } as ItemData);
      await persist();
      scheduleSync();
    }
    return;
  }

  const matches = (session.siteLogins(frame.url) as Match[]).filter((m) => m.quality !== "related");
  const items = matches.map((m) => session!.get(m.id) as Item);
  let target: Item | undefined;
  if (username) {
    // The same user name on another host of the domain is often another
    // account (www.amazon.com and signin.aws.amazon.com): only a login saved
    // for this host is updated; elsewhere, only an exact match counts (as
    // already saved), and a different password is saved as a new login.
    const sameUser = (i: Item) => i.username.toLowerCase() === username.toLowerCase();
    target = items.find((i, n) => matches[n].quality === "host" && sameUser(i)) ?? items.find((i) => sameUser(i) && i.password === password);
  }
  // A change-password form without a user name: the login whose password
  // was entered as the current one, else the one used in this tab.
  if (!target && s.newPassword && s.password) target = items.find((i) => i.password === s.password);
  if (!target && !username) {
    const used = tabLogin(frame.tabId, frame.url);
    target = items.find((i) => i.id === used);
  }
  if (target && target.password === password) return;
  if (!target && items.some((i) => i.password === password && !username)) return;

  pendingSaves.set(frame.tabId, {
    token: token(),
    kind: target ? "update" : "save",
    itemId: target?.id ?? null,
    url: frame.url,
    username: username || target?.username || "",
    password,
    at: Date.now(),
  });
  // Shown once the page has settled (a sign-in usually navigates).
  setTimeout(() => void showPrompt(frame.tabId), 1500);
}

async function showPrompt(tabId: number): Promise<void> {
  const p = pendingSave(tabId);
  if (!p) return;
  const top = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null);
  // Only on the same site (a sign-in may redirect elsewhere): otherwise a
  // badge, and the popup offers it.
  if (!top?.url || core.registrableDomain(hostOf(top.url)) !== core.registrableDomain(hostOf(p.url))) {
    chrome.action.setBadgeText({ tabId, text: "1" });
    return;
  }
  await chrome.tabs.sendMessage(tabId, { type: "show-prompt", token: p.token }, { frameId: 0 }).catch(() => null);
}

async function answerPrompt(p: PendingSave, tabId: number, answer: string): Promise<void> {
  pendingSaves.delete(tabId);
  chrome.action.setBadgeText({ tabId, text: "" });
  if (!session) return;
  if (answer === "never") {
    const s = await settings();
    s.neverSave.push(originOf(p.url));
    await chrome.storage.local.set({ settings: s });
    return;
  }
  if (answer !== "save") return;
  const item = p.kind === "update" && p.itemId ? (session.get(p.itemId) as Item | undefined) : undefined;
  if (item) {
    // (Deleted meanwhile: saved as a new login instead.)
    session.update(item.id, { ...item, password: p.password, username: item.username || p.username } as ItemData);
  } else {
    session.add({ kind: "login", name: core.registrableDomain(hostOf(p.url)), username: p.username, password: p.password, uris: [{ uri: originOf(p.url) }], totp: "", notes: "", folder: "", favorite: false, fields: [] });
  }
  await persist();
  scheduleSync();
}

// ---- Passkeys ----------------------------------------------------------------------
//
// Pages ask through src/webauthn (navigator.credentials.create and .get).
// The site is the frame's origin as Chrome reports it; its relying party id
// must be that host or a domain above it (not a public suffix). Creating a
// passkey, or signing in with one, is confirmed in a window of
// CleanPassword's own: a page can't cover or click into another window. A
// page asking in its sign-in field (conditional mediation) gets its passkeys
// in the inline menu instead. Whatever CleanPassword can't do goes to
// Chrome's own passkey support.

type PasskeyAnswer = { fallback: true } | { error: { name: string; message: string } } | { result: Record<string, unknown> };

interface PasskeyRequest {
  frame: FrameRef;
  /** The page's id for the request (to cancel it). */
  pageId: number;
  kind: "create" | "get";
  options: Record<string, any>;
  rpId: string;
  conditional: boolean;
  windowId?: number;
  resolve: (a: PasskeyAnswer) => void;
}
const passkeyRequests = new Map<string, PasskeyRequest>();

const NOT_ALLOWED = { error: { name: "NotAllowedError", message: "The operation either timed out or was not allowed." } };

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256b64(text: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

function finishPasskey(token: string, answer: PasskeyAnswer): void {
  const r = passkeyRequests.get(token);
  if (!r) return;
  passkeyRequests.delete(token);
  r.resolve(answer);
  if (r.windowId !== undefined) void chrome.windows.remove(r.windowId).catch(() => {});
}

/** Whether two refs are the same document (as far as Chrome said). */
function sameDocument(a: FrameRef, b: FrameRef): boolean {
  return a.tabId === b.tabId && a.frameId === b.frameId && (!a.documentId || !b.documentId || a.documentId === b.documentId);
}

/** The waiting conditional request of a frame's document, if any (the
 *  newest: a page asking again replaces what it asked before). */
function conditionalFor(f: FrameRef): string | undefined {
  let found: string | undefined;
  for (const [t, r] of passkeyRequests) if (r.conditional && sameDocument(r.frame, f)) found = t;
  return found;
}

function idsOf(list: unknown): string[] {
  return Array.isArray(list) ? list.map((c: { id: string }) => c.id) : [];
}

function conditionalChoices(f: FrameRef): PasskeyChoice[] {
  const t = conditionalFor(f);
  const r = t ? passkeyRequests.get(t) : undefined;
  if (!r || !session) return [];
  return session.passkeysFor(r.rpId, idsOf(r.options.allowCredentials)) as PasskeyChoice[];
}

async function webauthn(frame: FrameRef, msg: Msg): Promise<PasskeyAnswer> {
  const kind = msg.kind as "create" | "get";
  const o = (msg.options ?? {}) as PasskeyRequest["options"];
  // Only top frames (embedded sign-ins need permissions this can't check).
  if (frame.frameId !== 0) return { fallback: true };
  const rpId = String((kind === "create" ? o.rp?.id : o.rpId) || hostOf(frame.url)).toLowerCase();
  if (!core.rpIdAllowed(rpId, frame.origin)) return { fallback: true };
  if (!(await chrome.storage.local.get("vault")).vault) return { fallback: true };
  await restore();
  const conditional = kind === "get" && msg.mediation === "conditional";
  if (kind === "create") {
    if (!(o.pubKeyCredParams ?? []).some((p: { alg: number }) => p.alg === -7)) return { fallback: true };
    if (o.authenticatorSelection?.authenticatorAttachment === "cross-platform") return { fallback: true };
  } else if (session) {
    const s = session;
    const choices = await exclusive(() => s.passkeysFor(rpId, idsOf(o.allowCredentials)) as PasskeyChoice[]);
    if (!choices.length) return { fallback: true };
  } else if (conditional) {
    return { fallback: true };
  }
  // One window per tab at a time: a page can't open a stream of them.
  if (!conditional) {
    for (const r of passkeyRequests.values()) if (r.frame.tabId === frame.tabId && !r.conditional) return NOT_ALLOWED;
  }
  // A page asking in its sign-in field again: the request before is over.
  if (conditional) {
    for (const [t, r] of passkeyRequests) if (r.conditional && sameDocument(r.frame, frame)) finishPasskey(t, NOT_ALLOWED);
  }
  return new Promise<PasskeyAnswer>((resolve) => {
    const t = token();
    const req: PasskeyRequest = { frame, pageId: Number(msg.id), kind, options: o, rpId, conditional, resolve };
    passkeyRequests.set(t, req);
    if (conditional) return; // answered from the inline menu
    void chrome.windows
      .create({ url: chrome.runtime.getURL("passkey.html#" + t), type: "popup", width: 420, height: 560, focused: true })
      .then((w) => {
        if (passkeyRequests.has(t)) req.windowId = w?.id;
        else if (w?.id !== undefined) void chrome.windows.remove(w.id).catch(() => {});
      })
      // No window, no way to answer: Chrome's own passkeys instead (and the
      // tab isn't left blocked by a request no one can see).
      .catch(() => finishPasskey(t, { fallback: true }));
  });
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [t, r] of passkeyRequests) if (r.windowId === windowId) finishPasskey(t, NOT_ALLOWED);
});

function passkeyState(token: string): PasskeyState | null {
  const r = passkeyRequests.get(token);
  if (!r) return null;
  const o = r.options;
  const s = session;
  return {
    kind: r.kind,
    host: hostOf(r.frame.url),
    rpId: r.rpId,
    rpName: String(o.rp?.name ?? ""),
    userName: String(o.user?.name ?? ""),
    locked: !s,
    choices: s && r.kind === "get" ? (s.passkeysFor(r.rpId, idsOf(o.allowCredentials)) as PasskeyChoice[]) : [],
    logins:
      s && r.kind === "create"
        ? (s.siteLogins("https://" + r.rpId) as Match[]).filter((m) => m.quality !== "related").map((m) => ({ id: m.id, name: m.name, username: m.username }))
        : [],
    excluded: !!s && r.kind === "create" && (s.passkeyExcluded(r.rpId, idsOf(o.excludeCredentials)) as boolean),
  };
}

async function passkeyAssertion(r: PasskeyRequest, itemId: string, credentialId: string): Promise<Record<string, unknown>> {
  const s = session;
  if (!s) throw new Error("locked");
  const cdj = core.clientDataJson("webauthn.get", String(r.options.challenge), r.frame.origin, false);
  const a = s.assertPasskey(itemId, credentialId, r.rpId, await sha256b64(cdj)) as Record<string, string>;
  await persist();
  scheduleSync();
  return { id: a.credential_id, clientDataJSON: b64url(new TextEncoder().encode(cdj)), authenticatorData: a.authenticator_data, signature: a.signature, userHandle: a.user_handle };
}

async function passkeyAnswer(token: string, msg: Msg): Promise<{ error: string | null }> {
  const r = passkeyRequests.get(token);
  if (!r) return { error: "This request has ended." };
  switch (msg.action) {
    case "fallback":
      finishPasskey(token, { fallback: true });
      return { error: null };
    case "cancel":
      finishPasskey(token, NOT_ALLOWED);
      return { error: null };
    case "excluded":
      finishPasskey(token, { error: { name: "InvalidStateError", message: "A passkey for this account is already saved." } });
      return { error: null };
  }
  const s = session;
  if (!s) return { error: "Unlock CleanPassword first." };
  // The tab must still show the site that asked.
  if (!(await stillThere(r.frame))) {
    finishPasskey(token, NOT_ALLOWED);
    return { error: "The page changed." };
  }
  touch();
  if (msg.action === "use") {
    finishPasskey(token, { result: await passkeyAssertion(r, String(msg.itemId), String(msg.credentialId)) });
    return { error: null };
  }
  if (msg.action === "create") {
    const o = r.options;
    const cdj = core.clientDataJson("webauthn.create", String(o.challenge), r.frame.origin, false);
    const reg = s.createPasskey(
      { rp_id: r.rpId, rp_name: o.rp?.name ?? "", user_handle: o.user?.id ?? "", user_name: o.user?.name ?? "", user_display_name: o.user?.displayName ?? "" },
      (msg.itemId as string) || undefined,
    ) as Record<string, string>;
    await persist();
    scheduleSync();
    finishPasskey(token, {
      result: {
        id: reg.credential_id,
        clientDataJSON: b64url(new TextEncoder().encode(cdj)),
        attestationObject: reg.attestation_object,
        authenticatorData: reg.authenticator_data,
        publicKey: reg.public_key,
      },
    });
    return { error: null };
  }
  return { error: "unknown action" };
}

// ---- Messages ------------------------------------------------------------------

type Msg = { type: string; [k: string]: unknown };

/** Messages from the content script in web pages: they may come from a page
 *  that's hostile, so they get no vault data back. */
async function fromPage(msg: Msg, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const frame = frameOf(sender);
  if (!frame) return null;
  switch (msg.type) {
    case "menu-open": {
      const cfg = await settings();
      if (!cfg.inlineMenu || cfg.menuOff.includes(frame.origin)) return null;
      await restore();
      const role = msg.role as Role;
      const kind = msg.kind as FormKind;
      // Nothing to offer: no menu (a locked vault still offers unlocking,
      // where there's a vault at all).
      if (!session && !(await chrome.storage.local.get("vault")).vault) return null;
      const passkeysWaiting = conditionalFor(frame) !== undefined;
      if (session && !passkeysWaiting && (role === "username" || role === "current-password") && kind !== "signup" && (session.matches(frame.url) as Match[]).length === 0) return null;
      if (session && role === "otp" && !tabLogin(frame.tabId, frame.url)) return null;
      const t = token();
      const embeddedIn = await embeddingPage(frame);
      const suggestion = role === "new-password" || role === "confirm-password" ? core.generateForSite(hostOf(frame.url), (msg.passwordRules as string) || undefined) : null;
      menus.set(t, { frame, role, kind, groupId: String(msg.groupId), embeddedIn, suggestion, created: Date.now() });
      // Old tokens go.
      for (const [k, m] of menus) if (Date.now() - m.created > 30 * 60_000) menus.delete(k);
      saveMenus();
      return { token: t };
    }
    case "menu-closed":
      if (menus.delete(String(msg.token))) saveMenus();
      return null;
    case "webauthn":
      return webauthn(frame, msg);
    case "webauthn-cancel": {
      for (const [t, r] of passkeyRequests) {
        if (r.frame.tabId === frame.tabId && r.frame.frameId === frame.frameId && r.pageId === msg.id) finishPasskey(t, { error: { name: "AbortError", message: "The operation was aborted." } });
      }
      return null;
    }
    case "submitted":
      await restore();
      await submitted(frame, msg.data as Submission);
      return null;
    case "prompt-pending": {
      // The top frame of a page that just loaded asks if a save is waiting.
      if (frame.frameId !== 0) return null;
      const p = pendingSave(frame.tabId);
      if (p && core.registrableDomain(hostOf(p.url)) === core.registrableDomain(hostOf(frame.url))) return { token: p.token };
      return null;
    }
    case "command-target": {
      // The focused frame answers a keyboard shortcut or context menu: only
      // just after one was given in this tab.
      const issued = commandsIssued.get(frame.tabId);
      commandsIssued.delete(frame.tabId);
      if (!issued || Date.now() - issued.at > 3000 || issued.which !== msg.which) return null;
      await restore();
      if (!session) {
        await openPopup();
        return null;
      }
      // A form from another site, embedded in this page: the menu asks first
      // (docs/autofill.md); a shortcut can't, so it doesn't fill there.
      if (await embeddingPage(frame)) return null;
      const groupId = String(msg.groupId);
      if (msg.which === "generate") {
        const pw = core.generateForSite(hostOf(frame.url), (msg.passwordRules as string) || undefined);
        await fillGenerated(frame, groupId, msg.kind as FormKind, pw);
        return null;
      }
      const matches = session.matches(frame.url) as Match[];
      const preferred = tabLogin(frame.tabId, frame.url);
      const pick = matches.find((m) => m.id === preferred) ?? matches[0];
      if (pick) await fillItem(frame, groupId, msg.kind as FormKind, pick.id);
      return null;
    }
  }
  return null;
}

/** The tab whose page a popup action is for. The popup opened as a window
 *  of its own (when Chrome can't open it under its button) is itself the
 *  last focused window: then it's the browser window's tab. */
async function activeTab(sender: chrome.runtime.MessageSender): Promise<chrome.tabs.Tab | undefined> {
  if (sender.tab && new URL(sender.url ?? EXT_ORIGIN).searchParams.has("window")) {
    const w = await chrome.windows.getLastFocused({ windowTypes: ["normal"] }).catch(() => null);
    if (w?.id === undefined) return undefined;
    const [tab] = await chrome.tabs.query({ active: true, windowId: w.id });
    return tab;
  }
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

async function openPopup(): Promise<void> {
  try {
    await chrome.action.openPopup();
  } catch {
    await chrome.windows.create({ url: chrome.runtime.getURL("popup.html?window=1"), type: "popup", width: 380, height: 600 });
  }
}

/** Messages from the extension's own pages. */
async function fromExtension(msg: Msg, sender: chrome.runtime.MessageSender): Promise<unknown> {
  await restore();
  if (session) touch();
  switch (msg.type) {
    // -- Setup and locking
    case "state": {
      const { vault } = await chrome.storage.local.get("vault");
      const info = typeof vault === "string" ? core.lockedInfo(vault) : null;
      return { state: session ? "unlocked" : vault ? "locked" : "setup", info, lastSync, unsynced: session?.hasUnsyncedChanges() ?? false };
    }
    case "probe": {
      const found = await core.fetchHeader(msg.config, msg.credentials, s3fetch);
      return { exists: !!found };
    }
    case "create": {
      const s = core.Session.create(msg.config, msg.credentials, String(msg.password));
      await becameUnlocked(s);
      return { ok: true };
    }
    case "join": {
      const found = (await core.fetchHeader(msg.config, msg.credentials, s3fetch)) as { header: string; etag: string } | null;
      if (!found) throw new Error("there's no vault in that folder any more");
      const s = core.Session.join(msg.config, msg.credentials, found.header, found.etag, String(msg.password));
      await becameUnlocked(s);
      return { ok: true };
    }
    case "unlock": {
      const { vault } = await chrome.storage.local.get("vault");
      const s = core.Session.unlock(String(vault), String(msg.password));
      await becameUnlocked(s);
      return { ok: true };
    }
    case "lock":
      await lock();
      return { ok: true };
    case "forget": {
      // Removes the vault from this browser (not from S3).
      await lock();
      await chrome.storage.local.remove("vault");
      return { ok: true };
    }
    case "settings":
      return settings();
    case "set-settings": {
      const s = { ...(await settings()), ...(msg.settings as Partial<Settings>) };
      await chrome.storage.local.set({ settings: s });
      if ("replaceChrome" in (msg.settings as object)) await applyReplaceChrome();
      touch();
      return s;
    }
    case "generate":
      return core.generatePassword(msg.recipe as Recipe);
    case "passkey-state":
      return passkeyState(String(msg.token));
    case "passkey-answer":
      return passkeyAnswer(String(msg.token), msg);
    case "strength":
      return core.strength(String(msg.password));
  }

  // Everything else needs the vault unlocked.
  const s = session;
  if (!s) throw new Error("locked");
  const changed = async <T>(v: T): Promise<T> => {
    await persist();
    scheduleSync();
    return v;
  };
  switch (msg.type) {
    case "items":
      return s.items();
    case "trash":
      return s.trash();
    case "get":
      return s.get(String(msg.id));
    case "folders":
      return s.folders();
    case "search":
      return s.search(String(msg.query));
    case "audit":
      return s.audit();
    case "duplicates":
      return s.duplicates();
    case "merge-duplicates":
      return changed(s.mergeDuplicates());
    case "totp":
      return s.totp(String(msg.id));
    case "add":
      return changed(s.add(msg.data));
    case "update":
      return changed(s.update(String(msg.id), msg.data));
    case "delete":
      return changed(s.delete(String(msg.id)));
    case "restore":
      return changed(s.restore(String(msg.id)));
    case "delete-passkey":
      return changed(s.deletePasskey(String(msg.id), String(msg.credentialId)));
    case "purge":
      return changed(s.purge(String(msg.id)));
    case "sync":
      return syncNow();
    case "import":
      return changed(s.importFile(String(msg.text), (msg.password as string) || undefined));
    case "import-needs-password":
      return core.importNeedsPassword(String(msg.text));
    case "export":
      return s.exportJson();
    case "change-password":
      return changed(s.changeMasterPassword(String(msg.current), String(msg.password)));
    case "set-credentials":
      return changed(s.setCredentials(msg.credentials as Credentials));
    case "account":
      return { config: s.config() as S3Config, accessKeyId: s.accessKeyId(), lastSync: s.lastSync() };

    // -- The page in the current tab (from the popup)
    case "tab-matches": {
      const tab = await activeTab(sender);
      const url = tab?.url ?? "";
      return { host: hostOf(url), matches: /^https?:/.test(url) ? unique(s, s.matches(url) as Match[], tab?.id ? tabLogin(tab.id, url) : null) : [], pending: pendingSave(tab?.id) ?? null };
    }
    case "tab-fill": {
      // From the popup (a user gesture): fill the page's focused (or first)
      // sign-in form in the top frame.
      const tab = await activeTab(sender);
      if (!tab?.id) return { error: "no page" };
      // One document: the fill goes to the page that said where to fill, not
      // to one the tab has navigated to since.
      const top = await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 }).catch(() => null);
      if (!top?.url) return { error: "no page" };
      const documentId = (top as { documentId?: string }).documentId;
      const frame: FrameRef = { tabId: tab.id, frameId: 0, documentId, url: top.url, origin: originOf(top.url) };
      const target = (await chrome.tabs.sendMessage(tab.id, { type: "fill-target" }, documentId ? { documentId } : { frameId: 0 }).catch(() => null)) as { groupId: string; kind: FormKind } | null;
      if (!target) return { error: "There's no sign-in form on this page." };
      return { error: await fillItem(frame, target.groupId, target.kind, String(msg.id), !!msg.anySite) };
    }
    case "tab-answer-prompt": {
      const tab = await activeTab(sender);
      const p = pendingSave(tab?.id);
      if (p && tab?.id) await answerPrompt(p, tab.id, String(msg.answer));
      return null;
    }

    // -- The inline menu (an extension iframe in a page)
    case "menu-state": {
      const m = menus.get(String(msg.token));
      if (!m || sender.tab?.id !== m.frame.tabId) return null;
      const preferredId = tabLogin(m.frame.tabId, m.frame.url);
      const matches = (session ? unique(s, s.matches(m.frame.url) as Match[], preferredId) : []).filter(() => m.role !== "new-password" || m.kind === "change-password");
      const state: MenuState = {
        locked: false,
        role: m.role,
        kind: m.kind,
        host: hostOf(m.frame.url),
        matches,
        embeddedIn: m.embeddedIn,
        suggestion: m.suggestion,
        preferredId,
        totpIds: matches.filter((x) => !!(s.get(x.id) as Item | undefined)?.totp).map((x) => x.id),
        passkeys: m.role === "username" || m.role === "current-password" ? conditionalChoices(m.frame) : [],
      };
      return state;
    }
    case "menu-passkey": {
      // A passkey picked in the sign-in field's menu, for the page's
      // waiting (conditional) request.
      const m = menus.get(String(msg.token));
      if (!m || sender.tab?.id !== m.frame.tabId) return { error: "expired" };
      const t = conditionalFor(m.frame);
      const req = t ? passkeyRequests.get(t) : undefined;
      if (!req || !t) return { error: "The page isn't asking for a passkey any more." };
      if (!(await stillThere(req.frame))) {
        finishPasskey(t, NOT_ALLOWED);
        return { error: "The page changed." };
      }
      finishPasskey(t, { result: await passkeyAssertion(req, String(msg.itemId), String(msg.credentialId)) });
      touch();
      return { error: null };
    }
    case "menu-fill": {
      const m = menus.get(String(msg.token));
      if (!m || sender.tab?.id !== m.frame.tabId) return { error: "expired" };
      const kind: FormKind = m.role === "otp" ? "otp" : m.kind;
      return { error: await fillItem(m.frame, m.groupId, kind, String(msg.id)) };
    }
    case "menu-generate": {
      const m = menus.get(String(msg.token));
      if (!m || sender.tab?.id !== m.frame.tabId || !m.suggestion) return { error: "expired" };
      return { error: await fillGenerated(m.frame, m.groupId, m.kind, m.suggestion) };
    }
    case "menu-off": {
      const m = menus.get(String(msg.token));
      if (!m) return null;
      const st = await settings();
      st.menuOff.push(m.frame.origin);
      await chrome.storage.local.set({ settings: st });
      return null;
    }

    // -- The save prompt (an extension iframe in a page)
    case "prompt-state": {
      const p = pendingSave(sender.tab?.id);
      if (!p || p.token !== msg.token) return null;
      const item = p.itemId ? (s.get(p.itemId) as Item | undefined) : undefined;
      const state: PromptState = { kind: p.kind, host: hostOf(p.url), username: p.username, name: item?.name ?? core.registrableDomain(hostOf(p.url)) };
      return state;
    }
    case "prompt-answer": {
      const tabId = sender.tab?.id;
      const p = pendingSave(tabId);
      if (!p || !tabId || p.token !== msg.token) return null;
      await answerPrompt(p, tabId, String(msg.answer));
      return null;
    }
  }
  throw new Error(`unknown message ${msg.type}`);
}

/** Menu messages when locked: the menu offers to unlock. */
async function lockedMenu(msg: Msg, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const m = menus.get(String(msg.token));
  if (!m || sender.tab?.id !== m.frame.tabId) return null;
  if (msg.type === "menu-state") {
    const state: MenuState = { locked: true, role: m.role, kind: m.kind, host: hostOf(m.frame.url), matches: [], embeddedIn: m.embeddedIn, suggestion: null, preferredId: null, totpIds: [], passkeys: [] };
    return state;
  }
  if (msg.type === "menu-unlock") await openPopup();
  return null;
}

chrome.runtime.onMessage.addListener((msg: Msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id || typeof msg?.type !== "string") return false;
  const fromOurPage = sender.url?.startsWith(EXT_ORIGIN + "/") ?? false;
  const handle = async () => {
    await menusReady;
    if (!fromOurPage) return fromPage(msg, sender);
    await restore();
    if (!session && msg.type.startsWith("menu-")) return lockedMenu(msg, sender);
    return fromExtension(msg, sender);
  };
  // Vault calls wait for a running sync (these three queue themselves).
  // A passkey request waits for the user, so it doesn't hold the queue (its
  // vault calls queue themselves).
  const queued = ["sync", "lock", "forget", "webauthn", "webauthn-cancel"].includes(msg.type) ? handle() : exclusive(handle);
  queued.then(
    (value) => reply({ ok: true, value }),
    (e: unknown) => reply({ ok: false, error: String((e as Error)?.message ?? e), name: (e as Error)?.name }),
  );
  return true;
});

// ---- Browser events ----------------------------------------------------------------

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "autolock") await lock();
  if (a.name === "sync") {
    await restore();
    if (session) await syncNow();
  }
});

chrome.idle.onStateChanged.addListener(async (state) => {
  if (state === "locked" && (await settings()).lockOnIdle) await lock();
});

chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId === 0) void showPrompt(d.tabId);
});

// A frame showing a new document: what the old one asked for is over (its
// page is gone, and a request kept would answer the next page's instead).
chrome.webNavigation.onCommitted.addListener((d) => {
  const now = { tabId: d.tabId, frameId: d.frameId, documentId: (d as { documentId?: string }).documentId, url: d.url, origin: "" };
  for (const [t, r] of passkeyRequests) {
    if (r.frame.tabId === d.tabId && r.frame.frameId === d.frameId && !(now.documentId && r.frame.documentId === now.documentId)) finishPasskey(t, NOT_ALLOWED);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabLogins.delete(tabId);
  pendingSaves.delete(tabId);
  generatedIn.delete(tabId);
  stepUsernames.delete(tabId);
  for (const [t, r] of passkeyRequests) if (r.frame.tabId === tabId) finishPasskey(t, { error: { name: "NotAllowedError", message: "The tab was closed." } });
});

/** Keyboard shortcuts and context-menu commands given, by tab. */
const commandsIssued = new Map<number, { which: string; at: number }>();

chrome.commands.onCommand.addListener(async (command, tab) => {
  if (!tab?.id || (command !== "fill" && command !== "generate")) return;
  commandsIssued.set(tab.id, { which: command, at: Date.now() });
  // Each frame checks whether it has the focus; that one answers.
  await chrome.tabs.sendMessage(tab.id, { type: "command", which: command }).catch(() => null);
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "fill", title: "Fill login", contexts: ["editable"] });
  chrome.contextMenus.create({ id: "generate", title: "Fill a strong password", contexts: ["editable"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  commandsIssued.set(tab.id, { which: String(info.menuItemId), at: Date.now() });
  await chrome.tabs.sendMessage(tab.id, { type: "command", which: info.menuItemId }, { frameId: info.frameId ?? 0 }).catch(() => null);
});

void restore();
void applyReplaceChrome();
