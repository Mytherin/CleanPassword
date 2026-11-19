// The content script, in every frame of every web page. It finds sign-in
// forms, shows the inline menu on them, fills what the service worker sends
// after the user picked a login, and notices sign-ins to offer saving them.
// It never holds the vault: it gets the values for one fill at a time.

import type { FillValues, Submission } from "../shared/types";
import { deepContains, scan, type Group } from "./classify";
import { fillGroup } from "./fill";
import { Overlay } from "./overlay";

let groups: Group[] = [];
const menu = new Overlay("menu.html", "below");
const prompt = new Overlay("prompt.html", "corner");
let menuToken: string | null = null;
let menuField: HTMLInputElement | null = null;
/** No menu while a fill moves the focus through the fields, and just after. */
let fillingUntil = 0;

function send<T = unknown>(msg: Record<string, unknown>): Promise<T | null> {
  return chrome.runtime
    .sendMessage(msg)
    .then((r: { ok: boolean; value: T } | undefined) => (r?.ok ? r.value : null))
    .catch(() => null);
}

// ---- Scanning --------------------------------------------------------------------

let scanTimer: ReturnType<typeof setTimeout> | undefined;
function rescan(): void {
  groups = scan(document);
}
function rescanSoon(): void {
  clearTimeout(scanTimer);
  scanTimer = setTimeout(rescan, 350);
}

function groupOf(el: Element | null): Group | undefined {
  if (!(el instanceof HTMLInputElement)) return undefined;
  return groups.find((g) => g.roles.has(el));
}

/** An element's shadow root, closed ones too (through chrome.dom). */
function shadowRootOf(el: Element): ShadowRoot | null {
  if (el.shadowRoot) return el.shadowRoot;
  try {
    return chrome.dom?.openOrClosedShadowRoot?.(el as HTMLElement) ?? null;
  } catch {
    return null;
  }
}

/** The focused element inside `el`'s shadow roots, or `el`. */
function focusedWithin(el: Element | null): Element | null {
  let a = el;
  for (let r = a && shadowRootOf(a); r?.activeElement; r = shadowRootOf(a!)) a = r.activeElement;
  return a;
}

/** The element with the focus, inside shadow roots too. */
function deepActive(): Element | null {
  return focusedWithin(document.activeElement);
}

/** The element an event is for. Events from inside a closed shadow root
 *  reach the document as if from its host: then it's the focused element
 *  inside that host (where a click or a key goes). */
function eventTarget(e: Event): Element | null {
  const t = e.composedPath()[0] as Element;
  return t instanceof HTMLInputElement ? t : focusedWithin(t);
}

// ---- The inline menu ---------------------------------------------------------------

menu.onClose = () => {
  if (menuToken) void send({ type: "menu-closed", token: menuToken });
  menuToken = null;
  menuField = null;
};

/** The field a menu is being asked for (focus and click both ask). */
let opening: HTMLInputElement | null = null;

async function openMenu(field: HTMLInputElement): Promise<void> {
  const g = groupOf(field);
  const role = g?.roles.get(field);
  if (!g || !role || menu.disabled) return;
  if (Date.now() < fillingUntil) return;
  if ((menuField === field && menu.isOpen) || opening === field) return;
  const r = field.getBoundingClientRect();
  if (r.width < 60) return;
  opening = field;
  let res: { token: string } | null;
  try {
    res = await send<{ token: string }>({ type: "menu-open", role, kind: g.kind, groupId: g.id, passwordRules: g.passwordRules });
  } finally {
    if (opening === field) opening = null;
  }
  if (!res) return;
  // The focus may have moved on meanwhile.
  if (deepActive() !== field) {
    void send({ type: "menu-closed", token: res.token });
    return;
  }
  // Showing closes the menu before (which reports its own token closed).
  menu.show(res.token, field);
  if (menu.isOpen) {
    menuToken = res.token;
    menuField = field;
  }
}

document.addEventListener(
  "focusin",
  (e) => {
    if (!e.isTrusted) return;
    const target = eventTarget(e);
    if (!(target instanceof HTMLInputElement)) return;
    if (!groupOf(target)) rescan();
    void openMenu(target);
  },
  true,
);

document.addEventListener(
  "click",
  (e) => {
    if (!e.isTrusted) return;
    const target = eventTarget(e);
    if (target instanceof HTMLInputElement && groupOf(target) && !menu.isOpen) void openMenu(target);
    if (target) maybeSubmitClick(target);
  },
  true,
);

document.addEventListener(
  "focusout",
  () => {
    // Moving into the menu itself keeps it open.
    setTimeout(() => {
      const a = document.activeElement;
      if (menu.isOpen && a !== menu.element && deepActive() !== menuField) menu.close();
    }, 150);
  },
  true,
);

document.addEventListener(
  "keydown",
  (e) => {
    if (!e.isTrusted) return;
    const target = eventTarget(e);
    if (menu.isOpen && target === menuField) {
      if (e.key === "Escape") menu.close();
      else if (e.key === "ArrowDown") {
        e.preventDefault();
        menu.focusInside();
      }
    }
    if (e.key === "Enter" && target instanceof HTMLInputElement) {
      const g = groupOf(target);
      if (g) capture(g);
    }
  },
  true,
);

document.addEventListener(
  "input",
  (e) => {
    // Typing: the menu steps aside (as Safari's does).
    if (e.isTrusted && menu.isOpen && eventTarget(e) === menuField) menu.close();
  },
  true,
);

window.addEventListener("resize", () => menu.close());

// ---- The save prompt -------------------------------------------------------------------

let promptToken: string | null = null;

/** Shows the save prompt, unless it's already showing this one (showing it
 *  again would start its click delay over). */
function showPrompt(token: string): void {
  if (prompt.isOpen && promptToken === token) return;
  promptToken = token;
  prompt.show(token, null);
}

// ---- Noticing sign-ins ---------------------------------------------------------------

const sentAt = new WeakMap<Element, number>();

function valueOf(g: Group, role: string): string {
  const f = g.fields.find((x) => g.roles.get(x.el) === role);
  return f?.el.value ?? "";
}

function capture(g: Group): void {
  const s: Submission = {
    kind: g.kind,
    username: valueOf(g, "username"),
    password: valueOf(g, "current-password"),
    newPassword: valueOf(g, "new-password"),
  };
  if (!s.username && !s.password && !s.newPassword) return;
  const last = sentAt.get(g.root) ?? 0;
  if (Date.now() - last < 3000) return;
  sentAt.set(g.root, Date.now());
  void send({ type: "submitted", data: s });
}

document.addEventListener(
  "submit",
  (e) => {
    const form = e.composedPath()[0];
    for (const g of groups) if (g.root === form || (form instanceof Element && deepContains(form, g.root))) capture(g);
  },
  true,
);

const SUBMITISH = /log.?in|sign.?in|sign.?up|register|continue|next|submit|save|change|update|create|join|weiter|anmelden|suivant|siguiente|entrar|accedi/i;

function maybeSubmitClick(target: Element): void {
  const button = target.closest?.("button, input[type=submit], input[type=button], [role=button], a");
  if (!button) return;
  const text = `${(button as HTMLInputElement).value ?? ""} ${button.textContent ?? ""} ${button.getAttribute("aria-label") ?? ""} ${button.id}`;
  const isSubmit = button.matches("[type=submit]") || SUBMITISH.test(text);
  if (!isSubmit) return;
  for (const g of groups) {
    if (deepContains(g.root, button) || g.fields.some((f) => f.el.value && deepContains(button.parentElement?.parentElement ?? button, f.el))) {
      capture(g);
    }
  }
}

// ---- Messages from the service worker ------------------------------------------------

chrome.runtime.onMessage.addListener((msg: { type: string; [k: string]: unknown }, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  switch (msg.type) {
    case "fill": {
      rescan();
      const g = groups.find((x) => x.id === msg.groupId);
      if (!g) {
        reply({ ok: false });
        return false;
      }
      menu.close();
      fillingUntil = Infinity;
      fillGroup(g, msg.values as FillValues)
        .then(reply, () => reply({ ok: false }))
        .finally(() => (fillingUntil = Date.now() + 500));
      return true;
    }
    case "fill-target": {
      // The popup asks where to fill: the focused form, or the first one.
      rescan();
      const g = groupOf(deepActive()) ?? groups.find((x) => x.kind === "login") ?? groups.find((x) => x.kind !== "signup" && x.kind !== "reset-password");
      reply(g ? { groupId: g.id, kind: g.kind } : null);
      return false;
    }
    case "command": {
      // A keyboard shortcut or the context menu: the frame with the focus
      // answers.
      if (!document.hasFocus()) return false;
      rescan();
      const g = groupOf(deepActive());
      if (g) void send({ type: "command-target", which: msg.which, groupId: g.id, kind: g.kind, passwordRules: g.passwordRules });
      return false;
    }
    case "show-prompt":
      if (window === window.top) showPrompt(String(msg.token));
      return false;
  }
  return false;
});

// ---- Start -------------------------------------------------------------------------

new MutationObserver(() => rescanSoon()).observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ["type", "autocomplete", "name", "id", "placeholder", "aria-label", "style", "hidden", "disabled", "readonly"],
});
rescan();

if (window === window.top) {
  // A save waiting from the sign-in that led here.
  void send<{ token: string }>({ type: "prompt-pending" }).then((r) => r && showPrompt(r.token));
}
