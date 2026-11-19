// The inline menu, under a sign-in field. An extension page in an iframe:
// the page can't read it or click it.
//
// It acts only on trusted clicks and keys, and only once Chrome has
// reported it fully visible (not covered, not see-through) for half a
// second (IntersectionObserver v2), so a page can't trick a click onto it.

import type { Match, MenuState } from "../shared/types";
import { ask, h, monogram } from "../shared/ui";

const token = location.hash.slice(1);
const root = document.getElementById("root")!;
let state: MenuState | null = null;
let rows: HTMLButtonElement[] = [];
/** What each row does, given the (trusted) event that chose it. */
const actions = new WeakMap<HTMLButtonElement, (e: Event) => void>();
let confirming: string | null = null;

// With more logins than fit, the list scrolls and a field above it narrows it
// down by name or user name. The field lives across renders, keeping what was
// typed and the focus.
const FILTER_FROM = 7;
const filter = h("input", {
  class: "filter",
  type: "search",
  placeholder: "Filter logins",
  "aria-label": "Filter logins",
  autocomplete: "off",
  spellcheck: "false",
});
filter.addEventListener("input", () => {
  confirming = null;
  render();
});

// ---- Click safety -------------------------------------------------------------------

let visibleSince = 0;
let ioSupported = false;
try {
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        const vis = (e as IntersectionObserverEntry & { isVisible?: boolean }).isVisible;
        if (vis === undefined) continue;
        ioSupported = true;
        visibleSince = vis ? visibleSince || performance.now() : 0;
      }
    },
    { threshold: [1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
  );
  io.observe(document.body);
} catch {}
const shownAt = performance.now();

function safeToAct(e: Event): boolean {
  if (!e.isTrusted) return false;
  const now = performance.now();
  if (now - shownAt < 500) return false;
  if (ioSupported && (!visibleSince || now - visibleSince < 500)) return false;
  return true;
}

// ---- Rendering -----------------------------------------------------------------------

function close(): void {
  parent.postMessage({ type: "close" }, "*");
}

/** Tells the page's overlay how tall the menu is (only the number). */
function resize(): void {
  const height = Math.ceil(root.getBoundingClientRect().height);
  if (height > 0) parent.postMessage({ type: "height", height }, "*");
}
new ResizeObserver(resize).observe(root);

async function act(e: Event, f: () => Promise<{ error: string | null } | null | undefined>): Promise<void> {
  if (!safeToAct(e)) return;
  const r = await f().catch((err: Error) => ({ error: err.message }));
  // A menu the extension has forgotten can't do anything: it goes (the
  // field gets a new one when it's next clicked).
  if (r?.error === "expired") close();
  else if (r?.error) {
    const shown = root.querySelector(".error.act");
    const box = h("div", { class: "error act", style: "padding: 4px 12px" }, r.error);
    if (shown) shown.replaceWith(box);
    else root.append(box);
    resize();
  } else close();
}

function row(icon: Node, title: string, sub: string, onAct: (e: Event) => void, cls = ""): HTMLButtonElement {
  const b = h("button", { class: `row ${cls}`, role: "option", onclick: onAct }, icon, h("span", { class: "text" }, h("div", { class: "title" }, title), h("div", { class: "sub" }, sub)));
  rows.push(b);
  actions.set(b, onAct);
  return b;
}

function matchRow(m: Match): HTMLButtonElement {
  const otp = state!.role === "otp";
  const sub =
    confirming === m.id
      ? `Fill into ${state!.host}, embedded in ${state!.embeddedIn}? Click again.`
      : otp
        ? "Fill one-time code"
        : m.quality === "related"
          ? `${m.username || "No user name"} · shared sign-in`
          : m.username || "No user name";
  return row(monogram(m.name), m.name, sub, (e) => {
    if (state!.embeddedIn && confirming !== m.id) {
      if (!safeToAct(e)) return;
      confirming = m.id;
      render();
      return;
    }
    void act(e, () => ask("menu-fill", { token, id: m.id }));
  }, confirming === m.id ? "confirm" : "");
}

function render(): void {
  // Taking the filter out of the page (to rebuild it) takes its focus away.
  const filtering = document.activeElement === filter;
  rows = [];
  root.replaceChildren();
  const s = state;
  if (!s) return;
  if (s.locked) {
    root.append(row(h("span", { class: "mono", style: "background:var(--accent)" }, "🔒"), "Unlock CleanPassword", `to sign in to ${s.host}`, (e) => void act(e, () => ask("menu-unlock", { token }))));
  } else {
    if (s.embeddedIn) root.append(h("div", { class: "warn", style: "margin: 4px 8px" }, `This form is from ${s.host}, inside a page from ${s.embeddedIn}.`));
    if (s.suggestion) {
      root.append(row(h("span", { class: "mono", style: "background:var(--ok)" }, "✓"), "Use strong password", s.suggestion, (e) => void act(e, () => ask("menu-generate", { token })), "suggest"));
      rows[rows.length - 1].querySelector(".sub")!.classList.add("secret");
    }
    // The page asked for a passkey in its sign-in field: those first.
    for (const p of s.passkeys ?? []) {
      root.append(row(h("span", { class: "mono", style: "background:var(--accent)" }, "🔑"), p.user_name || p.user_display_name || p.item_name, `Passkey · ${p.item_name}`,
        (e) => void act(e, () => ask("menu-passkey", { token, itemId: p.item_id, credentialId: p.credential_id })), "passkey"));
    }
    let matches = s.matches;
    if (s.role === "otp") matches = matches.filter((m) => s.totpIds.includes(m.id));
    if (s.role !== "new-password" && s.role !== "confirm-password") {
      // The login chosen at the step before comes first.
      matches = [...matches].sort((a, b) => Number(b.id === s.preferredId) - Number(a.id === s.preferredId));
      if (matches.length >= FILTER_FROM) {
        root.append(filter);
        if (filtering) filter.focus();
        const q = filter.value.trim().toLowerCase();
        if (q) matches = matches.filter((m) => m.name.toLowerCase().includes(q) || (m.username ?? "").toLowerCase().includes(q));
      }
      const list = h("div", { class: "list" });
      for (const m of matches) list.append(matchRow(m));
      if (!matches.length && filter.value.trim()) list.append(h("div", { class: "small muted", style: "padding: 8px 12px" }, "No matching logins"));
      root.append(list);
    }
  }
  root.append(
    h("div", { class: "foot small muted" },
      h("span", {}, "CleanPassword"),
      s.locked ? null : h("button", { class: "link small", onclick: (e: Event) => void act(e, async () => (await ask("menu-off", { token }), null)) }, "Not on this site"),
    ),
  );
  if (document.activeElement !== filter) rows[0]?.classList.add("selected");
  resize();
}

// ---- Keyboard --------------------------------------------------------------------------

const firstListed = (): HTMLButtonElement | undefined => rows.find((r) => r.closest(".list"));

document.addEventListener("keydown", (e) => {
  const filtering = filter.isConnected;
  if (document.activeElement === filter) {
    if (e.key === "ArrowDown") firstListed()?.focus();
    else if (e.key === "Enter") {
      // With the key itself: a script's click() isn't trusted, and is ignored.
      const first = firstListed();
      if (first) actions.get(first)?.(e);
    }
    else if (e.key === "Escape") {
      if (filter.value) {
        filter.value = "";
        render();
      } else close();
    } else return;
    e.preventDefault();
    return;
  }
  const i = rows.indexOf(document.activeElement as HTMLButtonElement);
  if (e.key === "ArrowDown") rows[Math.min(i + 1, rows.length - 1)]?.focus();
  else if (e.key === "ArrowUp") {
    // From the first login, up goes to the filter (when there is one).
    if (filtering && i >= 0 && rows[i] === firstListed()) filter.focus();
    else if (i <= 0) close();
    else rows[i - 1].focus();
  } else if (e.key === "Escape") close();
  else if (filtering && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
    // Typing on a row types into the filter.
    filter.focus();
    return;
  } else return;
  e.preventDefault();
});

// From the page's overlay. The page itself can post here too (it shares the
// overlay's window), but it doesn't know the token.
window.addEventListener("message", (e) => {
  if (e.data?.token !== token) return;
  if (e.data?.type === "focus-first") rows[0]?.focus();
  // As tall as there's room for in the page's window, the list scrolling.
  if (e.data?.type === "max-height" && typeof e.data.height === "number") root.style.maxHeight = `${e.data.height}px`;
});

ask<MenuState | null>("menu-state", { token })
  .then((s) => {
    state = s;
    if (!s) close();
    else render();
  })
  .catch(() => close());
