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
let confirming: string | null = null;

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
  if (r?.error) {
    root.append(h("div", { class: "error", style: "padding: 4px 12px" }, r.error));
    resize();
  } else close();
}

function row(icon: Node, title: string, sub: string, onAct: (e: Event) => void, cls = ""): HTMLButtonElement {
  const b = h("button", { class: `row ${cls}`, role: "option", onclick: onAct }, icon, h("span", { class: "text" }, h("div", { class: "title" }, title), h("div", { class: "sub" }, sub)));
  rows.push(b);
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
      for (const m of matches.slice(0, 6)) root.append(matchRow(m));
    }
  }
  root.append(
    h("div", { class: "foot small muted" },
      h("span", {}, "CleanPassword"),
      s.locked ? null : h("button", { class: "link small", onclick: (e: Event) => void act(e, async () => (await ask("menu-off", { token }), null)) }, "Not on this site"),
    ),
  );
  rows[0]?.classList.add("selected");
  resize();
}

// ---- Keyboard --------------------------------------------------------------------------

document.addEventListener("keydown", (e) => {
  const i = rows.indexOf(document.activeElement as HTMLButtonElement);
  if (e.key === "ArrowDown") rows[Math.min(i + 1, rows.length - 1)]?.focus();
  else if (e.key === "ArrowUp") {
    if (i <= 0) close();
    else rows[i - 1].focus();
  } else if (e.key === "Escape") close();
  else return;
  e.preventDefault();
});

window.addEventListener("message", (e) => {
  if (e.data?.type === "focus-first") rows[0]?.focus();
});

ask<MenuState | null>("menu-state", { token })
  .then((s) => {
    state = s;
    if (!s) close();
    else render();
  })
  .catch(() => close());
