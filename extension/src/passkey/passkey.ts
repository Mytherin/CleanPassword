// The passkey window: "Sign in to example.com with a passkey?" or "Save a
// passkey for example.com?", opened by the service worker when a page asks
// (see the Passkeys section of src/background/index.ts). A window of its
// own, so the page can't cover it or click in it. It unlocks the vault if
// needed, and offers the browser's own passkeys ("another device") instead.

import type { PasskeyState } from "../shared/types";
import { ask, CoreError, h, monogram } from "../shared/ui";

const token = location.hash.slice(1);
const root = document.getElementById("root")!;
let shownAt = performance.now();

/** Acts only on trusted clicks, and not in the window's first moments. */
async function answer(e: Event, action: string, extra: Record<string, unknown> = {}): Promise<void> {
  if (!e.isTrusted || performance.now() - shownAt < 400) return;
  const r = await ask<{ error: string | null }>("passkey-answer", { token, action, ...extra }).catch((x: Error) => ({ error: x.message }));
  if (r.error) {
    root.append(h("div", { class: "error", role: "alert" }, r.error));
  } else {
    window.close();
  }
}

function otherWays(): HTMLElement {
  return h(
    "div",
    { class: "actions" },
    h("button", { class: "btn", onclick: (e: Event) => void answer(e, "fallback") }, "Use Another Device or Security Key"),
    h("button", { class: "btn", onclick: (e: Event) => void answer(e, "cancel") }, "Cancel"),
  );
}

async function draw(): Promise<void> {
  const s = await ask<PasskeyState | null>("passkey-state", { token }).catch(() => null);
  if (!s) return window.close();
  shownAt = performance.now();
  const site = s.rpName || s.rpId;
  const title =
    s.kind === "get" ? `Sign in to ${s.host} with a passkey?` : s.excluded ? `A passkey for ${s.userName || "this account"} is already saved` : `Save a passkey for ${s.userName || "your account"} on ${s.rpId}?`;
  const head = h("div", { class: "head" }, monogram(site), h("h1", {}, title));
  const body: Node[] = [];

  if (s.locked) {
    const pw = h("input", { type: "password", placeholder: "Master password", autocomplete: "current-password" });
    const err = h("div", { class: "error", role: "alert" });
    const form = h("form", { style: "display:flex; flex-direction:column; gap:8px" }, h("p", { class: "muted", style: "margin:0" }, "Unlock CleanPassword to continue."), pw, err,
      h("button", { class: "btn primary", type: "submit" }, "Unlock"));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await ask("unlock", { password: pw.value });
        await draw();
      } catch (x) {
        err.textContent = x instanceof CoreError && x.kind === "WrongPassword" ? "That's not the master password." : (x as Error).message;
      }
    });
    body.push(form);
    setTimeout(() => pw.focus(), 0);
  } else if (s.kind === "get") {
    if (!s.choices.length) body.push(h("p", { class: "muted" }, `CleanPassword has no passkey for ${s.rpId}.`));
    else {
      body.push(h("div", { class: "list" }, ...s.choices.map((c) =>
        h("button", { class: "row", onclick: (e: Event) => void answer(e, "use", { itemId: c.item_id, credentialId: c.credential_id }) },
          h("span", { class: "mono", style: "background:var(--accent)" }, "🔑"),
          h("span", { class: "text" }, h("div", { class: "title" }, c.user_name || c.user_display_name || c.item_name), h("div", { class: "sub" }, c.item_name))))));
    }
  } else if (s.excluded) {
    body.push(h("p", { class: "muted", style: "text-align:center" }, `CleanPassword already has a passkey for this account on ${s.rpId}.`),
      h("button", { class: "btn primary", onclick: (e: Event) => void answer(e, "excluded") }, "OK"));
  } else {
    const target = h("select", {}, h("option", { value: "" }, "A new login"), ...s.logins.map((l) => h("option", { value: l.id }, `${l.name}${l.username ? ` (${l.username})` : ""}`)));
    const same = s.logins.find((l) => l.username && l.username.toLowerCase() === s.userName.toLowerCase());
    if (same) target.value = same.id;
    body.push(h("p", { class: "muted", style: "margin:0; text-align:center" }, "A passkey lets you sign in without a password. It's kept in CleanPassword, encrypted, on all your devices."));
    if (s.logins.length) body.push(h("label", {}, "Save on", target));
    body.push(h("button", { class: "btn primary", onclick: (e: Event) => void answer(e, "create", { itemId: target.value }) }, "Save Passkey"));
  }
  root.replaceChildren(head, ...(body.filter(Boolean) as Node[]), s.excluded ? h("div", {}) : otherWays());
}

void draw();
