// "Save password?" / "Update password?", in the corner of the page after a
// sign-in, and "Which account?" after a generated password was saved
// without a user name. An extension page in an iframe, like the inline menu.

import type { PromptState } from "../shared/types";
import { safeToAct } from "../shared/clicksafe";
import { ask, h, monogram } from "../shared/ui";

const token = location.hash.slice(1);
const root = document.getElementById("root")!;

function close(): void {
  parent.postMessage({ type: "close" }, "*");
}

let field: HTMLInputElement | null = null;

function answer(e: Event, a: string): void {
  // As the inline menu: only a click on the prompt fully visible for a
  // moment (a page could otherwise trick the user into saving a password it
  // chose over the one saved).
  if (!safeToAct(e)) return;
  void ask("prompt-answer", { token, answer: a, ...(field ? { username: field.value } : {}) }).finally(close);
}

ask<PromptState | null>("prompt-state", { token }).then((s) => {
  if (!s) return close();
  const update = s.kind === "update";
  const onlyUsername = s.kind === "username";
  const title = onlyUsername
    ? `Which account is the new password for?`
    : update ? `Update the password for ${s.name}?` : `Save this password for ${s.host}?`;

  // The user name: a password is rarely any use without one, so it's shown
  // in a field to fill in or correct, a missing one in red. Not found on the
  // page, it's filled in with the best guess (one saved for the site, else
  // the email address used most), marked as such.
  let userRow: Node;
  let primary: HTMLButtonElement;
  if (s.usernameFixed) {
    userRow = h("div", { class: "sub muted small" }, s.username);
  } else {
    const guessed = !s.username && s.suggestions.length > 0;
    const list = h("datalist", { id: "names" }, ...s.suggestions.map((u) => h("option", { value: u })));
    field = h("input", {
      class: "user", type: "text", value: s.username || s.suggestions[0] || "", list: "names",
      placeholder: "User name or email", autocomplete: "off", spellcheck: "false", "aria-label": "User name",
    });
    const note = h("div", { class: "note small" });
    const refresh = () => {
      const empty = !field!.value.trim();
      field!.classList.toggle("missing", empty);
      note.className = `note small ${empty ? "bad" : "muted"}`;
      note.textContent = empty
        ? "No user name: most sites need one with the password."
        : guessed && field!.value === s.suggestions[0] ? "Not found on the page: check it's this account's." : "";
      note.hidden = !note.textContent;
      if (onlyUsername) primary.disabled = empty;
    };
    field.addEventListener("input", refresh);
    field.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !primary.disabled) answer(e, "save");
    });
    userRow = h("div", { class: "userbox" }, field, list, note);
    queueMicrotask(refresh);
  }
  primary = h("button", { class: "btn primary", onclick: (e: Event) => answer(e, "save") }, update ? "Update" : "Save");

  root.append(
    h("div", { class: "head" },
      monogram(s.name),
      h("div", { style: "min-width:0;flex:1" },
        h("div", { class: "title", style: "font-weight:600" }, title),
        onlyUsername ? h("div", { class: "sub muted small" }, `Its password is saved for ${s.host}, with no user name.`) : null,
        s.usernameFixed ? userRow : null,
      ),
    ),
    ...(s.usernameFixed ? [] : [userRow]),
    h("div", { class: "actions" },
      update || onlyUsername ? null : h("button", { class: "btn small", onclick: (e: Event) => answer(e, "never") }, "Never for this site"),
      h("button", { class: "btn", onclick: (e: Event) => answer(e, "dismiss") }, "Not now"),
      primary,
    ),
  );
  const resize = () => {
    const height = Math.ceil(root.getBoundingClientRect().height);
    if (height > 0) parent.postMessage({ type: "height", height }, "*");
  };
  new ResizeObserver(resize).observe(root);
  resize();
}, close);
