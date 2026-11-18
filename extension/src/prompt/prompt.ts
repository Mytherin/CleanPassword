// "Save password?" / "Update password?", in the corner of the page after a
// sign-in. An extension page in an iframe, like the inline menu.

import type { PromptState } from "../shared/types";
import { ask, h, monogram } from "../shared/ui";

const token = location.hash.slice(1);
const root = document.getElementById("root")!;
const shownAt = performance.now();

function close(): void {
  parent.postMessage({ type: "close" }, "*");
}

function answer(e: Event, a: string): void {
  if (!e.isTrusted || performance.now() - shownAt < 500) return;
  void ask("prompt-answer", { token, answer: a }).finally(close);
}

ask<PromptState | null>("prompt-state", { token }).then((s) => {
  if (!s) return close();
  const update = s.kind === "update";
  root.append(
    h("div", { class: "head" },
      monogram(s.name),
      h("div", {},
        h("div", { class: "title", style: "font-weight:600" }, update ? `Update the password for ${s.name}?` : `Save this password for ${s.host}?`),
        h("div", { class: "sub muted small" }, s.username || "No user name"),
      ),
    ),
    h("div", { class: "actions" },
      update ? null : h("button", { class: "btn small", onclick: (e: Event) => answer(e, "never") }, "Never for this site"),
      h("button", { class: "btn", onclick: (e: Event) => answer(e, "dismiss") }, "Not now"),
      h("button", { class: "btn primary", onclick: (e: Event) => answer(e, "save") }, update ? "Update" : "Save"),
    ),
  );
  const resize = () => {
    const height = Math.ceil(root.getBoundingClientRect().height);
    if (height > 0) parent.postMessage({ type: "height", height }, "*");
  };
  new ResizeObserver(resize).observe(root);
  resize();
}, close);
