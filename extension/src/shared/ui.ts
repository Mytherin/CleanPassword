// Small helpers for the extension's pages.

export class CoreError extends Error {
  constructor(message: string, public kind?: string) {
    super(message);
  }
}

/** Asks the service worker; throws its error. */
export async function ask<T = unknown>(type: string, args: Record<string, unknown> = {}): Promise<T> {
  const r = (await chrome.runtime.sendMessage({ type, ...args })) as { ok: boolean; value?: T; error?: string; name?: string } | undefined;
  if (!r) throw new CoreError("CleanPassword isn't responding");
  if (!r.ok) throw new CoreError(r.error ?? "failed", r.name);
  return r.value as T;
}

type Child = Node | string | null | undefined | false;
type Attrs = Record<string, string | number | boolean | EventListener | null | undefined>;

/** `h("button", {class: "x", onclick: f}, "Text")` */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: (Child | Child[])[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
    else if (k === "value") (el as HTMLInputElement).value = String(v);
    else if (k === "checked") (el as HTMLInputElement).checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c);
  return el;
}

/** A coloured circle with the first letter of a name, as an item's icon. */
export function monogram(name: string): HTMLElement {
  const letter = (name.trim()[0] ?? "?").toUpperCase();
  let hash = 0;
  for (const c of name) hash = (hash * 31 + c.charCodeAt(0)) | 0;
  const hue = Math.abs(hash) % 360;
  return h("span", { class: "mono", style: `background:hsl(${hue} 55% 48%)`, "aria-hidden": "true" }, letter);
}

export async function copy(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}
