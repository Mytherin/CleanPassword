// Finding sign-in forms in a page, and what each field is.
//
// The approach (see docs/autofill.md) combines what works best in the open
// implementations: Chromium's form parser (autocomplete only when
// consistent, password roles by structure, username as the nearest
// preceding field), Firefox's new-password signals, and Bitwarden's
// field-name lists and visibility rules; with Apple's model for multi-step
// sign-ins (a username-only form is a form of its own).
//
// Everything here only reads the page.

import type { FormKind, Role } from "../shared/types";
import * as K from "./keywords";
import * as F from "./keywords-firefox";

export interface FieldInfo {
  el: HTMLInputElement;
  type: string;
  /** Was a password field at some point (show-password toggles). */
  everPassword: boolean;
  /** autocomplete tokens, lowercase. */
  ac: string[];
  /** id, name, placeholder, aria-label, title and labels, lowercase. */
  text: string;
  /** The same without spaces, dashes, dots and underscores. */
  squashed: string;
  visible: boolean;
  index: number;
}

export interface Group {
  id: string;
  root: Element;
  fields: FieldInfo[];
  roles: Map<HTMLInputElement, Role>;
  kind: FormKind;
  /** The `passwordrules` attribute of the new-password field, if any. */
  passwordRules: string;
}

const SKIP_TYPES = new Set(["hidden", "submit", "button", "image", "reset", "file", "range", "color", "date", "datetime-local", "month", "week", "time", "checkbox", "radio", "search", "url"]);
const MAX_FIELDS = 200;
const MAX_HOSTS = 256;

const everPasswords = new WeakSet<HTMLInputElement>();
const groupIds = new WeakMap<Element, string>();
let nextGroupId = 1;

// ---- Collecting ---------------------------------------------------------------

/** The shadow root of an element, also closed ones (content scripts can
 *  open those through chrome.dom). */
function shadowOf(el: Element): ShadowRoot | null {
  if (el.shadowRoot) return el.shadowRoot;
  const dom = (globalThis as unknown as { chrome?: { dom?: { openOrClosedShadowRoot?: (e: Element) => ShadowRoot | null } } }).chrome?.dom;
  try {
    return dom?.openOrClosedShadowRoot?.(el) ?? null;
  } catch {
    return null;
  }
}

/** Inputs in the document and its shadow roots, in document order. */
export function collectInputs(doc: Document): HTMLInputElement[] {
  const out: HTMLInputElement[] = [];
  let hosts = 0;
  const walk = (root: Document | ShadowRoot, depth: number) => {
    for (const el of Array.from(root.querySelectorAll("*"))) {
      if (out.length >= MAX_FIELDS) return;
      if (el instanceof HTMLInputElement) {
        if (!SKIP_TYPES.has(el.type.toLowerCase())) out.push(el);
      }
      // Shadow roots hang off custom elements (or any element, if open).
      if ((el.localName.includes("-") || el.shadowRoot) && depth < 8 && hosts < MAX_HOSTS) {
        const sr = shadowOf(el);
        if (sr) {
          hosts++;
          walk(sr, depth + 1);
        }
      }
    }
  };
  walk(doc, 0);
  return out;
}

/** The parent across shadow boundaries. */
export function parentOf(el: Element): Element | null {
  if (el.parentElement) return el.parentElement;
  const root = el.getRootNode();
  return root instanceof ShadowRoot ? root.host : null;
}

function ancestors(el: Element): Element[] {
  const out: Element[] = [];
  for (let e: Element | null = el; e; e = parentOf(e)) out.push(e);
  return out;
}

/** Whether `a` contains `b`, across shadow roots. */
export function deepContains(a: Element, b: Element): boolean {
  for (let e: Element | null = b; e; e = parentOf(e)) if (e === a) return true;
  return false;
}

function labelText(el: HTMLInputElement): string {
  const parts: string[] = [];
  try {
    for (const l of Array.from(el.labels ?? [])) parts.push(l.textContent ?? "");
  } catch {}
  const root = el.getRootNode() as Document | ShadowRoot;
  for (const attr of ["aria-labelledby", "aria-describedby"]) {
    for (const id of (el.getAttribute(attr) ?? "").split(/\s+/).filter(Boolean)) {
      parts.push(root.getElementById?.(id)?.textContent ?? "");
    }
  }
  // No label: the text just before the field (a common pattern).
  if (!parts.join("").trim()) {
    const prev = el.previousElementSibling;
    if (prev && prev.textContent && prev.textContent.length < 60) parts.push(prev.textContent);
  }
  return parts.join(" ").replace(/\s+/g, " ").trim().slice(0, 200);
}

function signals(el: HTMLInputElement): string {
  const attrs = ["id", "name", "placeholder", "aria-label", "title", "autocomplete", "data-testid"].map((a) => el.getAttribute(a) ?? "");
  return [...attrs, labelText(el)].join(" ").toLowerCase();
}

/** Bitwarden's visibility rules: big enough, displayed, not transparent,
 *  and (in the viewport) not covered by something else. */
export function isViewable(el: HTMLElement): boolean {
  if (!el.isConnected) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width < 10 || rect.height < 10) return false;
  const win = el.ownerDocument.defaultView;
  if (!win) return false;
  if (rect.right < 0 || rect.bottom + win.scrollY < 0) return false;
  for (let e: Element | null = el; e; e = parentOf(e)) {
    const s = win.getComputedStyle(e);
    if (s.display === "none" || (e === el && (s.visibility === "hidden" || s.visibility === "collapse"))) return false;
    if (parseFloat(s.opacity) < 0.1) return false;
    if (s.clipPath && s.clipPath !== "none" && /inset\(50%|circle\(0|polygon\(0/.test(s.clipPath)) return false;
  }
  const cx = rect.left + rect.width / 2;
  const cy = rect.top + rect.height / 2;
  if (cx > win.innerWidth) {
    // Off to the right: only where the page scrolls to (a field pushed out
    // past `overflow-x: hidden` is a trap no one can see).
    const doc = el.ownerDocument;
    const clipped = [doc.documentElement, doc.body].some((e) => e && /hidden|clip/.test(win.getComputedStyle(e).overflowX));
    if (clipped || rect.left + win.scrollX >= (doc.scrollingElement ?? doc.documentElement).scrollWidth) return false;
    return true;
  }
  if (cx < 0 || cy < 0 || cy > win.innerHeight) return true; // below the fold: fine
  const root = el.getRootNode() as Document | ShadowRoot;
  const hit = root.elementFromPoint?.(cx, cy);
  if (!hit || hit === el || deepContains(el, hit) || deepContains(hit, el)) return true;
  const labels = (el as HTMLInputElement).labels;
  if (labels && Array.from(labels).some((l) => l === hit || deepContains(l, hit))) return true;
  return hit.hasAttribute("data-cleanpassword");
}

function fieldInfo(el: HTMLInputElement, index: number, viewable: (e: HTMLElement) => boolean): FieldInfo {
  const type = (el.getAttribute("type") ?? "text").toLowerCase();
  if (el.type === "password") everPasswords.add(el);
  const text = signals(el);
  return {
    el,
    type: el.type.toLowerCase() || type,
    everPassword: everPasswords.has(el),
    ac: (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter(Boolean),
    text,
    squashed: text.replace(/[\s_\-.]/g, ""),
    visible: viewable(el),
    index,
  };
}

// ---- Grouping -------------------------------------------------------------------

function lowestCommonAncestor(a: Element, b: Element): Element | null {
  const chain = new Set(ancestors(a));
  for (let e: Element | null = b; e; e = parentOf(e)) if (chain.has(e)) return e;
  return null;
}

function groupId(root: Element): string {
  let id = groupIds.get(root);
  if (!id) groupIds.set(root, (id = `g${nextGroupId++}`));
  return id;
}

function isPasswordish(f: FieldInfo): boolean {
  return f.type === "password" || f.everPassword;
}

function group(fields: FieldInfo[]): Map<Element, FieldInfo[]> {
  const groups = new Map<Element, FieldInfo[]>();
  const add = (root: Element, f: FieldInfo) => {
    const g = groups.get(root) ?? [];
    g.push(f);
    groups.set(root, g);
  };
  const formless: FieldInfo[] = [];
  for (const f of fields) {
    if (f.el.form) add(f.el.form, f);
    else formless.push(f);
  }
  // Without a <form>: a password field and the fields before it, up to
  // their lowest common ancestor, make a group.
  const placed = new Set<FieldInfo>();
  for (const p of formless.filter(isPasswordish)) {
    if (placed.has(p)) continue;
    const before = formless.filter((f) => f.index < p.index && !placed.has(f) && !isPasswordish(f));
    const nearest = before[before.length - 1];
    let root = nearest ? lowestCommonAncestor(p.el, nearest.el) : null;
    root ??= parentOf(parentOf(p.el) ?? p.el) ?? p.el;
    for (const f of formless) if (!placed.has(f) && deepContains(root, f.el)) {
      add(root, f);
      placed.add(f);
    }
  }
  // The rest (username-only steps, one-time codes): by their nearest
  // form-like container.
  for (const f of formless) {
    if (placed.has(f)) continue;
    let root: Element | null = null;
    for (let e = parentOf(f.el); e; e = parentOf(e)) {
      if (e.matches("[role=form],dialog,[role=dialog],fieldset") || e.localName === "body") {
        root = e;
        break;
      }
    }
    root ??= parentOf(parentOf(f.el) ?? f.el) ?? f.el;
    add(root, f);
  }
  return groups;
}

// ---- Classifying ----------------------------------------------------------------

/** Text near a group that tells what it's for: its attributes, its submit
 *  button, and the heading above it. */
interface Context {
  formAttrs: string;
  submitText: string;
  heading: string;
  hasForgotLink: boolean;
  hasRememberMe: boolean;
  hasNewsletter: boolean;
}

function context(root: Element, fields: FieldInfo[]): Context {
  const formAttrs = ["id", "name", "class", "action", "aria-label"].map((a) => root.getAttribute(a) ?? "").join(" ");
  const buttons = Array.from(root.querySelectorAll("button, input[type=submit], [role=button]"));
  const submit = buttons.find((b) => b.matches("[type=submit], input[type=submit]")) ?? (buttons.length === 1 ? buttons[0] : undefined);
  const submitText = submit ? ((submit as HTMLInputElement).value || submit.textContent || submit.getAttribute("aria-label") || "").trim() : "";
  let heading = "";
  for (let e: Element | null = root; e && !heading; e = parentOf(e)) {
    const h = e.querySelector("h1, h2, h3, [role=heading]");
    if (h) heading = (h.textContent ?? "").trim().slice(0, 100);
  }
  const links = Array.from(root.querySelectorAll("a, button")).map((a) => a.textContent ?? "").join(" ");
  const checkboxes = Array.from(root.querySelectorAll("input[type=checkbox]")).map((c) => `${c.id} ${c.getAttribute("name") ?? ""} ${(c as HTMLInputElement).labels?.[0]?.textContent ?? ""}`).join(" ");
  void fields;
  return {
    formAttrs,
    submitText,
    heading,
    hasForgotLink: F.FORGOT_STRING_RE.test(links),
    hasRememberMe: F.REMEMBER_ME_RE.test(checkboxes),
    hasNewsletter: F.NEWSLETTER_RE.test(checkboxes),
  };
}

function isOtp(f: FieldInfo, groupHasPassword: boolean): boolean {
  if (K.RECOVERY_RE.test(f.text)) return false;
  if (f.ac.includes("one-time-code")) return true;
  if (K.ONE_TIME_RE.test(f.text) || K.TOTP_WORDS.some((w) => f.squashed.includes(w.replace(/[\s_\-.]/g, "")))) return true;
  const short = f.el.maxLength >= 4 && f.el.maxLength <= 8;
  return !groupHasPassword && K.AMBIGUOUS_TOTP_RE.test(f.text) && (f.el.inputMode === "numeric" || short);
}

/** Single-digit boxes in a row (a split one-time code). */
function splitOtp(fields: FieldInfo[]): FieldInfo[] {
  const ones = fields.filter((f) => f.el.maxLength === 1 && f.visible && !isPasswordish(f));
  return ones.length >= 4 && ones.length <= 8 ? ones : [];
}

/** How likely a password field is a new password (sign-up, change), as a
 *  probability. Firefox's signals, added up (see docs/autofill.md). */
function newPasswordScore(f: FieldInfo, next: FieldInfo | undefined, ctx: Context, others: number): number {
  let s = -1.35;
  const label = f.text;
  if (F.NEW_STRING_RE.test(label)) s += 3;
  if (F.CONFIRM_STRING_RE.test(label)) s += 2.5;
  if (F.CURRENT_STRING_RE.test(label)) s -= 3;
  if (F.REGISTER_ACTION_RE.test(ctx.formAttrs) || K.REGISTER_ATTR_RE.test(ctx.formAttrs)) s += 2;
  if (F.REGISTER_STRING_RE.test(ctx.submitText)) s += 3;
  if (F.LOGIN_RE.test(ctx.submitText)) s -= 2.5;
  if (F.REGISTER_STRING_RE.test(ctx.heading)) s += 2;
  if (K.LOGIN_HEADING_RE.test(ctx.heading) || F.LOGIN_RE.test(ctx.heading)) s -= 2;
  if (next && F.CONFIRM_STRING_RE.test(next.text)) s += 2.5;
  if (ctx.hasForgotLink) s -= 2;
  if (ctx.hasRememberMe) s -= 1;
  if (ctx.hasNewsletter) s += 1.5;
  if (others >= 3) s += 1.5;
  return 1 / (1 + Math.exp(-s));
}

function usernameScore(f: FieldInfo, distance: number): number {
  if (isPasswordish(f) || K.SEARCH_RE.test(f.squashed) || K.IGNORE_RE.test(f.text)) return -Infinity;
  if (!["text", "email", "tel", "number", ""].includes(f.type)) return -Infinity;
  let s = 0;
  if (f.ac.includes("username")) s += 10;
  if (f.type === "email" || f.ac.includes("email")) s += 4;
  if (K.USERNAME_WORDS.some((w) => f.squashed.includes(w.replace(/[\s_\-.]/g, ""))) || /username/.test(f.text)) s += 4;
  else if (K.AMBIGUOUS_USERNAME_RE.test(f.text)) s += 2;
  if (distance === 1) s += 1;
  if (K.NOT_USERNAME_RE.test(f.text)) s -= 6;
  if (isOtp(f, true)) s -= 6;
  return s;
}

/** Autocomplete is used only if it's consistent within the group
 *  (Chromium's rule): one username, one current password, at most two new
 *  passwords, and password tokens only on password fields. */
function autocompleteUsable(fields: FieldInfo[]): boolean {
  let u = 0, c = 0, n = 0;
  for (const f of fields) {
    const last = f.ac[f.ac.length - 1];
    if (last === "username") u++;
    if (last === "current-password") c++;
    if (last === "new-password") n++;
    if ((last === "current-password" || last === "new-password") && !isPasswordish(f)) return false;
  }
  return u <= 1 && c <= 1 && n <= 2;
}

function classifyGroup(root: Element, fields: FieldInfo[]): Group {
  const roles = new Map<HTMLInputElement, Role>();
  const ctx = context(root, fields);
  const useAc = autocompleteUsable(fields);
  const acOf = (f: FieldInfo) => (useAc ? f.ac[f.ac.length - 1] ?? "" : "");

  const passwords = fields.filter((f) => isPasswordish(f) && f.visible && !K.NOT_PASSWORD_RE.test(f.text) && !isOtp(f, false) && acOf(f) !== "one-time-code");
  const otherVisible = fields.filter((f) => !isPasswordish(f) && f.visible).length;

  // One-time codes.
  const split = splitOtp(fields);
  for (const f of split) roles.set(f.el, "otp");
  if (!split.length) {
    for (const f of fields) if (f.visible && !isPasswordish(f) && isOtp(f, passwords.length > 0)) roles.set(f.el, "otp");
    for (const f of fields) if (isPasswordish(f) && f.visible && isOtp(f, false)) roles.set(f.el, "otp");
  }

  // Passwords: current, new or confirm.
  const kinds: Role[] = passwords.map((f, i) => {
    const ac = acOf(f);
    if (ac === "current-password") return "current-password";
    if (ac === "new-password") return "new-password";
    const p = newPasswordScore(f, passwords[i + 1], ctx, otherVisible);
    if (p >= 0.75) return "new-password";
    if (p <= 0.35) return "current-password";
    return passwords.length === 1 ? "current-password" : "new-password";
  });
  if (passwords.length === 2 && kinds[0] === kinds[1]) {
    // Chromium's structural rule: two password fields are new + confirm
    // when the second asks to confirm, otherwise current + new.
    if (F.CONFIRM_STRING_RE.test(passwords[1].text) || kinds[0] === "new-password") {
      kinds[0] = "new-password";
      kinds[1] = "confirm-password";
    } else {
      kinds[0] = "current-password";
      kinds[1] = "new-password";
    }
  } else if (passwords.length >= 3) {
    kinds[0] = acOf(passwords[0]) === "new-password" ? "new-password" : "current-password";
    kinds[1] = "new-password";
    kinds[2] = "confirm-password";
    for (let i = 3; i < kinds.length; i++) kinds[i] = "confirm-password";
  }
  for (let i = 1; i < kinds.length; i++) {
    if (kinds[i] === "new-password" && kinds[i - 1] === "new-password") kinds[i] = "confirm-password";
  }
  passwords.forEach((f, i) => roles.set(f.el, kinds[i]));

  // The user name: the best of the fields before the first password.
  const firstPw = passwords[0];
  let username: FieldInfo | undefined;
  if (firstPw) {
    const before = fields.filter((f) => f.index < firstPw.index && !roles.has(f.el) && (f.visible || f.type === "email" || f.type === "tel"));
    let best = -Infinity;
    before.forEach((f, i) => {
      const s = usernameScore(f, before.length - i);
      if (s > best || (s === best && s > -Infinity)) {
        best = s;
        username = f;
      }
    });
    if (best <= 0 || !username?.visible) username = undefined;
  } else {
    // No password: a username-only step of a multi-step sign-in, if it
    // clearly is one (otherwise it's a newsletter box or the like).
    const cands = fields.filter((f) => f.visible && !roles.has(f.el) && usernameScore(f, 1) > -Infinity);
    if (cands.length === 1) {
      const f = cands[0];
      const s = usernameScore(f, 1);
      const loginish = K.LOGIN_BUTTON_RE.test(ctx.submitText) || F.LOGIN_RE.test(ctx.submitText) || K.LOGIN_HEADING_RE.test(ctx.heading) || F.LOGIN_RE.test(ctx.formAttrs);
      const explicit = f.ac.includes("username") || f.ac.includes("webauthn");
      if (explicit || s >= 6 || (s >= 4 && loginish)) {
        if (!/\b(search|code|add)\b/i.test(f.text)) username = f;
      }
    }
  }
  if (username) roles.set(username.el, "username");

  const has = (r: Role) => Array.from(roles.values()).includes(r);
  let kind: FormKind = "none";
  if (has("current-password") && has("new-password")) kind = "change-password";
  else if (has("new-password")) kind = username ? "signup" : "reset-password";
  else if (has("current-password")) kind = username ? "login" : "password-only";
  else if (username) kind = "username-only";
  else if (has("otp")) kind = "otp";
  const newPw = passwords.find((f) => roles.get(f.el) === "new-password");
  return { id: groupId(root), root, fields, roles, kind, passwordRules: newPw?.el.getAttribute("passwordrules") ?? "" };
}

/** The sign-in forms in a document. */
export function scan(doc: Document, viewable: (e: HTMLElement) => boolean = isViewable): Group[] {
  const inputs = collectInputs(doc);
  const fields = inputs.map((el, i) => fieldInfo(el, i, viewable));
  const out: Group[] = [];
  for (const [root, fs] of group(fields)) {
    const g = classifyGroup(root, fs);
    if (g.kind !== "none") out.push(g);
  }
  return out;
}
