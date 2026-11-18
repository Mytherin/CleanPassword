// Putting values into a page's fields so that the page notices, whatever it
// is built with (React, Vue and Angular keep their own copy of each field's
// value and only update it from the right events).
//
// The sequence is the one Bitwarden, WebKit and Chromium converge on: focus,
// keydown, the value through the native setter (which frameworks' own
// setters don't intercept), input, keyup, change; then a check that the
// value stuck, with a second try through the editing command for fields
// that rewrite it.

import type { FillValues, Role } from "../shared/types";
import type { Group } from "./classify";
import { isViewable } from "./classify";

const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function fire(el: HTMLInputElement, value: string): void {
  el.focus({ preventScroll: true });
  el.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, composed: true, key: "Unidentified" }));
  valueSetter.call(el, value);
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: value }));
  el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, composed: true, key: "Unidentified" }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Sets one field; false if it can't take the value. */
async function setField(el: HTMLInputElement, value: string): Promise<boolean> {
  if (!el.isConnected || el.disabled || el.readOnly || !isViewable(el)) return false;
  if (el.maxLength > 0 && value.length > el.maxLength) return false;
  if (el.value === value) return true;
  fire(el, value);
  await sleep(100);
  if (el.value !== value) {
    // Masked inputs and editor frameworks: type it as the user would.
    el.focus({ preventScroll: true });
    el.select();
    document.execCommand("insertText", false, value);
    await sleep(50);
  }
  return el.value === value;
}

export interface FillResult {
  ok: boolean;
  /** What the group's user name field holds after filling. */
  username?: string;
}

/** Fills a group's fields by role, in page order. Only visible fields: a
 *  hidden field is never filled (pages hide fields to skim credentials). */
export async function fillGroup(group: Group, values: FillValues): Promise<FillResult> {
  const byRole = (r: Role) => group.fields.filter((f) => group.roles.get(f.el) === r).map((f) => f.el);
  const plan: [HTMLInputElement, string][] = [];
  const username = byRole("username")[0];
  if (values.username !== undefined && username && values.username !== "") plan.push([username, values.username]);
  if (values.password !== undefined) for (const el of byRole("current-password")) plan.push([el, values.password]);
  if (values.newPassword !== undefined) {
    for (const el of [...byRole("new-password"), ...byRole("confirm-password")]) plan.push([el, values.newPassword]);
  }
  if (values.totp !== undefined) {
    const otp = byRole("otp");
    if (otp.length > 1 && otp.every((el) => el.maxLength === 1)) {
      Array.from(values.totp).forEach((c, i) => otp[i] && plan.push([otp[i], c]));
    } else if (otp[0]) {
      plan.push([otp[0], values.totp]);
    }
  }
  if (!plan.length) return { ok: false };
  plan.sort((a, b) => group.fields.findIndex((f) => f.el === a[0]) - group.fields.findIndex((f) => f.el === b[0]));

  let ok = true;
  for (const [el, v] of plan) {
    ok = (await setField(el, v)) && ok;
    await sleep(20);
  }
  // Leave the focus where the user can press Enter.
  const last = plan[plan.length - 1][0];
  last.focus({ preventScroll: true });
  return { ok, username: username?.value };
}
