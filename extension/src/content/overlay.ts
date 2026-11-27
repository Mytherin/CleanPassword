// The inline menu and the save prompt, shown in web pages.
//
// Each is an extension page in an iframe, so the page can't read what it
// shows (the logins) or click it with script (events don't cross into a
// cross-origin frame, and the menu only acts on trusted clicks). The iframe
// sits in a closed shadow root on an element with a random name, shown in
// the top layer (a popover) above everything the page has.
//
// Against clickjacking (pages making the menu invisible, or covering it, to
// trick a click: the 2025 "DOM-based extension clickjacking" attacks), the
// host checks before showing and while shown that nothing makes the page or
// the field transparent, that no other top-layer element competes, and that
// the menu is the topmost thing where it is; and the menu itself accepts
// clicks only while Chrome reports it fully visible (IntersectionObserver
// v2), and not in its first half second.

import { parentOf } from "./classify";

const EXT_ORIGIN = new URL(chrome.runtime.getURL("")).origin;

function randomName(): string {
  const b = crypto.getRandomValues(new Uint8Array(6));
  return "cp-" + Array.from(b, (x) => x.toString(36)).join("");
}

/** Something in the page makes the anchor (or the page) see-through or
 *  hidden, which a clickjacking page would do. */
export function pageLooksHostile(anchor: Element | null): boolean {
  const win = window;
  const chain: Element[] = [document.documentElement, document.body].filter(Boolean) as Element[];
  for (let e: Element | null = anchor; e; e = parentOf(e)) chain.push(e);
  for (const e of chain) {
    const s = win.getComputedStyle(e);
    if (parseFloat(s.opacity) < 0.9) return true;
    if (s.filter && /opacity\(|blur\(/.test(s.filter)) return true;
    if (s.visibility === "hidden") return true;
    if (s.mixBlendMode && s.mixBlendMode !== "normal") return true;
    if (s.transform && /matrix\(0, 0, 0, 0|scale\(0/.test(s.transform)) return true;
  }
  return false;
}

/** The window's size less its scrollbars: what's under a scrollbar isn't
 *  visible, and a frame running under one (innerWidth counts it: 17px on
 *  Windows) is never reported entirely visible, so it ignores every click. */
function viewport(): { width: number; height: number } {
  const e = document.compatMode === "BackCompat" ? document.body : document.documentElement;
  const width = e?.clientWidth || window.innerWidth;
  const height = e?.clientHeight || window.innerHeight;
  return { width: Math.min(width, window.innerWidth), height: Math.min(height, window.innerHeight) };
}

export class Overlay {
  private host: HTMLElement | null = null;
  private frame: HTMLIFrameElement | null = null;
  private observer: MutationObserver | null = null;
  private foreignMutations = 0;
  private reshown: number[] = [];
  private anchor: HTMLElement | null = null;
  private token = "";
  /** The frame has loaded our page (it has messaged us). Until then its
   *  window is the initial about:blank, of the page's origin, and posting to
   *  it fails. */
  private ready = false;
  private focusPending = false;
  /** Top-layer elements already open when ours was last shown: ours is
   *  above them. Only ones opened since can cover it. */
  private beneath = new Set<Element>();
  private timer: ReturnType<typeof setInterval> | undefined;
  onClose: (() => void) | null = null;
  disabled = false;

  constructor(private page: "menu.html" | "prompt.html", private placement: "below" | "corner") {
    window.addEventListener("message", (e) => this.onMessage(e));
    // An element already beneath ours, shown again, goes on top of it.
    document.addEventListener(
      "toggle",
      (e) => {
        if ((e as ToggleEvent).newState === "open" && e.target !== this.host) this.beneath.delete(e.target as Element);
      },
      true,
    );
  }

  private topLayer(): Element[] {
    return Array.from(document.querySelectorAll(":popover-open, :modal")).filter((e) => e !== this.host);
  }

  /** Shows ours on top of everything in the top layer. */
  private raise(host: HTMLElement): void {
    try {
      if (host.matches(":popover-open")) host.hidePopover();
      host.showPopover();
    } catch {}
    this.beneath = new Set(this.topLayer());
  }

  get isOpen(): boolean {
    return !!this.host;
  }

  get element(): HTMLElement | null {
    return this.host;
  }

  show(token: string, anchor: HTMLElement | null): void {
    if (this.disabled) return;
    this.close();
    if (pageLooksHostile(anchor)) return;
    this.anchor = anchor;
    const host = document.createElement(randomName());
    host.setAttribute("data-cleanpassword", "");
    host.setAttribute("popover", "manual");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    // Where it goes (top, left, width, height) is set inline: `:host` rules
    // marked important would win over those.
    style.textContent = `:host{position:fixed!important;margin:0!important;padding:0!important;border:0!important;overflow:visible!important;background:transparent!important;opacity:1!important;filter:none!important;transform:none!important;display:block!important;z-index:2147483647!important;color-scheme:normal!important;max-width:none!important;max-height:none!important}
      iframe{display:block;border:0;width:100%;height:100%;color-scheme:normal;border-radius:10px;box-shadow:0 8px 28px rgba(0,0,0,.28)}`;
    const frame = document.createElement("iframe");
    frame.src = chrome.runtime.getURL(this.page) + "#" + token;
    // Nothing of the page's; only the menu may copy (its suggested password).
    frame.setAttribute("allow", this.page === "menu.html" ? "clipboard-write" : "");
    frame.title = "CleanPassword";
    shadow.append(style, frame);
    // A field in a modal dialog: everything outside that dialog is inert,
    // so ours goes inside it (in the top layer all the same).
    let modal: Element | null = null;
    for (let e: Element | null = anchor; e && !modal; e = parentOf(e)) if (e.localName === "dialog" && e.matches(":modal")) modal = e;
    (modal ?? document.documentElement).append(host);
    this.host = host;
    this.frame = frame;
    this.token = token;
    this.ready = false;
    this.focusPending = false;
    this.size(this.placement === "below" ? 52 : 140);
    this.position();
    this.raise(host);
    // The page meddling with our element: put it back, or give up.
    this.foreignMutations = 0;
    this.observer = new MutationObserver((records) => {
      const foreign = records.some((r) =>
        r.attributeName === "style" ? host.getAttribute("style") !== this.ownStyle : r.attributeName === "popover" ? host.getAttribute("popover") !== "manual" : true,
      );
      if (!foreign) return;
      if (++this.foreignMutations > 10) {
        this.close();
        this.disabled = true;
        return;
      }
      host.setAttribute("popover", "manual");
      if (this.ownStyle !== null) host.setAttribute("style", this.ownStyle);
    });
    this.observer.observe(host, { attributes: true });
    this.timer = setInterval(() => this.guard(), 250);
  }

  close(): void {
    clearInterval(this.timer);
    this.observer?.disconnect();
    this.host?.remove();
    const was = !!this.host;
    this.host = null;
    this.frame = null;
    this.anchor = null;
    if (was) this.onClose?.();
  }

  /** Keyboard users: arrow down from the field into the menu. */
  focusInside(): void {
    this.frame?.focus();
    if (!this.ready) {
      this.focusPending = true;
      return;
    }
    this.frame?.contentWindow?.postMessage({ type: "focus-first", token: this.token }, EXT_ORIGIN);
  }

  private width = 320;
  private height = 52;
  private top = 0;
  private left = 0;
  /** The style attribute as we last set it (other changes are the page's). */
  private ownStyle: string | null = null;

  /** The most height there is for it in the window. The menu must fit
   *  entirely: it takes clicks only while Chrome reports all of it visible, so
   *  one running off the bottom of the window would ignore every click. */
  private room = 420;
  /** How tall the menu would like to be. */
  private wanted = 52;

  private size(height: number): void {
    if (!(height >= 24)) return;
    this.wanted = Math.min(height, 420);
    this.height = Math.min(this.wanted, this.room);
    this.position();
  }

  /** Tells the frame how tall it may be (it scrolls its list to fit). */
  private sendRoom(): void {
    if (!this.ready) return;
    this.frame?.contentWindow?.postMessage({ type: "max-height", height: this.room, token: this.token }, EXT_ORIGIN);
  }

  private applyStyle(): void {
    const host = this.host;
    if (!host) return;
    const css =
      `inset:auto!important;top:${this.top}px!important;left:${this.left}px!important;` +
      `width:${this.width}px!important;height:${this.height}px!important`;
    if (host.getAttribute("style") === css) return;
    this.ownStyle = css;
    host.setAttribute("style", css);
  }

  private position(): void {
    if (!this.host) return;
    const view = viewport();
    let room: number;
    if (this.placement === "corner" || !this.anchor) {
      this.width = 340;
      this.top = 12;
      this.left = Math.max(4, view.width - this.width - 12);
      room = view.height - 24;
    } else {
      const r = this.anchor.getBoundingClientRect();
      // Whole pixels: a frame of fractional width shows its page a pixel
      // narrower than that page lays out, and Chrome then reports the menu
      // as not entirely visible, ignoring every click (as on AWS's sign-in).
      this.width = Math.round(Math.min(Math.max(r.width, 280), 360));
      this.left = Math.max(4, Math.min(r.left, view.width - this.width - 4));
      // Below the field, or above it when there's more room there.
      const below = Math.floor(view.height - r.bottom - 12);
      const above = Math.floor(r.top - 12);
      const up = this.wanted > below && above > below;
      room = up ? above : below;
      this.height = Math.min(this.wanted, Math.max(room, 24));
      this.top = up ? r.top - 4 - this.height : r.bottom + 4;
    }
    room = Math.max(24, Math.min(420, room));
    if (room !== this.room) {
      this.room = room;
      this.sendRoom();
    }
    this.applyStyle();
  }

  /** Re-checks the page while shown. */
  private guard(): void {
    const host = this.host;
    if (!host) return;
    if (!host.isConnected || (this.anchor && !this.anchor.isConnected)) return this.close();
    if (pageLooksHostile(this.anchor)) return this.close();
    const view = viewport();
    if (this.anchor) {
      const r = this.anchor.getBoundingClientRect();
      if (r.bottom < 0 || r.top > view.height) return this.close();
    }
    this.position();
    // An element put in the top layer after ours could cover it: re-show ours
    // on top, a few times; if it keeps happening, give up on this page.
    // (Ones open from before, a page's dialog or popover, stay beneath it.)
    if (!host.matches(":popover-open") || this.topLayer().some((e) => !this.beneath.has(e))) {
      const now = Date.now();
      this.reshown = this.reshown.filter((t) => now - t < 5000);
      if (this.reshown.length >= 5) {
        this.close();
        this.disabled = true;
        return;
      }
      this.reshown.push(now);
      this.raise(host);
    }
    // Ours must be what's at its own corners and centre.
    const r = host.getBoundingClientRect();
    const pts: [number, number][] = [
      [r.left + r.width / 2, r.top + r.height / 2],
      [r.left + 6, r.top + 6],
      [r.right - 6, r.top + 6],
      [r.left + 6, r.bottom - 6],
      [r.right - 6, r.bottom - 6],
    ];
    for (const [x, y] of pts) {
      if (x < 0 || y < 0 || x > view.width || y > view.height) continue;
      const hit = document.elementFromPoint(x, y);
      if (hit && hit !== host) return this.close();
    }
  }

  private onMessage(e: MessageEvent): void {
    if (!this.frame || e.source !== this.frame.contentWindow || e.origin !== EXT_ORIGIN) return;
    const m = e.data as { type?: string; height?: number };
    if (!this.ready) {
      this.ready = true;
      if (this.focusPending) {
        this.focusPending = false;
        this.focusInside();
      }
    }
    if (m.type === "height" && typeof m.height === "number") {
      this.sendRoom();
      this.size(m.height);
    }
    if (m.type === "close") {
      const anchor = this.anchor;
      this.close();
      if (anchor && this.placement === "below") (anchor as HTMLElement).focus({ preventScroll: true });
    }
  }
}
