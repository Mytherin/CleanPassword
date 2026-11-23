// Click safety for the extension's iframes in web pages (the inline menu and
// the save prompt): a page can't click them itself (only trusted events
// count), and can't trick the user into clicking them while they're covered,
// see-through or just appeared (Intersection Observer v2 reports whether the
// frame is really visible, also through the page's styling of its ancestors).

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

/** Whether `e` is a click the user meant: trusted, and on a frame that's
 *  been fully visible for a moment. */
export function safeToAct(e: Event): boolean {
  if (!e.isTrusted) return false;
  const now = performance.now();
  if (now - shownAt < 500) return false;
  if (ioSupported && (!visibleSince || now - visibleSince < 500)) return false;
  return true;
}
