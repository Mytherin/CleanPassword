// Passes passkey requests from the page script (src/webauthn/page.ts) to
// the service worker, and its answers back. A content script, at
// document_start, so requests made while the page loads aren't missed.
//
// The service worker identifies the site from Chrome's own record of this
// frame, not from anything in the message.

window.addEventListener("message", (e) => {
  const d = e.data as { __cleanpassword?: string; id?: number; kind?: string; options?: unknown; mediation?: string } | null;
  if (e.source !== window || !d || typeof d.id !== "number") return;
  if (d.__cleanpassword === "cancel") {
    void chrome.runtime.sendMessage({ type: "webauthn-cancel", id: d.id }).catch(() => {});
    return;
  }
  if (d.__cleanpassword !== "request" || (d.kind !== "create" && d.kind !== "get")) return;
  const id = d.id;
  chrome.runtime
    .sendMessage({ type: "webauthn", id, kind: d.kind, options: d.options, mediation: d.mediation })
    .then((r: { ok: boolean; value: unknown } | undefined) => (r?.ok && r.value ? r.value : { fallback: true }))
    .catch(() => ({ fallback: true }))
    .then((answer) => window.postMessage({ __cleanpassword: "reply", id, ...(answer as object) }, "*"));
});
