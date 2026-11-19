// Passkeys for web pages: runs in the page's own JavaScript world (the
// manifest's "world": "MAIN", before the page's scripts), and stands in for
// navigator.credentials.create and .get when a site asks for a passkey.
//
// It holds nothing secret and decides nothing: it turns the request into
// plain data for CleanPassword (through the bridge content script and the
// service worker, which checks the site and asks the user in a window of
// its own), and the answer back into the PublicKeyCredential the page
// expects. When CleanPassword has nothing to offer (no vault, no passkey
// for the site, a kind of key it can't make, the user's choice), the
// browser's own passkey support takes over as if CleanPassword weren't
// there.

type Json = Record<string, unknown>;

(() => {
  const creds = navigator.credentials;
  if (!creds || typeof window.PublicKeyCredential !== "function") return;
  const nativeCreate = creds.create.bind(creds);
  const nativeGet = creds.get.bind(creds);

  // ---- base64url ---------------------------------------------------------

  function toB64(src: BufferSource): string {
    // Not `instanceof ArrayBuffer`: a buffer from another frame (realm) isn't
    // one, and would come out empty.
    const bytes = ArrayBuffer.isView(src) ? new Uint8Array(src.buffer, src.byteOffset, src.byteLength) : new Uint8Array(src);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64(s: string): ArrayBuffer {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  const ids = (list?: PublicKeyCredentialDescriptor[]) => (list ?? []).map((c) => ({ id: toB64(c.id), type: c.type, transports: c.transports }));

  // ---- Talking to the extension -------------------------------------------

  let next = 1;
  const waiting = new Map<number, (r: Json) => void>();
  window.addEventListener("message", (e) => {
    const d = e.data as Json | null;
    if (e.source !== window || !d || d.__cleanpassword !== "reply") return;
    const done = waiting.get(d.id as number);
    if (done) {
      waiting.delete(d.id as number);
      done(d);
    }
  });

  function ask(kind: "create" | "get", options: Json, mediation: string | undefined, signal?: AbortSignal | null): Promise<Json> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      const id = next++;
      waiting.set(id, resolve);
      signal?.addEventListener("abort", () => {
        if (!waiting.delete(id)) return;
        window.postMessage({ __cleanpassword: "cancel", id }, "*");
        reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      });
      window.postMessage({ __cleanpassword: "request", id, kind, options, mediation }, "*");
    });
  }

  // ---- The credentials ------------------------------------------------------

  /** A PublicKeyCredential made from the extension's answer (plain data with
   *  the real prototypes, as other password managers make them). */
  function credential(kind: "create" | "get", r: Json): PublicKeyCredential {
    const clientDataJSON = fromB64(r.clientDataJSON as string);
    let response: Json;
    if (kind === "create") {
      const authData = fromB64(r.authenticatorData as string);
      const publicKey = fromB64(r.publicKey as string);
      response = {
        clientDataJSON,
        attestationObject: fromB64(r.attestationObject as string),
        getTransports: () => ["hybrid", "internal"],
        getAuthenticatorData: () => authData,
        getPublicKey: () => publicKey,
        getPublicKeyAlgorithm: () => -7,
      };
      Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    } else {
      response = {
        clientDataJSON,
        authenticatorData: fromB64(r.authenticatorData as string),
        signature: fromB64(r.signature as string),
        userHandle: r.userHandle ? fromB64(r.userHandle as string) : null,
      };
      Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    }
    const extensions = kind === "create" ? { credProps: { rk: true } } : {};
    const cred: Json = {
      id: r.id,
      rawId: fromB64(r.id as string),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => extensions,
      toJSON: () => ({
        id: r.id,
        rawId: r.id,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: extensions,
        response:
          kind === "create"
            ? {
                clientDataJSON: r.clientDataJSON,
                attestationObject: r.attestationObject,
                authenticatorData: r.authenticatorData,
                publicKey: r.publicKey,
                publicKeyAlgorithm: -7,
                transports: ["hybrid", "internal"],
              }
            : { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, signature: r.signature, userHandle: r.userHandle ?? null },
      }),
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred as unknown as PublicKeyCredential;
  }

  function answer(kind: "create" | "get", r: Json, native: () => Promise<Credential | null>): Promise<Credential | null> {
    if (r.fallback) return native();
    const e = r.error as { name: string; message: string } | undefined;
    if (e) throw new DOMException(e.message, e.name);
    return Promise.resolve(credential(kind, r.result as Json));
  }

  creds.create = async function create(options?: CredentialCreationOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) return nativeCreate(options);
    const request = {
      rp: { id: pk.rp.id, name: pk.rp.name },
      user: { id: toB64(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
      challenge: toB64(pk.challenge),
      pubKeyCredParams: pk.pubKeyCredParams.map((p) => ({ type: p.type, alg: p.alg })),
      excludeCredentials: ids(pk.excludeCredentials),
      authenticatorSelection: pk.authenticatorSelection ?? {},
      attestation: pk.attestation,
    };
    return answer("create", await ask("create", request, undefined, options?.signal), () => nativeCreate(options));
  };

  creds.get = async function get(options?: CredentialRequestOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) return nativeGet(options);
    const request = {
      rpId: pk.rpId,
      challenge: toB64(pk.challenge),
      allowCredentials: ids(pk.allowCredentials),
      userVerification: pk.userVerification,
    };
    return answer("get", await ask("get", request, options?.mediation, options?.signal), () => nativeGet(options));
  };
})();
