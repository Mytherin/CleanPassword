// What the extension keeps between sessions: the vault (sealed) and the
// settings, in the extension's own IndexedDB. Not chrome.storage.local:
// content scripts can read and write that one, so a compromised page
// renderer could take the sealed vault for offline guessing, or turn
// auto-lock off. IndexedDB belongs to the extension's origin, which pages
// and content scripts can't reach.
//
// The same shape as chrome.storage.local's get/set/remove, for the few
// keys used. What older versions kept in chrome.storage.local moves here
// the first time.

const DB = "cleanpassword";
const STORE = "kv";
const MOVED = ["vault", "settings"];

let opened: Promise<IDBDatabase> | null = null;

function db(): Promise<IDBDatabase> {
  opened ??= new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }).then(async (d) => {
    await moveFromStorageLocal(d);
    return d;
  });
  opened.catch(() => (opened = null));
  return opened;
}

function run<T>(d: IDBDatabase, mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T> | void): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = d.transaction(STORE, mode);
    const req = f(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(req ? req.result : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

async function moveFromStorageLocal(d: IDBDatabase): Promise<void> {
  const old = await chrome.storage.local.get(MOVED);
  const keys = Object.keys(old);
  if (!keys.length) return;
  await run(d, "readwrite", (s) => {
    for (const k of keys) s.put(old[k], k);
  });
  await chrome.storage.local.remove(keys);
}

export const store = {
  async get(key: string): Promise<Record<string, unknown>> {
    const d = await db();
    const v = await run(d, "readonly", (s) => s.get(key));
    return v === undefined ? {} : { [key]: v };
  },
  async set(items: Record<string, unknown>): Promise<void> {
    const d = await db();
    await run(d, "readwrite", (s) => {
      for (const [k, v] of Object.entries(items)) s.put(v, k);
    });
  },
  async remove(key: string): Promise<void> {
    const d = await db();
    await run(d, "readwrite", (s) => {
      s.delete(key);
    });
  },
};
