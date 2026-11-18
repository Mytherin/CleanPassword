// The classifier alone, for tests that load it into fixture pages
// (test/run.mjs): window.cleanpasswordScan() returns each group's kind and
// its fields' roles, by the fields' ids or names.

import { scan } from "./classify";

(window as unknown as { cleanpasswordScan: () => unknown }).cleanpasswordScan = () =>
  scan(document).map((g) => ({
    kind: g.kind,
    roles: Object.fromEntries(Array.from(g.roles).map(([el, role]) => [el.id || el.name || "?", role])),
  }));
