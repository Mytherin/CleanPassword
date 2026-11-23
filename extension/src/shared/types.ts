// Types shared by the service worker, the content script and the pages.

export type ItemKind = "login" | "note" | "wifi" | "card" | "identity";
export type UriMatch = "domain" | "host" | "startswith" | "exact" | "regex" | "never";

export interface ItemUri {
  uri: string;
  match?: UriMatch | null;
}

export interface Field {
  name: string;
  value: string;
  hidden: boolean;
}

export interface ItemData {
  kind: ItemKind;
  name: string;
  username: string;
  password: string;
  uris: ItemUri[];
  totp: string;
  notes: string;
  folder: string;
  favorite: boolean;
  /** Asks for Face ID / the master password before showing secrets. */
  reprompt?: boolean;
  fields: Field[];
}

export interface Item extends ItemData {
  id: string;
  history: { password: string; retired: string }[];
  created: string;
  modified: string;
  password_modified?: string;
  deleted?: string;
  passkeys?: { credential_id: string; rp_id: string; rp_name: string; user_name: string; created: string }[];
}

export type Quality = "related" | "domain" | "host";

export interface Match {
  id: string;
  name: string;
  username: string;
  quality: Quality;
}

export interface S3Config {
  bucket: string;
  region: string;
  prefix: string;
  endpoint?: string | null;
}

export interface Credentials {
  access_key_id: string;
  secret_access_key: string;
  session_token?: string | null;
}

export interface SyncReport {
  downloaded: number;
  uploaded: number;
  removed: number;
  merged: number;
  pending: number;
  password_changed_elsewhere: boolean;
}

export type Recipe =
  | { kind: "apple" }
  | { kind: "random"; length: number; lowercase: boolean; uppercase: boolean; digits: boolean; symbols: boolean; avoid_ambiguous: boolean }
  | { kind: "passphrase"; words: number; separator: string; capitalize: boolean; number: boolean };

export interface Settings {
  /** Lock after this many minutes without use (0: only when the browser closes). */
  autoLockMinutes: number;
  /** Lock when the computer locks. */
  lockOnIdle: boolean;
  /** Show the menu when a sign-in field is focused. */
  inlineMenu: boolean;
  /** Offer to save new logins. */
  offerToSave: boolean;
  /** Origins never to offer saving on. */
  neverSave: string[];
  /** Origins where the inline menu is off. */
  menuOff: string[];
  /** Turn off Chrome's own offer to save passwords, so the two don't compete
   *  (Chrome turns it back on when the extension is disabled or removed). */
  replaceChrome: boolean;
  recipe: Recipe;
}

export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  lockOnIdle: true,
  inlineMenu: true,
  offerToSave: true,
  neverSave: [],
  menuOff: [],
  replaceChrome: true,
  recipe: { kind: "apple" },
};

/** What a sign-in field is. */
export type Role = "username" | "current-password" | "new-password" | "confirm-password" | "otp";

/** What a group of fields (a form) is for. */
export type FormKind = "login" | "password-only" | "username-only" | "signup" | "change-password" | "reset-password" | "otp" | "none";

/** Values to put into a group's fields. */
export interface FillValues {
  username?: string;
  password?: string;
  newPassword?: string;
  totp?: string;
}

/** What the content script reports when a form is submitted. */
export interface Submission {
  kind: FormKind;
  username: string;
  password: string;
  newPassword: string;
}

/** The state the inline menu shows. */
export interface MenuState {
  locked: boolean;
  role: Role;
  kind: FormKind;
  host: string;
  matches: Match[];
  /** Set when the form is in a frame from another site than the page. */
  embeddedIn: string | null;
  /** A suggested password, for new-password fields. */
  suggestion: string | null;
  /** The login chosen at an earlier step of this sign-in. */
  preferredId: string | null;
  /** Items with TOTP codes among the matches. */
  totpIds: string[];
  /** Passkeys to sign in with, when the page asked for one in its sign-in
   *  field (WebAuthn conditional mediation). */
  passkeys: PasskeyChoice[];
}

export interface PasskeyChoice {
  item_id: string;
  item_name: string;
  credential_id: string;
  user_name: string;
  user_display_name: string;
}

/** What the passkey window shows. */
export interface PasskeyState {
  kind: "create" | "get";
  host: string;
  rpId: string;
  rpName: string;
  userName: string;
  locked: boolean;
  choices: PasskeyChoice[];
  /** Logins a new passkey can be saved on (create). */
  logins: { id: string; name: string; username: string }[];
  /** The site already has a passkey of this account in the vault. */
  excluded: boolean;
}

export interface PromptState {
  kind: "save" | "update";
  host: string;
  username: string;
  name: string;
}
