# CleanPassword

A password manager that looks and behaves like Apple's Passwords app, whose vault lives in **an S3 bucket of your own**, end-to-end encrypted, with a **Chrome extension** and an **iPhone app** (with AutoFill). Like its sibling [CleanNotes](../CleanNotes), there is no server: each device talks to S3 directly with an IAM key you create.

- **Shared Rust core** (`core/`): the vault, its encryption, S3 sync, the password generator, website matching, TOTP codes, and imports. The Chrome extension runs it as WebAssembly (`wasm/`); the iPhone app and its AutoFill extension call it through UniFFI (`ffi/`). Both read and write the same vault.
- **Chrome extension** (`extension/`): popup, inline autofill menu, save/update prompts, generator, Bitwarden import.
- **iPhone app** (`ios/`): SwiftUI app plus an AutoFill credential provider, so iOS offers your logins above the keyboard and in Safari.

## What it does

- Logins (user name, password, websites, TOTP, notes, custom fields, folder, favorite) and secure notes. Cards, identities and SSH keys from Bitwarden become secure notes with their details as fields.
- **Password generator:**
  - Apple-style `dobdyp-1ruzfa-hiFtoz` is the default.
  - Random (length and character classes) and EFF-wordlist passphrases are also available.
  - On sites in Apple's password-rules list, or with a `passwordrules` attribute, it follows the site's rules.
- **One-time codes** (TOTP): RFC 6238 with SHA-1/256/512, `otpauth://` URIs and Steam codes.
- **Password history:** every changed password is kept, the last 20 per item.
- **Trash:** deleted items can be recovered for 30 days.
- **Security recommendations:** weak and reused passwords.
- **Sync** between any number of devices.
  - Edits made on two devices are merged field by field. When both changed the same password, the losing one goes into the history.
  - An edit beats a delete.
  - Everything works offline and syncs later.
- **Import:**
  - Bitwarden JSON, including **password-protected exports**, which are decrypted in the core so no plaintext copy of the vault needs to touch the disk.
  - Bitwarden CSV.
  - CSV from Chrome, Edge, Safari/Apple Passwords, Firefox, 1Password and LastPass.
- **Export:** unencrypted Bitwarden JSON, which most password managers import.
- **Master password change:** other devices pick up the new password at their next sync.

### Chrome extension

- **Inline menu** under sign-in fields, on focus:
  - Logins for the site, the exact host first.
  - "Use strong password" on sign-up and change-password forms.
  - One-time codes on 2FA fields.
  - "Unlock" when the vault is locked.
- **Multi-step sign-ins** (user name, then password, then code) remember the login you chose for the next step.
- **Generated passwords are saved immediately**, so they can't be lost if the sign-up fails.
- **Save / Update prompts** after you sign in with a password that isn't saved, or has changed.
- **Shortcuts:** Ctrl+Shift+L (⌘⇧L) fills the best login, Ctrl+Shift+9 fills a strong password, Ctrl+Shift+Y opens the popup. The right-click menu offers the same.
- **Auto-lock** after 15 minutes without use (configurable), and when the computer locks.

### iPhone app

- **The Passwords screen, as in Apple's Passwords app:** tiles for **All**, **Codes**, **Security** and **Deleted** with their counts, your folders below them, and search across everything. The "…" menu has Settings, the generator and Lock Now; the bottom toolbar shows the sync status and New Password.
  - **All and folders** list items by name in letter sections. Touch and hold an item to copy its user name, password or code, or to delete it.
  - **Codes** shows each item's current verification code with a countdown ring; tap one to copy it.
  - **Security** lists reused passwords, then weak ones.
  - **Deleted** keeps items 30 days; swipe to recover or delete for good.
- **An item** shows its icon, name and modified date on top, then user name, password (dots until tapped), verification code, websites, fields, notes and earlier passwords, each with a copy button. Edit opens the editor, with the generator and a strength meter.
- The Chrome popup has the same tiles, under the logins for the current site.
- **Face ID unlock.** It's optional, uses a keychain item readable only after biometric authentication, and is forgotten when the enrolled faces change.
- **Auto-lock** after time in the background.
- **The AutoFill extension** works from the keyboard, the QuickType suggestions and Safari. It unlocks with Face ID or the master password. The suggestions above the keyboard register only user names and websites with iOS, never passwords.
- **Copied passwords** stay on this device (no Universal Clipboard) and are cleared after 90 seconds.

## Security model

| Where | What it holds |
|---|---|
| **S3** (`<folder>/vault.json`) | Vault id, Argon2id settings and salt, and the **vault key** sealed with the master key. |
| **S3** (`<folder>/items/<uuid>.bin`) | One item each, sealed with the vault key, padded to 512-byte blocks. |
| **Each device** (`chrome.storage.local`, or a file in the iOS App Group) | The S3 settings and `vault.json` in clear. Everything else is sealed with the vault key: the **AWS access key**, the items, and sync state. |
| **Chrome, while unlocked** | The vault key in `chrome.storage.session`: memory only, not readable by content scripts. Removed when the vault locks. |
| **iPhone, with Face ID on** | The vault key in the keychain, `ThisDeviceOnly` and `biometryCurrentSet`. |

**Keys.**
- **Master key:** Argon2id of the master password, with 46 MiB memory, 3 passes and 1 lane. That's above OWASP's recommendation and fits iOS's AutoFill memory limit. The settings are stored with the vault, so they can be raised later.
- **Vault key:** 32 random bytes, wrapped by the master key. Changing the master password re-wraps this one key instead of re-encrypting everything.

**Encryption.** Everything is sealed with XChaCha20-Poly1305 and a random nonce. The associated data names the vault and item id, so ciphertexts can't be moved between items or vaults. Keys are wiped from memory when dropped.

**What S3 and anyone with access to the bucket can see:**
- the number of items
- their padded sizes
- when they change

They never see names, websites, user names or passwords.

Limits that can't be avoided without a server:
- Whoever controls the bucket can delete items or serve an older version of one.
- An HTTPS man-in-the-middle with a trusted certificate could do the same.

They can't read or forge items. Turn on **S3 versioning**, so a deleted or overwritten item can be restored.

**Autofill.** See [docs/autofill.md](docs/autofill.md). In short:
- The content script in web pages never sees the vault.
- The inline menu is an extension-origin iframe in a closed shadow root that the page can't read or click by script.
- Every fill needs a user gesture.
- Fills are authorised by the frame origin Chrome reports, never by what the page claims.
- An `https` login is never offered on an `http` page.
- Hidden fields are never filled.
- The menu refuses to show, or closes, when the page is see-through, covered, or fighting for the top layer. Clicks count only once Chrome has reported the menu fully visible for 500 ms, which defends against the 2025 "DOM-based extension clickjacking" attacks.

**Master password.** At least 10 characters, ideally a few unrelated words (the setup screens show how strong it is). It can't be recovered: there's no server, and no one else holds a key.

## Setting up AWS

1. Create a bucket. Keep "Block all public access" on. **Turn on versioning**: it keeps old versions of items as a backup.
2. In IAM, create a user without console access, with this inline policy (replace `BUCKET`, and `CleanPassword` if you choose another folder):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::BUCKET" },
       { "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
         "Resource": "arn:aws:s3:::BUCKET/CleanPassword/*" }
     ]
   }
   ```

   `s3:ListBucket` has no folder condition on purpose: without list permission that applies to every request, S3 answers "access denied" instead of "not found" for a missing object, and CleanPassword couldn't tell a new folder from a forbidden one. The cost is that the key can list the names of every object in the bucket, so give CleanPassword a bucket of its own.
3. Create an access key for that user ("Application running outside AWS") and enter it in the extension or the app, with the bucket, its region and the folder.

**Sharing a folder with CleanNotes.** CleanPassword can use the same bucket, folder and access key as [CleanNotes](../CleanNotes): enter CleanNotes' folder (e.g. `CleanNotes`) instead of `CleanPassword` when setting up. The two apps' objects don't overlap, and each ignores the other's:

```text
<folder>/vault.json, items/…                                       CleanPassword
<folder>/head, notes/…, folders/…, attachments/…, encryption.json   CleanNotes
```

CleanPassword's vault is encrypted with its own master password either way, whether or not the notes folder has an encryption key. Its changes don't touch `head`, so they don't make CleanNotes devices sync. (`core/src/sync.rs` tests this: `shares_a_folder_with_cleannotes`.)

S3-compatible services (Cloudflare R2, MinIO, …) work too, as long as they support conditional writes (`If-Match`, `If-None-Match: *`). Enter their endpoint under "S3-compatible service".

## Building

### Rust core

```sh
cargo test --workspace      # core, wasm bindings, Swift bindings
```

### Chrome extension

Needs Rust with the `wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.100 (`cargo install wasm-bindgen-cli --version 0.2.100`) and Node 22.

```sh
cd extension
npm install
npm run build        # → extension/dist: chrome://extensions → Developer mode → Load unpacked
npm run typecheck
node test/run.mjs    # tests in Chrome (set CHROME=… if it isn't found)
```

`test/run.mjs` tests in the installed Chrome:
1. **The field classifier** on 18 kinds of sign-in form: plain, formless, multi-step, sign-up, change-password, one-time codes, shadow DOM, and traps such as newsletter boxes, search boxes, honeypots and card codes.
2. **The whole extension against a fake S3 server:** setup, filling through the inline menu (into a React-style controlled input), the first-click guard, a generated password, the save prompt, what S3 holds, the locked menu, and refusing to show on a see-through page.

### iPhone app

On a Mac with Xcode 15+, rustup and XcodeGen (`brew install xcodegen`):

```sh
ios/build-rust.sh           # the core as an XCFramework, and its Swift bindings
cd ios && xcodegen          # CleanPassword.xcodeproj from project.yml
open CleanPassword.xcodeproj
```

**Signing.** Choose your team under Signing for both targets. The App Group (`group.com.cleanpassword.app`) and the AutoFill capability are in the entitlements. Change the bundle ids and group if they're taken in your account.

**Turning on AutoFill.** In Settings → General → AutoFill & Passwords, turn on CleanPassword. The app's Settings has a shortcut.

**Tests:** ⌘U, or `xcodebuild test -project CleanPassword.xcodeproj -scheme CleanPassword -destination 'platform=iOS Simulator,name=iPhone 16'`.

**CI.** `.github/workflows/ci.yml` runs three jobs:
1. the Rust tests and clippy
2. the extension build and its Chrome tests (and uploads the built extension)
3. the iOS build and tests in the Simulator

## Importing from Bitwarden

In Bitwarden, open **Tools → Export vault** and choose the `.json` format. There are two options:

- **Encrypted → "Password protected"** (recommended): CleanPassword asks for the export's password and decrypts the file in memory.
- **Unencrypted JSON:** delete the file once it's imported.

"Account restricted" encrypted exports can only be opened by Bitwarden itself; CleanPassword says so if given one. Passkeys can't be moved between password managers, and the import tells you how many were left behind.

Then import:
- **In Chrome:** popup → ⚙ → Import.
- **On the iPhone:** Settings → Import….

Importing the same file again skips the items already there.

## Layout

```text
core/        Rust: vault, crypto, sync, s3, generator, rules, matching, totp, import (+ data/: wordlist, Apple's quirks)
wasm/        the core for the extension (wasm-bindgen)
ffi/         the core for Swift (UniFFI)
extension/   Chrome MV3 extension (TypeScript, esbuild); test/ runs it in Chrome
ios/         SwiftUI app, AutoFill extension, tests (XcodeGen project)
docs/        autofill design and research
```

## Not yet

- **Passkeys.** They can't be imported between managers. Storing new ones needs the passkey provider APIs on both platforms.
- **One-time codes in iOS AutoFill:** iOS 18's `ProvidesOneTimeCodes`.
- **Saving new passwords from iOS AutoFill.** iOS doesn't let third-party providers do it before iOS 18's new APIs; add them in the app for now.
- **Sharing vaults between people:** one vault per bucket folder for now.
- **Clearing the clipboard in Chrome** after copying, which needs an offscreen document.
- **A "never fill here" per-field override**, and per-site fixes for sites the heuristics get wrong.
