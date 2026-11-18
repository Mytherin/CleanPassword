# How autofill works, and why

CleanPassword's Chrome autofill is built from what users rate best and from the best open implementations. This page records what was learned and what was decided. Research was done in November 2026.

## What users prefer

The evidence is anecdotal: forums, store reviews and comparisons. There's no rigorous benchmark.

- **Apple Passwords in Safari** is the one people call "least fussy". The reasons:
  - It's built into the browser and the OS.
  - It never fills silently.
  - It anchors suggestions on the field you're in.
  - It handles multi-step sign-ins well.
  - When you use a login on a new domain, it offers to add that domain to the login.

  Apple's iCloud Passwords extension for Chrome, by contrast, is rated poorly. So what's worth copying is Apple's *behaviour*, not its extension.
- **1Password's inline menu** is praised as polished and reliable on unusual forms. Complaints are about it covering page controls.
- **Bitwarden** is reliable but "fiddly". Complaints:
  - its menu appears in non-login fields (chat boxes, command palettes, custom dropdowns)
  - its icon covers the site's "show password" button
  - there's no per-field opt-out
- **Proton Pass** users report missed fields and missed save prompts.

**Conclusion.** Use Apple's interaction model: fill only on user action, anchored to the focused field, and treat multi-step forms as first-class. Combine the detection heuristics of Chromium, Firefox and Bitwarden, the open implementations where the best rules live. On top of that, add Bitwarden's 2025 hardening against clickjacking, plus a little more.

## Detection (`extension/src/content/classify.ts`)

1. **Collecting.**
   - Inputs come from the document and from open and closed shadow roots (`chrome.dom.openOrClosedShadowRoot`), up to 200 fields.
   - A field counts only if it's **viewable**: at least 10×10 px, displayed, not nearly transparent (anywhere up the tree), and not covered by another element. A covered field passes if it's below the fold or the cover is its own label. This is how hidden "honeypot" fields that skim credentials are never filled.
   - A field that was ever `type=password` stays a password field when a show-password toggle makes it text (Firefox's `hasBeenTypePassword`).
2. **Grouping.**
   - Fields are grouped by their `<form>`.
   - Without one, a password field and the fields before it, up to their lowest common ancestor, make a group.
   - Other formless fields are grouped by their nearest form-like container.
3. **Roles.**
   - **Autocomplete attributes** are used only when they're consistent within the group (Chromium's rule). That means at most one `username`, at most one `current-password`, at most two `new-password`, and password tokens only on password fields.
   - **One-time codes:**
     - `autocomplete=one-time-code`, Chromium's `kOneTimePwdRe`, or Bitwarden's TOTP field names count.
     - Ambiguous names ("code", "pin") count only with `inputmode=numeric` or a 4–8 character limit, and no password field in the group.
     - Recovery codes are excluded.
     - 4–8 single-character boxes in a row are one split code.
   - **New vs current password:** Firefox's signals, added up and passed through a sigmoid (≥ 0.75 new, ≤ 0.35 current). The signals are:
     - "new" / "confirm" / "current" in the label
     - registration words in the form's attributes and its submit button
     - the heading above the form
     - a "forgot password" link
     - "remember me" and newsletter checkboxes
     - the number of other fields
   - **Two or three password fields:** Chromium's structural rules apply (current + new, or new + confirm; current + new + confirm).
   - **User name:** the best-scoring field before the first password field. `autocomplete=username` scores most; then `type=email`, Bitwarden's user name words, and ambiguous words ("login", "account", "phone"). Ties go to the nearest field. Newsletter, confirm-email, coupon and search fields are excluded.
   - **A user-name-only form** (step one of a multi-step sign-in) needs one of: `autocomplete=username`/`webauthn`, a strong user name signal, or a login-ish submit button or heading ("Next", "Continue", "Sign in"). Without that, an email box is a newsletter form and is left alone.
4. **Form type** (Chromium's table): login, password-only (step two), username-only (step one), signup, change-password, reset-password, or one-time code.

The rules are tested on 18 fixtures in `extension/test/fixtures.mjs`. Each new site that goes wrong should become a fixture.

## Interaction

- The menu opens on **focus or click** of a classified field (trusted events only). It never opens on page load, in fields narrower than 60 px, or when there's nothing to offer. A locked vault still shows "Unlock".
- **Contents of the menu:**
  - logins saved for this host first, then the rest of the domain, then sites that share sign-ins (Apple's list, marked "shared sign-in")
  - the login chosen at the previous step of this sign-in, pre-selected
  - **Use strong password** on new-password fields, following the site's rules
  - one-time codes on OTP fields, for the login just used in this tab
- **Closing:** typing closes it (as Safari's does), and so do Escape, blur, scrolling the field out of view, and resizing. Arrow-down moves into the menu.
- **"Not on this site"** turns the menu off for that site.
- **Filling** puts values only into the group of the focused field, in page order, then leaves the focus where Enter submits. A saved (current) password never goes into a new-password field.
- **No auto-submit and no fill on page load.** Chromium itself waits for the user in a dozen cases. Doing so always is simpler and safer.

### The fill sequence (`fill.ts`)

This is what Bitwarden, WebKit and Chromium converge on, and it works with React, Vue and Angular:

1. Focus the field.
2. Dispatch `keydown`.
3. Set the value through the **native** `HTMLInputElement` value setter. From the content script's isolated world this bypasses frameworks' own value trackers.
4. Dispatch `input` (`insertReplacementText`), then `keyup`, then `change`.
5. After 100 ms, check the value stuck. If not, retry through `execCommand('insertText')`, for masked inputs.

The end-to-end test fills a field that tracks its value the way React does.

## Matching (`core/src/matching.rs`)

- **Registrable domain** (eTLD+1, Public Suffix List) by default: `accounts.example.co.uk` matches `example.co.uk`, but `alice.github.io` doesn't match `mallory.github.io`.
- Matches on the exact host rank first. Bitwarden's other modes are supported: host, starts-with, exact, regex and never.
- A saved non-default port must match.
- **An `https` login is never offered on an `http` page.** An `http` login may be used on `https`.
- Apple's `shared-credentials.json` groups (`envato.com` ~ `themeforest.net`, …) are offered, ranked last and marked.
- Picking a login for a site it isn't saved for (from the popup) adds the site to it, as Apple does.

## Trust boundaries and clickjacking

- **The vault lives only in the service worker.** The content script gets a menu token, and only the values for one fill, after the user picks a login. The service worker sends those only to that frame's `documentId`.
- **Which site a frame is** always comes from Chrome (`sender.origin`, `sender.url`, `webNavigation`). Before filling, the service worker checks the frame is still on that origin.
- **Embedded forms.** A form in an iframe from another site than the page gets a warning in the menu, and a second click to confirm.
- **Keyboard shortcuts and context-menu fills** are only accepted from a frame within 3 seconds of Chrome delivering the command to that tab.
- **The menu and save prompt** are extension pages in iframes. The page can't read them or click them with script, because events don't cross into a cross-origin frame.
- **Their host element** has a random name and a closed shadow root, and is shown in the top layer as a popover. It's re-asserted if the page meddles with it, and given up after repeated meddling.
- **The host closes, or never opens,** if any of these hold:
  - The page, its body or any ancestor of the field is less than 90% opaque, filtered, blended, scaled to nothing or hidden.
  - Another element keeps taking the top layer: ours is re-shown at most 5 times in 5 seconds, then disabled for the page.
  - Anything other than the menu is at its centre or corners.
  - The field is detached or scrolled away.
- **The menu acts only on trusted clicks and keys,** only after it has been shown for 500 ms, and only while Chrome's IntersectionObserver v2 (`trackVisibility`) reports it fully visible for that long. That observer is Chrome's own guarantee that nothing covers the frame or makes it see-through, which page CSS can't fake.

## Saving

- The content script keeps the values typed into sign-in fields in memory. It reports them once when the form is submitted:
  - a real `submit` event
  - a click on a sign-in/up/continue/save button in or near the form
  - Enter in one of its fields

  Each form reports at most once every 3 seconds.
- **No prompt when:**
  - the password is empty, under 2 characters, or a site's mask (`••••`)
  - it's already saved for this user
  - it was generated and saved here, in which case the user name is filled in silently
  - saving is turned off for the site
- **Prompt type:**
  - "Save" for a new user name.
  - "Update" when the user name exists with another password, or when a change-password form's current password matches a login.
  - A user name entered at step one of a multi-step sign-in is remembered for 10 minutes for step two.
- **Where the prompt appears:** in the corner of the page once it has loaded, if it's the same site. Otherwise the toolbar badge shows it and the popup offers it.

## Sources

- **Bitwarden** browser extension: `apps/browser/src/autofill/` in github.com/bitwarden/clients (GPL-3.0; ideas and word lists only). The relevant services are collect-autofill-content, dom-element-visibility, inline-menu-field-qualification, insert-autofill-content and autofill-constants.
- **Chromium** password manager form parsing: `components/password_manager/core/browser/form_parsing/form_data_parser.cc`, `password_form_filling.cc` and `autofill_regex_constants.h` (BSD; regexes in `keywords.ts` with attribution).
- **Firefox** `toolkit/components/passwordmgr/` (`LoginManagerChild`, `NewPasswordModel`) (MPL-2.0; regexes in `keywords-firefox.ts`, which stays under the MPL).
- **Apple** `password-manager-resources` (MIT): `quirks/shared-credentials.json` and `quirks/password-rules.json`, in `core/data/`.
- **WebKit** `AutofillElements.cpp`, for username-only detection and pairing by focus order.
- **Clickjacking:** Marek Tóth, "DOM-based Extension Clickjacking" (DEF CON 33, 2025), and the vendor fixes that followed.
