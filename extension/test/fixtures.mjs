// Sign-in forms as sites build them, with what the classifier should make
// of each: the kind of each form found, and each field's role (by id or
// name). Forms the classifier should ignore are simply not listed.

export const fixtures = {
  "plain login": {
    html: `<h1>Sign in</h1><form action="/session"><label for="u">Email</label><input id="u" name="email" type="email">
      <label for="p">Password</label><input id="p" name="password" type="password"><button type="submit">Sign in</button>
      <a href="/forgot">Forgot password?</a></form>`,
    expect: [{ kind: "login", roles: { u: "username", p: "current-password" } }],
  },
  "login with a generic user name field": {
    html: `<form><input name="j_id12" type="text"><input name="j_id13" type="password"><input type="submit" value="Log in"></form>`,
    expect: [{ kind: "login", roles: { j_id12: "username", j_id13: "current-password" } }],
  },
  "formless login (single-page app)": {
    html: `<div class="card"><h2>Welcome back</h2><div><div><input id="login" placeholder="Username" type="text"></div>
      <div><input id="pw" placeholder="Password" type="password"></div><div role="button">Log in</div></div></div>`,
    expect: [{ kind: "login", roles: { login: "username", pw: "current-password" } }],
  },
  "multi-step: user name first": {
    html: `<h1>Sign in</h1><form><input id="identifier" type="email" autocomplete="username webauthn"><button>Next</button></form>`,
    expect: [{ kind: "username-only", roles: { identifier: "username" } }],
  },
  "multi-step: email first without autocomplete": {
    html: `<h1>Log in to Example</h1><form><label>Email address <input id="email" type="email"></label><button type="submit">Continue</button></form>`,
    expect: [{ kind: "username-only", roles: { email: "username" } }],
  },
  "multi-step: then the password": {
    html: `<form><input type="hidden" name="username" value="me@example.com"><input id="pw" type="password" autocomplete="current-password"><button>Sign in</button></form>`,
    expect: [{ kind: "password-only", roles: { pw: "current-password" } }],
  },
  "sign-up": {
    html: `<h1>Create your account</h1><form action="/signup"><input id="email" type="email" placeholder="Email">
      <input id="new" type="password" placeholder="Password"><input id="confirm" type="password" placeholder="Confirm password">
      <label><input type="checkbox" name="newsletter"> Send me the newsletter</label><button type="submit">Create account</button></form>`,
    expect: [{ kind: "signup", roles: { email: "username", new: "new-password", confirm: "confirm-password" } }],
  },
  "sign-up with autocomplete": {
    html: `<form><input id="user" autocomplete="username"><input id="pw" type="password" autocomplete="new-password"><button>Go</button></form>`,
    expect: [{ kind: "signup", roles: { user: "username", pw: "new-password" } }],
  },
  "change password": {
    html: `<h2>Change password</h2><form><input id="cur" type="password" placeholder="Current password">
      <input id="n1" type="password" placeholder="New password"><input id="n2" type="password" placeholder="Repeat new password"><button>Save</button></form>`,
    expect: [{ kind: "change-password", roles: { cur: "current-password", n1: "new-password", n2: "confirm-password" } }],
  },
  "newsletter box is not a sign-in": {
    html: `<footer><form><label>Subscribe to our newsletter <input id="nl" type="email" placeholder="Your email"></label><button>Subscribe</button></form></footer>`,
    expect: [],
  },
  "search box is not a sign-in": {
    html: `<form role="search"><input id="q" type="text" name="q" placeholder="Search"><button>Go</button></form>`,
    expect: [],
  },
  "one-time code": {
    html: `<h1>Two-factor authentication</h1><form><input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><button>Verify</button></form>`,
    expect: [{ kind: "otp", roles: { code: "otp" } }],
  },
  "one-time code in six boxes": {
    html: `<form>${[1, 2, 3, 4, 5, 6].map((i) => `<input id="d${i}" maxlength="1" inputmode="numeric">`).join("")}<button>Verify</button></form>`,
    expect: [{ kind: "otp", roles: { d1: "otp", d2: "otp", d3: "otp", d4: "otp", d5: "otp", d6: "otp" } }],
  },
  "hidden honeypot fields are never sign-in fields": {
    html: `<form><input id="trap" name="username" type="text" style="display:none"><input id="trap2" type="password" style="opacity:0">
      <input id="u" name="login" type="text"><input id="p" type="password"><button>Log in</button></form>`,
    expect: [{ kind: "login", roles: { u: "username", p: "current-password" } }],
  },
  "login in a shadow root": {
    html: `<login-box></login-box><script>
      customElements.define("login-box", class extends HTMLElement { constructor() { super(); this.attachShadow({mode: "open"}).innerHTML =
        '<form><input id="su" autocomplete="username"><input id="sp" type="password"><button>Sign in</button></form>'; } });</script>`,
    expect: [{ kind: "login", roles: { su: "username", sp: "current-password" } }],
  },
  "login and sign-up on one page": {
    html: `<form id="a" action="/login"><h2>Sign in</h2><input id="lu" type="email"><input id="lp" type="password"><button>Sign in</button></form>
      <form id="b" action="/register"><h2>New here? Register</h2><input id="ru" type="email"><input id="rp" type="password" autocomplete="new-password"><button>Register</button></form>`,
    expect: [
      { kind: "login", roles: { lu: "username", lp: "current-password" } },
      { kind: "signup", roles: { ru: "username", rp: "new-password" } },
    ],
  },
  "card security code is not a password": {
    html: `<form><input id="cc" autocomplete="cc-number"><input id="cvc" name="cvc" type="password"><button>Pay</button></form>`,
    expect: [],
  },
  "show-password toggle keeps the role": {
    html: `<form><input id="u" autocomplete="username"><input id="p" type="password"><button>Log in</button></form>
      <script>window.toggle = () => document.getElementById("p").type = "text";</script>`,
    toggle: true,
    expect: [{ kind: "login", roles: { u: "username", p: "current-password" } }],
  },
};
