// Keywords for recognising sign-in fields.
//
// The regular expressions marked "Chromium" are from Chromium's password
// manager (components/password_manager/core/browser/form_parsing/ and
// components/autofill/core/common/autofill_regex_constants.h).
// Copyright 2013 The Chromium Authors; BSD-style license:
// https://chromium.googlesource.com/chromium/src/+/main/LICENSE
//
// The word lists marked "Bitwarden" restate the field names Bitwarden's
// extension recognises (apps/browser/src/autofill/services/
// autofill-constants.ts); lists of words, not its code.

/** Chromium kPasswordRe: names of password fields, in many languages. */
export const PASSWORD_RE =
  /pass(?:word|code)|pas(?:word|code)|pswrd|psw|pswd|pwd|parole|watchword|pasahitza|parol|lozinka|sifr|contrasenya|heslo|adgangskode|losen|wachtwoord|paswoord|salasana|passe|contrasinal|passwort|jelszo|sandi|signum|slaptazodis|kata|passord|haslo|senha|geslo|contrasena|khau/i;

/** Chromium kOneTimePwdRe: one-time code fields. */
export const ONE_TIME_RE =
  /one.?time|(?:\b|_)(?:otp|otc|totp|sms|2fa|mfa)(?:\b|_)|(?:otp|otc|totp|sms|2fa|mfa).?(?:code|token|input|val|pin|login|verif|pass|pwd|psw|auth|field)|(?:verif(?:y|ication)?|email|phone|text|login|input|txt|user).?(?:otp|otc|totp|sms|2fa|mfa)|sms.?otp|mfa.?otp|verif(?:y|ication)?.?code|(?:\b|_)vcode|(?:second|two|2).?factor|wfls-token|email_code/i;

/** Chromium: social security numbers and card security codes are never
 *  passwords. */
export const NOT_PASSWORD_RE = /ssn|social.?security.?(num(ber)?|#)*|cvc|cvv|cvn|csc|security.?code|card.?verif/i;

/** Bitwarden UsernameFieldNames (unambiguous). */
export const USERNAME_WORDS = [
  "username", "user name", "userid", "user id", "customer id", "login id", "benutzername", "benutzer name", "benutzerid",
  "benutzer id", "email", "email address", "e-mail", "e-mail address", "email adresse", "e-mail adresse", "邮箱",
];
/** Words that suggest a user name, less surely. */
export const AMBIGUOUS_USERNAME_RE = /login|\bid\b|account|user|phone|mobile|identifier|acct|benutzer|usuario|utilisateur|nutzer/i;

/** Bitwarden TotpFieldNames. */
export const TOTP_WORDS = [
  "2facode", "approvals_code", "mfacode", "onetimecode", "onetimepassword", "otc-code", "otp-code", "otpcode", "second-factor",
  "security_code", "security code", "totp", "totpcode", "twofa", "twofactor", "twofactorcode", "verificationcode",
  "verification code", "otc-confirmation",
];
/** Bitwarden AmbiguousTotpFieldNames: one-time codes only with more signs. */
export const AMBIGUOUS_TOTP_RE = /\b(code|pin|otc|otp|2fa|mfa)\b/i;
/** Recovery codes aren't one-time codes we can fill. */
export const RECOVERY_RE = /backup|recovery/i;

/** Bitwarden SearchFieldNames and FieldIgnoreList. */
export const SEARCH_RE = /search|query|\bfind\b|\bq\b|findanything/i;
export const IGNORE_RE = /captcha|forgot/i;

/** Fields that aren't sign-in fields although they look like user names. */
export const NOT_USERNAME_RE = /new.?e-?mail|neue e-mail|confirm.?e-?mail|e-?mail.?confirm|repeat.?e-?mail|newsletter|subscribe|subscription|mailing.?list|coupon|promo|voucher|gift.?card|search|comment|message|captcha|zip.?code|postal|\bcity\b|\bstreet\b|address.?line|billing|shipping/i;

/** Bitwarden RegistrationKeywords and AccountCreationFieldKeywords. */
export const REGISTER_ATTR_RE =
  /signup|sign-up|sign_up|register|registration|regform|join|create.?account|account.?create|createacct|new.?user|newuser|new_membership|create_customer|enroll|onboard/i;
/** Bitwarden UpdatePasswordFieldKeywords. */
export const CHANGE_PASSWORD_RE = /update.?password|change.?password|current.?password|kennwort ändern|reset.?password|new.?password/i;
/** Bitwarden StrongLoginHeadingKeywords and SubmitLoginButtonNames. */
export const LOGIN_HEADING_RE = /sign.?in|log.?in|log.?on|anmelden|einloggen|connexion|iniciar sesi[oó]n|accedi|inloggen|ログイン|로그인|登录|登入|войти|вход/i;
export const LOGIN_BUTTON_RE = /^(log.?in|sign.?in|submit|continue|next|verify|weiter|anmelden|suivant|siguiente|avanti|volgende|下一步|次へ|다음|продолжить|далее)$/i;
