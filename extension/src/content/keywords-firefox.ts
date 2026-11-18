/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// Regular expressions from Firefox's password manager
// (toolkit/components/passwordmgr/NewPasswordModel.sys.mjs and
// LoginHelper.sys.mjs), used to tell new-password fields (sign-up, change
// password) from current-password fields (sign-in). This file alone is
// under the MPL 2.0, as its source is; the rest of CleanPassword is MIT.

export const PASSWORD_STRING_RE =
  /password|passwort|رمز عبور|mot de passe|パスワード|비밀번호|암호|wachtwoord|senha|Пароль|parol|密码|contraseña|heslo|كلمة السر|kodeord|Κωδικός|pass code|Kata sandi|hasło|รหัสผ่าน|Şifre/i;
export const PASSWORD_ATTR_RE = /pw|pwd|passwd|pass/i;
export const NEW_STRING_RE = /new|erstellen|create|choose|設定|신규|Créer|Nouveau|baru|nouă|nieuw/i;
export const CONFIRM_STRING_RE =
  /wiederholen|wiederholung|confirm|repeat|confirmation|verify|retype|repite|確認|の確認|تکرار|re-enter|확인|bevestigen|confirme|Повторите|tassyklamak|再次输入|ještě jednou|gentag|re-type|confirmar|Répéter|conferma|Repetaţi|again|reenter|再入力|재입력|Ulangi|Bekræft/i;
export const CURRENT_STRING_RE = /current|old|aktuelles|derzeitiges|当前|Atual|actuel|curentă|sekarang/i;
export const FORGOT_STRING_RE =
  /vergessen|vergeten|forgot|oublié|dimenticata|Esqueceu|esqueci|Забыли|忘记|找回|Zapomenuté|lost|忘れた|忘れられた|忘れの方|재설정|찾기|فراموشی| را فراموش کرده اید|Восстановить|Unuttu|perdus|重新設定|reset|recover|remind|restore|trouble/i;
export const LOGIN_RE =
  /login|log in|log on|log-on|Войти|sign in|sigin|sign\/in|sign-in|sign on|sign-on|ورود|登录|Přihlásit se|Přihlaste|Авторизоваться|Авторизация|entrar|ログイン|로그인|inloggen|Συνδέσου|accedi|ログオン|Giriş Yap|登入|connecter|connectez-vous|Connexion|Вход/i;
export const REGISTER_STRING_RE =
  /create[a-zA-Z\s]+account|activate[a-zA-Z\s]+account|Zugang anlegen|Angaben prüfen|Konto erstellen|register|sign up|ثبت نام|登録|注册|cadastr|Зарегистрироваться|Регистрация|Bellige alynmak|تسجيل|ΕΓΓΡΑΦΗΣ|Εγγραφή|Créer mon compte|Créer un compte|Mendaftar|가입하기|inschrijving|Zarejestruj się|Deschideți un cont|Создать аккаунт|ร่วม|Üye Ol|registr|new account|ساخت حساب کاربری|Schrijf je|S'inscrire/i;
export const REGISTER_ACTION_RE = /register|signup|sign-up|create-account|account\/create|join|new_account|user\/create|sign\/up|membership\/create/i;
export const REMEMBER_ME_RE = /remember|auto_login|auto-login|save_mail|save-mail|ricordami|manter|mantenha|savelogin|auto login/i;
export const NEWSLETTER_RE = /newsletter|ニュースレター/i;
