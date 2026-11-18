# Data compiled into the core

- `eff_large_wordlist.txt`: the EFF's long wordlist for passphrases (7776 words), from https://www.eff.org/dice. © Electronic Frontier Foundation, CC BY 3.0 US.
- `shared-credentials.json` and `password-rules.json`: from Apple's [password-manager-resources](https://github.com/apple/password-manager-resources) (`quirks/`). The first lists sites that share one sign-in across domains; the second, websites' password rules. © Apple Inc., MIT licence (`apple-LICENSE.txt`).

To update the Apple files:

```sh
curl -o shared-credentials.json https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/shared-credentials.json
curl -o password-rules.json https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/password-rules.json
```
