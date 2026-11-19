# Data compiled into the core

- `eff_large_wordlist.txt`: the EFF's long wordlist for passphrases (7776 words), from https://www.eff.org/dice. © Electronic Frontier Foundation, CC BY 3.0 US.
- `shared-credentials.json` and `password-rules.json`: from Apple's [password-manager-resources](https://github.com/apple/password-manager-resources) (`quirks/`). The first lists sites that share one sign-in across domains; the second, websites' password rules. © Apple Inc., MIT licence (`apple-LICENSE.txt`).

- `separate-sites.json`: our own list of sites whose sign-ins are separate from the rest of their registrable domain, such as `aws.amazon.com` (AWS accounts) under `amazon.com` (shopping accounts). A listed host and every host under it count as that one website: their logins match each other, not the rest of the domain. Add a host to the list to split it off.

To update the Apple files:

```sh
curl -o shared-credentials.json https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/shared-credentials.json
curl -o password-rules.json https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/password-rules.json
```
