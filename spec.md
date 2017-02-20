(Note: What follows is fresh and untested. It also breaks the rule "Don't roll your own crypto". It needs peer review and we would love to hear from you!)

### Goal

The goal is to design a login system with authentication processes leaking minimal information. In particular we want:

1. Full at rest deniability of usernames. That is, we should not be able tell from looking at the database if a particular username is or is not associated with a user.
2. Full in use deniability of usernames (for registrations, login attempts, credential changes), 
except when the username is an email address used for magic links.
3. Full at rest deniability of login activity. (For example, no login counts, timestamps, IP addresses, etc. stored in the database.)

We also assume a passive snooper (rogue employee, government, cloud provider, etc.) that has both at rest read access to the databases, and in use read access to server activity. Even with this assumption, we want:

4. At rest and in use security

### Features

- The user uses his email address as an easy-to-remember username
- The user should be able to change his password and email address
- The user can opt-in to magic link verification (on top of the password) for extra security

### Definitions

* `e` is the user's email (used as a username)
* `p` is the user's password
* `s` is the user's secret, the concatenation `e || p`
* `m` is the user's mnemonic, 120 bits of entropy generated at registration 
* `c` is a challenge, assumed to be the current time in nanoseconds
* `H` is SHA256
* `priv(a)` is the Ed25519 private key derived from using `a` as seed, using PKDF2 as a key stretcher if needed.
* `pub(a)` is the Ed25519 public key derived from using `a` as seed, using PKDF2 as a key stretcher if needed.
* `E(b, pub(a))` is the encryption of `b` with `pub(a)`
* `S(b, priv(a))` is the signature of `b` with `priv(a)`

### Login scheme: from `s` to `m`

1. For every `s`, the server stores a mapping from the key `k = H(e) ⊕ H(H(s))` (here `⊕` is XOR) to a struct containing:
 * `pub(s)`
 * `E(m, pub(s))`
 * `magic`, a signed boolean indicating if magic link security is enabled
 * `c_last`, the last used challenge
2. The user sends `k`, `c` and `S(c, priv(s))` to the server. If `magic` is true, the user is expected to also send `e` and `H(S)`.
3. The server checks:
 * that `c` is within 3 minutes of the current server time (if not, the server returns the current server time)
 * that `S(c, priv(s))` is valid
 * that `c > c_last` (to guarantee uniqueness of `c`)
 * if `magic` is true, that the equality `k = H(e) ⊕ H(H(s))` holds
4. If the above checks all pass the server returns `E(m, pub(s))`. The user can then get `m` with `priv(s)`.

Notes:

1. If `magic` is true, an attacker cannot provide a fake `e` by construction.
2. Multiple encrypted mnemonics can be stored under the same key `k`.
3. If either `e` or `p` changes, a new mapping is created. The old mapping is deleted.
4. When creating a new mapping, never overwrite existing mappings. (Knowledge of `k` should not allow an attacker to overwrite the mapping.)
5. If magic link is never enabled, `e` can be any string (not necessarily a valid email address).
6. At rest, the database stores `k`, `pub(s)`, `E(m, pub(s))`, `m` and `c_last`:
  - `k`, `pub(s)` and `E(m, pub(s))` are random pieces of data, leaking no critical information
  - `k`, `pub(s)` and `E(m, pub(s))` can be faked, providing deniability
  - `k`, `pub(s)` and `E(m, pub(s))` can be length validated
  - `c_last` can be flushed if it is less than the current time minus 3 minutes
7. User requests disclose `k`, `c` and `S(c, priv(s))`, which leak no critical information. (Noise can be added to `c` to not leak the user's precise clock.) If `magic` is true, `e` is necessarily disclosed (to send the magic link) and `H(s)` leaks no critical information.
8. If the user attempts to log in without 2FA when `magic` is true, the signed `magic` is returned, verified by the client, and login is retried, sending the appropriate 2FA data.
