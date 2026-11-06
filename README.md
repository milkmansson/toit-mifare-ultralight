# MIFARE Ultralight / NTAG

MIFARE Ultralight and NTAG21x cards (pages, password authentication,
counters, version/signature) on top of the
[toit-nfc](https://github.com/milkmansson/toit-nfc) `Reader`/`Target`
interface.

## Works with any reader

Unlike [toit-mifare-classic](https://github.com/milkmansson/toit-mifare-classic),
nothing here needs raw-frame access. Page reads/writes and the
password-authentication (`PWD_AUTH`), version (`GET_VERSION`), counter
(`READ_CNT`) and signature (`READ_SIG`) commands are all plain
command/response exchanges, so `UltralightCard` works over any
`Target` — the PN532 included, which can't do MIFARE Classic Crypto1 at
all through this package family.

## Scope

Covers the command set shared across MIFARE Ultralight, Ultralight EV1,
and NTAG213/215/216. Deliberately out of scope for now:

- **Ultralight C's authentication.** It uses 3DES, not a plain password;
  the Toit SDK's `crypto` library has no 3DES, so this would need to bring
  its own.
- **Model-specific configuration pages** (`AUTH0`, `ACCESS`, `CFG0`,
  `CFG1`, the lock bytes). Their page numbers differ per model and memory
  size. `get-version` plus the relevant datasheet is how a caller would
  find and write these; this package doesn't try to guess a model from a
  SAK or UID.

## Status

`UltralightCard` (read, write, authenticate, get-version, read-signature,
read-counter) and `UltralightVersion` are implemented and unit-tested
against the GET_VERSION response documented for the NTAG213 in NXP's
datasheet — not yet checked against a real chip.

---

Parts of this repository were developed with the help of [Claude Code](https://claude.com/claude-code).
