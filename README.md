# MIFARE Ultralight / NTAG

MIFARE Ultralight and NTAG21x cards (pages, password and 3DES
authentication, counters, version/signature) on top of the
[toit-nfc](https://github.com/milkmansson/toit-nfc) `Reader`/`Target`
interface.

## Works with any reader

Unlike [toit-mifare-classic](https://github.com/milkmansson/toit-mifare-classic),
nothing here needs raw-frame access. Page reads/writes and all of the
authentication (`PWD_AUTH`, Ultralight C's 3DES exchange), version
(`GET_VERSION`), counter (`READ_CNT`) and signature (`READ_SIG`) commands
are plain command/response exchanges, so `UltralightCard` works over any
`Target` — the PN532 included, which can't do MIFARE Classic Crypto1 at
all through this package family.

## Scope

Covers the command set shared across MIFARE Ultralight, Ultralight C,
Ultralight EV1, and NTAG213/215/216. Deliberately out of scope for now:

- **Model-specific configuration pages** (`AUTH0`, `ACCESS`, `CFG0`,
  `CFG1`, the lock bytes). Their page numbers differ per model and memory
  size. `get-version` plus the relevant datasheet is how a caller would
  find and write these; this package doesn't try to guess a model from a
  SAK or UID.

## Status

`UltralightCard` (read, write, `authenticate` via `PWD_AUTH`,
`get-version`, `read-signature`, `read-counter`) and `UltralightVersion`
are implemented and unit-tested against the GET_VERSION response
documented for the NTAG213 in NXP's datasheet — not yet checked against a
real chip.

`authenticate-ultralight-c` (Ultralight C's 3DES mutual authentication,
via [toit-des](https://github.com/milkmansson/toit-des)) is also
implemented and tested by simulating both sides of the handshake with the
same key — this checks the CBC chaining, rotation and comparison logic is
internally self-consistent, but **the exact byte-level framing of the
second step's response (whether it carries a leading status byte before
the 8-byte encrypted nonce) hasn't been checked against a real Ultralight
C card or the datasheet text**, so the code accepts either shape rather
than committing to one. This is the first thing to verify once there's
hardware to test against.

---

Parts of this repository were developed with the help of [Claude Code](https://claude.com/claude-code).
