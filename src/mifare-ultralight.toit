// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import des show TripleDes cbc-encrypt cbc-decrypt
import nfc.reader show Target

/**
A MIFARE Ultralight or NTAG21x card, built on top of a $Target from any
  toit-nfc reader.

Unlike MIFARE Classic, none of this needs raw-frame access: page reads,
  page writes, and all the authentication/version/counter/signature
  commands are plain command/response exchanges over $Target.transceive,
  so this works on any reader (including the PN532, which can't do
  MIFARE Classic Crypto1 at all through this family of packages).

Covers the plain command set shared by MIFARE Ultralight, Ultralight C,
  Ultralight EV1, and NTAG213/215/216 (collectively "the Ultralight
  family"). Model-specific configuration (the exact page numbers of
  AUTH0/ACCESS/CFG0/CFG1, which differ per model and memory size) is out
  of scope here; $get-version plus the model's datasheet is how a caller
  would find those.
*/
class UltralightCard:
  static READ_ ::= 0x30
  static WRITE_ ::= 0xA2
  static FAST-READ_ ::= 0x3A
  static PWD-AUTH_ ::= 0x1B
  static AUTHENTICATE-1_ ::= 0x1A
  static AUTHENTICATE-2_ ::= 0xAF
  static GET-VERSION_ ::= 0x60
  static READ-SIG_ ::= 0x3C
  static READ-CNT_ ::= 0x39
  static ACK_ ::= #[0x0A]

  /**
  The factory-default password used by most NTAG21x boards before any
    configuration, and by some vendors' "blank" Ultralight-family cards.
  Not a MIFARE standard; just a common convention worth trying first.
  */
  static DEFAULT-PASSWORD := #[0xFF, 0xFF, 0xFF, 0xFF]

  target/Target

  constructor .target:

  /** The UID of the underlying $target. */
  uid -> ByteArray: return target.uid

  /**
  Reads 4 pages (16 bytes) starting at $page.

  Reading near the end of memory still returns 16 bytes; the card wraps
    around and returns pages from the start of memory for the part that
    would run past the end. Callers that know the card's exact page count
    (eg. from $get-version) should ignore the wrapped-around tail.
  */
  read --page/int -> ByteArray?:
    if not 0 <= page <= 0xFF: throw "INVALID_ARGUMENT"
    return target.transceive #[READ_, page] --check-crc

  /**
  Reads consecutive pages from $start to $end (inclusive), in one command.

  Not every card in the family implements FAST_READ; if the card doesn't,
    this returns null (a timeout) the same as any other unsupported
    command.
  */
  fast-read --start/int --end/int -> ByteArray?:
    if not 0 <= start <= 0xFF: throw "INVALID_ARGUMENT"
    if not start <= end <= 0xFF: throw "INVALID_ARGUMENT"
    return target.transceive #[FAST-READ_, start, end] --check-crc

  /**
  Writes exactly 4 bytes ($bytes) to $page.

  Unlike MIFARE Classic, a single write only touches one page (4 bytes),
    not a whole 16-byte block.
  */
  write --page/int bytes/ByteArray -> none:
    if not 0 <= page <= 0xFF: throw "INVALID_ARGUMENT"
    if bytes.size != 4: throw "UltralightCard.write: bytes must be 4 bytes long"
    response := target.transceive (#[WRITE_, page] + bytes)
    if response != ACK_: throw (UltralightException.from-response response)

  /**
  Authenticates with $password (4 bytes).

  Returns the 2-byte PACK (password acknowledge) sent back by the card on
    success, or null if the password was wrong. Models that implement this
    (NTAG213/215/216, Ultralight EV1) intentionally don't send a NAK on a
    wrong password — they just don't respond — so a null return here is
    the expected shape of a failure, not a communication error.
  */
  authenticate --password/ByteArray -> ByteArray?:
    if password.size != 4: throw "INVALID_ARGUMENT"
    return target.transceive (#[PWD-AUTH_] + password) --check-crc

  /**
  Authenticates with an Ultralight C card, using its 3DES mutual
    authentication (an ISO/IEC 11770-2 three-pass exchange).

  $key must be 16 bytes (2-key 3DES, which is the keying Ultralight C
    uses). Returns whether authentication succeeded.

  The exact byte-level framing of the second step's response (whether it
    carries a leading status byte before the 8-byte encrypted nonce) has
    not been checked against a real card or the datasheet text in this
    session — see this package's README — so this accepts either shape
    rather than committing to one.
  */
  authenticate-ultralight-c --key/ByteArray -> bool:
    if key.size != 16: throw "INVALID_ARGUMENT"
    cipher := TripleDes --key=key

    step1 := target.transceive #[AUTHENTICATE-1_, 0x00] --check-crc
    if not step1 or step1.size != 9 or step1[0] != 0xAF: return false
    encrypted-rnd-b := step1[1..9]
    rnd-b := cbc-decrypt cipher encrypted-rnd-b

    rnd-a := ByteArray 8: random 0x100
    rnd-b-rotated := rnd-b[1..] + rnd-b[..1]

    // Continues the CBC chain: this step's IV is the previous step's
    // ciphertext.
    plain := rnd-a + rnd-b-rotated
    encrypted := cbc-encrypt cipher plain --iv=encrypted-rnd-b

    step2 := target.transceive (#[AUTHENTICATE-2_] + encrypted) --check-crc
    if not step2: return false

    // The card should return Ek(RndA'). Accept either an 8-byte raw
    // response or a 9-byte one with a leading 0x00 status byte; see the
    // doc comment above.
    encrypted-rnd-a-rotated/ByteArray := ?
    if step2.size == 9 and step2[0] == 0x00:
      encrypted-rnd-a-rotated = step2[1..9]
    else:
      encrypted-rnd-a-rotated = step2
    if encrypted-rnd-a-rotated.size != 8: return false

    rnd-a-rotated := cbc-decrypt cipher encrypted-rnd-a-rotated --iv=encrypted[8..16]
    expected-rnd-a-rotated := rnd-a[1..] + rnd-a[..1]
    return rnd-a-rotated == expected-rnd-a-rotated

  /**
  Reads the card's version information (chip type, sub-type, memory size).

  Returns null if the card doesn't implement GET_VERSION (original
    MIFARE Ultralight and Ultralight C don't).
  */
  get-version -> UltralightVersion?:
    response := target.transceive #[GET-VERSION_] --check-crc
    if not response: return null
    return UltralightVersion.from-bytes response

  /**
  Reads the card's originality signature: a 32-byte ECC signature over the
    UID, used to check (against NXP's public key, not done by this method)
    that the card is a genuine NXP chip rather than a clone.

  Returns null if the card doesn't implement this command.
  */
  read-signature -> ByteArray?:
    return target.transceive #[READ-SIG_, 0x00] --check-crc

  /**
  Reads one-way counter $counter (0, 1, or 2 on NTAG213/215/216; the
    counters are 24-bit and only ever increment).

  Returns null if the card doesn't implement this command, or doesn't
    have that counter.
  */
  read-counter --counter/int -> int?:
    if not 0 <= counter <= 2: throw "INVALID_ARGUMENT"
    response := target.transceive #[READ-CNT_, counter] --check-crc
    if not response: return null
    if response.size != 3: throw "INVALID_RESPONSE"
    return response[0] | (response[1] << 8) | (response[2] << 16)

  /** Sends a HLTA to the underlying $target. */
  close -> none:
    target.close

/**
A NAK (negative acknowledge) from a $UltralightCard.write.

The NAK nibble is the same link-layer mechanism MIFARE Classic uses (see
  `MifareException` in toit-mifare-classic), so the generic codes share
  their meaning; $EEPROM-WRITE-ERROR is specific to the Ultralight family.
*/
class UltralightException:
  static INVALID-OPERATION ::= 0x00
  static PARITY-OR-CRC-ERROR ::= 0x01
  /** The EEPROM write itself failed (eg. the page is locked). */
  static EEPROM-WRITE-ERROR ::= 0x04

  /**
  The card did not return an ACK, and the response did not match any
    known NAK code either (including no response at all).
  */
  static INVALID-ERROR-RESPONSE ::= -1

  /** The received data, if any. */
  response/ByteArray?

  code/int

  constructor.from-response .response/ByteArray?:
    if not response or response.size != 1:
      code = INVALID-ERROR-RESPONSE
    else if response[0] == INVALID-OPERATION or response[0] == PARITY-OR-CRC-ERROR or
        response[0] == EEPROM-WRITE-ERROR:
      code = response[0]
    else:
      code = INVALID-ERROR-RESPONSE

  stringify -> string:
    if code == INVALID-OPERATION: return "Invalid operation"
    if code == PARITY-OR-CRC-ERROR: return "Parity or CRC error"
    if code == EEPROM-WRITE-ERROR: return "EEPROM write error"
    return "Invalid response: $response"

/**
The decoded response of $UltralightCard.get-version.

See NXP application note AN10752 / the NTAG21x datasheets for the exact
  encoding this is based on.
*/
class UltralightVersion:
  /** Fixed header byte, always 0x00. */
  header/int
  /** Vendor ID; 0x04 for NXP Semiconductors. */
  vendor-id/int
  product-type/int
  product-subtype/int
  major-product-version/int
  minor-product-version/int
  /**
  The storage-size byte, undecoded. See $storage-size-bytes for the
    decoded value.
  */
  storage-size-byte/int
  protocol-type/int

  constructor.from-bytes bytes/ByteArray:
    if bytes.size != 8: throw "INVALID_ARGUMENT"
    header = bytes[0]
    vendor-id = bytes[1]
    product-type = bytes[2]
    product-subtype = bytes[3]
    major-product-version = bytes[4]
    minor-product-version = bytes[5]
    storage-size-byte = bytes[6]
    protocol-type = bytes[7]

  /** Whether $vendor-id identifies this as a genuine NXP chip. */
  is-nxp -> bool: return vendor-id == 0x04

  /**
  The approximate user memory size in bytes, decoded from
    $storage-size-byte.

  The encoding is: the top 7 bits are an exponent n, so the size is
    2ⁿ bytes; the bottom bit, if set, means the real size is somewhere
    between 2ⁿ and 2ⁿ⁺¹ rather than being exactly 2ⁿ (see
    $is-storage-size-exact).
  */
  storage-size-bytes -> int:
    return 1 << (storage-size-byte >> 1)

  /** See $storage-size-bytes. */
  is-storage-size-exact -> bool:
    return storage-size-byte & 1 == 0

  /** Whether $protocol-type identifies this as ISO 14443-3 compliant. */
  is-iso-14443-3-compliant -> bool: return protocol-type == 0x03

  stringify -> string:
    return "UltralightVersion(vendor=$(%02x vendor-id), type=$(%02x product-type), "
        + "subtype=$(%02x product-subtype), version=$major-product-version.$minor-product-version, "
        + "storage~=$storage-size-bytes bytes$(is-storage-size-exact ? "" : "+"))"
