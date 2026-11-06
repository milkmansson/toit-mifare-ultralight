// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the TESTS_LICENSE file.

import expect show *
import mifare-ultralight show UltralightVersion UltralightException

main:
  test-version-decoding
  test-exception-decoding

test-version-decoding:
  // Mirrors the example GET_VERSION response documented for the NTAG213
  // in NXP's datasheet. Not checked against a real chip.
  version := UltralightVersion.from-bytes #[0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03]
  expect-equals 0x00 version.header
  expect-equals 0x04 version.vendor-id
  expect version.is-nxp
  expect-equals 0x04 version.product-type
  expect-equals 0x02 version.product-subtype
  expect-equals 1 version.major-product-version
  expect-equals 0 version.minor-product-version
  expect-equals 0x0F version.storage-size-byte
  // 0x0F >> 1 == 7, so 2^7 == 128 bytes, and the low bit is set, so it's
  // "128 to 256 bytes", not exactly 128. NTAG213 has 144 bytes of user
  // memory, consistent with that range.
  expect-equals 128 version.storage-size-bytes
  expect-not version.is-storage-size-exact
  expect-equals 0x03 version.protocol-type
  expect version.is-iso-14443-3-compliant

  // An exact power-of-two size (eg. a hypothetical 256-byte card).
  exact-version := UltralightVersion.from-bytes #[0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x10, 0x03]
  expect-equals 256 exact-version.storage-size-bytes
  expect exact-version.is-storage-size-exact

  expect-throw "INVALID_ARGUMENT": UltralightVersion.from-bytes #[0x00, 0x04]

test-exception-decoding:
  expect-equals
      UltralightException.INVALID-OPERATION
      (UltralightException.from-response #[0x00]).code
  expect-equals
      UltralightException.PARITY-OR-CRC-ERROR
      (UltralightException.from-response #[0x01]).code
  expect-equals
      UltralightException.EEPROM-WRITE-ERROR
      (UltralightException.from-response #[0x04]).code
  expect-equals
      UltralightException.INVALID-ERROR-RESPONSE
      (UltralightException.from-response #[0x99]).code
  expect-equals
      UltralightException.INVALID-ERROR-RESPONSE
      (UltralightException.from-response null).code
  expect-equals
      UltralightException.INVALID-ERROR-RESPONSE
      (UltralightException.from-response #[0x00, 0x01]).code
