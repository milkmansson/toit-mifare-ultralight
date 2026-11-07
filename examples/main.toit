// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

/**
Hardware test for $UltralightCard over a PN532 (I2C).

Unlike MIFARE Classic, none of this needs raw-frame access, so it all
  works over the PN532. Steps, in order of how likely they are to work
  on whatever Ultralight/NTAG21x card you have to hand:

1. UID + a plain page-0 read (every card in the family).
2. $UltralightCard.get-version, $UltralightCard.read-signature,
   $UltralightCard.read-counter (null on cards that don't implement
   them -- not a failure).
3. A write-then-read-back round trip on $SCRATCH-PAGE (set this to a
   page you're sure isn't locked/used -- the default is a guess, not a
   verified-safe page for your specific card; check your card's memory
   map before trusting it).
4. $UltralightCard.authenticate ($UltralightCard.DEFAULT-PASSWORD) if
   the card looks like an NTAG21x with password protection configured.
5. $UltralightCard.authenticate-ultralight-c, only if you have an
   actual Ultralight C card and know its key -- $AUTH-C-KEY is a
   placeholder, not a real default; fill it in or skip this step.
*/

import gpio
import i2c
import mifare-ultralight show UltralightCard UltralightException
import pn53x show Pn53x

// I2C test harness (2026-11-07); keep in sync with
// toit-pn53x/examples/main.toit if the wiring changes. IRQ/RESET are
// both optional -- see that file's comment -- and unset here since
// only VCC/GND/SDA/SCL are wired so far.
SDA ::= 19
SCL ::= 20
IRQ-PIN/int? ::= null
RESET-PIN/int? ::= null

// A page believed unused/unlocked on a typical blank NTAG21x -- verify
// against your actual card's memory map before trusting this.
SCRATCH-PAGE ::= 10

// Not a real default -- only set if you have an actual Ultralight C
// card and know its key.
AUTH-C-KEY/ByteArray? := null

main:
  sda := gpio.Pin SDA
  scl := gpio.Pin SCL
  irq := IRQ-PIN and (gpio.Pin IRQ-PIN)
  reset := RESET-PIN and (gpio.Pin RESET-PIN)

  bus := i2c.Bus --sda=sda --scl=scl --frequency=100_000
  device := bus.device Pn53x.I2C-ADDRESS
  pn53x := Pn53x.i2c device --irq=irq --reset=reset

  pn53x.on
  print "Firmware: $pn53x.miscellaneous.firmware-version"
  print "Waiting for an Ultralight/NTAG21x card..."

  target := null
  while not target:
    target = pn53x.poll
    if not target: sleep --ms=200

  print "Found: $target"
  card := UltralightCard target
  print "UID: $card.uid"

  page0 := card.read --page=0
  print "Page 0: $page0"
  if page0: print "PASS: plain read works."
  else: print "FAIL: expected page 0 data, got null -- check wiring/antenna first."

  version := card.get-version
  if version:
    print "GET_VERSION: $version"
  else:
    print "GET_VERSION not implemented by this card (expected for original Ultralight/Ultralight C)."

  signature := card.read-signature
  if signature: print "Signature: $signature"
  else: print "READ_SIG not implemented by this card."

  3.repeat: | counter/int |
    value := card.read-counter --counter=counter
    if value: print "Counter $counter: $value"
    else: print "Counter $counter not implemented/not present."

  print "Writing #[0x11, 0x22, 0x33, 0x44] to page $SCRATCH-PAGE..."
  exception := catch:
    card.write --page=SCRATCH-PAGE #[0x11, 0x22, 0x33, 0x44]
  if exception:
    print "Write failed: $exception -- try a different SCRATCH-PAGE."
  else:
    read-back := card.read --page=SCRATCH-PAGE
    written := read-back and read-back[..4] == #[0x11, 0x22, 0x33, 0x44]
    if written: print "PASS: write-then-read round trip matches."
    else: print "FAIL: read-back ($read-back) doesn't match what was written."

  pwd-result := card.authenticate --password=UltralightCard.DEFAULT-PASSWORD
  if pwd-result:
    print "PASS: PWD_AUTH with the common default password succeeded, PACK=$pwd-result."
  else:
    print "PWD_AUTH with the common default password failed or not configured (not necessarily a problem -- see the doc comment)."

  if AUTH-C-KEY:
    auth-c-result := card.authenticate-ultralight-c --key=AUTH-C-KEY
    print (auth-c-result ? "PASS: Ultralight C 3DES authentication succeeded." : "FAIL: Ultralight C authentication failed -- check the key.")
  else:
    print "Skipping Ultralight C authentication (AUTH-C-KEY not set)."

  card.close
  pn53x.off
  device.close
  bus.close
  if irq: irq.close
  if reset: reset.close
  scl.close
  sda.close
