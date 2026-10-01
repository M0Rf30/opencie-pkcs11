# Supported Cards & Readers — opencie-pkcs11

Which cards and readers `libopencie-pkcs11` recognises, how the chip is
identified, and what to do when your card is rejected.

---

## 1. Scope

Supported: **CIE 3.0** (Carta d'Identità Elettronica), both contactless (NFC)
and contact interfaces.

Not supported:

- CIE 2.0 and older contact-only cards
- Health cards (TS / CNS) and other Italian smart cards
- Other national eIDs

---

## 2. Recognised chips

The chip/applet is identified by the *historical bytes* of its ATR.

| Chip / applet | Historical-byte signature | Behaviour family | Example ATR |
|---|---|---|---|
| NXP | `80 31 80 65 49 54 4E 58 50` | NXP | `3B 8E 80 01 80 31 80 65 49 54 4E 58 50 12 0F FF 82 90 F0` |
| Gemalto | `80 31 80 65 B0 85 04 00 11` | Gemalto | `3B 8F 80 01 80 31 80 65 B0 85 04 00 11 12 0F FF 82 90 00 8A` |
| Gemalto 2 | `80 31 80 65 B0 85 03 00 EF` | Gemalto | |
| STMicro | `80 66 47 50 00 B8 00 7F` | STM | `3B 8B 80 01 80 66 47 50 00 B8 00 7F 82 90 00 2E` |
| STMicro 2 | `80 80 01 01` (no historical bytes) | STM2 | `3B 80 80 01 01` |
| STMicro 3 | `80 01 80 66 47 50 00 B8 00 94 82 90 00 C5` | STM3 | `3B 8B 80 01 80 66 47 50 00 B8 00 94 82 90 00 C5` |
| Actalis | `80 31 80 65 49 54 4A 34 41 … 88` | Actalis | `3B 8F 80 01 80 31 80 65 49 54 4A 34 41 12 0F FF 82 90 00 88` |
| Actalis 2023 | `80 31 80 65 49 54 4A 34 43 … 8A` | Actalis | `3B 8F 80 01 80 31 80 65 49 54 4A 34 43 12 0F FF 82 90 00 8A` |
| Actalis B946 | `80 31 80 65 49 54 4A 34 4C … 85` | Actalis | `3B 8F 80 01 80 31 80 65 49 54 4A 34 4C 12 0F FF 82 90 00 85` |
| Bit4id | `80 31 80 65 49 54 4A 34 42 … 8B` | Bit4id | `3B 8F 80 01 80 31 80 65 49 54 4A 34 42 12 0F FF 82 90 00 8B` |
| Bit4id 2023 | `80 31 80 65 49 54 4A 34 44 … 8D` | Bit4id | `3B 8F 80 01 80 31 80 65 49 54 4A 34 44 12 0F FF 82 90 00 8D` |
| Bit4id B9547 | `80 31 80 65 49 54 4A 34 49 … 80` | Bit4id | `3B 8F 80 01 80 31 80 65 49 54 4A 34 49 12 0F FF 82 90 00 80` |

The exact byte sequences live in `shared/src/csp/atr.cpp` (`atr_list`); that
file is the source of truth.

---

## 3. How detection works

### ATR sources

- **PC/SC readers** (contact and contactless): the ATR is the one reported by
  the reader.
- **NFC backends** (Android and the Linux kernel NFC backend): there is no real
  ATR, so one is synthesised as `3B (80|n) 80 01 <historical bytes> TCK`.
  - Android: the `IsoDep` historical bytes (NFC-A) or the NFC-B higher-layer
    response.
  - Linux kernel NFC: the historical bytes are taken from the ATS. Enable it
    with `OPENCIE_NFC_BACKEND=kernel`.
  - When the card exposes no historical bytes the minimal ATR
    `3B 80 80 01 01` is produced; this is exactly the STMicro 2 signature, and
    is how those cards are identified.

### Matching

1. **Exact match** against the table above.
2. **Family fallback**: an ATR containing the historical bytes
   `80 31 80 65 49 54 4A 34 xx` with an *unlisted* variant byte `xx` is treated
   as an Actalis/Bit4id card, and the unlisted variant is logged.
3. **Otherwise** the card is rejected as unsupported: entry points return
   `CKR_TOKEN_NOT_RECOGNIZED` (`0xE1`), `cie_last_error` reports kind
   `CIE_ERR_UNSUPPORTED_CARD` (`10`), and the ATR is written to the log as hex.

### Known limitation

ATRs whose historical bytes are all zero, such as
`3B 8F 80 01 00 00 00 00 00 00 00 00 00 00 00 FF 82 90 00 E3`, carry no
information about the chip and cannot be classified yet.

---

## 4. Readers

Any PC/SC reader with an ISO 14443 contactless interface or a contact slot
works.

- Combo readers expose several slots, for example
  `Alcor Link AK9567 00 00` (contact) and
  `Alcor Link AK9567 [Contactless Card Reader] 01 00` (contactless).
- During enrolment (`cie_enable`) **every** slot is tried; there is no need to
  disable built-in readers.
- The reader name returned by `cie_reader_name()` prefers a slot with a card
  present, then an empty contactless slot, then any other empty non-internal
  slot.

---

## 5. Reporting a new card

If your card is rejected as unsupported:

1. Get the ATR with `pcsc_scan` (from `pcsc-tools`), with the card on the
   reader.
2. Collect the log from `~/.CIEPKI/`
   (Flatpak: `~/.var/app/io.github.m0rf30.opencie/.CIEPKI/`). It contains the
   ATR that was rejected.
3. Open an issue at <https://github.com/M0Rf30/opencie/issues> with the ATR,
   the log, and the reader model.

---

## 6. Adding a new ATR (contributors)

1. Add an entry to `atr_list` in `shared/src/csp/atr.cpp` with the right
   `CIE_Type`.
2. If you introduced a new `CIE_Type` value, map it to its behaviour family in
   `cie_family()`.
3. Add a Catch2 case in `tests/test_atr.cpp`.

Never reorder or insert `CIE_Type` values in the middle: `ias.cpp` compares
`type >= CIE_NXP`. Append new values at the end.
