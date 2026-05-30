# Yuga table — research notes

Status: research / non-normative
Date: 2026-05-30
Author: Jérémy ZGONEC

This note records the analysis of the Vedic Yuga cosmology table as a
potential ingredient in the Esoptron / EPX transport stack. It is
informational only and has **no impact on the wire format or any
existing protocol**.

---

## 1. The table

| Divine years | Solar years    | Traditional name                |
| -----------: | -------------: | ------------------------------- |
|   12 000 000 |  4 320 000 000 | 1 Kalpa (Brahma's day)          |
|      852 000 |    306 720 000 | 1 Manvantara (71 Mahayugas + sandhya) |
|       12 000 |      4 320 000 | 1 Mahayuga (Chaturyuga)         |
|        4 800 |      1 728 000 | Satya / Krita Yuga              |
|        3 600 |      1 296 000 | Treta Yuga                      |
|        2 400 |        864 000 | Dvapara Yuga                    |
|        1 200 |        432 000 | Kali Yuga                       |

Constant ratio: **1 divine year = 360 solar years**.

Repeating top-of-image pattern `(4800, 852000)` encodes the 14 successive
Manvantaras separated by 15 Krita-Yuga sandhyas that together compose a
Kalpa:

    Kalpa = 14·Manvantara + 15·sandhya
          = 14·(71·Mahayuga) + 15·Krita_Yuga
          = 12 000 000 divine years

## 2. Information-theoretic assessment

| Property                              | Value                       |
| ------------------------------------- | --------------------------- |
| Public, fixed reference data          | Yes                         |
| Shannon entropy contribution          | **0 bits**                  |
| Compressible to                       | a single ratio + 4 integers |
| Secret-key material?                  | No (would be catastrophic)  |
| Usable as nonce / IV?                 | No (known to adversary)     |
| Source of randomness?                 | No                          |
| Wire-format compression candidate?    | No                          |

**Bottom line**: the table cannot make a *transfer* more efficient in
any measurable sense — bits/symbol, bits/second, error-rate, or
overhead are all unaffected by its presence or absence.

## 3. Where the table can legitimately contribute

The Yuga corpus has three dimensions that *are* useful, but none of
them is "transfer efficiency":

### 3.1 Mnemonic / UX vocabulary (real value)

The hierarchy (`Kalpa > Manvantara > Mahayuga > Yuga`) is a clean
4-level naming scheme for protocol artefacts: ceremonies, sessions,
attestation epochs, etc. The lexicon is culturally rich and
mathematically grounded (each level is a known multiple of the previous
one), which makes it pedagogically nice.

Example use:

    ceremony-id = ESPX-SIGMA.Manvantara-7.Mahayuga-23.Krita-001

This does **not** save any bytes; the underlying identifier is still
the usual 32-byte fingerprint. The Yuga form is a *display* layer.

### 3.2 Domain-separation strings (cryptographically neutral)

HKDF / SHAKE call sites already take `info=` and `salt=` constants. The
specific string is irrelevant to security; choosing names from the
Yuga corpus is purely aesthetic:

    hkdf(secret, salt=ceremony_fp, info=b"ESPX|Kalpa|2026|seal")

No effect, positive or negative, on security or efficiency.

### 3.3 Highly-composite base (incidental)

`360 = 2³ · 3² · 5` is one of the most composite small integers. It
divides cleanly into 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 18, 20, 24, 30,
36, 40, 45, 60, 72, 90, 120, 180.

This is useful for **geometric** designs (circular cards, radial
fiducial markers, angular subdivision), but the property belongs to
the number 360 itself — calling it "divine year" instead of "degree"
adds nothing.

## 4. What real transport-efficiency levers look like

For comparison, the levers that actually improve the EPX / Esoptron
data path:

| Lever                                    | Realistic gain   | Status         |
| ---------------------------------------- | ---------------- | -------------- |
| EPX-2 grid density (12·16 → 14·18 base-6) | ≈ +30 % payload  | spec'd (EPX-2) |
| RS GF(256) vs interleaved F₁₃            | ≈ +10 % + better bursts | spec'd (EPX-2) |
| zstd / LZMA on payload before encoding   | × 1.2-2 (content) | trivial        |
| bech32m compact checksum                 | -2 to -3 bytes   | spec'd (EPX-2) |
| Polar codes (near-Shannon)               | ≈ +5 % vs RS     | research       |
| Hybrid QR fallback                       | infrastructure leverage | spec'd (EPX-2) |

Each of these has a measurable, communicable gain. The Yuga table has
none. Conflating the two would *cost* clarity and review-ability for
zero technical benefit.

## 5. Decision and outcome

**Resolution**: do not embed the Yuga table into any cryptographic
primitive, wire format, or compression layer.

**Optional future module** (low priority, purely UX/narrative):

    src/eopx/lexicon/yuga.py

A small, side-effect-free helper that maps integer epochs to
human-readable `(Kalpa, Manvantara, Mahayuga, Yuga)` tuples and back.
Use-cases:

* Pretty-printing ceremony / epoch identifiers in CLI output.
* Translating ISO-8601 dates into a symbolic Yuga timestamp for
  ceremonial artefacts (invitations, posters).
* Documentation flavour.

If implemented, it must remain:

* **Optional**: never required by any crypto path.
* **Display-only**: producing strings, never bytes that participate
  in hashing/derivation.
* **Read-only**: never used to derive secrets, nonces, or salts.

## 6. Reference

The numerical content is drawn from standard Hindu cosmology
(Mahabharata, Manusmṛti, Surya Siddhanta, Vishnu Purana). The figures
are public-domain knowledge; no proprietary claim is made and none is
needed.

The reflexion in this document was triggered while drafting the EPX-2
v2 card specification and saved here for traceability so any future
contributor who proposes a similar idea finds the analysis already
done.
