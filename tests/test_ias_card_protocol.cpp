// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Hostile-card tests for the IAS protocol layer (shared/src/csp/ias.cpp).
//
// IAS talks to the card exclusively through the CToken transmit callback, so
// a fake card (a function from command APDU to response bytes) is enough to
// drive the file-read, GET RESPONSE and ASN.1 parsing paths with crafted
// answers. No hardware or secure-messaging session is needed: everything
// here runs on the plain (non-SM) channel.
#ifndef _WIN32

#include <openssl/bn.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <vector>

#include "crypto/des3.h"
#include "crypto/mac.h"
#include "crypto/sha256.h"
#include "csp/ias.h"
#include "util/array.h"
#include "util/util.h"
#include "util/util_exception.h"

namespace {

using Bytes = std::vector<uint8_t>;

// STM2 ATR: recognised by IAS::ReadCIEType(), so SelectAID_IAS() can set the
// card type (needed by InitDHParam) with a plain SELECT MF.
const uint8_t kStm2Atr[] = {0x3B, 0x80, 0x80, 0x01, 0x01};

Bytes Sw(uint16_t sw) {
  return {static_cast<uint8_t>(sw >> 8), static_cast<uint8_t>(sw & 0xFF)};
}

Bytes WithSw(Bytes body, uint16_t sw) {
  body.push_back(static_cast<uint8_t>(sw >> 8));
  body.push_back(static_cast<uint8_t>(sw & 0xFF));
  return body;
}

// A fake card: `handler` maps every command APDU to the full response
// (data + status word). Every command seen is recorded in `sent`.
class FakeCard {
 public:
  using Handler = std::function<Bytes(const Bytes &apdu)>;

  explicit FakeCard(Handler handler) : handler_(std::move(handler)) {}

  static HRESULT Transmit(void *data, uint8_t *apdu, DWORD apduSize,
                          uint8_t *resp, DWORD *respSize) {
    auto *self = static_cast<FakeCard *>(data);
    self->sent.emplace_back(apdu, apdu + apduSize);
    Bytes out = self->handler_(self->sent.back());
    if (out.size() > *respSize) return SCARD_E_INSUFFICIENT_BUFFER;
    std::memcpy(resp, out.data(), out.size());
    *respSize = static_cast<DWORD>(out.size());
    return SCARD_S_SUCCESS;
  }

  size_t Count(uint8_t ins) const {
    size_t n = 0;
    for (const auto &a : sent)
      if (a.size() >= 2 && a[1] == ins) ++n;
    return n;
  }

  std::vector<Bytes> sent;

 private:
  Handler handler_;
};

// A card holding a single transparent file: SELECT answers 9000, READ BINARY
// serves the file by offset and answers 6B00 past the end.
FakeCard::Handler FileCard(Bytes file) {
  return [file = std::move(file)](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xA4) return Sw(0x9000);
    if (apdu[1] == 0xB0) {
      size_t off = (static_cast<size_t>(apdu[2]) << 8) | apdu[3];
      size_t le = apdu.size() > 4 ? apdu[4] : 256;
      if (le == 0) le = 256;
      if (off >= file.size()) return Sw(0x6B00);
      size_t n = std::min(le, file.size() - off);
      return WithSw(Bytes(file.begin() + off, file.begin() + off + n), 0x9000);
    }
    return Sw(0x6D00);
  };
}

// DER helpers (definite lengths only).
Bytes Tlv(uint8_t tag, const Bytes &content) {
  Bytes out {tag};
  size_t n = content.size();
  if (n < 0x80) {
    out.push_back(static_cast<uint8_t>(n));
  } else if (n < 0x100) {
    out.push_back(0x81);
    out.push_back(static_cast<uint8_t>(n));
  } else {
    out.push_back(0x82);
    out.push_back(static_cast<uint8_t>(n >> 8));
    out.push_back(static_cast<uint8_t>(n & 0xFF));
  }
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

Bytes Cat(Bytes a, const Bytes &b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

// Positive DER INTEGER content of an unsigned big-endian value.
Bytes DerUInt(Bytes v) {
  if (!v.empty() && (v[0] & 0x80)) v.insert(v.begin(), 0x00);
  return Tlv(0x02, v);
}

Bytes FromHex(const char *hex) {
  BIGNUM *bn = nullptr;
  BN_hex2bn(&bn, hex);
  Bytes out(static_cast<size_t>(BN_num_bytes(bn)));
  BN_bn2bin(bn, out.data());
  BN_free(bn);
  return out;
}

Bytes BnBytes(const BIGNUM *bn, size_t padTo = 0) {
  size_t n = std::max(padTo, static_cast<size_t>(BN_num_bytes(bn)));
  Bytes out(n);
  BN_bn2binpad(bn, out.data(), static_cast<int>(n));
  return out;
}

// Standard 1024-bit MODP group with 160-bit prime-order subgroup (RFC 5114
// section 2.1), a valid group of the size class the card may announce.
const char *const kGroupP =
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
    "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
    "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
const char *const kGroupG =
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
    "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
    "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
const char *const kGroupQ = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";

struct DhGroup {
  Bytes g = FromHex(kGroupG), p = FromHex(kGroupP), q = FromHex(kGroupQ);
};

// Card answering the three GET DATA queries of InitDHParam (STM2 family: one
// parameter per query, selected by the byte before the trailing 00) and the
// DH key-exchange commands. `iccPub` is returned for the key exchange.
FakeCard::Handler DhCard(const DhGroup &grp, const Bytes &iccPub) {
  return [grp, iccPub](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xCB) {
      if (apdu[4] == 0x06)  // GET DATA of the ICC public key
        return WithSw(Tlv(0x30, Tlv(0x04, iccPub)), 0x9000);
      const Bytes &val = apdu[15] == 0x97   ? grp.g
                         : apdu[15] == 0x98 ? grp.p
                                            : grp.q;
      return WithSw(Tlv(0x30, Tlv(0x30, Tlv(0x30, Tlv(0x04, val)))), 0x9000);
    }
    return Sw(0x9000);
  };
}

struct Rig {
  explicit Rig(FakeCard::Handler h)
      : card(std::move(h)),
        ias(FakeCard::Transmit, ByteArray(kStm2Atr, sizeof(kStm2Atr))) {
    ias.SetCardContext(&card);
  }
  FakeCard card;
  IAS ias;
};

// A card able to complete the DH key exchange and then answer Secure
// Messaging commands with correctly protected responses. The test plays the
// ICC: it knows its DH private value, derives the session keys exactly like
// the host and seals responses with them, so the SM path (MAC verification,
// file reads, GET RESPONSE) can be driven end to end without hardware.
class SmCard {
 public:
  using OnSm = std::function<Bytes(SmCard &, const Bytes &apdu)>;

  explicit SmCard(OnSm onSm) : onSm_(std::move(onSm)) {
    BIGNUM *p =
        BN_bin2bn(grp.p.data(), static_cast<int>(grp.p.size()), nullptr);
    BIGNUM *g =
        BN_bin2bn(grp.g.data(), static_cast<int>(grp.g.size()), nullptr);
    BIGNUM *k = BN_bin2bn(k_.data(), static_cast<int>(k_.size()), nullptr);
    BIGNUM *y = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(y, g, k, p, ctx);
    iccPub = BnBytes(y, grp.p.size());
    BN_CTX_free(ctx);
    BN_free(y);
    BN_free(k);
    BN_free(g);
    BN_free(p);
  }

  FakeCard::Handler Handler() {
    return [this](const Bytes &apdu) -> Bytes {
      if (apdu[0] == 0x0C || apdu[1] == 0xC0) {  // SM command / GET RESPONSE
        if (encKey_.empty()) DeriveKeys();
        if (apdu[1] != 0xC0) ++smCommands;
        return onSm_(*this, apdu);
      }
      if (apdu[1] == 0x22) {  // MSE SET: capture the host DH public value
        size_t i = 12;        // 80 01 9B 83 01 xx 91 <len> <value>
        size_t len = apdu[i++];
        if (len == 0x81) len = apdu[i++];
        hostPub.assign(apdu.begin() + i, apdu.begin() + i + len);
        return Sw(0x9000);
      }
      if (apdu[1] == 0xCB) {
        if (apdu[4] == 0x06)  // GET DATA of the ICC public key
          return WithSw(Tlv(0x30, Tlv(0x04, iccPub)), 0x9000);
        const Bytes &val = apdu[15] == 0x97   ? grp.g
                           : apdu[15] == 0x98 ? grp.p
                                              : grp.q;
        return WithSw(Tlv(0x30, Tlv(0x30, Tlv(0x30, Tlv(0x04, val)))), 0x9000);
      }
      return Sw(0x9000);
    };
  }

  // Protected response (DO87/DO85 data, DO99 status, DO8E MAC) to the SM
  // command currently being answered, as the host expects it.
  Bytes Seal(const Bytes &data, uint16_t sw, uint8_t ins) {
    const uint64_t ssc = 1 + 2 * smCommands;  // initial SSC, +2 per exchange
    Bytes seq(8);
    for (int i = 0; i < 8; ++i)
      seq[7 - i] = static_cast<uint8_t>(ssc >> (8 * i));

    ByteDynArray iv(8);
    iv.fill(0);
    Bytes body;
    if (!data.empty()) {
      ByteDynArray padded = ISOPad(ByteArray(data.data(), data.size()));
      CDES3 des(ByteArray(encKey_.data(), encKey_.size()), iv);
      ByteDynArray ct = des.RawEncode(padded);
      Bytes ctb(ct.data(), ct.data() + ct.size());
      body = (ins & 1) ? Tlv(0x85, ctb) : Tlv(0x87, Cat({0x01}, ctb));
    }
    const Bytes statusDo = {0x99, 0x02, static_cast<uint8_t>(sw >> 8),
                            static_cast<uint8_t>(sw & 0xFF)};
    Bytes macIn = Cat(Cat(seq, body), statusDo);
    CMAC cmac(ByteArray(macKey_.data(), macKey_.size()), iv);
    ByteDynArray mac = cmac.Mac(ISOPad(ByteArray(macIn.data(), macIn.size())));
    Bytes out = Cat(Cat(body, statusDo), {0x8E, 0x08});
    out.insert(out.end(), mac.data(), mac.data() + mac.size());
    return WithSw(out, 0x9000);
  }

  DhGroup grp;
  Bytes iccPub;
  Bytes hostPub;
  uint64_t smCommands = 0;

 private:
  void DeriveKeys() {
    BIGNUM *p =
        BN_bin2bn(grp.p.data(), static_cast<int>(grp.p.size()), nullptr);
    BIGNUM *y =
        BN_bin2bn(hostPub.data(), static_cast<int>(hostPub.size()), nullptr);
    BIGNUM *k = BN_bin2bn(k_.data(), static_cast<int>(k_.size()), nullptr);
    BIGNUM *z = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(z, y, k, p, ctx);
    Bytes secret = BnBytes(z, grp.p.size());
    BN_CTX_free(ctx);
    BN_free(z);
    BN_free(k);
    BN_free(y);
    BN_free(p);
    CSHA256 sha;
    auto derive = [&](uint8_t diff) {
      Bytes in = Cat(secret, {0x00, 0x00, 0x00, diff});
      ByteDynArray d = sha.Digest(ByteArray(in.data(), in.size()));
      return Bytes(d.data(), d.data() + 16);
    };
    encKey_ = derive(1);
    macKey_ = derive(2);
  }

  OnSm onSm_;
  const Bytes k_ = {0x07, 0x65, 0x43, 0x21, 0x99, 0x31, 0x41, 0x59};
  Bytes encKey_, macKey_;
};

// An IAS with an established SM session against `card`.
struct SmRig {
  explicit SmRig(SmCard::OnSm onSm)
      : card(std::move(onSm)), rig(card.Handler()) {
    rig.ias.SelectAID_IAS();
    rig.ias.InitDHParam();
    rig.ias.DHKeyExchange();
  }
  SmCard card;
  Rig rig;
};

// SM-protected transparent file: SELECT answers 9000, READ BINARY serves
// 224-byte chunks by offset.
SmCard::OnSm SmFile(Bytes file) {
  return [file = std::move(file)](SmCard &c, const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xA4) return c.Seal({}, 0x9000, 0xA4);
    size_t off = (static_cast<size_t>(apdu[2]) << 8) | apdu[3];
    if (off >= file.size()) return c.Seal({}, 0x6B00, 0xB0);
    size_t n = std::min<size_t>(224, file.size() - off);
    return c.Seal(Bytes(file.begin() + off, file.begin() + off + n), 0x9000,
                  0xB0);
  };
}

// SM-protected eMRTD data group served with READ BINARY by SFI (P1 = 80|SFI,
// P2 = offset) for the first read and by absolute offset afterwards.
// `tail` bytes are served as-is (no padding to the declared length).
SmCard::OnSm SmDg(Bytes file) {
  return [file = std::move(file)](SmCard &c, const Bytes &apdu) -> Bytes {
    if (apdu[1] != 0xB0) return c.Seal({}, 0x9000, apdu[1]);
    size_t off = (apdu[2] & 0x80)
                     ? apdu[3]
                     : ((static_cast<size_t>(apdu[2]) << 8) | apdu[3]);
    size_t le = (apdu[6] == 0x97) ? apdu[8] : 224;
    if (off >= file.size()) return c.Seal({}, 0x6B00, 0xB0);
    size_t n = std::min(le, file.size() - off);
    return c.Seal(Bytes(file.begin() + off, file.begin() + off + n), 0x9000,
                  0xB0);
  };
}

Bytes DappFile() {
  Bytes modulus(256, 0x5A);
  modulus[0] = 0xC3;
  modulus[255] |= 1;
  return Tlv(0x30, Cat(DerUInt(modulus), DerUInt({0x01, 0x00, 0x01})));
}

}  // namespace

// CP-01: card-derived ASN.1 trees must be walked with checked accessors.

TEST_CASE("ReadDappPubKey rejects an empty EF instead of dereferencing it",
          "[ias][cp01]") {
  // First READ BINARY answers 6B00: the file content is empty, the parsed
  // tree has no root node.
  Rig rig(FileCard({}));
  ByteDynArray out;
  CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
}

TEST_CASE("ReadDappPubKey rejects a SEQUENCE missing its members",
          "[ias][cp01]") {
  ByteDynArray out;
  SECTION("no children at all") {
    Rig rig(FileCard({0x30, 0x00}));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
  SECTION("modulus only, exponent missing") {
    Rig rig(FileCard({0x30, 0x04, 0x02, 0x02, 0x00, 0xC3}));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
  SECTION("all-zero modulus") {
    Rig rig(
        FileCard({0x30, 0x08, 0x02, 0x02, 0x00, 0x00, 0x02, 0x02, 0x01, 0x01}));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
}

TEST_CASE("ReadDappPubKey strips DER sign padding from a well-formed key",
          "[ias][cp01]") {
  Bytes modulus(128, 0x5A);
  modulus[0] = 0xC3;  // top bit set: DER adds a 00 sign byte
  modulus[127] |= 1;
  Rig rig(
      FileCard(Tlv(0x30, Cat(DerUInt(modulus), DerUInt({0x01, 0x00, 0x01})))));
  ByteDynArray out;
  REQUIRE_NOTHROW(rig.ias.ReadDappPubKey(out));
  REQUIRE(rig.ias.DappModule.size() == modulus.size());
  CHECK(std::memcmp(rig.ias.DappModule.data(), modulus.data(),
                    modulus.size()) == 0);
  REQUIRE(rig.ias.DappPubKey.size() == 3);
  CHECK(rig.ias.DappPubKey[0] == 0x01);
  CHECK(rig.ias.DappPubKey[2] == 0x01);
}

TEST_CASE("InitDHParam and InitExtAuthKeyParam reject shallow ASN.1",
          "[ias][cp01]") {
  Rig rig([](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xCB) return WithSw({0x30, 0x00}, 0x9000);
    return Sw(0x9000);
  });
  rig.ias.SelectAID_IAS();  // sets the card type from the ATR
  CHECK_THROWS_AS(rig.ias.InitDHParam(), logged_error);
  CHECK_THROWS_AS(rig.ias.InitExtAuthKeyParam(), logged_error);
}

TEST_CASE("InitExtAuthKeyParam rejects a key template without its tags",
          "[ias][cp01]") {
  // Three nested SEQUENCEs, innermost empty: depth is right, tags are absent.
  Rig rig([](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xCB)
      return WithSw({0x30, 0x04, 0x30, 0x02, 0x30, 0x00}, 0x9000);
    return Sw(0x9000);
  });
  CHECK_THROWS_AS(rig.ias.InitExtAuthKeyParam(), logged_error);
}

TEST_CASE("SOD parsing rejects structurally empty input", "[ias][cp01]") {
  std::map<uint8_t, ByteDynArray> hashes;
  const uint8_t empty[] = {0x30, 0x00};
  CHECK_THROWS_AS(IAS::VerificaSOD(ByteArray(empty, sizeof(empty)), hashes),
                  logged_error);
  CHECK_THROWS_AS(IAS::VerificaSODPSS(ByteArray(empty, sizeof(empty)), hashes),
                  logged_error);
  CHECK_THROWS_AS(IAS::GetSODDigestAlg(ByteArray(empty, sizeof(empty))),
                  logged_error);
}

// CP-02: read and GET RESPONSE loops must terminate on a hostile card.

TEST_CASE("readfile reads a multi-chunk file and stops at EOF", "[ias][cp02]") {
  Bytes file(700);
  for (size_t i = 0; i < file.size(); ++i) file[i] = static_cast<uint8_t>(i);
  Rig rig(FileCard(file));
  ByteDynArray out;
  REQUIRE_NOTHROW(rig.ias.ReadSerialeCIE(out));
  REQUIRE(out.size() == file.size());
  CHECK(std::memcmp(out.data(), file.data(), file.size()) == 0);
}

TEST_CASE("readfile aborts when the card answers 9000 with no data",
          "[ias][cp02]") {
  Rig rig([](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xB0) return Sw(0x9000);  // success, zero bytes, forever
    return Sw(0x9000);
  });
  ByteDynArray out;
  CHECK_THROWS_AS(rig.ias.ReadSerialeCIE(out), logged_error);
  CHECK(rig.card.Count(0xB0) == 1);
}

TEST_CASE("readfile aborts on a file that never ends", "[ias][cp02]") {
  Rig rig([](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xB0) return WithSw(Bytes(224, 0xAA), 0x9000);
    return Sw(0x9000);
  });
  ByteDynArray out;
  CHECK_THROWS_AS(rig.ias.ReadSerialeCIE(out), logged_error);
  // 64 KiB of 224-byte chunks, never a 16-bit offset wraparound.
  CHECK(rig.card.Count(0xB0) <= 0x10000 / 224 + 2);
}

TEST_CASE("GET RESPONSE loop aborts when the card keeps saying 6100",
          "[ias][cp02]") {
  SECTION("empty chunks") {
    Rig rig([](const Bytes &apdu) -> Bytes {
      if (apdu[1] == 0xC0) return Sw(0x6100);
      return Sw(0x6100);
    });
    ByteDynArray out;
    CHECK_THROWS_AS(rig.ias.ReadSerialeCIE(out), logged_error);
    CHECK(rig.card.Count(0xC0) <= 1);
  }
  SECTION("non-empty chunks without end") {
    Rig rig([](const Bytes &apdu) -> Bytes {
      if (apdu[1] == 0xC0) return WithSw(Bytes(16, 0x55), 0x6100);
      return Sw(0x6100);
    });
    ByteDynArray out;
    CHECK_THROWS_AS(rig.ias.ReadSerialeCIE(out), logged_error);
    CHECK(rig.card.Count(0xC0) <= 64);
  }
}

TEST_CASE("GET RESPONSE still chains a finite 6100 sequence", "[ias][cp02]") {
  bool selected = false;
  int chunks = 0;
  Rig rig([&](const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xA4) {
      // SELECT: the card announces 6100 once, the data comes via GET RESPONSE.
      if (!selected) {
        selected = true;
        return Sw(0x6100);
      }
      return Sw(0x9000);
    }
    if (apdu[1] == 0xC0) {
      return ++chunks < 3 ? WithSw(Bytes(4, 0x11), 0x6100)
                          : WithSw(Bytes(4, 0x22), 0x9000);
    }
    return Sw(0x6B00);  // READ BINARY: empty file
  });
  ByteDynArray out;
  REQUIRE_NOTHROW(rig.ias.ReadSerialeCIE(out));
  CHECK(rig.card.Count(0xC0) == 3);
}

// CP-03: card-supplied DH group and ICC public key are validated.

TEST_CASE("InitDHParam accepts a well-formed group", "[ias][cp03]") {
  DhGroup grp;
  Rig rig(DhCard(grp, {}));
  rig.ias.SelectAID_IAS();
  CHECK_NOTHROW(rig.ias.InitDHParam());
}

TEST_CASE("InitDHParam rejects malformed or inconsistent groups",
          "[ias][cp03]") {
  DhGroup grp;
  SECTION("generator 1") { grp.g = {0x01}; }
  SECTION("generator 0") { grp.g = {0x00}; }
  SECTION("generator outside the order-q subgroup") { grp.g = {0x02}; }
  SECTION("even prime") { grp.p.back() &= 0xFE; }
  SECTION("order not dividing p-1") {
    BIGNUM *q = nullptr;

    q = BN_bin2bn(grp.q.data(), static_cast<int>(grp.q.size()), nullptr);
    BN_add_word(q, 2);
    grp.q = BnBytes(q);
    BN_free(q);
  }
  SECTION("prime far below the minimum size") {
    grp.p = Bytes(64, 0xFF);
    grp.q = {0x03};
  }
  SECTION("order as large as the prime") { grp.q = grp.p; }
  SECTION("oversized prime") { grp.p = Bytes(3000, 0xFF); }
  SECTION("empty generator") { grp.g.clear(); }
  Rig rig(DhCard(grp, {}));
  rig.ias.SelectAID_IAS();
  CHECK_THROWS_AS(rig.ias.InitDHParam(), logged_error);
}

TEST_CASE("DHKeyExchange validates the ICC public key", "[ias][cp03]") {
  DhGroup grp;
  BIGNUM *p = BN_bin2bn(grp.p.data(), static_cast<int>(grp.p.size()), nullptr);
  BIGNUM *g = BN_bin2bn(grp.g.data(), static_cast<int>(grp.g.size()), nullptr);
  BIGNUM *y = BN_new();
  BIGNUM *k = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_set_word(k, 0x1234567);
  BN_mod_exp(y, g, k, p, ctx);
  const Bytes validY = BnBytes(y, grp.p.size());
  const size_t plen = grp.p.size();

  Bytes badY;
  bool expectOk = false;
  SECTION("a genuine subgroup element is accepted") {
    badY = validY;
    expectOk = true;
  }
  SECTION("y = 0") { badY = Bytes(plen, 0x00); }
  SECTION("y = 1") { badY = Bytes {0x01}; }
  SECTION("y = p-1") {
    BIGNUM *pm1 = BN_dup(p);
    BN_sub_word(pm1, 1);
    badY = BnBytes(pm1);
    BN_free(pm1);
  }
  SECTION("y = p+1") {
    BIGNUM *pp1 = BN_dup(p);
    BN_add_word(pp1, 1);
    badY = BnBytes(pp1);
    BN_free(pp1);
  }
  SECTION("y outside the order-q subgroup") { badY = Bytes {0x02}; }
  SECTION("oversized y") { badY = Bytes(plen + 8, 0x7F); }
  SECTION("empty y") { badY = Bytes {}; }

  BN_CTX_free(ctx);
  BN_free(k);
  BN_free(y);
  BN_free(g);
  BN_free(p);

  Rig rig(DhCard(grp, badY));
  rig.ias.SelectAID_IAS();
  REQUIRE_NOTHROW(rig.ias.InitDHParam());
  if (expectOk)
    CHECK_NOTHROW(rig.ias.DHKeyExchange());
  else
    CHECK_THROWS_AS(rig.ias.DHKeyExchange(), logged_error);
}

TEST_CASE("DHKeyExchange refuses to run without DH parameters", "[ias][cp03]") {
  Rig rig([](const Bytes &) -> Bytes { return Sw(0x9000); });
  CHECK_THROWS_AS(rig.ias.DHKeyExchange(), logged_error);
}

TEST_CASE("ReadDappPubKey rejects out-of-range RSA keys", "[ias][cp03]") {
  ByteDynArray out;
  SECTION("modulus below 1024 bits") {
    Bytes modulus(64, 0xC1);
    Rig rig(FileCard(
        Tlv(0x30, Cat(DerUInt(modulus), DerUInt({0x01, 0x00, 0x01})))));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
  SECTION("even modulus") {
    Bytes modulus(128, 0xC2);
    Rig rig(FileCard(
        Tlv(0x30, Cat(DerUInt(modulus), DerUInt({0x01, 0x00, 0x01})))));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
  SECTION("oversized exponent") {
    Bytes modulus(128, 0xC3);
    Rig rig(
        FileCard(Tlv(0x30, Cat(DerUInt(modulus), DerUInt(Bytes(64, 0x7F))))));
    CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), logged_error);
  }
}

// CP-04: SOD verification enforces digests, signer identity and SHA-1 ban.

namespace {

const Bytes kOidSha256 = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};

Bytes Digest32(uint8_t fill) { return Bytes(32, fill); }

Bytes DgEntry(const Bytes &num, const Bytes &digest) {
  return Tlv(0x30, Cat(Tlv(0x02, num), Tlv(0x04, digest)));
}

Bytes Lds(uint8_t version, const Bytes &hashOid, const Bytes &dgEntries) {
  return Tlv(0x30, Cat(Cat(Tlv(0x02, {version}), Tlv(0x30, Tlv(0x06, hashOid))),
                       Tlv(0x30, dgEntries)));
}

std::map<uint8_t, ByteDynArray> HostDigests(
    std::initializer_list<std::pair<uint8_t, Bytes>> in) {
  std::map<uint8_t, ByteDynArray> out;
  for (const auto &e : in)
    out[e.first] = ByteDynArray(ByteArray(e.second.data(), e.second.size()));
  return out;
}

void VerifyLds(const Bytes &lds, uint8_t version,
               const std::map<uint8_t, ByteDynArray> &hashes) {
  IAS::VerifyLdsSecurityObject(ByteArray(lds.data(), lds.size()), version,
                               ByteArray(kOidSha256.data(), kOidSha256.size()),
                               hashes);
}

}  // namespace

TEST_CASE("LDSSecurityObject digests must match the files read",
          "[ias][cp04]") {
  const Bytes dgs =
      Cat(Cat(DgEntry({0xA1}, Digest32(1)), DgEntry({0x00, 0xA2}, Digest32(2))),
          DgEntry({0xA3}, Digest32(3)));
  const Bytes lds = Lds(0, kOidSha256, dgs);

  SECTION("all digests equal") {
    CHECK_NOTHROW(VerifyLds(
        lds, 0, HostDigests({{0xA1, Digest32(1)}, {0xA2, Digest32(2)}})));
  }
  SECTION("a DG listed in the SOD but never read is ignored") {
    CHECK_NOTHROW(VerifyLds(lds, 0, HostDigests({{0xA3, Digest32(3)}})));
  }
  SECTION("digest mismatch is fatal") {
    CHECK_THROWS_AS(
        VerifyLds(lds, 0,
                  HostDigests({{0xA1, Digest32(1)}, {0xA2, Digest32(9)}})),
        logged_error);
  }
  SECTION("a file read but absent from the SOD is fatal") {
    CHECK_THROWS_AS(
        VerifyLds(lds, 0,
                  HostDigests({{0xA1, Digest32(1)}, {0xA4, Digest32(4)}})),
        logged_error);
  }
  SECTION("an empty host digest never matches") {
    CHECK_THROWS_AS(VerifyLds(lds, 0, HostDigests({{0xA1, Bytes {}}})),
                    logged_error);
  }
  SECTION("no host digests at all is fatal") {
    CHECK_THROWS_AS(VerifyLds(lds, 0, {}), logged_error);
  }
  SECTION("wrong version or digest algorithm is fatal") {
    CHECK_THROWS_AS(VerifyLds(lds, 1, HostDigests({{0xA1, Digest32(1)}})),
                    logged_error);
    const Bytes sha1Oid = {0x2B, 0x0E, 0x03, 0x02, 0x1A};
    CHECK_THROWS_AS(
        VerifyLds(Lds(0, sha1Oid, dgs), 0, HostDigests({{0xA1, Digest32(1)}})),
        logged_error);
  }
  SECTION("duplicate DG entries are fatal") {
    const Bytes dup =
        Lds(0, kOidSha256,
            Cat(DgEntry({0xA1}, Digest32(1)), DgEntry({0xA1}, Digest32(1))));
    CHECK_THROWS_AS(VerifyLds(dup, 0, HostDigests({{0xA1, Digest32(1)}})),
                    logged_error);
  }
  SECTION("a malformed DG number is fatal") {
    const Bytes bad = Lds(0, kOidSha256, DgEntry({}, Digest32(1)));
    CHECK_THROWS_AS(VerifyLds(bad, 0, HostDigests({{0xA1, Digest32(1)}})),
                    logged_error);
  }
}

TEST_CASE("VerificaSOD rejects a SHA-1 signature algorithm", "[ias][cp04]") {
  const Bytes oidSignedData = {0x2A, 0x86, 0x48, 0x86, 0xF7,
                               0x0D, 0x01, 0x07, 0x02};
  const Bytes oidLds = {0x67, 0x81, 0x08, 0x01, 0x01, 0x01};
  const Bytes oidContentType = {0x2A, 0x86, 0x48, 0x86, 0xF7,
                                0x0D, 0x01, 0x09, 0x03};
  const Bytes oidMessageDigest = {0x2A, 0x86, 0x48, 0x86, 0xF7,
                                  0x0D, 0x01, 0x09, 0x04};
  const Bytes oidSha1WithRsa = {0x2A, 0x86, 0x48, 0x86, 0xF7,
                                0x0D, 0x01, 0x01, 0x05};
  const Bytes oidSha256WithRsa = {0x2A, 0x86, 0x48, 0x86, 0xF7,
                                  0x0D, 0x01, 0x01, 0x0B};

  auto buildSod = [&](const Bytes &sigAlgo) {
    const Bytes lds = Lds(0, kOidSha256, DgEntry({0xA1}, Digest32(1)));
    const Bytes encap =
        Tlv(0x30, Cat(Tlv(0x06, oidLds), Tlv(0xA0, Tlv(0x04, lds))));
    const Bytes signedAttrs =
        Tlv(0xA0, Cat(Tlv(0x30, Cat(Tlv(0x06, oidContentType),
                                    Tlv(0x31, Tlv(0x06, oidLds)))),
                      Tlv(0x30, Cat(Tlv(0x06, oidMessageDigest),
                                    Tlv(0x31, Tlv(0x04, Digest32(7)))))));
    const Bytes sid = Tlv(0x30, Cat(Tlv(0x30, Tlv(0x31, {})), Tlv(0x02, {1})));
    const Bytes signerInfo =
        Tlv(0x30, Cat(Cat(Cat(Cat(Cat(Tlv(0x02, {1}), sid),
                                  Tlv(0x30, Tlv(0x06, kOidSha256))),
                              signedAttrs),
                          Tlv(0x30, Tlv(0x06, sigAlgo))),
                      Tlv(0x04, Bytes(128, 0x11))));
    const Bytes cert = Tlv(0x30, Tlv(0x02, {1}));
    const Bytes signedData =
        Tlv(0x30, Cat(Cat(Cat(Cat(Tlv(0x02, {3}),
                                  Tlv(0x31, Tlv(0x30, Tlv(0x06, kOidSha256)))),
                              encap),
                          Tlv(0xA0, cert)),
                      Tlv(0x31, signerInfo)));
    // EF.SOD: application tag 0x77 wrapping the CMS ContentInfo.
    return Tlv(0x77,
               Tlv(0x30, Cat(Tlv(0x06, oidSignedData), Tlv(0xA0, signedData))));
  };

  std::map<uint8_t, ByteDynArray> hashes = HostDigests({{0xA1, Digest32(1)}});

  SECTION("sha1WithRSAEncryption") {
    Bytes sod = buildSod(oidSha1WithRsa);
    CHECK_THROWS_WITH(
        IAS::VerificaSOD(ByteArray(sod.data(), sod.size()), hashes),
        Catch::Matchers::ContainsSubstring("SHA-1"));
  }
  SECTION("sha256WithRSAEncryption gets past the algorithm check") {
    // The messageDigest attribute does not match the content digest, so the
    // next check (not the algorithm one) is what rejects it.
    Bytes sod = buildSod(oidSha256WithRsa);
    CHECK_THROWS_WITH(
        IAS::VerificaSOD(ByteArray(sod.data(), sod.size()), hashes),
        Catch::Matchers::ContainsSubstring("does not match"));
  }
}

// CP-08: Secure Messaging responses must carry a valid, final MAC.

TEST_CASE("Secure Messaging responses without a valid MAC are rejected",
          "[ias][cp08]") {
  DhGroup grp;
  BIGNUM *p = BN_bin2bn(grp.p.data(), static_cast<int>(grp.p.size()), nullptr);
  BIGNUM *g = BN_bin2bn(grp.g.data(), static_cast<int>(grp.g.size()), nullptr);
  BIGNUM *y = BN_new();
  BIGNUM *k = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_set_word(k, 0x7654321);
  BN_mod_exp(y, g, k, p, ctx);
  const Bytes iccPub = BnBytes(y, grp.p.size());
  BN_CTX_free(ctx);
  BN_free(k);
  BN_free(y);
  BN_free(g);
  BN_free(p);

  const Bytes status = {0x99, 0x02, 0x90, 0x00};
  const Bytes zeroMac = Cat({0x8E, 0x08}, Bytes(8, 0x00));
  Bytes smResponse;
  SECTION("wrong MAC") { smResponse = Cat(status, zeroMac); }
  SECTION("no status word DO") { smResponse = zeroMac; }
  SECTION("no MAC DO") { smResponse = status; }
  SECTION("data after the MAC") {
    smResponse = Cat(Cat(status, zeroMac), {0x00});
  }
  SECTION("short MAC") { smResponse = Cat(status, {0x8E, 0x04, 1, 2, 3, 4}); }

  FakeCard::Handler plain = DhCard(grp, iccPub);
  Rig rig([plain, smResponse](const Bytes &apdu) -> Bytes {
    if (apdu[0] == 0x0C) return WithSw(smResponse, 0x9000);  // SM command
    return plain(apdu);
  });
  rig.ias.SelectAID_IAS();
  REQUIRE_NOTHROW(rig.ias.InitDHParam());
  REQUIRE_NOTHROW(rig.ias.DHKeyExchange());
  REQUIRE(rig.ias.ActiveSM);

  // ReadDappPubKey goes through readfile_SM once the session is active.
  ByteDynArray out;
  CHECK_THROWS_AS(rig.ias.ReadDappPubKey(out), card_link_error);
}

// SM path end to end: key agreement, MAC verification, bounded loops.

TEST_CASE("SM session: DH agreement lets a multi-chunk file be read",
          "[ias][sm]") {
  const Bytes file = DappFile();
  REQUIRE(file.size() > 224);  // needs two READ BINARY rounds
  SmRig rig(SmFile(file));
  ByteDynArray out;
  REQUIRE_NOTHROW(rig.rig.ias.ReadDappPubKey(out));
  CHECK(rig.rig.ias.DappModule.size() == 256);
  CHECK(rig.rig.ias.DappPubKey.size() == 3);
}

TEST_CASE("SM session: host DH public value is a fresh subgroup element",
          "[ias][sm][ct3]") {
  SmRig a(SmFile({})), b(SmFile({}));
  REQUIRE(a.card.hostPub.size() == a.card.grp.p.size());
  CHECK(a.card.hostPub != b.card.hostPub);  // new ephemeral key every time

  BIGNUM *p = BN_bin2bn(a.card.grp.p.data(),
                        static_cast<int>(a.card.grp.p.size()), nullptr);
  BIGNUM *q = BN_bin2bn(a.card.grp.q.data(),
                        static_cast<int>(a.card.grp.q.size()), nullptr);
  BIGNUM *y = BN_bin2bn(a.card.hostPub.data(),
                        static_cast<int>(a.card.hostPub.size()), nullptr);
  BIGNUM *r = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_exp(r, y, q, p, ctx);
  CHECK(BN_is_one(r));
  CHECK(BN_cmp(y, BN_value_one()) > 0);
  BN_CTX_free(ctx);
  BN_free(r);
  BN_free(y);
  BN_free(q);
  BN_free(p);
}

TEST_CASE("SM responses with a corrupted MAC or payload are rejected",
          "[ias][sm][cp08]") {
  const Bytes file = DappFile();
  enum { kMac, kCipher, kNone } flip = kNone;
  SECTION("untouched response is accepted") { flip = kNone; }
  SECTION("bit flip in the MAC") { flip = kMac; }
  SECTION("bit flip in the ciphertext") { flip = kCipher; }

  auto inner = SmFile(file);
  SmRig rig([&](SmCard &c, const Bytes &apdu) -> Bytes {
    Bytes r = inner(c, apdu);
    if (apdu[1] == 0xB0 && r.size() > 20) {
      if (flip == kMac) r[r.size() - 3] ^= 0x01;  // last MAC byte
      if (flip == kCipher) r[5] ^= 0x80;          // inside DO87
    }
    return r;
  });
  ByteDynArray out;
  if (flip == kNone)
    CHECK_NOTHROW(rig.rig.ias.ReadDappPubKey(out));
  else
    CHECK_THROWS_AS(rig.rig.ias.ReadDappPubKey(out), card_link_error);
}

TEST_CASE("SM file read is bounded against hostile cards", "[ias][sm][cp02]") {
  SECTION("endless file") {
    SmRig rig([](SmCard &c, const Bytes &apdu) -> Bytes {
      if (apdu[1] == 0xA4) return c.Seal({}, 0x9000, 0xA4);
      return c.Seal(Bytes(224, 0xAB), 0x9000, 0xB0);
    });
    ByteDynArray out;
    CHECK_THROWS_AS(rig.rig.ias.ReadDappPubKey(out), logged_error);
    CHECK(rig.rig.card.Count(0xB0) < 1000);
  }
  SECTION("empty chunk answered 9000") {
    SmRig rig([](SmCard &c, const Bytes &apdu) -> Bytes {
      if (apdu[1] == 0xA4) return c.Seal({}, 0x9000, 0xA4);
      return c.Seal({}, 0x9000, 0xB0);
    });
    ByteDynArray out;
    CHECK_THROWS_AS(rig.rig.ias.ReadDappPubKey(out), logged_error);
    CHECK(rig.rig.card.Count(0xB0) < 10);
  }
}

TEST_CASE("SM GET RESPONSE loop is bounded", "[ias][sm][cp02]") {
  const bool nonEmpty = GENERATE(false, true);
  SmRig rig([nonEmpty](SmCard &c, const Bytes &apdu) -> Bytes {
    if (apdu[1] == 0xA4) return c.Seal({}, 0x9000, 0xA4);
    if (apdu[1] == 0xC0 || apdu[1] == 0xB0)  // endless 61xx chain
      return WithSw(nonEmpty ? Bytes(8, 0x11) : Bytes {}, 0x6100);
    return Sw(0x6D00);
  });
  ByteDynArray out;
  CHECK_THROWS_AS(rig.rig.ias.ReadDappPubKey(out), logged_error);
  CHECK(rig.rig.card.Count(0xC0) < 200);
}

// CP-11: readDGbySFI validates the TLV length it parses.

TEST_CASE("readDGbySFI reads a well-formed multi-chunk data group",
          "[ias][sm][cp11]") {
  Bytes body(500);
  for (size_t i = 0; i < body.size(); ++i) body[i] = static_cast<uint8_t>(i);
  const Bytes dg = Tlv(0x75, body);
  SmRig rig(SmDg(dg));
  ByteDynArray out;
  REQUIRE_NOTHROW(rig.rig.ias.ReadDG1(out));
  REQUIRE(out.size() == dg.size());
  CHECK(std::memcmp(out.data(), dg.data(), dg.size()) == 0);
}

TEST_CASE("readDGbySFI rejects malformed or inconsistent TLV lengths",
          "[ias][sm][cp11]") {
  Bytes file;
  SECTION("unsupported length form 0x83") {
    file = Bytes {0x75, 0x83, 0x00, 0x01, 0x00};
    file.resize(300, 0x11);
  }
  SECTION("indefinite length 0x80") {
    file = Bytes(300, 0x11), file[0] = 0x75, file[1] = 0x80;
  }
  SECTION("declared size above the cap") {
    file = Bytes {0x75, 0x82, 0xFF, 0xFF};
    file.resize(300, 0x11);
  }
  SECTION("file shorter than declared") {
    file = Bytes {0x75, 0x82, 0x01, 0x00};  // declares 256 content bytes
    file.resize(100, 0x11);
  }
  SECTION("truncated length field") { file = Bytes {0x75, 0x82, 0x01}; }
  SECTION("longer than declared") {
    file = Bytes {0x75, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  }
  SECTION("first read returns less than a header") { file = Bytes {0x75}; }
  SmRig rig(SmDg(file));
  ByteDynArray out;
  CHECK_THROWS_WITH(rig.rig.ias.ReadDG1(out),
                    Catch::Matchers::ContainsSubstring("readDGbySFI - "));
}

#endif  // _WIN32
