// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "csp/pace.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>

#include "crypto/mac.h"

namespace pace {

namespace {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

void wipe(Bytes& b) {
  if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
}

void append(Bytes& dst, const Bytes& src) {
  dst.insert(dst.end(), src.begin(), src.end());
}

std::string hex2(unsigned v) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%04x", v);
  return buf;
}

Bytes encodeLength(size_t n) {
  if (n < 0x80) return {static_cast<uint8_t>(n)};
  if (n <= 0xFF) return {0x81, static_cast<uint8_t>(n)};
  return {0x82, static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
}

/** BER-TLV encode (1 or 2 byte tag). */
Bytes tlv(uint32_t tag, const Bytes& value) {
  Bytes out;
  if (tag > 0xFF) out.push_back(static_cast<uint8_t>(tag >> 8));
  out.push_back(static_cast<uint8_t>(tag));
  append(out, encodeLength(value.size()));
  append(out, value);
  return out;
}

struct Tlv {
  uint32_t tag = 0;
  size_t valOff = 0;
  size_t valLen = 0;
  size_t next = 0;  ///< offset of the following TLV
};

/** Parse one TLV of @p b in [pos, end). */
bool parseTlv(const Bytes& b, size_t pos, size_t end, Tlv& t) {
  if (end > b.size() || pos >= end) return false;
  uint32_t tag = b[pos++];
  if ((tag & 0x1F) == 0x1F) {
    if (pos >= end) return false;
    tag = (tag << 8) | b[pos++];
  }
  if (pos >= end) return false;
  size_t len = b[pos++];
  if (len & 0x80) {
    const size_t n = len & 0x7F;
    if (n < 1 || n > 2 || pos + n > end) return false;
    len = 0;
    for (size_t i = 0; i < n; ++i) len = (len << 8) | b[pos++];
  }
  if (len > end - pos) return false;
  t.tag = tag;
  t.valOff = pos;
  t.valLen = len;
  t.next = pos + len;
  return true;
}

/** Find the first child TLV with @p tag inside the value of @p parent. */
bool findChild(const Bytes& b, const Tlv& parent, uint32_t tag, Bytes& value) {
  size_t pos = parent.valOff;
  const size_t end = parent.valOff + parent.valLen;
  while (pos < end) {
    Tlv t;
    if (!parseTlv(b, pos, end, t)) return false;
    if (t.tag == tag) {
      value.assign(b.begin() + static_cast<long>(t.valOff),
                   b.begin() + static_cast<long>(t.valOff + t.valLen));
      return true;
    }
    pos = t.next;
  }
  return false;
}

struct EvpCtxDel {
  void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDel>;

struct BnDel {
  void operator()(BIGNUM* b) const { BN_clear_free(b); }
};
using Bn = std::unique_ptr<BIGNUM, BnDel>;

struct BnCtxDel {
  void operator()(BN_CTX* c) const { BN_CTX_free(c); }
};
using BnCtx = std::unique_ptr<BN_CTX, BnCtxDel>;

struct GroupDel {
  void operator()(EC_GROUP* g) const { EC_GROUP_free(g); }
};
using Group = std::unique_ptr<EC_GROUP, GroupDel>;

struct PointDel {
  void operator()(EC_POINT* p) const { EC_POINT_free(p); }
};
using Point = std::unique_ptr<EC_POINT, PointDel>;

Bn bnFromBytes(const Bytes& b) {
  return Bn(BN_bin2bn(b.data(), static_cast<int>(b.size()), nullptr));
}

Bytes bnToBytes(const BIGNUM* bn, size_t len) {
  Bytes out(len);
  if (BN_bn2binpad(bn, out.data(), static_cast<int>(len)) < 0) return {};
  return out;
}

const EVP_CIPHER* cbcCipher(Cipher c) {
  switch (c) {
    case Cipher::TDES:
      return EVP_des_ede3_cbc();
    case Cipher::AES128:
      return EVP_aes_128_cbc();
    case Cipher::AES192:
      return EVP_aes_192_cbc();
    case Cipher::AES256:
      return EVP_aes_256_cbc();
  }
  return nullptr;
}

/** 3DES key from a 16-byte two-key value: K1 || K2 || K1. */
Bytes expandTdesKey(const Bytes& key) {
  if (key.size() == 24) return key;
  Bytes k = key;
  if (key.size() == 16) k.insert(k.end(), key.begin(), key.begin() + 8);
  return k;
}

Bytes cbcImpl(Cipher c, const Bytes& key, const Bytes& iv, const Bytes& data,
              bool encrypt) {
  const EVP_CIPHER* cipher = cbcCipher(c);
  Bytes k = (c == Cipher::TDES) ? expandTdesKey(key) : key;
  const size_t bs = blockSize(c);
  if (!cipher || data.size() % bs != 0 || iv.size() != bs ||
      k.size() != static_cast<size_t>(EVP_CIPHER_get_key_length(cipher))) {
    wipe(k);
    return {};
  }
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  Bytes out(data.size() + bs);
  int len1 = 0, len2 = 0;
  bool ok = ctx && EVP_CipherInit_ex(ctx.get(), cipher, nullptr, k.data(),
                                     iv.data(), encrypt ? 1 : 0) == 1;
  if (ok) {
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    ok = EVP_CipherUpdate(ctx.get(), out.data(), &len1, data.data(),
                          static_cast<int>(data.size())) == 1 &&
         EVP_CipherFinal_ex(ctx.get(), out.data() + len1, &len2) == 1;
  }
  wipe(k);
  if (!ok) return {};
  out.resize(static_cast<size_t>(len1 + len2));
  return out;
}

uint8_t oddParity(uint8_t b) {
  uint8_t v = b & 0xFE;
  int bits = 0;
  for (int i = 1; i < 8; ++i) bits += (v >> i) & 1;
  return static_cast<uint8_t>(v | ((bits % 2) == 0 ? 1 : 0));
}

// ---------------------------------------------------------------------------
// Standardized domain parameters (ICAO 9303-11 §9.5.1 / TR-03110)
// ---------------------------------------------------------------------------

struct CurveEntry {
  int id;
  int nid;
  const char* name;
};

constexpr CurveEntry kCurves[] = {
    {8, NID_X9_62_prime192v1, "secp192r1"},
    {9, NID_brainpoolP192r1, "brainpoolP192r1"},
    {10, NID_secp224r1, "secp224r1"},
    {11, NID_brainpoolP224r1, "brainpoolP224r1"},
    {12, NID_X9_62_prime256v1, "secp256r1"},
    {13, NID_brainpoolP256r1, "brainpoolP256r1"},
    {14, NID_brainpoolP320r1, "brainpoolP320r1"},
    {15, NID_secp384r1, "secp384r1"},
    {16, NID_brainpoolP384r1, "brainpoolP384r1"},
    {17, NID_brainpoolP512r1, "brainpoolP512r1"},
    {18, NID_secp521r1, "secp521r1"},
};

const CurveEntry* findCurve(int id) {
  const auto* it =
      std::find_if(std::begin(kCurves), std::end(kCurves),
                   [id](const CurveEntry& c) { return c.id == id; });
  return it == std::end(kCurves) ? nullptr : it;
}

// Standardized DH domain parameters of RFC 5114 (ICAO 9303-11 table 4):
//   id 0: 1024-bit MODP group with 160-bit prime order subgroup
//   id 1: 2048-bit MODP group with 224-bit prime order subgroup
//   id 2: 2048-bit MODP group with 256-bit prime order subgroup
constexpr const char* kDh0P =
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
    "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
    "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
constexpr const char* kDh0G =
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
    "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
    "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
constexpr const char* kDh0Q = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
constexpr const char* kDh1P =
    "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75"
    "E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6"
    "6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
    "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836"
    "81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074"
    "15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
    "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29"
    "E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";
constexpr const char* kDh1G =
    "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3"
    "A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652"
    "BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
    "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1"
    "19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC"
    "B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
    "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD"
    "7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";
constexpr const char* kDh1Q =
    "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";
constexpr const char* kDh2P =
    "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00"
    "E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C"
    "209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
    "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76"
    "B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E"
    "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
    "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103"
    "A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";
constexpr const char* kDh2G =
    "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125"
    "10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62"
    "901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
    "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193"
    "B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A"
    "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
    "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3"
    "2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";
constexpr const char* kDh2Q =
    "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3";

struct DhGroup {
  int id;
  const char* p;
  const char* g;
  const char* q;
};

constexpr DhGroup kDhGroups[] = {
    {0, kDh0P, kDh0G, kDh0Q},
    {1, kDh1P, kDh1G, kDh1Q},
    {2, kDh2P, kDh2G, kDh2Q},
};

const DhGroup* findDhGroup(int id) {
  const auto* it = std::find_if(std::begin(kDhGroups), std::end(kDhGroups),
                                [id](const DhGroup& g) { return g.id == id; });
  return it == std::end(kDhGroups) ? nullptr : it;
}

// ---------------------------------------------------------------------------
// ECDH Generic Mapping
// ---------------------------------------------------------------------------

class EcMapping : public GenericMapping {
 public:
  explicit EcMapping(int paramId) {
    const CurveEntry* c = findCurve(paramId);
    if (!c) return;
    group_.reset(EC_GROUP_new_by_curve_name(c->nid));
    ctx_.reset(BN_CTX_new());
    if (!group_ || !ctx_) {
      group_.reset();
      return;
    }
    order_.reset(BN_new());
    if (!order_ || !EC_GROUP_get_order(group_.get(), order_.get(), ctx_.get()))
      group_.reset();
    fieldLen_ =
        static_cast<size_t>((EC_GROUP_get_degree(group_.get()) + 7) / 8);
  }

  bool valid() const { return group_ != nullptr; }

  Bytes mappingPublicKey(const Bytes& fixed) override {
    return newKeyPair(fixed, nullptr, mapPriv_, mapPub_);
  }

  bool mapNonce(const Bytes& chipKey, const Bytes& nonce) override {
    if (!valid() || !mapPriv_ || nonce.empty()) return false;
    Point chip = decode(chipKey);
    if (!chip) return false;
    if (mapPub_ &&
        EC_POINT_cmp(group_.get(), chip.get(), mapPub_.get(), ctx_.get()) == 0)
      return false;
    Point h(EC_POINT_new(group_.get()));
    Point gp(EC_POINT_new(group_.get()));
    Bn s = bnFromBytes(nonce);
    Bn one(BN_new());
    if (!h || !gp || !s || !one || !BN_one(one.get())) return false;
    // H = d_map * PK_map,IC
    if (!EC_POINT_mul(group_.get(), h.get(), nullptr, chip.get(),
                      mapPriv_.get(), ctx_.get()) ||
        EC_POINT_is_at_infinity(group_.get(), h.get()))
      return false;
    // G' = s*G + H
    if (!EC_POINT_mul(group_.get(), gp.get(), s.get(), h.get(), one.get(),
                      ctx_.get()) ||
        EC_POINT_is_at_infinity(group_.get(), gp.get()))
      return false;
    mapped_ = std::move(gp);
    return true;
  }

  Bytes mappedGenerator() const override {
    return mapped_ ? encode(mapped_.get()) : Bytes();
  }

  Bytes agreementPublicKey(const Bytes& fixed) override {
    if (!mapped_) return {};
    return newKeyPair(fixed, mapped_.get(), agrPriv_, agrPub_);
  }

  bool agree(const Bytes& chipKey, Bytes& shared) override {
    if (!valid() || !agrPriv_ || !agrPub_) return false;
    Point chip = decode(chipKey);
    if (!chip) return false;
    if (EC_POINT_cmp(group_.get(), chip.get(), agrPub_.get(), ctx_.get()) == 0)
      return false;
    Point k(EC_POINT_new(group_.get()));
    Bn x(BN_new()), y(BN_new());
    if (!k || !x || !y) return false;
    if (!EC_POINT_mul(group_.get(), k.get(), nullptr, chip.get(),
                      agrPriv_.get(), ctx_.get()) ||
        EC_POINT_is_at_infinity(group_.get(), k.get()))
      return false;
    if (!EC_POINT_get_affine_coordinates(group_.get(), k.get(), x.get(),
                                         y.get(), ctx_.get()))
      return false;
    shared = bnToBytes(x.get(), fieldLen_);
    return !shared.empty();
  }

 private:
  Point decode(const Bytes& enc) const {
    // 04 || X || Y only: reject compressed/hybrid encodings.
    if (enc.size() != 1 + 2 * fieldLen_ || enc[0] != 0x04) return nullptr;
    Point p(EC_POINT_new(group_.get()));
    if (!p) return nullptr;
    // oct2point verifies that the point is on the curve.
    if (!EC_POINT_oct2point(group_.get(), p.get(), enc.data(), enc.size(),
                            ctx_.get()))
      return nullptr;
    if (EC_POINT_is_at_infinity(group_.get(), p.get())) return nullptr;
    return p;
  }

  Bytes encode(const EC_POINT* p) const {
    Bytes out(1 + 2 * fieldLen_);
    size_t n =
        EC_POINT_point2oct(group_.get(), p, POINT_CONVERSION_UNCOMPRESSED,
                           out.data(), out.size(), ctx_.get());
    if (n != out.size()) return {};
    return out;
  }

  /** Generate d, Q = d*base (base = nullptr -> the curve generator). */
  Bytes newKeyPair(const Bytes& fixed, const EC_POINT* base, Bn& priv,
                   Point& pub) {
    if (!valid()) return {};
    Bn d(BN_new());
    if (!d) return {};
    if (!fixed.empty()) {
      d = bnFromBytes(fixed);
      if (!d) return {};
    } else {
      do {
        if (!BN_priv_rand_range_ex(d.get(), order_.get(), 0, ctx_.get()))
          return {};
      } while (BN_is_zero(d.get()));
    }
    Point q(EC_POINT_new(group_.get()));
    if (!q) return {};
    const bool ok = base ? EC_POINT_mul(group_.get(), q.get(), nullptr, base,
                                        d.get(), ctx_.get())
                         : EC_POINT_mul(group_.get(), q.get(), d.get(), nullptr,
                                        nullptr, ctx_.get());
    if (!ok) return {};
    priv = std::move(d);
    pub = std::move(q);
    return encode(pub.get());
  }

  Group group_;
  BnCtx ctx_;
  Bn order_;
  size_t fieldLen_ = 0;
  Bn mapPriv_, agrPriv_;
  Point mapPub_, agrPub_, mapped_;
};

// ---------------------------------------------------------------------------
// DH Generic Mapping (group 0)
// ---------------------------------------------------------------------------

class DhMapping : public GenericMapping {
 public:
  explicit DhMapping(int paramId) {
    ctx_.reset(BN_CTX_new());
    const DhGroup* grp = findDhGroup(paramId);
    if (!grp) return;
    BIGNUM* p = nullptr;
    BIGNUM* g = nullptr;
    BIGNUM* q = nullptr;
    BN_hex2bn(&p, grp->p);
    BN_hex2bn(&g, grp->g);
    BN_hex2bn(&q, grp->q);
    p_.reset(p);
    g_.reset(g);
    q_.reset(q);
    pLen_ = p_ ? static_cast<size_t>(BN_num_bytes(p_.get())) : 0;
  }

  bool valid() const { return ctx_ && p_ && g_ && q_; }

  Bytes mappingPublicKey(const Bytes& fixed) override {
    return newKeyPair(fixed, g_.get(), mapPriv_);
  }

  bool mapNonce(const Bytes& chipKey, const Bytes& nonce) override {
    if (!valid() || !mapPriv_ || nonce.empty()) return false;
    Bn y = checkedPeer(chipKey);
    Bn s = bnFromBytes(nonce);
    Bn h(BN_new()), gs(BN_new()), gp(BN_new());
    if (!y || !s || !h || !gs || !gp) return false;
    // H = y^x mod p ; g' = g^s * H mod p
    if (!BN_mod_exp(h.get(), y.get(), mapPriv_.get(), p_.get(), ctx_.get()) ||
        !BN_mod_exp(gs.get(), g_.get(), s.get(), p_.get(), ctx_.get()) ||
        !BN_mod_mul(gp.get(), gs.get(), h.get(), p_.get(), ctx_.get()))
      return false;
    if (BN_is_one(gp.get()) || BN_is_zero(gp.get())) return false;
    mapped_ = std::move(gp);
    return true;
  }

  Bytes mappedGenerator() const override {
    return mapped_ ? bnToBytes(mapped_.get(), pLen_) : Bytes();
  }

  Bytes agreementPublicKey(const Bytes& fixed) override {
    if (!mapped_) return {};
    agrPub_ = newKeyPair(fixed, mapped_.get(), agrPriv_);
    return agrPub_;
  }

  bool agree(const Bytes& chipKey, Bytes& shared) override {
    if (!valid() || !agrPriv_) return false;
    Bn y = checkedPeer(chipKey);
    if (!y) return false;
    Bn own = bnFromBytes(agrPub_);
    if (own && BN_cmp(own.get(), y.get()) == 0) return false;
    Bn k(BN_new());
    if (!k ||
        !BN_mod_exp(k.get(), y.get(), agrPriv_.get(), p_.get(), ctx_.get()))
      return false;
    if (BN_is_one(k.get())) return false;
    shared = bnToBytes(k.get(), pLen_);
    return !shared.empty();
  }

 private:
  /** Peer value must be in [2, p-2] and in the order-q subgroup. */
  Bn checkedPeer(const Bytes& enc) const {
    if (enc.size() != pLen_) return nullptr;
    Bn y = bnFromBytes(enc);
    Bn pm1(BN_dup(p_.get())), chk(BN_new());
    if (!y || !pm1 || !chk || !BN_sub_word(pm1.get(), 1)) return nullptr;
    if (BN_cmp(y.get(), BN_value_one()) <= 0 || BN_cmp(y.get(), pm1.get()) >= 0)
      return nullptr;
    if (!BN_mod_exp(chk.get(), y.get(), q_.get(), p_.get(), ctx_.get()) ||
        !BN_is_one(chk.get()))
      return nullptr;
    return y;
  }

  Bytes newKeyPair(const Bytes& fixed, const BIGNUM* base, Bn& priv) {
    if (!valid()) return {};
    Bn x(BN_new());
    if (!x) return {};
    if (!fixed.empty()) {
      x = bnFromBytes(fixed);
      if (!x) return {};
    } else {
      do {
        if (!BN_priv_rand_range_ex(x.get(), q_.get(), 0, ctx_.get())) return {};
      } while (BN_is_zero(x.get()));
    }
    Bn pub(BN_new());
    if (!pub || !BN_mod_exp(pub.get(), base, x.get(), p_.get(), ctx_.get()))
      return {};
    priv = std::move(x);
    return bnToBytes(pub.get(), pLen_);
  }

  BnCtx ctx_;
  Bn p_, g_, q_;
  size_t pLen_ = 0;
  Bn mapPriv_, agrPriv_, mapped_;
  Bytes agrPub_;
};

// ---------------------------------------------------------------------------
// OID handling
// ---------------------------------------------------------------------------

const uint8_t kPaceOidPrefix[] = {0x04, 0x00, 0x7F, 0x00,
                                  0x07, 0x02, 0x02, 0x04};

bool isPaceInfoOid(const Bytes& oid) {
  return oid.size() == sizeof(kPaceOidPrefix) + 2 &&
         std::equal(std::begin(kPaceOidPrefix), std::end(kPaceOidPrefix),
                    oid.begin());
}

bool cipherFromOid(uint8_t v, Cipher& c) {
  switch (v) {
    case 1:
      c = Cipher::TDES;
      return true;
    case 2:
      c = Cipher::AES128;
      return true;
    case 3:
      c = Cipher::AES192;
      return true;
    case 4:
      c = Cipher::AES256;
      return true;
    default:
      return false;
  }
}

int cipherRank(Cipher c) {
  switch (c) {
    case Cipher::AES256:
      return 4;
    case Cipher::AES192:
      return 3;
    case Cipher::AES128:
      return 2;
    case Cipher::TDES:
      return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// APDU plumbing
// ---------------------------------------------------------------------------

/** Send a plain APDU, following 61xx (GET RESPONSE) and 6Cxx (Le fix). */
uint16_t sendPlain(const Transmit& tx, Bytes apdu, Bytes& resp) {
  resp.clear();
  uint16_t sw = tx(apdu, resp);
  if ((sw >> 8) == 0x6C && apdu.size() >= 5 && apdu.size() <= 261) {
    apdu.back() = static_cast<uint8_t>(sw & 0xFF);
    resp.clear();
    sw = tx(apdu, resp);
  }
  int guard = 0;
  while ((sw >> 8) == 0x61 && guard++ < 64) {
    const Bytes get = {0x00, 0xC0, 0x00, 0x00, static_cast<uint8_t>(sw & 0xFF)};
    Bytes more;
    sw = tx(get, more);
    append(resp, more);
  }
  return sw;
}

Bytes buildApdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                const Bytes& data, int le) {
  Bytes a = {cla, ins, p1, p2};
  if (!data.empty()) {
    a.push_back(static_cast<uint8_t>(data.size()));
    append(a, data);
  }
  if (le >= 0) a.push_back(static_cast<uint8_t>(le == 256 ? 0 : le));
  return a;
}

/** Extended-length case 4 APDU (Lc and Le on three bytes, Le = 65536). */
Bytes buildExtApdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                   const Bytes& data) {
  Bytes a = {cla,
             ins,
             p1,
             p2,
             0x00,
             static_cast<uint8_t>(data.size() >> 8),
             static_cast<uint8_t>(data.size())};
  append(a, data);
  a.push_back(0x00);
  a.push_back(0x00);
  return a;
}

Result fail(uint16_t sw, const std::string& detail, bool link = false) {
  Result r;
  r.status = Status::Failed;
  r.sw = sw;
  r.detail = detail;
  r.linkError = link;
  return r;
}

Result success() {
  Result r;
  r.status = Status::Ok;
  r.sw = 0x9000;
  return r;
}

bool isAuthRejected(uint16_t sw) {
  return (sw >> 8) == 0x63 || sw == 0x6982 || sw == 0x6A80;
}

/**
 * Send one SM-protected command and return the inner status word.
 * Transport errors propagate as exceptions; an SM verification failure is
 * reported through @p linkError (the bytes we got cannot be trusted).
 */
bool smSend(const Transmit& tx, SecureChannel& ch, uint8_t cla, uint8_t ins,
            uint8_t p1, uint8_t p2, const Bytes& data, int le, Bytes& plain,
            uint16_t& sw, std::string& why, bool& linkError) {
  linkError = false;
  Bytes resp;
  uint16_t outer = 0;
  for (int attempt = 0; attempt < 2; ++attempt) {
    Bytes apdu = ch.wrap(cla, ins, p1, p2, data, le);
    outer = sendPlain(tx, apdu, resp);
    if ((outer >> 8) == 0x6C && resp.empty() && attempt == 0 && le >= 0) {
      // The card rejected the Le without processing the command: its SSC
      // did not move, ours did.
      ch.rollbackSsc();
      le = (outer & 0xFF) == 0 ? 256 : (outer & 0xFF);
      continue;
    }
    break;
  }
  if (resp.empty()) {
    // No protected body: the chip refused the command outright.
    sw = outer;
    why = "unprotected status " + hex2(outer);
    return false;
  }
  uint16_t inner = 0;
  if (!ch.unwrap(resp, plain, inner)) {
    sw = 0;
    why = "secure messaging response verification failed";
    linkError = true;
    return false;
  }
  sw = inner;
  return true;
}

Result smCommand(const Transmit& tx, SecureChannel& ch, uint8_t cla,
                 uint8_t ins, uint8_t p1, uint8_t p2, const Bytes& data, int le,
                 Bytes& plain, uint16_t& sw) {
  std::string why;
  bool link = false;
  if (!smSend(tx, ch, cla, ins, p1, p2, data, le, plain, sw, why, link))
    return fail(sw, why, link);
  return success();
}

/** Total size of a file from its first bytes (TLV header). */
bool fileSizeFromHeader(const Bytes& b, size_t& total) {
  if (b.size() < 2) return false;
  size_t idx = 1;
  if ((b[0] & 0x1F) == 0x1F) idx = 2;  // two-byte tag
  if (idx >= b.size()) return false;
  size_t len = 0, hdr = 0;
  if (b[idx] < 0x80) {
    len = b[idx];
    hdr = idx + 1;
  } else if (b[idx] == 0x81 && b.size() >= idx + 2) {
    len = b[idx + 1];
    hdr = idx + 2;
  } else if (b[idx] == 0x82 && b.size() >= idx + 3) {
    len = (static_cast<size_t>(b[idx + 1]) << 8) | b[idx + 2];
    hdr = idx + 3;
  } else {
    return false;
  }
  total = hdr + len;
  return true;
}

using ReadFn = std::function<Result(size_t off, size_t le, Bytes& out)>;

Result readTransparent(const ReadFn& read, size_t chunk, Bytes& out) {
  constexpr size_t kMaxFile = 1u << 20;
  out.clear();
  Bytes b;
  Result r = read(0, 4, b);
  if (r.status != Status::Ok) return r;
  size_t total = 0;
  if (!fileSizeFromHeader(b, total) || total > kMaxFile)
    return fail(0, "unparseable file header");
  out = b;
  if (out.size() > total) out.resize(total);
  while (out.size() < total) {
    const size_t n = std::min(chunk, total - out.size());
    b.clear();
    r = read(out.size(), n, b);
    if (r.status != Status::Ok) return r;
    if (b.empty())
      return fail(0x6282, "short read at offset " + std::to_string(out.size()));
    if (b.size() > total - out.size()) b.resize(total - out.size());
    append(out, b);
  }
  return success();
}

constexpr size_t kPlainChunk = 0xE0;
constexpr size_t kSmChunk = 0xC0;

}  // namespace

// ---------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------

namespace crypto {

static Bytes digest(const EVP_MD* md, const Bytes& in) {
  Bytes out(EVP_MAX_MD_SIZE);
  unsigned int n = 0;
  if (EVP_Digest(in.data(), in.size(), out.data(), &n, md, nullptr) != 1)
    return {};
  out.resize(n);
  return out;
}

Bytes sha1(const Bytes& in) { return digest(EVP_sha1(), in); }
Bytes sha256(const Bytes& in) { return digest(EVP_sha256(), in); }

Bytes aesEcbEncrypt(const Bytes& key, const Bytes& block) {
  const EVP_CIPHER* c = nullptr;
  if (key.size() == 16)
    c = EVP_aes_128_ecb();
  else if (key.size() == 24)
    c = EVP_aes_192_ecb();
  else if (key.size() == 32)
    c = EVP_aes_256_ecb();
  if (!c || block.size() % 16 != 0) return {};
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  Bytes out(block.size() + 16);
  int l1 = 0, l2 = 0;
  if (!ctx ||
      EVP_EncryptInit_ex(ctx.get(), c, nullptr, key.data(), nullptr) != 1)
    return {};
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  if (EVP_EncryptUpdate(ctx.get(), out.data(), &l1, block.data(),
                        static_cast<int>(block.size())) != 1 ||
      EVP_EncryptFinal_ex(ctx.get(), out.data() + l1, &l2) != 1)
    return {};
  out.resize(static_cast<size_t>(l1 + l2));
  return out;
}

Bytes cbcEncrypt(Cipher c, const Bytes& key, const Bytes& iv,
                 const Bytes& data) {
  return cbcImpl(c, key, iv, data, true);
}

Bytes cbcDecrypt(Cipher c, const Bytes& key, const Bytes& iv,
                 const Bytes& data) {
  return cbcImpl(c, key, iv, data, false);
}

Bytes aesCmac(const Bytes& key, const Bytes& data) {
  const char* name = nullptr;
  if (key.size() == 16)
    name = "AES-128-CBC";
  else if (key.size() == 24)
    name = "AES-192-CBC";
  else if (key.size() == 32)
    name = "AES-256-CBC";
  else
    return {};
  EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
  if (!mac) return {};
  EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
  Bytes out(16);
  size_t n = 0;
  bool ok = false;
  if (ctx) {
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                         const_cast<char*>(name), 0),
        OSSL_PARAM_construct_end()};
    ok = EVP_MAC_init(ctx, key.data(), key.size(), params) == 1 &&
         EVP_MAC_update(ctx, data.data(), data.size()) == 1 &&
         EVP_MAC_final(ctx, out.data(), &n, out.size()) == 1;
  }
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  if (!ok) return {};
  out.resize(n);
  return out;
}

Bytes retailMac(const Bytes& key16, const Bytes& paddedData) {
  if (key16.size() != 16 || paddedData.empty() || paddedData.size() % 8 != 0)
    return {};
  // ISO 9797-1 MAC algorithm 3 with a zero IV: the same retail MAC the IAS
  // secure messaging already uses.
  const uint8_t zeroIv[8] = {0};
  try {
    CMAC mac(ByteArray(key16.data(), key16.size()), ByteArray(zeroIv, 8));
    ByteDynArray m = mac.Mac(ByteArray(paddedData.data(), paddedData.size()));
    return Bytes(m.data(), m.data() + m.size());
  } catch (const std::exception&) {
    return {};
  }
}

Bytes pad(const Bytes& in, size_t block) {
  Bytes out = in;
  out.push_back(0x80);
  while (out.size() % block != 0) out.push_back(0x00);
  return out;
}

bool unpad(Bytes& data) {
  size_t i = data.size();
  while (i > 0 && data[i - 1] == 0x00) --i;
  if (i == 0 || data[i - 1] != 0x80) return false;
  data.resize(i - 1);
  return true;
}

}  // namespace crypto

size_t blockSize(Cipher c) { return c == Cipher::TDES ? 8 : 16; }

size_t keyLength(Cipher c) {
  switch (c) {
    case Cipher::TDES:
    case Cipher::AES128:
      return 16;
    case Cipher::AES192:
      return 24;
    case Cipher::AES256:
      return 32;
  }
  return 0;
}

Bytes kdf(Cipher c, const Bytes& k, uint32_t counter) {
  Bytes in = k;
  in.push_back(static_cast<uint8_t>(counter >> 24));
  in.push_back(static_cast<uint8_t>(counter >> 16));
  in.push_back(static_cast<uint8_t>(counter >> 8));
  in.push_back(static_cast<uint8_t>(counter));
  Bytes h = (c == Cipher::AES192 || c == Cipher::AES256) ? crypto::sha256(in)
                                                         : crypto::sha1(in);
  wipe(in);
  const size_t len = keyLength(c);
  if (h.size() < len) return {};
  h.resize(len);
  if (c == Cipher::TDES)
    std::transform(h.begin(), h.end(), h.begin(), oddParity);
  return h;
}

Bytes decryptNonce(Cipher c, const Bytes& kpi, const Bytes& encNonce) {
  return crypto::cbcDecrypt(c, kpi, Bytes(blockSize(c), 0), encNonce);
}

Bytes tokenInput(const Params& p, const Bytes& publicKey) {
  Bytes v = tlv(0x06, p.oid);
  append(v, tlv(p.ec ? 0x86 : 0x84, publicKey));
  return tlv(0x7F49, v);
}

Bytes authToken(const Params& p, const Bytes& ksMac, const Bytes& publicKey) {
  const Bytes in = tokenInput(p, publicKey);
  Bytes mac;
  if (p.cipher == Cipher::TDES)
    mac = crypto::retailMac(ksMac, crypto::pad(in, 8));
  else
    mac = crypto::aesCmac(ksMac, in);
  if (mac.size() >= 8) mac.resize(8);
  return mac;
}

// ---------------------------------------------------------------------------
// EF.CardAccess
// ---------------------------------------------------------------------------

std::vector<PaceInfo> parseCardAccess(const Bytes& ca) {
  std::vector<PaceInfo> out;
  Tlv top;
  if (!parseTlv(ca, 0, ca.size(), top)) return out;

  // SecurityInfos ::= SET OF SecurityInfo, each a SEQUENCE.
  std::vector<Tlv> seqs;
  if (top.tag == 0x31) {
    size_t pos = top.valOff;
    const size_t end = top.valOff + top.valLen;
    while (pos < end) {
      Tlv t;
      if (!parseTlv(ca, pos, end, t)) break;
      if (t.tag == 0x30) seqs.push_back(t);
      pos = t.next;
    }
  } else if (top.tag == 0x30) {
    seqs.push_back(top);
  }

  for (const Tlv& s : seqs) {
    size_t pos = s.valOff;
    const size_t end = s.valOff + s.valLen;
    Tlv t;
    if (!parseTlv(ca, pos, end, t) || t.tag != 0x06) continue;
    PaceInfo info;
    info.oid.assign(ca.begin() + static_cast<long>(t.valOff),
                    ca.begin() + static_cast<long>(t.valOff + t.valLen));
    if (!isPaceInfoOid(info.oid)) continue;
    pos = t.next;
    auto readInt = [&](int& dst) {
      Tlv i;
      if (pos >= end || !parseTlv(ca, pos, end, i) || i.tag != 0x02 ||
          i.valLen < 1 || i.valLen > 2)
        return false;
      int v = 0;
      for (size_t k = 0; k < i.valLen; ++k) v = (v << 8) | ca[i.valOff + k];
      dst = v;
      pos = i.next;
      return true;
    };
    if (!readInt(info.version)) continue;
    int pid = -1;
    if (readInt(pid)) info.parameterId = pid;
    out.push_back(std::move(info));
  }
  return out;
}

bool selectProtocol(const std::vector<PaceInfo>& infos, Params& out) {
  int bestScore = -1;
  for (const PaceInfo& i : infos) {
    if (!isPaceInfoOid(i.oid)) continue;
    const uint8_t mapId = i.oid[8];
    Cipher cipher;
    if (!cipherFromOid(i.oid[9], cipher)) continue;
    Params p;
    p.oid = i.oid;
    p.cipher = cipher;
    p.parameterId = i.parameterId;
    switch (mapId) {
      case 1:  // DH-GM
        p.ec = false;
        p.mapping = Mapping::GM;
        if (!findDhGroup(i.parameterId)) continue;
        break;
      case 2:  // ECDH-GM
      case 6:  // ECDH-CAM (PACE phase identical to GM)
        p.ec = true;
        p.mapping = (mapId == 2) ? Mapping::GM : Mapping::CAM;
        if (!findCurve(i.parameterId)) continue;
        break;
      default:  // Integrated Mapping is not supported
        continue;
    }
    const int score = (p.ec ? 1000 : 0) + cipherRank(cipher) * 10 +
                      (p.mapping == Mapping::GM ? 1 : 0);
    if (score > bestScore) {
      bestScore = score;
      out = p;
    }
  }
  return bestScore >= 0;
}

const char* curveName(int id) {
  const CurveEntry* c = findCurve(id);
  return c ? c->name : "";
}

std::string describe(const Params& p) {
  std::string s = p.ec ? "ECDH-" : "DH-";
  s += p.mapping == Mapping::GM ? "GM"
                                : (p.mapping == Mapping::CAM ? "CAM" : "IM");
  switch (p.cipher) {
    case Cipher::TDES:
      s += " 3DES";
      break;
    case Cipher::AES128:
      s += " AES-128";
      break;
    case Cipher::AES192:
      s += " AES-192";
      break;
    case Cipher::AES256:
      s += " AES-256";
      break;
  }
  if (p.ec)
    s += std::string(" ") + curveName(p.parameterId);
  else
    s += std::string(" modp-") + std::to_string(p.parameterId);
  return s;
}

std::unique_ptr<GenericMapping> makeMapping(const Params& p) {
  if (p.mapping == Mapping::IM) return nullptr;
  if (p.ec) {
    auto m = std::make_unique<EcMapping>(p.parameterId);
    if (!m->valid()) return nullptr;
    return m;
  }
  if (!findDhGroup(p.parameterId)) return nullptr;
  auto m = std::make_unique<DhMapping>(p.parameterId);
  if (!m->valid()) return nullptr;
  return m;
}

// ---------------------------------------------------------------------------
// SecureChannel
// ---------------------------------------------------------------------------

SecureChannel::SecureChannel(Cipher c, Bytes ksEnc, Bytes ksMac,
                             Bytes initialSsc)
    : cipher_(c),
      ksEnc_(std::move(ksEnc)),
      ksMac_(std::move(ksMac)),
      ssc_(std::move(initialSsc)) {
  if (ssc_.empty()) ssc_.assign(blockSize(c), 0);
}

SecureChannel::~SecureChannel() {
  wipe(ksEnc_);
  wipe(ksMac_);
}

SecureChannel::SecureChannel(SecureChannel&& o) noexcept
    : cipher_(o.cipher_),
      ksEnc_(std::move(o.ksEnc_)),
      ksMac_(std::move(o.ksMac_)),
      ssc_(std::move(o.ssc_)) {
  o.ksEnc_.clear();
  o.ksMac_.clear();
}

SecureChannel& SecureChannel::operator=(SecureChannel&& o) noexcept {
  if (this != &o) {
    wipe(ksEnc_);
    wipe(ksMac_);
    cipher_ = o.cipher_;
    ksEnc_ = std::move(o.ksEnc_);
    ksMac_ = std::move(o.ksMac_);
    ssc_ = std::move(o.ssc_);
    o.ksEnc_.clear();
    o.ksMac_.clear();
  }
  return *this;
}

void SecureChannel::incrementSsc() {
  for (size_t i = ssc_.size(); i-- > 0;)
    if (++ssc_[i] != 0) break;
}

void SecureChannel::rollbackSsc() {
  for (size_t i = ssc_.size(); i-- > 0;)
    if (ssc_[i]-- != 0) break;
}

Bytes SecureChannel::iv() const {
  if (cipher_ == Cipher::TDES) return Bytes(8, 0);
  return crypto::aesEcbEncrypt(ksEnc_, ssc_);
}

Bytes SecureChannel::mac(const Bytes& paddedInput) const {
  Bytes m = (cipher_ == Cipher::TDES) ? crypto::retailMac(ksMac_, paddedInput)
                                      : crypto::aesCmac(ksMac_, paddedInput);
  if (m.size() >= 8) m.resize(8);
  return m;
}

Bytes SecureChannel::wrap(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                          const Bytes& data, int le) {
  const size_t bs = blockSize(cipher_);
  incrementSsc();

  const Bytes header = {static_cast<uint8_t>(cla | 0x0C), ins, p1, p2};
  Bytes dos;
  if (!data.empty()) {
    const Bytes enc =
        crypto::cbcEncrypt(cipher_, ksEnc_, iv(), crypto::pad(data, bs));
    if (ins & 1) {
      append(dos, tlv(0x85, enc));
    } else {
      Bytes v = {0x01};
      append(v, enc);
      append(dos, tlv(0x87, v));
    }
  }
  if (le >= 0)
    append(dos, tlv(0x97, Bytes {static_cast<uint8_t>(le == 256 ? 0 : le)}));

  Bytes n = ssc_;
  append(n, crypto::pad(header, bs));
  append(n, dos);
  append(dos, tlv(0x8E, mac(crypto::pad(n, bs))));

  Bytes apdu = header;
  if (dos.size() > 0xFF) return {};  // short APDUs only
  apdu.push_back(static_cast<uint8_t>(dos.size()));
  append(apdu, dos);
  apdu.push_back(0x00);
  return apdu;
}

bool SecureChannel::unwrap(const Bytes& rdata, Bytes& plain, uint16_t& sw) {
  const size_t bs = blockSize(cipher_);
  incrementSsc();
  plain.clear();

  Bytes macInput = ssc_;
  Bytes enc;
  bool have99 = false, have8e = false, haveEnc = false;
  Bytes receivedMac;
  size_t pos = 0;
  while (pos < rdata.size()) {
    Tlv t;
    if (!parseTlv(rdata, pos, rdata.size(), t)) return false;
    const auto first = rdata.begin() + static_cast<long>(pos);
    const auto last = rdata.begin() + static_cast<long>(t.next);
    if (have8e) return false;  // DO'8E' must be last
    switch (t.tag) {
      case 0x87:
        if (haveEnc || have99 || t.valLen < 1 || rdata[t.valOff] != 0x01)
          return false;
        enc.assign(rdata.begin() + static_cast<long>(t.valOff) + 1, last);
        haveEnc = true;
        macInput.insert(macInput.end(), first, last);
        break;
      case 0x85:
        if (haveEnc || have99) return false;
        enc.assign(rdata.begin() + static_cast<long>(t.valOff), last);
        haveEnc = true;
        macInput.insert(macInput.end(), first, last);
        break;
      case 0x99:
        if (have99 || t.valLen != 2) return false;
        sw =
            static_cast<uint16_t>((rdata[t.valOff] << 8) | rdata[t.valOff + 1]);
        have99 = true;
        macInput.insert(macInput.end(), first, last);
        break;
      case 0x8E:
        if (t.valLen != 8) return false;
        receivedMac.assign(rdata.begin() + static_cast<long>(t.valOff), last);
        have8e = true;
        break;
      default:
        return false;
    }
    pos = t.next;
  }
  if (!have99 || !have8e) return false;

  const Bytes expected = mac(crypto::pad(macInput, bs));
  if (expected.size() != 8 ||
      CRYPTO_memcmp(expected.data(), receivedMac.data(), 8) != 0)
    return false;

  if (haveEnc && !enc.empty()) {
    if (enc.size() % bs != 0) return false;
    plain = crypto::cbcDecrypt(cipher_, ksEnc_, iv(), enc);
    if (plain.empty() || !crypto::unpad(plain)) {
      plain.clear();
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Protocol drivers
// ---------------------------------------------------------------------------

Result readCardAccess(const Transmit& tx, Bytes& out) {
  // EF.CardAccess lives in the MF, which is not selected after a reset
  // (a read before SELECT MF answers 6982). Then try the short file
  // identifier (READ BINARY with SFI 1C) and fall back to SELECT FID 011C.
  {
    Bytes ignored;
    sendPlain(tx, buildApdu(0x00, 0xA4, 0x00, 0x0C, {}, -1), ignored);
  }
  bool selected = false;
  ReadFn read = [&](size_t off, size_t le, Bytes& data) -> Result {
    Bytes apdu;
    if (!selected && off == 0) {
      apdu = buildApdu(0x00, 0xB0, 0x9C, 0x00, {}, static_cast<int>(le));
    } else {
      apdu =
          buildApdu(0x00, 0xB0, static_cast<uint8_t>(off >> 8),
                    static_cast<uint8_t>(off & 0xFF), {}, static_cast<int>(le));
    }
    const uint16_t sw = sendPlain(tx, apdu, data);
    if (sw != 0x9000 && sw != 0x6282)
      return fail(sw, "READ BINARY EF.CardAccess sw=" + hex2(sw));
    return success();
  };

  Result r = readTransparent(
      [&](size_t off, size_t le, Bytes& data) {
        Result rr = read(off, le, data);
        if (rr.status == Status::Ok && off == 0) selected = true;
        return rr;
      },
      kPlainChunk, out);
  if (r.status == Status::Ok) return r;

  // Fallback: SELECT EF by FID, then read by offset.
  Bytes resp;
  const Bytes sel = buildApdu(0x00, 0xA4, 0x02, 0x0C, {0x01, 0x1C}, -1);
  const uint16_t sw = sendPlain(tx, sel, resp);
  if (sw != 0x9000) return fail(sw, "SELECT EF.CardAccess sw=" + hex2(sw));
  selected = true;
  return readTransparent(read, kPlainChunk, out);
}

Result performPace(const Transmit& tx, const std::string& can, const Params& p,
                   std::unique_ptr<SecureChannel>& channel,
                   const Options& opt) {
  channel.reset();
  auto mapping = makeMapping(p);
  if (!mapping) {
    Result r;
    r.status = Status::Unsupported;
    r.detail = "PACE parameters not supported";
    return r;
  }

  // --- MSE:Set AT (CAN is password type 2) ---
  Bytes mse = tlv(0x80, p.oid);
  append(mse, Bytes {0x83, 0x01, opt.passwordRef});
  Bytes resp;
  uint16_t sw = sendPlain(tx, buildApdu(0x00, 0x22, 0xC1, 0xA4, mse, -1), resp);
  if (sw != 0x9000 && p.parameterId >= 0 &&
      (sw == 0x6A80 || sw == 0x6A86 || sw == 0x6A88 || sw == 0x6B00)) {
    // Some chips want the domain parameter reference explicitly.
    append(mse, Bytes {0x84, 0x01, static_cast<uint8_t>(p.parameterId)});
    sw = sendPlain(tx, buildApdu(0x00, 0x22, 0xC1, 0xA4, mse, -1), resp);
  }
  if (sw != 0x9000) return fail(sw, "MSE:Set AT sw=" + hex2(sw));

  // One General Authenticate round: returns the child TLV @p wantTag.
  auto gaStep = [&](uint8_t cla, const Bytes& inner, uint32_t wantTag,
                    Bytes& value, uint16_t& swOut) -> Result {
    const Bytes data = tlv(0x7C, inner);
    Bytes r;
    // Public keys of the 2048-bit DH groups do not fit a short APDU:
    // ICAO 9303-11 9.3.1 requires extended length for GENERAL AUTHENTICATE.
    const Bytes apdu = data.size() > 0xFF
                           ? buildExtApdu(cla, 0x86, 0x00, 0x00, data)
                           : buildApdu(cla, 0x86, 0x00, 0x00, data, 0);
    swOut = sendPlain(tx, apdu, r);
    if (swOut != 0x9000)
      return fail(swOut, "GENERAL AUTHENTICATE sw=" + hex2(swOut));
    Tlv outer;
    if (!parseTlv(r, 0, r.size(), outer) || outer.tag != 0x7C ||
        !findChild(r, outer, wantTag, value))
      return fail(0, "malformed GENERAL AUTHENTICATE response");
    return success();
  };

  const Cipher c = p.cipher;
  Bytes canBytes =
      opt.password.empty() ? Bytes(can.begin(), can.end()) : opt.password;
  Bytes kpi = kdf(c, canBytes, 3);
  wipe(canBytes);
  if (kpi.empty()) return fail(0, "KDF failure");

  // --- Step 1: encrypted nonce ---
  Bytes encNonce;
  Result r = gaStep(0x10, Bytes {}, 0x80, encNonce, sw);
  if (r.status != Status::Ok) {
    wipe(kpi);
    if (isAuthRejected(sw) && (sw >> 8) == 0x63) r.status = Status::WrongCan;
    return r;
  }
  Bytes nonce = decryptNonce(c, kpi, encNonce);
  wipe(kpi);
  if (nonce.empty()) return fail(0, "nonce decryption failed");

  // --- Step 2: nonce mapping ---
  const Bytes mapPub = mapping->mappingPublicKey(opt.fixedMappingKey);
  if (mapPub.empty()) {
    wipe(nonce);
    return fail(0, "mapping key generation failed");
  }
  Bytes chipMapPub;
  r = gaStep(0x10, tlv(0x81, mapPub), 0x82, chipMapPub, sw);
  if (r.status != Status::Ok) {
    wipe(nonce);
    return r;
  }
  const bool mapped = mapping->mapNonce(chipMapPub, nonce);
  wipe(nonce);
  if (!mapped) return fail(0, "invalid chip mapping key");

  // --- Step 3: key agreement ---
  const Bytes ifdPub = mapping->agreementPublicKey(opt.fixedAgreementKey);
  if (ifdPub.empty()) return fail(0, "agreement key generation failed");
  Bytes icPub;
  r = gaStep(0x10, tlv(0x83, ifdPub), 0x84, icPub, sw);
  if (r.status != Status::Ok) return r;
  Bytes shared;
  if (!mapping->agree(icPub, shared)) return fail(0, "invalid chip public key");

  Bytes ksEnc = kdf(c, shared, 1);
  Bytes ksMac = kdf(c, shared, 2);
  wipe(shared);
  if (ksEnc.empty() || ksMac.empty()) {
    wipe(ksEnc);
    wipe(ksMac);
    return fail(0, "session key derivation failed");
  }

  // --- Step 4: mutual authentication ---
  const Bytes tIfd = authToken(p, ksMac, icPub);
  const Bytes tIc = authToken(p, ksMac, ifdPub);
  Bytes chipToken;
  r = gaStep(0x00, tlv(0x85, tIfd), 0x86, chipToken, sw);
  if (r.status != Status::Ok) {
    wipe(ksEnc);
    wipe(ksMac);
    if (isAuthRejected(sw)) {
      r.status = Status::WrongCan;
      r.detail =
          "PACE mutual authentication rejected by the chip (sw=" + hex2(sw) +
          ")";
    }
    return r;
  }
  if (tIc.size() != 8 || chipToken.size() != 8 ||
      CRYPTO_memcmp(tIc.data(), chipToken.data(), 8) != 0) {
    wipe(ksEnc);
    wipe(ksMac);
    Result w;
    w.status = Status::WrongCan;
    w.sw = 0x9000;
    w.detail = "PACE chip authentication token mismatch";
    return w;
  }

  channel =
      std::make_unique<SecureChannel>(c, std::move(ksEnc), std::move(ksMac));
  return success();
}

Result selectEmrtdApplication(const Transmit& tx, SecureChannel& ch) {
  const Bytes aid = {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
  Bytes plain;
  uint16_t sw = 0;
  Result r = smCommand(tx, ch, 0x00, 0xA4, 0x04, 0x0C, aid, -1, plain, sw);
  if (r.status != Status::Ok) return r;
  if (sw != 0x9000) return fail(sw, "SELECT eMRTD AID sw=" + hex2(sw));
  return success();
}

Result readFileSm(const Transmit& tx, SecureChannel& ch, uint16_t fid,
                  Bytes& out) {
  Bytes plain;
  uint16_t sw = 0;
  const Bytes fidBytes = {static_cast<uint8_t>(fid >> 8),
                          static_cast<uint8_t>(fid & 0xFF)};
  Result r = smCommand(tx, ch, 0x00, 0xA4, 0x02, 0x0C, fidBytes, -1, plain, sw);
  if (r.status != Status::Ok) return r;
  if (sw != 0x9000) return fail(sw, "SELECT EF sw=" + hex2(sw));

  ReadFn read = [&](size_t off, size_t le, Bytes& data) -> Result {
    uint16_t isw = 0;
    Result rr;
    if (off < 0x8000) {
      rr = smCommand(tx, ch, 0x00, 0xB0, static_cast<uint8_t>(off >> 8),
                     static_cast<uint8_t>(off & 0xFF), {}, static_cast<int>(le),
                     data, isw);
    } else {
      // Offsets above 0x7FFF need READ BINARY (odd INS) with DO'54'.
      const Bytes offDo = tlv(0x54, Bytes {static_cast<uint8_t>(off >> 8),
                                           static_cast<uint8_t>(off & 0xFF)});
      rr = smCommand(tx, ch, 0x00, 0xB1, 0x00, 0x00, offDo,
                     static_cast<int>(le), data, isw);
    }
    if (rr.status != Status::Ok) return rr;
    if (isw != 0x9000 && isw != 0x6282)
      return fail(isw, "READ BINARY sw=" + hex2(isw));
    return success();
  };
  return readTransparent(read, kSmChunk, out);
}

}  // namespace pace
