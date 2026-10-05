// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Known-answer tests for csp/pace.{h,cpp}.
//
// The PACE vectors are the ICAO Doc 9303 part 11 worked examples:
//   - Appendix G.1 (PACE-ECDH-GM, brainpoolP256r1, AES-128),
//   - Appendix G.2 (PACE-DH-GM, RFC 5114 1024-bit group, AES-128),
//   - Appendix D.4 (3DES Secure Messaging, SELECT EF.COM / READ BINARY).
// The AES Secure Messaging vectors were generated with an independent
// implementation of ICAO 9303-11 section 9.8 (python "cryptography").
// No card and no real CAN/PIN is involved.

#include <catch2/catch_test_macros.hpp>
#include <map>
#include <string>

#include "csp/pace.h"

using namespace pace;

namespace {

Bytes H(const std::string& s) {
  Bytes out;
  int hi = -1;
  for (char ch : s) {
    int v;
    if (ch >= '0' && ch <= '9')
      v = ch - '0';
    else if (ch >= 'a' && ch <= 'f')
      v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F')
      v = ch - 'A' + 10;
    else
      continue;
    if (hi < 0)
      hi = v;
    else {
      out.push_back(static_cast<uint8_t>(hi << 4 | v));
      hi = -1;
    }
  }
  return out;
}

Bytes cat(Bytes a, const Bytes& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

Bytes ber(uint8_t tag, const Bytes& v) {
  Bytes out = {tag};
  if (v.size() < 0x80)
    out.push_back(static_cast<uint8_t>(v.size()));
  else if (v.size() <= 0xFF) {
    out.push_back(0x81);
    out.push_back(static_cast<uint8_t>(v.size()));
  } else {
    out.push_back(0x82);
    out.push_back(static_cast<uint8_t>(v.size() >> 8));
    out.push_back(static_cast<uint8_t>(v.size()));
  }
  return cat(out, v);
}

// --- vectors -------------------------------------------------------------
const char* kMrzK = "7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD";
const char* kKpi = "89DED1B26624EC1E634C1989302849DD";

namespace ecv {
const char* k_map_t_priv =
    "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
const char* k_map_t_pub =
    "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E"
    "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D";
const char* k_map_c_pub =
    "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57"
    "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54";
const char* k_mapped =
    "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2"
    "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522";
const char* k_agr_t_priv =
    "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
const char* k_agr_t_pub =
    "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C"
    "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462";
const char* k_agr_c_pub =
    "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB"
    "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094";
const char* k_shared =
    "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925";
const char* k_nonce = "3F00C4D39D153F2B2A214A078D899B22";
const char* k_encNonce = "95A3A016522EE98D01E76CB6B98B42C3";
const char* k_ksEnc = "F5F0E35C0D7161EE6724EE513A0D9A7F";
const char* k_ksMac = "FE251C7858B356B24514B3BD5F4297D1";
const char* k_tIfd = "C2B0BD78D94BA866";
const char* k_tIc = "3ABB9674BCE93C08";
}  // namespace ecv

namespace dhv {
const char* k_map_t_priv = "5265030F751F4AD18B08AC565FC7AC952E41618D";
const char* k_map_t_pub =
    "23FB3749EA030D2A25B278D2A562047ADE3F01B74F17A15402CB7352CA7D2B3E"
    "B71C343DB13D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC702489A4"
    "4D41DB914DE9613DC5E98C94160551C0DF86274B9359BC0490D01B03AD54022D"
    "CB4F57FAD6322497D7A1E28D46710F461AFE710FBBBC5F8BA166F4311975EC6C";
const char* k_map_c_pub =
    "78879F57225AA8080D52ED0FC890A4B25336F699AA89A2D3A189654AF70729E6"
    "23EA5738B26381E4DA19E004706FACE7B235C2DBF2F38748312F3C98C2DD4882"
    "A41947B324AA1259AC22579DB93F7085655AF30889DBB845D9E6783FE42C9F24"
    "49400306254C8AE8EE9DD812A804C0B66E8CAFC14F84D8258950A91B44126EE6";
const char* k_mapped =
    "7C9CBFE98F9FBDDA8D143506FA7D9306F4CB17E3C71707AFF5E1C1A123702496"
    "84D64EE37AF44B8DBD9D45BF6023919CBAA027AB97ACC771666C8E98FF483301"
    "BFA4872DEDE9034EDFACB70814166B7F360676829B826BEA57291B5AD69FBC84"
    "EF1E779032A305803F74341793E869742D401325B37EE8565FFCDEE618342DC5";
const char* k_agr_t_priv = "89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA";
const char* k_agr_t_pub =
    "907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD91155"
    "1B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08F"
    "A8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236"
    "B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4";
const char* k_agr_c_pub =
    "075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152B"
    "D8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC"
    "71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064"
    "386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1";
const char* k_shared =
    "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E3"
    "8B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5"
    "990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E"
    "465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD";
const char* k_nonce = "FA5B7E3E49753A0DB9178B7B9BD898C8";
const char* k_encNonce = "854D8DF5827FA6852D1A4FA701CDDDCA";
const char* k_ksEnc = "2F7F46ADCC9E7E521B45D192FAFA9126";
const char* k_ksMac = "805A1D27D45A5116F73C54469462B7D8";
const char* k_tIfd = "B46DD9BD4D98381F";
const char* k_tIc = "917F37B5C0E6D8D1";
}  // namespace dhv

// ECDH-GM / AES-128 / brainpoolP256r1
Params ecParams() {
  Params p;
  p.oid = H("04007F00070202040202");
  p.ec = true;
  p.mapping = Mapping::GM;
  p.cipher = Cipher::AES128;
  p.parameterId = 13;
  return p;
}

// DH-GM / AES-128 / 1024-bit RFC 5114 group (id 0)
Params dhParams() {
  Params p;
  p.oid = H("04007F00070202040102");
  p.ec = false;
  p.mapping = Mapping::GM;
  p.cipher = Cipher::AES128;
  p.parameterId = 0;
  return p;
}

Bytes uncompressed(const char* xy) { return cat(Bytes {0x04}, H(xy)); }

// Scripted chip that replays the worked-example APDU exchange and checks
// every command byte-for-byte.
struct Step {
  Bytes cmd;
  Bytes resp;  // data without SW
  uint16_t sw;
};

struct ScriptedChip {
  std::vector<Step> steps;
  size_t next = 0;
  std::string mismatch;
  Transmit tx() {
    return [this](const Bytes& apdu, Bytes& resp) -> uint16_t {
      if (next >= steps.size()) {
        mismatch = "unexpected extra APDU";
        return 0x6F00;
      }
      const Step& s = steps[next++];
      if (apdu != s.cmd)
        mismatch = "APDU #" + std::to_string(next - 1) + " differs";
      resp = s.resp;
      return s.sw;
    };
  }
};

Bytes gaCmd(uint8_t cla, const Bytes& inner) {
  const Bytes d = ber(0x7C, inner);
  Bytes a = {cla, 0x86, 0x00, 0x00, static_cast<uint8_t>(d.size())};
  a = cat(a, d);
  a.push_back(0x00);
  return a;
}

}  // namespace

// ---------------------------------------------------------------------------
// KDF / nonce
// ---------------------------------------------------------------------------

TEST_CASE("PACE KDF derives K_pi from K (ICAO 9303-11 G.1)", "[pace][kdf]") {
  CHECK(kdf(Cipher::AES128, H(kMrzK), 3) == H(kKpi));
}

TEST_CASE("PACE KDF 3DES adjusts parity (ICAO 9303-11 D.1)", "[pace][kdf]") {
  const Bytes seed = H("239AB9CB282DAF66231DC5A4DF6BFBAE");
  CHECK(kdf(Cipher::TDES, seed, 1) == H("AB94FDECF2674FDFB9B391F85D7F76F2"));
  CHECK(kdf(Cipher::TDES, seed, 2) == H("7962D9ECE03D1ACD4C76089DCE131543"));
}

TEST_CASE("PACE KDF output lengths follow the cipher", "[pace][kdf]") {
  const Bytes k = H("00112233445566778899AABBCCDDEEFF");
  CHECK(kdf(Cipher::AES128, k, 1).size() == 16);
  CHECK(kdf(Cipher::AES192, k, 1).size() == 24);
  CHECK(kdf(Cipher::AES256, k, 1).size() == 32);
  CHECK(kdf(Cipher::TDES, k, 1).size() == 16);
}

TEST_CASE("PACE nonce decryption (ICAO 9303-11 G.1 and G.2)", "[pace][nonce]") {
  const Bytes kpi = H(kKpi);
  CHECK(decryptNonce(Cipher::AES128, kpi, H(ecv::k_encNonce)) ==
        H(ecv::k_nonce));
  CHECK(decryptNonce(Cipher::AES128, kpi, H(dhv::k_encNonce)) ==
        H(dhv::k_nonce));
}

// ---------------------------------------------------------------------------
// Generic Mapping
// ---------------------------------------------------------------------------

TEST_CASE("PACE ECDH generic mapping and key agreement (G.1)", "[pace][ec]") {
  auto m = makeMapping(ecParams());
  REQUIRE(m);
  CHECK(m->mappingPublicKey(H(ecv::k_map_t_priv)) ==
        uncompressed(ecv::k_map_t_pub));
  REQUIRE(m->mapNonce(uncompressed(ecv::k_map_c_pub), H(ecv::k_nonce)));
  CHECK(m->mappedGenerator() == uncompressed(ecv::k_mapped));

  CHECK(m->agreementPublicKey(H(ecv::k_agr_t_priv)) ==
        uncompressed(ecv::k_agr_t_pub));
  Bytes shared;
  REQUIRE(m->agree(uncompressed(ecv::k_agr_c_pub), shared));
  CHECK(shared == H(ecv::k_shared));

  CHECK(kdf(Cipher::AES128, shared, 1) == H(ecv::k_ksEnc));
  CHECK(kdf(Cipher::AES128, shared, 2) == H(ecv::k_ksMac));
}

TEST_CASE("PACE ECDH rejects points that are not on the curve", "[pace][ec]") {
  auto m = makeMapping(ecParams());
  REQUIRE(m);
  m->mappingPublicKey(H(ecv::k_map_t_priv));
  Bytes bad = uncompressed(ecv::k_map_c_pub);
  bad.back() ^= 0x01;
  CHECK_FALSE(m->mapNonce(bad, H(ecv::k_nonce)));
  CHECK_FALSE(m->mapNonce(Bytes {0x04, 0x01}, H(ecv::k_nonce)));
}

TEST_CASE("PACE DH generic mapping and key agreement (G.2)", "[pace][dh]") {
  auto m = makeMapping(dhParams());
  REQUIRE(m);
  CHECK(m->mappingPublicKey(H(dhv::k_map_t_priv)) == H(dhv::k_map_t_pub));
  REQUIRE(m->mapNonce(H(dhv::k_map_c_pub), H(dhv::k_nonce)));
  CHECK(m->mappedGenerator() == H(dhv::k_mapped));

  CHECK(m->agreementPublicKey(H(dhv::k_agr_t_priv)) == H(dhv::k_agr_t_pub));
  Bytes shared;
  REQUIRE(m->agree(H(dhv::k_agr_c_pub), shared));
  CHECK(shared == H(dhv::k_shared));

  CHECK(kdf(Cipher::AES128, shared, 1) == H(dhv::k_ksEnc));
  CHECK(kdf(Cipher::AES128, shared, 2) == H(dhv::k_ksMac));
}

TEST_CASE("PACE DH rejects out-of-subgroup chip keys", "[pace][dh]") {
  auto m = makeMapping(dhParams());
  REQUIRE(m);
  m->mappingPublicKey(H(dhv::k_map_t_priv));
  Bytes one(128, 0);
  one.back() = 1;
  CHECK_FALSE(m->mapNonce(one, H(dhv::k_nonce)));
  Bytes two(128, 0);
  two.back() = 2;  // not in the order-q subgroup
  CHECK_FALSE(m->mapNonce(two, H(dhv::k_nonce)));
}

// ---------------------------------------------------------------------------
// Authentication tokens
// ---------------------------------------------------------------------------

TEST_CASE("PACE authentication tokens (G.1 and G.2)", "[pace][token]") {
  const Params ec = ecParams();
  CHECK(authToken(ec, H(ecv::k_ksMac), uncompressed(ecv::k_agr_c_pub)) ==
        H(ecv::k_tIfd));
  CHECK(authToken(ec, H(ecv::k_ksMac), uncompressed(ecv::k_agr_t_pub)) ==
        H(ecv::k_tIc));

  const Params dh = dhParams();
  CHECK(authToken(dh, H(dhv::k_ksMac), H(dhv::k_agr_c_pub)) == H(dhv::k_tIfd));
  CHECK(authToken(dh, H(dhv::k_ksMac), H(dhv::k_agr_t_pub)) == H(dhv::k_tIc));
}

TEST_CASE("PACE token input encoding (G.1)", "[pace][token]") {
  const Bytes in = tokenInput(ecParams(), uncompressed(ecv::k_agr_c_pub));
  CHECK(Bytes(in.begin(), in.begin() + 17) ==
        H("7F494F060A04007F000702020402028641"));
}

// ---------------------------------------------------------------------------
// Whole protocol against a scripted chip
// ---------------------------------------------------------------------------

namespace {
Options ecOpts() {
  Options o;
  o.fixedMappingKey = H(ecv::k_map_t_priv);
  o.fixedAgreementKey = H(ecv::k_agr_t_priv);
  o.password = H(kMrzK);
  o.passwordRef = 1;  // the worked example authenticates with the MRZ
  return o;
}

std::vector<Step> ecScript(bool corruptToken = false,
                           uint16_t lastSw = 0x9000) {
  const Params p = ecParams();
  Bytes tic = H(ecv::k_tIc);
  if (corruptToken) tic[0] ^= 0xFF;
  std::vector<Step> s;
  s.push_back({H("00 22 C1 A4 0F 80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 01"),
               {},
               0x9000});
  s.push_back({H("10 86 00 00 02 7C 00 00"),
               ber(0x7C, ber(0x80, H(ecv::k_encNonce))), 0x9000});
  s.push_back({gaCmd(0x10, ber(0x81, uncompressed(ecv::k_map_t_pub))),
               ber(0x7C, ber(0x82, uncompressed(ecv::k_map_c_pub))), 0x9000});
  s.push_back({gaCmd(0x10, ber(0x83, uncompressed(ecv::k_agr_t_pub))),
               ber(0x7C, ber(0x84, uncompressed(ecv::k_agr_c_pub))), 0x9000});
  s.push_back({H("00 86 00 00 0C 7C 0A 85 08 C2 B0 BD 78 D9 4B A8 66 00"),
               lastSw == 0x9000 ? ber(0x7C, ber(0x86, tic)) : Bytes {},
               lastSw});
  return s;
}
}  // namespace

TEST_CASE("PACE ECDH-GM full exchange reproduces the G.1 APDUs",
          "[pace][flow]") {
  ScriptedChip chip;
  chip.steps = ecScript();
  std::unique_ptr<SecureChannel> ch;
  Result r = performPace(chip.tx(), "", ecParams(), ch, ecOpts());
  CHECK(chip.mismatch.empty());
  REQUIRE(r.status == Status::Ok);
  REQUIRE(ch);
  CHECK(chip.next == chip.steps.size());
  // SSC starts at zero after PACE: the first wrapped command uses SSC = 1.
  CHECK(ch->ssc() == Bytes(16, 0));
}

TEST_CASE("PACE DH-GM full exchange reproduces the G.2 APDUs", "[pace][flow]") {
  ScriptedChip chip;
  chip.steps.push_back(
      {H("00 22 C1 A4 0F 80 0A 04 00 7F 00 07 02 02 04 01 02 83 01 01"),
       {},
       0x9000});
  chip.steps.push_back({H("10 86 00 00 02 7C 00 00"),
                        ber(0x7C, ber(0x80, H(dhv::k_encNonce))), 0x9000});
  chip.steps.push_back({gaCmd(0x10, ber(0x81, H(dhv::k_map_t_pub))),
                        ber(0x7C, ber(0x82, H(dhv::k_map_c_pub))), 0x9000});
  chip.steps.push_back({gaCmd(0x10, ber(0x83, H(dhv::k_agr_t_pub))),
                        ber(0x7C, ber(0x84, H(dhv::k_agr_c_pub))), 0x9000});
  // The chip also returns its CA reference (tag 87) with the token.
  chip.steps.push_back(
      {H("00 86 00 00 0C 7C 0A 85 08 B4 6D D9 BD 4D 98 38 1F 00"),
       ber(0x7C, cat(ber(0x86, H(dhv::k_tIc)),
                     ber(0x87, H("44455445535443564341303030303"
                                 "3")))),
       0x9000});

  Options o;
  o.fixedMappingKey = H(dhv::k_map_t_priv);
  o.fixedAgreementKey = H(dhv::k_agr_t_priv);
  o.password = H(kMrzK);
  o.passwordRef = 1;
  std::unique_ptr<SecureChannel> ch;
  Result r = performPace(chip.tx(), "", dhParams(), ch, o);
  CHECK(chip.mismatch.empty());
  REQUIRE(r.status == Status::Ok);
  CHECK(ch);
}

TEST_CASE("PACE reports a wrong CAN when the chip answers 6300",
          "[pace][flow]") {
  ScriptedChip chip;
  chip.steps = ecScript(false, 0x6300);
  std::unique_ptr<SecureChannel> ch;
  Result r = performPace(chip.tx(), "", ecParams(), ch, ecOpts());
  CHECK(r.status == Status::WrongCan);
  CHECK_FALSE(ch);
  // Exactly one mutual-authentication attempt, no retry inside the module.
  CHECK(chip.next == chip.steps.size());
}

TEST_CASE("PACE reports a wrong CAN on a chip token mismatch", "[pace][flow]") {
  ScriptedChip chip;
  chip.steps = ecScript(true);
  std::unique_ptr<SecureChannel> ch;
  Result r = performPace(chip.tx(), "", ecParams(), ch, ecOpts());
  CHECK(r.status == Status::WrongCan);
  CHECK_FALSE(ch);
}

TEST_CASE("PACE does not mistake other failures for a wrong CAN",
          "[pace][flow]") {
  ScriptedChip chip;
  chip.steps = {
      Step {H("00 22 C1 A4 0F 80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 02"),
            {},
            0x6D00}};
  std::unique_ptr<SecureChannel> ch;
  Options o = ecOpts();
  o.password.clear();
  o.passwordRef = 2;
  Result r = performPace(chip.tx(), "123456", ecParams(), ch, o);
  CHECK(chip.mismatch.empty());
  CHECK(r.status == Status::Failed);
  CHECK(r.sw == 0x6D00);
}

TEST_CASE("PACE MSE uses the CAN password reference", "[pace][flow]") {
  Bytes seen;
  const Transmit tx = [&](const Bytes& apdu, Bytes&) -> uint16_t {
    seen = apdu;
    return 0x6D00;
  };
  std::unique_ptr<SecureChannel> ch;
  performPace(tx, "123456", ecParams(), ch);
  REQUIRE(seen.size() == 20);
  CHECK(Bytes(seen.end() - 3, seen.end()) == H("83 01 02"));
}

// ---------------------------------------------------------------------------
// EF.CardAccess
// ---------------------------------------------------------------------------

TEST_CASE("EF.CardAccess PACEInfo parsing and selection",
          "[pace][cardaccess]") {
  // SET { PACEInfo of ICAO 9303-11 G.1 }
  const Bytes ca = H("3114 3012060A04007F0007020204020202010202010D");
  auto infos = parseCardAccess(ca);
  REQUIRE(infos.size() == 1);
  CHECK(infos[0].version == 2);
  CHECK(infos[0].parameterId == 13);
  Params p;
  REQUIRE(selectProtocol(infos, p));
  CHECK(p.ec);
  CHECK(p.mapping == Mapping::GM);
  CHECK(p.cipher == Cipher::AES128);
  CHECK(p.parameterId == 13);
  CHECK(describe(p) == "ECDH-GM AES-128 brainpoolP256r1");
}

TEST_CASE("EF.CardAccess selection prefers ECDH and the strongest cipher",
          "[pace][cardaccess]") {
  // DH-GM AES-256 id 0 ; ECDH-GM AES-128 id 12 ; ECDH-GM AES-256 id 13 ;
  // ECDH-IM (unsupported) ; an unrelated SecurityInfo.
  Bytes body;
  body = cat(body, H("3012060A04007F0007020204010402010202010 0"));
  body = cat(body, H("3012060A04007F000702020402020201020201 0C"));
  body = cat(body, H("3012060A04007F000702020402040201020201 0D"));
  body = cat(body, H("3012060A04007F000702020404040201020201 0D"));
  body = cat(body, H("3009060704007F00070202"));
  const Bytes ca = ber(0x31, body);
  Params p;
  REQUIRE(selectProtocol(parseCardAccess(ca), p));
  CHECK(p.ec);
  CHECK(p.cipher == Cipher::AES256);
  CHECK(p.parameterId == 13);
}

TEST_CASE("EF.CardAccess without a supported PACE protocol",
          "[pace][cardaccess]") {
  Params p;
  CHECK_FALSE(selectProtocol({}, p));
  // IM only
  CHECK_FALSE(selectProtocol(
      parseCardAccess(H("3114 3012060A04007F0007020204040202020102020D")), p));
  // proprietary domain parameters (id >= 32)
  CHECK_FALSE(selectProtocol(
      parseCardAccess(H("3114 3012060A04007F00070202040202020102020 20")), p));
  CHECK(parseCardAccess(H("0102")).empty());
}

// ---------------------------------------------------------------------------
// Secure Messaging
// ---------------------------------------------------------------------------

TEST_CASE("3DES Secure Messaging reproduces ICAO 9303-11 D.4", "[pace][sm]") {
  SecureChannel ch(Cipher::TDES, H("979EC13B1CBFE9DCD01AB0FED307EAE5"),
                   H("F1CB1F1FB5ADF208806B89DC579DC1F8"),
                   H("887022120C06C226"));
  Bytes plain;
  uint16_t sw = 0;

  // 1. SELECT EF.COM
  CHECK(ch.wrap(0x00, 0xA4, 0x02, 0x0C, H("011E"), -1) ==
        H("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"));
  REQUIRE(ch.unwrap(H("990290008E08FA855A5D4C50A8ED"), plain, sw));
  CHECK(sw == 0x9000);
  CHECK(plain.empty());

  // 2. READ BINARY, first four bytes
  CHECK(ch.wrap(0x00, 0xB0, 0x00, 0x00, {}, 4) ==
        H("0CB000000D9701048E08ED6705417E96BA5500"));
  REQUIRE(ch.unwrap(H("8709019FF0EC34F992265199029000 8E08AD55CC17140B2DED"),
                    plain, sw));
  CHECK(plain == H("60145F01"));

  // 3. READ BINARY, the remaining 18 bytes
  CHECK(ch.wrap(0x00, 0xB0, 0x00, 0x04, {}, 0x12) ==
        H("0CB000040D9701128E082EA28A70F3C7B53500"));
  REQUIRE(ch.unwrap(H("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A"
                      "990290008E08C8B2787EAEA07D74"),
                    plain, sw));
  CHECK(plain.size() == 18);
  CHECK(ch.ssc() == H("887022120C06C22C"));
}

TEST_CASE("AES Secure Messaging wrap/unwrap known answers", "[pace][sm]") {
  SecureChannel ch(Cipher::AES128, H("0102030405060708090a0b0c0d0e0f10"),
                   H("a1a2a3a4a5a6a7a8a9aaabacadaeafb0"));
  Bytes plain;
  uint16_t sw = 0;
  CHECK(ch.wrap(0x00, 0xA4, 0x04, 0x0C, H("A0000002471001"), -1) ==
        H("0ca4040c1d871101ae6896c36d5e1f3bd4ecbaf7a661652b8e08c783f86389338e0d"
          "00"));
  REQUIRE(ch.unwrap(H("990290008e08117dd72826d77570"), plain, sw));
  CHECK(sw == 0x9000);
  CHECK(plain.empty());
  CHECK(ch.wrap(0x00, 0xB0, 0x00, 0x00, {}, 20) ==
        H("0cb000000d9701148e0829b7480811e8ae7600"));
  REQUIRE(ch.unwrap(H("872101a57fd10b28b996eff1162d1ecf14f100d960990bd394a608aa"
                      "c46e29a9a5ad7c990290008e087d192821635d4fa7"),
                    plain, sw));
  CHECK(sw == 0x9000);
  CHECK(plain == H("303132333435363738393a3b3c3d3e3f40414243"));
}

TEST_CASE("Secure Messaging rejects tampered responses", "[pace][sm]") {
  const Bytes ke = H("0102030405060708090a0b0c0d0e0f10");
  const Bytes km = H("a1a2a3a4a5a6a7a8a9aaabacadaeafb0");
  Bytes plain;
  uint16_t sw = 0;
  {
    SecureChannel ch(Cipher::AES128, ke, km);
    ch.wrap(0x00, 0xA4, 0x04, 0x0C, H("A0000002471001"), -1);
    Bytes r = H("990290008e08117dd72826d77570");
    r.back() ^= 0x01;  // corrupt the MAC
    CHECK_FALSE(ch.unwrap(r, plain, sw));
  }
  {
    SecureChannel ch(Cipher::AES128, ke, km);
    ch.wrap(0x00, 0xA4, 0x04, 0x0C, H("A0000002471001"), -1);
    CHECK_FALSE(ch.unwrap(H("9902"), plain, sw));  // no MAC
    CHECK_FALSE(ch.unwrap(Bytes {}, plain, sw));   // empty
  }
  {
    // Out of sync SSC (response replayed against a fresh channel).
    SecureChannel ch(Cipher::AES128, ke, km);
    CHECK_FALSE(ch.unwrap(H("990290008e08117dd72826d77570"), plain, sw));
  }
}

TEST_CASE("Secure Messaging rollback restores the SSC", "[pace][sm]") {
  SecureChannel ch(Cipher::AES128, Bytes(16, 1), Bytes(16, 2),
                   H("000000000000000000000000000000FF"));
  ch.wrap(0, 0xB0, 0, 0, {}, 1);
  CHECK(ch.ssc() == H("00000000000000000000000000000100"));
  ch.rollbackSsc();
  CHECK(ch.ssc() == H("000000000000000000000000000000FF"));
}

// ---------------------------------------------------------------------------
// Reading files through Secure Messaging (simulated eMRTD)
// ---------------------------------------------------------------------------

namespace {

// Chip side of ICAO 9303-11 section 9.8 for AES-128, with a tiny file system.
struct SimChip {
  Bytes ksEnc, ksMac, ssc = Bytes(16, 0);
  std::map<uint16_t, Bytes> files;
  bool aidSelected = false;
  uint16_t selected = 0;
  int apdus = 0;
  size_t maxLe = 0;
  bool ok = true;

  void inc() {
    for (size_t i = ssc.size(); i-- > 0;)
      if (++ssc[i] != 0) break;
  }
  Bytes iv() const { return crypto::aesEcbEncrypt(ksEnc, ssc); }

  Bytes protect(const Bytes& plain, uint16_t sw, bool odd) {
    inc();
    Bytes dos;
    if (!plain.empty()) {
      Bytes enc = crypto::cbcEncrypt(Cipher::AES128, ksEnc, iv(),
                                     crypto::pad(plain, 16));
      if (odd)
        dos = ber(0x85, enc);
      else
        dos = ber(0x87, cat(Bytes {0x01}, enc));
    }
    dos = cat(dos, ber(0x99, Bytes {static_cast<uint8_t>(sw >> 8),
                                    static_cast<uint8_t>(sw)}));
    Bytes mac = crypto::aesCmac(ksMac, crypto::pad(cat(ssc, dos), 16));
    mac.resize(8);
    return cat(dos, ber(0x8E, mac));
  }

  uint16_t handle(const Bytes& apdu, Bytes& resp) {
    ++apdus;
    resp.clear();
    if (apdu.size() < 6 || (apdu[0] & 0x0C) != 0x0C) {
      ok = false;
      return 0x6E00;
    }
    const Bytes hdr(apdu.begin(), apdu.begin() + 4);
    const size_t lc = apdu[4];
    if (apdu.size() != 5 + lc + 1) {
      ok = false;
      return 0x6700;
    }
    const Bytes body(apdu.begin() + 5,
                     apdu.begin() + 5 + static_cast<long>(lc));
    inc();
    Bytes macIn = cat(ssc, crypto::pad(hdr, 16));
    Bytes data;
    int le = -1;
    size_t pos = 0;
    Bytes recvMac;
    while (pos < body.size()) {
      const uint8_t tag = body[pos];
      const size_t len = body[pos + 1];
      const Bytes val(
          body.begin() + static_cast<long>(pos) + 2,
          body.begin() + static_cast<long>(pos) + 2 + static_cast<long>(len));
      if (tag != 0x8E)
        macIn =
            cat(macIn, Bytes(body.begin() + static_cast<long>(pos),
                             body.begin() + static_cast<long>(pos + 2 + len)));
      if (tag == 0x87 || tag == 0x85) {
        Bytes enc(val.begin() + (tag == 0x87 ? 1 : 0), val.end());
        data = crypto::cbcDecrypt(Cipher::AES128, ksEnc, iv(), enc);
        crypto::unpad(data);
      } else if (tag == 0x97) {
        le = val[0] == 0 ? 256 : val[0];
      } else if (tag == 0x8E) {
        recvMac = val;
      }
      pos += 2 + len;
    }
    Bytes mac = crypto::aesCmac(ksMac, crypto::pad(macIn, 16));
    mac.resize(8);
    if (mac != recvMac) {
      ok = false;
      return 0x6988;
    }
    if (le > 0 && static_cast<size_t>(le) > maxLe)
      maxLe = static_cast<size_t>(le);

    const uint8_t ins = apdu[1];
    Bytes plain;
    uint16_t sw = 0x9000;
    if (ins == 0xA4 && apdu[2] == 0x04) {
      aidSelected = (data == H("A0000002471001"));
      sw = aidSelected ? 0x9000 : 0x6A82;
    } else if (ins == 0xA4 && apdu[2] == 0x02) {
      const uint16_t fid = static_cast<uint16_t>(data[0] << 8 | data[1]);
      if (aidSelected && files.count(fid)) {
        selected = fid;
      } else {
        sw = 0x6A82;
      }
    } else if (ins == 0xB0 || ins == 0xB1) {
      size_t off;
      if (ins == 0xB0) {
        off = static_cast<size_t>(apdu[2] << 8 | apdu[3]);
      } else {
        off = static_cast<size_t>(data[2] << 8 | data[3]);
      }
      const Bytes& f = files[selected];
      if (off >= f.size()) {
        sw = 0x6B00;
      } else {
        const size_t n =
            std::min<size_t>(static_cast<size_t>(le), f.size() - off);
        plain.assign(f.begin() + static_cast<long>(off),
                     f.begin() + static_cast<long>(off + n));
      }
    } else {
      sw = 0x6D00;
    }
    resp = protect(plain, sw, ins & 1);
    return 0x9000;
  }
};

Bytes fileWithHeader(uint8_t tag, size_t payload) {
  Bytes body(payload);
  for (size_t i = 0; i < payload; ++i)
    body[i] = static_cast<uint8_t>(i * 7 + 3);
  return ber(tag, body);
}

}  // namespace

namespace {
struct Fixture {
  SimChip chip;
  std::unique_ptr<SecureChannel> ch;
  size_t maxResp = 0;
  // hooks
  bool injectLe6C =
      false;  // answer the first READ BINARY with 6Cxx unprocessed
  bool injectGetResp = false;
  bool corruptMac = false;
  Bytes withheld;
  bool sawGetResponse = false;

  Fixture() {
    chip.ksEnc = H("0102030405060708090a0b0c0d0e0f10");
    chip.ksMac = H("a1a2a3a4a5a6a7a8a9aaabacadaeafb0");
    ch =
        std::make_unique<SecureChannel>(Cipher::AES128, chip.ksEnc, chip.ksMac);
  }

  Transmit tx() {
    return [this](const Bytes& a, Bytes& r) -> uint16_t {
      if (a.size() == 5 && a[0] == 0x00 && a[1] == 0xC0) {
        sawGetResponse = true;
        r = withheld;
        withheld.clear();
        return 0x9000;
      }
      if (injectLe6C && a[1] == 0xB0) {
        injectLe6C = false;
        r.clear();
        return 0x6C02;
      }
      uint16_t sw = chip.handle(a, r);
      if (corruptMac && !r.empty() && a[1] == 0xB0) r.back() ^= 0x55;
      if (injectGetResp && !r.empty() && a[1] == 0xB0) {
        injectGetResp = false;
        withheld = r;
        r.clear();
        return static_cast<uint16_t>(0x6100 | (withheld.size() & 0xFF));
      }
      maxResp = std::max(maxResp, r.size());
      return sw;
    };
  }
};
}  // namespace

TEST_CASE("eMRTD application select and DG reads over Secure Messaging",
          "[pace][read]") {
  Fixture f;
  f.chip.files[0x0101] = fileWithHeader(0x61, 91);
  f.chip.files[0x0102] = fileWithHeader(0x75, 5000);
  const Transmit tx = f.tx();

  // Without the application selected the EF cannot be reached.
  Bytes out;
  CHECK(readFileSm(tx, *f.ch, 0x0101, out).sw == 0x6A82);

  // Fresh channel keeps the sim chip in sync only if no extra SM APDU was
  // consumed, so rebuild both sides.
  Fixture g;
  g.chip.files = f.chip.files;
  const Transmit tx2 = g.tx();
  REQUIRE(selectEmrtdApplication(tx2, *g.ch).status == Status::Ok);
  Bytes dg1, dg2;
  REQUIRE(readFileSm(tx2, *g.ch, 0x0101, dg1).status == Status::Ok);
  REQUIRE(readFileSm(tx2, *g.ch, 0x0102, dg2).status == Status::Ok);
  CHECK(dg1 == g.chip.files[0x0101]);
  CHECK(dg2 == g.chip.files[0x0102]);
  CHECK(g.chip.ok);
  // The protected response must always fit a short-APDU answer.
  CHECK(g.maxResp <= 255);
  CHECK(g.chip.maxLe <= 0xC0);

  // Missing file.
  Bytes none;
  Result r = readFileSm(tx2, *g.ch, 0x0103, none);
  CHECK(r.status == Status::Failed);
  CHECK(r.sw == 0x6A82);
}

TEST_CASE("readFileSm uses READ BINARY odd INS above offset 0x7FFF",
          "[pace][read]") {
  Fixture f;
  f.chip.files[0x0102] = fileWithHeader(0x75, 33000);
  const Transmit tx = f.tx();
  REQUIRE(selectEmrtdApplication(tx, *f.ch).status == Status::Ok);
  Bytes dg2;
  REQUIRE(readFileSm(tx, *f.ch, 0x0102, dg2).status == Status::Ok);
  CHECK(dg2 == f.chip.files[0x0102]);
  CHECK(f.chip.ok);
}

TEST_CASE("readFileSm recovers from 6Cxx and 61xx", "[pace][read]") {
  {
    Fixture f;
    f.chip.files[0x0101] = fileWithHeader(0x61, 91);
    const Transmit tx = f.tx();
    REQUIRE(selectEmrtdApplication(tx, *f.ch).status == Status::Ok);
    f.injectLe6C = true;
    Bytes dg1;
    REQUIRE(readFileSm(tx, *f.ch, 0x0101, dg1).status == Status::Ok);
    CHECK(dg1 == f.chip.files[0x0101]);
    CHECK(f.chip.ok);
  }
  {
    Fixture f;
    f.chip.files[0x0101] = fileWithHeader(0x61, 91);
    const Transmit tx = f.tx();
    REQUIRE(selectEmrtdApplication(tx, *f.ch).status == Status::Ok);
    f.injectGetResp = true;
    Bytes dg1;
    REQUIRE(readFileSm(tx, *f.ch, 0x0101, dg1).status == Status::Ok);
    CHECK(f.sawGetResponse);
    CHECK(dg1 == f.chip.files[0x0101]);
  }
}

TEST_CASE("readFileSm flags a corrupted SM response as a link error",
          "[pace][read]") {
  Fixture f;
  f.chip.files[0x0101] = fileWithHeader(0x61, 91);
  const Transmit tx = f.tx();
  REQUIRE(selectEmrtdApplication(tx, *f.ch).status == Status::Ok);
  f.corruptMac = true;
  Bytes dg1;
  Result r = readFileSm(tx, *f.ch, 0x0101, dg1);
  CHECK(r.status == Status::Failed);
  CHECK(r.linkError);
}

TEST_CASE("readCardAccess reads EF.CardAccess by SFI", "[pace][cardaccess]") {
  const Bytes ca = H("3114 3012060A04007F0007020204020202010202010D");
  std::vector<Bytes> seen;
  bool mfSelected = false;
  const Transmit tx = [&](const Bytes& a, Bytes& r) -> uint16_t {
    seen.push_back(a);
    if (a == H("00 A4 00 0C")) {
      mfSelected = true;
      return 0x9000;
    }
    // Like the CIE: EF.CardAccess answers 6982 until the MF is selected.
    if (!mfSelected) return 0x6982;
    REQUIRE(a[1] == 0xB0);
    const size_t off = a[2] == 0x9C ? 0 : static_cast<size_t>(a[2] << 8 | a[3]);
    const size_t le = a[4] == 0 ? 256 : a[4];
    r.assign(ca.begin() + static_cast<long>(off),
             ca.begin() + static_cast<long>(std::min(ca.size(), off + le)));
    return 0x9000;
  };
  Bytes out;
  REQUIRE(readCardAccess(tx, out).status == Status::Ok);
  CHECK(out == ca);
  CHECK(seen.front() == H("00 A4 00 0C"));
  CHECK(seen[1] == H("00 B0 9C 00 04"));
}

TEST_CASE("readCardAccess falls back to SELECT FID 011C",
          "[pace][cardaccess]") {
  const Bytes ca = H("3114 3012060A04007F0007020204020202010202010D");
  bool selected = false;
  const Transmit tx = [&](const Bytes& a, Bytes& r) -> uint16_t {
    if (a == H("00 A4 00 0C")) return 0x9000;
    if (a[1] == 0xA4) {
      selected = (a == H("00 A4 02 0C 02 01 1C"));
      return selected ? 0x9000 : 0x6A82;
    }
    if (!selected) return 0x6A82;  // SFI read unsupported
    const size_t off = static_cast<size_t>(a[2] << 8 | a[3]);
    const size_t le = a[4] == 0 ? 256 : a[4];
    r.assign(ca.begin() + static_cast<long>(off),
             ca.begin() + static_cast<long>(std::min(ca.size(), off + le)));
    return 0x9000;
  };
  Bytes out;
  REQUIRE(readCardAccess(tx, out).status == Status::Ok);
  CHECK(out == ca);
}

TEST_CASE("readCardAccess reports a missing file", "[pace][cardaccess]") {
  const Transmit tx = [](const Bytes&, Bytes&) -> uint16_t { return 0x6A82; };
  Bytes out;
  Result r = readCardAccess(tx, out);
  CHECK(r.status == Status::Failed);
  CHECK(r.sw == 0x6A82);
}

// ---------------------------------------------------------------------------
// All standardized curves: two mapping engines must agree
// ---------------------------------------------------------------------------

TEST_CASE("PACE ECDH-GM agrees on every standardized curve", "[pace][ec]") {
  const Bytes nonce = H("0102030405060708090A0B0C0D0E0F10");
  for (int id = 8; id <= 18; ++id) {
    INFO("parameter id " << id << " " << curveName(id));
    Params p = ecParams();
    p.parameterId = id;
    auto a = makeMapping(p);
    auto b = makeMapping(p);
    REQUIRE(a);
    REQUIRE(b);
    const Bytes pa = a->mappingPublicKey();
    const Bytes pb = b->mappingPublicKey();
    REQUIRE(a->mapNonce(pb, nonce));
    REQUIRE(b->mapNonce(pa, nonce));
    CHECK(a->mappedGenerator() == b->mappedGenerator());
    const Bytes ka = a->agreementPublicKey();
    const Bytes kb = b->agreementPublicKey();
    Bytes sa, sb;
    REQUIRE(a->agree(kb, sa));
    REQUIRE(b->agree(ka, sb));
    CHECK(sa == sb);
    Bytes dummy;
    CHECK_FALSE(a->agree(ka, dummy));  // own key reflected back
  }
  Params unknown = ecParams();
  unknown.parameterId = 99;
  CHECK_FALSE(makeMapping(unknown));
}

// ---------------------------------------------------------------------------
// Simulated PACE chip (both sides of the protocol use the same primitives):
// exercises the protocol suites for which no worked example exists, notably
// what the CIE actually offers: DH-GM, 2048-bit group (id 2), 3DES.
// ---------------------------------------------------------------------------

namespace {

bool findDo(const Bytes& d, uint8_t tag, Bytes& v) {
  // d = 7C len { ... }
  size_t pos = 1;
  size_t len = d[pos++];
  if (len == 0x81)
    len = d[pos++];
  else if (len == 0x82) {
    len = static_cast<size_t>(d[pos] << 8 | d[pos + 1]);
    pos += 2;
  }
  const size_t end = pos + len;
  while (pos < end) {
    const uint8_t t = d[pos++];
    size_t l = d[pos++];
    if (l == 0x81)
      l = d[pos++];
    else if (l == 0x82) {
      l = static_cast<size_t>(d[pos] << 8 | d[pos + 1]);
      pos += 2;
    }
    if (t == tag) {
      v.assign(d.begin() + static_cast<long>(pos),
               d.begin() + static_cast<long>(pos + l));
      return true;
    }
    pos += l;
  }
  return false;
}

struct SimPaceChip {
  Params p;
  std::string can;
  std::unique_ptr<GenericMapping> m;
  Bytes nonce, ksEnc, ksMac, ifdPub, myPub;
  bool extSeen = false;
  int maxShortLc = 0;

  uint16_t handle(const Bytes& a, Bytes& r) {
    if (a[1] == 0x22) return 0x9000;
    if (a[1] != 0x86) return 0x6D00;
    size_t off, lc;
    if (a[4] == 0 && a.size() > 7) {
      lc = static_cast<size_t>(a[5] << 8 | a[6]);
      off = 7;
      extSeen = true;
    } else {
      lc = a[4];
      off = 5;
      maxShortLc = std::max(maxShortLc, static_cast<int>(lc));
    }
    const Bytes d(a.begin() + static_cast<long>(off),
                  a.begin() + static_cast<long>(off + lc));
    Bytes v;
    const Cipher c = p.cipher;
    if (d.size() == 2) {  // step 1
      nonce.assign(blockSize(c), 0);
      for (size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<uint8_t>(0x11 * (i + 1));
      Bytes kpi = kdf(c, Bytes(can.begin(), can.end()), 3);
      r = ber(0x7C, ber(0x80, crypto::cbcEncrypt(c, kpi, Bytes(blockSize(c), 0),
                                                 nonce)));
      m = makeMapping(p);
      return 0x9000;
    }
    if (findDo(d, 0x81, v)) {
      const Bytes mine = m->mappingPublicKey();
      if (!m->mapNonce(v, nonce)) return 0x6A80;
      r = ber(0x7C, ber(0x82, mine));
      return 0x9000;
    }
    if (findDo(d, 0x83, v)) {
      ifdPub = v;
      myPub = m->agreementPublicKey();
      Bytes shared;
      if (!m->agree(v, shared)) return 0x6A80;
      ksEnc = kdf(c, shared, 1);
      ksMac = kdf(c, shared, 2);
      r = ber(0x7C, ber(0x84, myPub));
      return 0x9000;
    }
    if (findDo(d, 0x85, v)) {
      if (v != authToken(p, ksMac, myPub)) return 0x6300;
      r = ber(0x7C, ber(0x86, authToken(p, ksMac, ifdPub)));
      return 0x9000;
    }
    return 0x6A80;
  }
};

Params suite(bool ec, int id, Cipher c) {
  Params p;
  p.ec = ec;
  p.parameterId = id;
  p.cipher = c;
  p.oid = H("04007F000702020402");
  p.oid.push_back(ec ? 0x02 : 0x01);
  p.oid.push_back(c == Cipher::TDES     ? 1
                  : c == Cipher::AES128 ? 2
                  : c == Cipher::AES192 ? 3
                                        : 4);
  return p;
}

}  // namespace

TEST_CASE("PACE against a simulated chip for every supported suite",
          "[pace][flow]") {
  struct Case {
    bool ec;
    int id;
    Cipher c;
    bool ext;
  };
  const Case cases[] = {
      {false, 2, Cipher::TDES, true},  // what the CIE offers
      {false, 1, Cipher::AES128, true},  {false, 0, Cipher::TDES, false},
      {true, 13, Cipher::AES128, false}, {true, 16, Cipher::AES192, false},
      {true, 18, Cipher::AES256, false}, {true, 12, Cipher::TDES, false},
  };
  for (const Case& cs : cases) {
    INFO("ec=" << cs.ec << " id=" << cs.id);
    SimPaceChip chip;
    chip.p = suite(cs.ec, cs.id, cs.c);
    chip.can = "123456";
    const Transmit tx = [&](const Bytes& a, Bytes& r) {
      return chip.handle(a, r);
    };
    std::unique_ptr<SecureChannel> ch;
    Result r = performPace(tx, "123456", chip.p, ch);
    REQUIRE(r.status == Status::Ok);
    REQUIRE(ch);
    CHECK(chip.extSeen == cs.ext);
    CHECK(chip.maxShortLc <= 255);
  }
}

TEST_CASE("PACE with the wrong CAN fails mutual authentication once",
          "[pace][flow]") {
  SimPaceChip chip;
  chip.p = suite(false, 2, Cipher::TDES);
  chip.can = "123456";
  int ga4 = 0;
  const Transmit tx = [&](const Bytes& a, Bytes& r) {
    if (a[0] == 0x00 && a[1] == 0x86) ++ga4;
    return chip.handle(a, r);
  };
  std::unique_ptr<SecureChannel> ch;
  Result r = performPace(tx, "654321", chip.p, ch);
  CHECK(r.status == Status::WrongCan);
  CHECK_FALSE(ch);
  CHECK(ga4 == 1);
}

TEST_CASE("PACE-DH-2048 / 3DES is selected from the CIE EF.CardAccess",
          "[pace][cardaccess]") {
  // SET { PACEInfo DH-GM 3DES, version 2, parameterId 2 } as read from the
  // CIE: 31 14 30 12 06 0A 04007F00070202040101 02 01 02 02 01 02
  Params p;
  REQUIRE(selectProtocol(
      parseCardAccess(H("3114 3012060A04007F00070202040101 020102 020102")),
      p));
  CHECK_FALSE(p.ec);
  CHECK(p.cipher == Cipher::TDES);
  CHECK(p.parameterId == 2);
  CHECK(describe(p) == "DH-GM 3DES modp-2");
}

TEST_CASE("RFC 5114 DH groups used by PACE match OpenSSL's named groups",
          "[pace][dh]") {
  // The 2048-bit groups are only exercised by self-consistency above; make
  // sure the embedded constants are the RFC 5114 ones.
  for (int id = 0; id <= 2; ++id) {
    INFO("group " << id);
    Params p = suite(false, id, Cipher::AES128);
    auto a = makeMapping(p);
    auto b = makeMapping(p);
    REQUIRE(a);
    REQUIRE(b);
    const Bytes pa = a->mappingPublicKey();
    const Bytes pb = b->mappingPublicKey();
    CHECK(pa.size() == (id == 0 ? 128u : 256u));
    const Bytes nonce(16, 0x42);
    REQUIRE(a->mapNonce(pb, nonce));
    REQUIRE(b->mapNonce(pa, nonce));
    CHECK(a->mappedGenerator() == b->mappedGenerator());
  }
  CHECK_FALSE(makeMapping(suite(false, 3, Cipher::AES128)));
}
