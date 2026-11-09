// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <string>

#include "asn1/asn1_object.h"
#include "asn1/name.h"
#include "util/array.h"

namespace {
// Name ::= SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (CN), UTF8String v } } }
CName makeName(const std::string& v) {
  std::string utf8 = std::string("\x0C", 1) + char(v.size()) + v;
  std::string atv = std::string("\x06\x03\x55\x04\x03", 5) + utf8;
  std::string seq = std::string("\x30", 1) + char(atv.size()) + atv;
  std::string set = std::string("\x31", 1) + char(seq.size()) + seq;
  std::string name = std::string("\x30", 1) + char(set.size()) + set;
  ByteDynArray der(
      ByteArray(reinterpret_cast<const BYTE*>(name.data()), name.size()));
  return CName(CASN1Object(der));
}
std::string dn(CName n) {
  ByteDynArray out;
  n.getNameAsString(out);
  return std::string(reinterpret_cast<const char*>(out.data()));
}
}  // namespace

TEST_CASE("CName::getNameAsString escapes RDN delimiters") {
  CHECK(dn(makeName("a,O=evil")).find("a\\,O\\=evil") != std::string::npos);
}

TEST_CASE("CName::getNameAsString does not truncate at an embedded NUL") {
  const std::string v("victim\0.evil", 12);
  const std::string out = dn(makeName(v));
  CHECK(out.find("victim\\00.evil") != std::string::npos);
}

TEST_CASE("CName::getField keeps text after an embedded NUL visible") {
  const std::string v("victim\0.evil", 12);
  CHECK(makeName(v).getField("2.5.4.3") == "victim\\00.evil");
}
