// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <fstream>
#include <string>

#include "util/array.h"
#include "util/properties.h"

static ByteDynArray strToBDA(const std::string& s) {
  ByteDynArray ba(s.size());
  std::memcpy(ba.data(), s.data(), s.size());
  return ba;
}

// ── Construction
// ──────────────────────────────────────────────────────────────

TEST_CASE("Properties default constructor is empty", "[properties]") {
  Properties p;
  CHECK(p.size() == 0);
}

TEST_CASE("Properties copy constructor copies entries", "[properties]") {
  Properties src;
  src.putProperty("key", "value");
  Properties dst(src);
  REQUIRE(dst.size() == 1);
  CHECK(std::string(dst.getProperty("key")) == "value");
}

// ── putProperty / getProperty
// ─────────────────────────────────────────────────

TEST_CASE("putProperty and getProperty round-trip", "[properties]") {
  Properties p;
  p.putProperty("foo", "bar");
  REQUIRE(p.size() == 1);
  CHECK(std::string(p.getProperty("foo")) == "bar");
}

TEST_CASE("getProperty returns default for missing key", "[properties]") {
  Properties p;
  CHECK(p.getProperty("missing", "def") == std::string("def"));
  CHECK(p.getProperty("missing") == nullptr);
}

TEST_CASE("getProperty with null name returns default", "[properties]") {
  Properties p;
  p.putProperty("x", "1");
  CHECK(p.getProperty(nullptr, "fallback") == std::string("fallback"));
}

TEST_CASE("putProperty with null name or value is no-op", "[properties]") {
  Properties p;
  p.putProperty(nullptr, "v");
  p.putProperty("k", nullptr);
  CHECK(p.size() == 0);
}

TEST_CASE("putProperty overwrites existing key", "[properties]") {
  Properties p;
  p.putProperty("k", "first");
  p.putProperty("k", "second");
  CHECK(std::string(p.getProperty("k")) == "second");
  CHECK(p.size() == 1);
}

// ── getIntProperty
// ────────────────────────────────────────────────────────────

TEST_CASE("getIntProperty parses integer value", "[properties]") {
  Properties p;
  p.putProperty("port", "8080");
  CHECK(p.getIntProperty("port") == 8080);
}

TEST_CASE("getIntProperty returns default for missing key", "[properties]") {
  Properties p;
  CHECK(p.getIntProperty("missing", 42) == 42);
  CHECK(p.getIntProperty("missing") == 0);
}

TEST_CASE("getIntProperty parses negative integer", "[properties]") {
  Properties p;
  p.putProperty("n", "-7");
  CHECK(p.getIntProperty("n") == -7);
}

// ── contains / remove / removeAll ────────────────────────────────────────────

TEST_CASE("contains returns true for existing key", "[properties]") {
  Properties p;
  p.putProperty("a", "1");
  CHECK(p.contains("a") == true);
  CHECK(p.contains("b") == false);
  CHECK(p.contains(nullptr) == false);
}

TEST_CASE("remove deletes existing key", "[properties]") {
  Properties p;
  p.putProperty("a", "1");
  p.putProperty("b", "2");
  p.remove("a");
  CHECK(p.contains("a") == false);
  CHECK(p.contains("b") == true);
  CHECK(p.size() == 1);
}

TEST_CASE("remove with null or missing key is no-op", "[properties]") {
  Properties p;
  p.putProperty("x", "1");
  p.remove(nullptr);
  p.remove("missing");
  CHECK(p.size() == 1);
}

TEST_CASE("removeAll clears all properties", "[properties]") {
  Properties p;
  p.putProperty("a", "1");
  p.putProperty("b", "2");
  p.removeAll();
  CHECK(p.size() == 0);
}

// ── load from ByteDynArray
// ────────────────────────────────────────────────────

TEST_CASE("load from ByteDynArray parses key=value", "[properties]") {
  Properties p;
  ByteDynArray ba = strToBDA("host=localhost\nport=9000\n");
  REQUIRE(p.load(ba) == 0);
  CHECK(std::string(p.getProperty("host")) == "localhost");
  CHECK(p.getIntProperty("port") == 9000);
}

TEST_CASE("load from ByteDynArray skips comments and sections",
          "[properties]") {
  Properties p;
  ByteDynArray ba =
      strToBDA("# comment\n[section]\nkey=val\n\n# another\nother=x\n");
  REQUIRE(p.load(ba) == 0);
  CHECK(p.contains("key") == true);
  CHECK(p.contains("other") == true);
  CHECK(p.contains("section") == false);
  CHECK(p.size() == 2);
}

TEST_CASE("load from ByteDynArray trims whitespace around =", "[properties]") {
  Properties p;
  ByteDynArray ba = strToBDA("  name  =  Alice  \n");
  REQUIRE(p.load(ba) == 0);
  CHECK(std::string(p.getProperty("name")) == "Alice");
}

TEST_CASE("load from ByteDynArray skips lines without =", "[properties]") {
  Properties p;
  ByteDynArray ba = strToBDA("noequals\nkey=val\n");
  REQUIRE(p.load(ba) == 0);
  CHECK(p.size() == 1);
  CHECK(p.contains("key") == true);
}

// ── load from file
// ────────────────────────────────────────────────────────────

TEST_CASE("load from file parses key=value", "[properties]") {
  const char* path = "/tmp/opencode_test_props.properties";
  {
    std::ofstream f(path);
    f << "# comment\n[section]\nfoo=bar\nbaz=42\n";
  }
  Properties p;
  REQUIRE(p.load(path) == 0);
  CHECK(std::string(p.getProperty("foo")) == "bar");
  CHECK(p.getIntProperty("baz") == 42);
  CHECK(p.size() == 2);
}

TEST_CASE("load from nonexistent file returns -1", "[properties]") {
  Properties p;
  CHECK(p.load("/tmp/opencode_no_such_file_xyz.properties") == -1);
}
