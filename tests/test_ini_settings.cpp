// SPDX-License-Identifier: LGPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string>
#include <vector>

#include "util/array.h"
#include "util/ini_settings.h"

// The global registry accumulates across all tests. Each TEST_CASE that
// checks GetNumIniSettings() clears it first.

// ── IniSettingsInt
// ────────────────────────────────────────────────────────────

TEST_CASE("IniSettingsInt stores fields and returns default", "[ini]") {
  _iniSettings.clear();
  IniSettingsInt s("General", "Timeout", 30, "Connection timeout");
  CHECK(s.GetTypeId() == 0);
  CHECK(s.section == "General");
  CHECK(s.name == "Timeout");
  CHECK(s.description == "Connection timeout");
  CHECK(s.defaultVal == 30);
  // GetValue always returns defaultVal (file reading is stubbed)
  CHECK(s.GetValue("any.ini") == 30);
}

TEST_CASE("IniSettingsInt registers in global list", "[ini]") {
  _iniSettings.clear();
  IniSettingsInt s("S", "N", 0, "D");
  CHECK(GetNumIniSettings() == 1);
  CHECK(_iniSettings[0] == &s);
}

// ── IniSettingsBool
// ───────────────────────────────────────────────────────────

TEST_CASE("IniSettingsBool stores fields and returns default", "[ini]") {
  _iniSettings.clear();
  IniSettingsBool s("Flags", "Enabled", true, "Enable feature");
  CHECK(s.GetTypeId() == 2);
  CHECK(s.section == "Flags");
  CHECK(s.name == "Enabled");
  CHECK(s.defaultVal == true);
  CHECK(s.GetValue("any.ini") == true);

  IniSettingsBool s2("Flags", "Debug", false, "Debug mode");
  CHECK(s2.GetValue("any.ini") == false);
}

// ── IniSettingsString
// ─────────────────────────────────────────────────────────

TEST_CASE("IniSettingsString stores fields", "[ini]") {
  _iniSettings.clear();
  IniSettingsString s("Network", "Host", "localhost", "Server hostname");
  CHECK(s.GetTypeId() == 1);
  CHECK(s.section == "Network");
  CHECK(s.name == "Host");
  CHECK(s.defaultVal == "localhost");
}

TEST_CASE("IniSettingsString GetValue falls back to default when stub is null",
          "[ini]") {
  // GetIniString stub resizes buf to 100 null chars; c_str()[0]==0 triggers
  // the fallback to defaultVal.
  _iniSettings.clear();
  IniSettingsString s("S", "K", "default", "D");
  std::string val;
  s.GetValue("any.ini", val);
  CHECK(val == "default");
}

// ── IniSettingsByteArray
// ──────────────────────────────────────────────────────

TEST_CASE("IniSettingsByteArray stores fields", "[ini]") {
  _iniSettings.clear();
  const uint8_t raw[] = {0xDE, 0xAD};
  ByteArray def(raw, 2);
  IniSettingsByteArray s("Crypto", "Key", def, "Crypto key");
  CHECK(s.GetTypeId() == 3);
  CHECK(s.section == "Crypto");
  CHECK(s.name == "Key");
  REQUIRE(s.defaultVal.size() == 2);
  CHECK(s.defaultVal[0] == 0xDE);
  CHECK(s.defaultVal[1] == 0xAD);
}

// ── IniSettingsB64
// ────────────────────────────────────────────────────────────

TEST_CASE("IniSettingsB64 from ByteArray default stores correctly", "[ini]") {
  _iniSettings.clear();
  const uint8_t raw[] = {0x01, 0x02, 0x03};
  ByteArray def(raw, 3);
  IniSettingsB64 s("Crypto", "Token", def, "Auth token");
  CHECK(s.GetTypeId() == 4);
  REQUIRE(s.defaultVal.size() == 3);
  CHECK(s.defaultVal[0] == 0x01);
  CHECK(s.defaultVal[1] == 0x02);
  CHECK(s.defaultVal[2] == 0x03);
}

TEST_CASE("IniSettingsB64 from base64 string default decodes correctly",
          "[ini]") {
  // base64("AQID") = {0x01, 0x02, 0x03}
  _iniSettings.clear();
  IniSettingsB64 s("Crypto", "Token", "AQID", "Auth token");
  CHECK(s.GetTypeId() == 4);
  REQUIRE(s.defaultVal.size() == 3);
  CHECK(s.defaultVal[0] == 0x01);
  CHECK(s.defaultVal[1] == 0x02);
  CHECK(s.defaultVal[2] == 0x03);
}

// ── GetNumIniSettings / GetIniSettings
// ────────────────────────────────────────

TEST_CASE("GetNumIniSettings reflects registered count", "[ini]") {
  _iniSettings.clear();
  CHECK(GetNumIniSettings() == 0);
  IniSettingsInt a("S", "A", 1, "DA");
  CHECK(GetNumIniSettings() == 1);
  IniSettingsBool b("S", "B", false, "DB");
  CHECK(GetNumIniSettings() == 2);
}

TEST_CASE("GetIniSettings serializes int setting correctly", "[ini]") {
  _iniSettings.clear();
  IniSettingsInt s("MySection", "MyKey", 99, "My description");

  // First call with nullptr returns required size
  int sz = GetIniSettings(0, nullptr);
  REQUIRE(sz > 0);

  std::string buf(sz, '\0');
  int sz2 = GetIniSettings(0, buf.data());
  CHECK(sz2 == sz);

  // Format: "section|name|description|typeId|defaultVal"
  // typeId=0, defaultVal stored as int (char value 99 = 'c')
  CHECK(buf.find("MySection") != std::string::npos);
  CHECK(buf.find("MyKey") != std::string::npos);
  CHECK(buf.find("My description") != std::string::npos);
  CHECK(buf.find("|0|") != std::string::npos);
}

TEST_CASE("GetIniSettings serializes string setting correctly", "[ini]") {
  _iniSettings.clear();
  IniSettingsString s("Sec", "Key", "hello", "Desc");

  int sz = GetIniSettings(0, nullptr);
  REQUIRE(sz > 0);
  std::string buf(sz, '\0');
  GetIniSettings(0, buf.data());

  CHECK(buf.find("Sec") != std::string::npos);
  CHECK(buf.find("Key") != std::string::npos);
  CHECK(buf.find("|1|") != std::string::npos);
  CHECK(buf.find("hello") != std::string::npos);
}
