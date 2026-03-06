// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file ini_settings.h
 * @brief INI file settings parser with typed accessors.
 *
 * Provides a family of classes for reading typed configuration values
 * (int, string, bool, byte array, base64) from INI-format files,
 * with support for default values and self-registration.
 */

#pragma once
#include <string>
#include <vector>

#include "util/array.h"
#include "util/definitions.h"

class IniSettings;

/** @brief Global registry of all INI setting definitions. */
extern std::vector<IniSettings*> _iniSettings;

/**
 * @brief Base class for a single INI file setting.
 *
 * Each instance represents one configuration key within a section
 * and is auto-registered in the global _iniSettings list.
 */
class IniSettings {
 public:
  int typeId; /**< Type identifier for the setting (int, string, etc.). */
  std::string section;     /**< INI section name (e.g. "[General]"). */
  std::string name;        /**< Key name within the section. */
  std::string description; /**< Human-readable description of the setting. */

  /**
   * @brief Construct a setting definition.
   * @param typeId Type identifier.
   * @param section INI section name.
   * @param name Key name.
   * @param description Human-readable description.
   */
  IniSettings(int typeId, const char* section, const char* name,
              const char* description);

  /**
   * @brief Get the type identifier.
   * @return Type ID value.
   */
  int GetTypeId();

  /** @brief Virtual destructor. */
  virtual ~IniSettings();
};

/**
 * @brief INI setting with integer value type.
 */
class IniSettingsInt : public IniSettings {
 public:
  int defaultVal; /**< Default value if key is absent. */

  /**
   * @brief Construct an integer setting.
   * @param section INI section name.
   * @param name Key name.
   * @param defaultValue Default integer value.
   * @param description Human-readable description.
   */
  IniSettingsInt(const char* section, const char* name, int defaultValue,
                 const char* description);
  ~IniSettingsInt();

  /**
   * @brief Read the integer value from an INI file.
   * @param fileName Path to the INI file.
   * @return The integer value, or defaultVal if not found.
   */
  int GetValue(const char* fileName);
};

/**
 * @brief INI setting with string value type.
 */
class IniSettingsString : public IniSettings {
 public:
  std::string defaultVal; /**< Default value if key is absent. */

  /**
   * @brief Construct a string setting.
   * @param section INI section name.
   * @param name Key name.
   * @param defaultValue Default string value.
   * @param description Human-readable description.
   */
  IniSettingsString(const char* section, const char* name,
                    const char* defaultValue, const char* description);
  ~IniSettingsString();

  /**
   * @brief Read the string value from an INI file.
   * @param fileName Path to the INI file.
   * @param[out] value Receives the string value.
   */
  void GetValue(const char* fileName, std::string& value);
};

/**
 * @brief INI setting with boolean value type.
 */
class IniSettingsBool : public IniSettings {
 public:
  bool defaultVal; /**< Default value if key is absent. */

  /**
   * @brief Construct a boolean setting.
   * @param section INI section name.
   * @param name Key name.
   * @param defaultValue Default boolean value.
   * @param description Human-readable description.
   */
  IniSettingsBool(const char* section, const char* name, bool defaultValue,
                  const char* description);
  ~IniSettingsBool();

  /**
   * @brief Read the boolean value from an INI file.
   * @param fileName Path to the INI file.
   * @return The boolean value, or defaultVal if not found.
   */
  bool GetValue(const char* fileName);
};

/**
 * @brief INI setting with raw byte array value type.
 */
class IniSettingsByteArray : public IniSettings {
 public:
  ByteDynArray defaultVal; /**< Default value if key is absent. */

  /**
   * @brief Construct a byte array setting.
   * @param section INI section name.
   * @param name Key name.
   * @param defaultValue Default byte array value.
   * @param description Human-readable description.
   */
  IniSettingsByteArray(const char* section, const char* name,
                       ByteArray defaultValue, const char* description);
  ~IniSettingsByteArray();

  /**
   * @brief Read the byte array value from an INI file.
   * @param fileName Path to the INI file.
   * @param[out] value Receives the byte array value.
   */
  void GetValue(const char* fileName, ByteDynArray& value);
};

/**
 * @brief INI setting with Base64-encoded byte array value type.
 */
class IniSettingsB64 : public IniSettings {
 public:
  ByteDynArray defaultVal; /**< Default value if key is absent. */

  /**
   * @brief Construct a Base64 setting from a raw byte array default.
   * @param section INI section name.
   * @param name Key name.
   * @param defaultValue Default byte array value.
   * @param description Human-readable description.
   */
  IniSettingsB64(const char* section, const char* name, ByteArray defaultValue,
                 const char* description);

  /**
   * @brief Construct a Base64 setting from a Base64-encoded string default.
   * @param section INI section name.
   * @param name Key name.
   * @param defaultValueB64 Default value as a Base64-encoded string.
   * @param description Human-readable description.
   */
  IniSettingsB64(const char* section, const char* name,
                 const char* defaultValueB64, const char* description);
  ~IniSettingsB64();

  /**
   * @brief Read the Base64-decoded byte array value from an INI file.
   * @param fileName Path to the INI file.
   * @param[out] value Receives the decoded byte array value.
   */
  void GetValue(const char* fileName, ByteDynArray& value);
};

extern "C" {
/**
 * @brief Get the total number of registered INI settings.
 * @return Number of settings in the global registry.
 */
int GetNumIniSettings();

/**
 * @brief Retrieve INI setting information by index.
 * @param i Zero-based index of the setting.
 * @param data Output buffer to receive the setting data.
 * @return 0 on success, non-zero on failure.
 */
int GetIniSettings(int i, void* data);
}
