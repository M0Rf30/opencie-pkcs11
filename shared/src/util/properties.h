// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file properties.h
 * @brief Key-value property/configuration management.
 *
 * Provides the Properties class for loading, storing, and querying
 * string and integer configuration properties from files or byte arrays.
 */

#pragma once

#include <string>
#include <unordered_map>

#include "array.h"

/**
 * @brief Key-value property store for configuration data.
 *
 * Supports loading properties from files or byte arrays and provides
 * typed accessors with default values.
 */
class Properties {
 public:
  /** @brief Default constructor. Creates an empty property store. */
  Properties();

  /**
   * @brief Copy constructor. Copies all properties from another store.
   * @param defaults Source property store to copy from.
   */
  Properties(const Properties& defaults);

  /** @brief Virtual destructor. */
  virtual ~Properties();

  /**
   * @brief Load properties from a file.
   * @param szFilePath Path to the properties file.
   * @return 0 on success, non-zero on failure.
   */
  long load(const char* szFilePath);

  /**
   * @brief Load properties from a byte array.
   * @param props Byte array containing property data.
   * @return 0 on success, non-zero on failure.
   */
  long load(const ByteDynArray& props);

  /**
   * @brief Set a property value.
   * @param szName Property key name.
   * @param szValue Property value string.
   */
  void putProperty(const char* szName, const char* szValue);

  /**
   * @brief Retrieve a string property value.
   * @param szName Property key name.
   * @param szDefaultValue Value returned if the key is not found.
   * @return The property value, or szDefaultValue if not found.
   */
  const char* getProperty(const char* szName,
                          const char* szDefaultValue = nullptr) const;

  /**
   * @brief Retrieve an integer property value.
   * @param szName Property key name.
   * @param nDefaultValue Value returned if the key is not found.
   * @return The integer property value, or nDefaultValue if not found.
   */
  int getIntProperty(const char* szName, int nDefaultValue = 0) const;

  /**
   * @brief Remove a property by key.
   * @param szName Property key name to remove.
   */
  void remove(const char* szName);

  /** @brief Remove all properties from the store. */
  void removeAll();

  /**
   * @brief Check whether a property exists.
   * @param szName Property key name.
   * @return true if the key exists, false otherwise.
   */
  bool contains(const char* szName) const;

  /**
   * @brief Get the number of stored properties.
   * @return Number of key-value pairs.
   */
  int size() const;

 private:
  std::unordered_map<std::string, std::string> m_properties;
  mutable std::string m_tempResult; /**< Temporary buffer for returning const
                                       char* from getProperty. */
};
