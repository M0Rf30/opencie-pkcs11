// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "properties.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

Properties::Properties() = default;

Properties::Properties(const Properties& defaults)
    : m_properties(defaults.m_properties) {}

Properties::~Properties() = default;

long Properties::load(const char* szFilePath) {
  try {
    std::ifstream file(szFilePath);
    if (!file.is_open()) {
      return -1;  // File could not be opened
    }

    std::string line;
    while (std::getline(file, line)) {
      // Skip empty lines, comments (#), and sections ([])
      if (line.empty() || line[0] == '#' || line[0] == '[') {
        continue;
      }

      // Find the equals sign
      size_t equalPos = line.find('=');
      if (equalPos == std::string::npos) {
        continue;  // No equals sign, skip line
      }

      // Extract name and value
      std::string name = line.substr(0, equalPos);
      std::string value = line.substr(equalPos + 1);

      // Trim whitespace from name and value
      name.erase(0, name.find_first_not_of(" \t\r\n"));
      name.erase(name.find_last_not_of(" \t\r\n") + 1);
      value.erase(0, value.find_first_not_of(" \t\r\n"));
      value.erase(value.find_last_not_of(" \t\r\n") + 1);

      if (!name.empty()) {
        m_properties[name] = value;
      }
    }
  } catch (...) {
    return -1;
  }

  return 0;
}

long Properties::load(const ByteDynArray& props) {
  try {
    // Convert ByteDynArray to string
    std::string content(reinterpret_cast<const char*>(props.data()),
                        props.size());
    std::istringstream stream(content);

    std::string line;
    while (std::getline(stream, line)) {
      // Skip empty lines, comments (#), and sections ([])
      if (line.empty() || line[0] == '#' || line[0] == '[') {
        continue;
      }

      // Find the equals sign
      size_t equalPos = line.find('=');
      if (equalPos == std::string::npos) {
        continue;  // No equals sign, skip line
      }

      // Extract name and value
      std::string name = line.substr(0, equalPos);
      std::string value = line.substr(equalPos + 1);

      // Trim whitespace from name and value
      name.erase(0, name.find_first_not_of(" \t\r\n"));
      name.erase(name.find_last_not_of(" \t\r\n") + 1);
      value.erase(0, value.find_first_not_of(" \t\r\n"));
      value.erase(value.find_last_not_of(" \t\r\n") + 1);

      if (!name.empty()) {
        m_properties[name] = value;
      }
    }
  } catch (...) {
    return -1;
  }

  return 0;
}

void Properties::putProperty(const char* szName, const char* szValue) {
  if (szName && szValue) {
    m_properties[std::string(szName)] = std::string(szValue);
  }
}

const char* Properties::getProperty(const char* szName,
                                    const char* szDefaultValue) const {
  if (!szName) {
    return szDefaultValue;
  }

  auto it = m_properties.find(std::string(szName));
  if (it != m_properties.end()) {
    // Store result in mutable member to return const char*
    m_tempResult = it->second;
    return m_tempResult.c_str();
  }

  return szDefaultValue;
}

int Properties::getIntProperty(const char* szName, int nDefaultValue) const {
  const char* szValue = getProperty(szName, nullptr);
  if (szValue) {
    return static_cast<int>(strtol(szValue, nullptr, 10));
  }
  return nDefaultValue;
}

void Properties::remove(const char* szName) {
  if (szName) {
    m_properties.erase(std::string(szName));
  }
}

void Properties::removeAll() { m_properties.clear(); }

bool Properties::contains(const char* szName) const {
  if (!szName) {
    return false;
  }
  return m_properties.find(std::string(szName)) != m_properties.end();
}

int Properties::size() const { return static_cast<int>(m_properties.size()); }