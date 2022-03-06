// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "properties.h"

#include <cstdlib>
#include <ctime>

#include "text_file_reader.h"

#define TZSET tzset

#define SAFEDELETE(pointer) \
  try {                     \
    if (pointer) {          \
      delete pointer;       \
      pointer = nullptr;       \
    }                       \
  } catch (...) {           \
  }

// Construction/Destruction
#define MAX_ALLOC_SIZE 512

UUCProperties::UUCProperties() {
  m_pStringTable = new UUCStringTable();
  m_bAllocated = true;
}

UUCProperties::UUCProperties(const UUCProperties& defaults)
    : m_pStringTable(defaults.m_pStringTable) {
  m_bAllocated = false;
}

UUCProperties::~UUCProperties() {
  if (m_bAllocated) SAFEDELETE(m_pStringTable);

  m_pStringTable = nullptr;
}

long UUCProperties::load(const char* szFilePath) {
  try {
    UUCTextFileReader textFileReader(szFilePath);

    char* szName;
    char* szValue;

    long nEOF = -1;

    UUCByteArray line;
    long nRes = textFileReader.readLine(line);

    char* szLine = (char*)line.getContent();

    while (nRes != nEOF) {
      if (szLine[0] != '#' && szLine[0] != '[') {  // salta i commenti
        szName = strtok(szLine, "=");
        szValue = strtok(nullptr, "\n");
        putProperty(szName, szValue);
      }

      line.removeAll();
      nRes = textFileReader.readLine(line);
      szLine = (char*)line.getContent();
    }
  } catch (long nErr) {
    return nErr;
  } catch (...) {
    return -1;
  }

  return 0;
}

long UUCProperties::load(const UUCByteArray& props) {
  char* szName;
  char* szValue;
  char* szEqual;
  char* szProps = (char*)props.getContent();
  char* szLine = strtok(szProps, "\r\n");

  while (szLine) {
    if (szLine[0] != '#' && szLine[0] != '[') {  // salta i commenti
      szEqual = strstr(szLine, "=");
      szEqual[0] = 0;
      szName = szLine;
      szValue = szEqual + 1;
      putProperty(szName, szValue);
      szLine = strtok(nullptr, "\r\n");
    } else {
      szLine = strtok(nullptr, "\r\n");  // strlen(szLine) + 1;
      // szProps += strlen(szLine) + 1;
    }
  }

  return 0;
}

int UUCProperties::getIntProperty(const char* szName,
                                  int nDefaultValue /*= nullptr*/) const {
  const char* szVal = getProperty(szName, nullptr);
  if (szVal)
    return strtol(szVal, nullptr, 10);
  else
    return nDefaultValue;
}

const char* UUCProperties::getProperty(
    const char* szName, const char* szDefaultValue /*= nullptr*/) const {
  char* szValue;
  char* szName1 = const_cast<char*>(szName);
  if (m_pStringTable->containsKey(szName1)) {
    m_pStringTable->get(szName1, szValue);
    return szValue;
  } else {
    return szDefaultValue;
  }
}

void UUCProperties::putProperty(const char* szName, const char* szValue) {
  m_pStringTable->put(const_cast<char*>(szName), const_cast<char*>(szValue));
}

UUCStringTable* UUCProperties::getPropertyTable() const {
  return m_pStringTable;
}

bool UUCProperties::contains(const char* szName) const {
  return m_pStringTable->containsKey(const_cast<char*>(szName));
}

void UUCProperties::remove(const char* szName) {
  m_pStringTable->remove(const_cast<char*>(szName));
}

void UUCProperties::removeAll() { m_pStringTable->removeAll(); }

int UUCProperties::size() const { return m_pStringTable->size(); }
