// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "string_table.h"

#include <cstdlib>
#include <cstring>

#include <string>

// Construction/Destruction

UUCStringTable::UUCStringTable(int initialCapacity, float loadFactor)
    : UUCHashtable<char*, char*>(initialCapacity, loadFactor) {}

UUCStringTable::UUCStringTable(int initialCapacity)
    : UUCHashtable<char*, char*>(initialCapacity) {}

UUCStringTable::UUCStringTable() {}

UUCStringTable::~UUCStringTable() { removeAll(); }

void UUCStringTable::put(char* const& szKey, char* const& szValue) {
  char* szOldValue = nullptr;
  char* szOldKey = szKey;

  if (containsKey(szKey)) {
    get(szOldKey, szOldValue);
  } else {
    szOldKey = nullptr;
  }

  std::string sNewValue(szValue);
  std::string sNewKey(szKey);

  UUCHashtable<char*, char*>::put(const_cast<char*>(sNewKey.c_str()),
                                  const_cast<char*>(sNewValue.c_str()));

  if (szOldKey) delete szOldKey;
  if (szOldValue) delete szOldValue;
}

unsigned long UUCStringTable::getHashValue(char* const& szKey) const {
  return UUCStringTable::getHash((const char*)szKey);
}

unsigned long UUCStringTable::getHash(const char* szKey) {
  int h = 0;
  int off = 0;
  char* val = const_cast<char*>(szKey);
  std::string sKey(szKey);
  size_t len = sKey.size();

  if (len < 16) {
    for (unsigned long i = len; i > 0; i--) {
      h = (h * 37) + val[off++];
    }
  } else {
    // only sample some characters
    unsigned long skip = len / 8;
    for (int i = len; i > 0; i -= skip, off += skip) {
      h = (h * 39) + val[off];
    }
  }

  return h;
}

bool UUCStringTable::equal(char* const& szKey1, char* const& szKey2) const {
  return strcmp(szKey1, szKey2) == 0;
}

bool UUCStringTable::remove(char* const& szKey) {
  char* szNewValue;

  char* szNewKey = szKey;
  ;

  if (containsKey(szKey)) {
    get(szNewKey, szNewValue);

    UUCHashtable<char*, char*>::remove(szNewKey);

    delete szNewKey;
    delete szNewValue;
    return true;
  }

  return false;
}
