// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "m7m_parser.h"

#include "crypto/base64.h"

#include <algorithm>
#include <cstdlib>
char* find(const char* szContent, int len, char* szSubstr);

M7MParser::M7MParser() {}

int M7MParser::Load(const char* m7m, int m7mlen) {
  int len = m7mlen;

  const char* begin = strstr(m7m, "boundary=\"");
  if (begin == nullptr) return -1;

  const char* end = strstr(begin + 10, "\"");
  if (end == nullptr) return -1;

  UUCByteArray boundary;
  boundary.append(reinterpret_cast<const BYTE*>("--"), 2);
  boundary.append(reinterpret_cast<const BYTE*>(begin) + 10, (end - begin - 10));

  char* szBoundary = const_cast<char*>(reinterpret_cast<const char*>(boundary.getContent()));
  int boundadyLen = boundary.getLength();
  szBoundary[boundadyLen] = 0;

  begin = find(m7m, len, szBoundary);
  if (begin == nullptr) return -1;

  begin += boundadyLen;

  len = m7mlen - (begin - m7m);

  end = find(begin, len, szBoundary);
  if (end == nullptr) return -1;

  const char* firstPart = begin;
  int firstPartLen = end - begin;

  len = m7mlen - (end - m7m);

  begin = find(end, len, szBoundary);
  if (begin == nullptr) return -1;

  begin += boundadyLen;

  len = m7mlen - (begin - m7m);

  end = find(begin + boundadyLen, len, szBoundary);
  if (end == nullptr) return -1;

  char* secondPart = const_cast<char*>(begin);
  int secondPartLen = end - begin;

  const char* toFind = "\r\n\r\n";

  begin = strstr(firstPart, toFind);
  if (begin == nullptr) return -1;

  begin += strlen(toFind);
  char* szContent = const_cast<char*>(begin);
  int contentLen = firstPartLen - strlen(toFind);

  if (strstr(firstPart, "pkcs7-mime") != nullptr)
    m_p7m.append(reinterpret_cast<BYTE*>(szContent), contentLen);
  else if (strstr(firstPart, "timestamp") != nullptr)
    m_tsr.append(reinterpret_cast<BYTE*>(szContent), contentLen);

  end = 0;
  begin = strstr(secondPart, toFind);
  if (begin == nullptr) return -1;

  end = secondPart + secondPartLen;
  begin += strlen(toFind);

  szContent = const_cast<char*>(begin);
  contentLen = end - begin;

  if (strstr(secondPart, "pkcs7-mime") != nullptr)
    m_p7m.append(reinterpret_cast<BYTE*>(szContent), contentLen);
  else if (strstr(secondPart, "timestamp") != nullptr)
    m_tsr.append(reinterpret_cast<BYTE*>(szContent), contentLen);

  return 0;
}

int M7MParser::GetP7M(UUCByteArray& p7m) {
  p7m.append(m_p7m);
  return 0;
}

int M7MParser::GetTSR(UUCByteArray& tsr) {
  if (m_tsr.getContent()[0] != 0x30) {
    std::string encoded(reinterpret_cast<const char*>(m_tsr.getContent()),
                        static_cast<size_t>(m_tsr.getLength()));
    encoded.erase(std::remove_if(encoded.begin(), encoded.end(),
                                 [](char c) { return c == '\r' || c == '\n'; }),
                  encoded.end());

    ByteDynArray decoded;
    CBase64().Decode(encoded.c_str(), decoded);

    tsr.append(decoded.data(), decoded.size());
  } else {
    tsr.append(m_tsr);
  }

  return 0;
}

char* find(const char* szContent, int len, char* szSubstr) {
  int substrlen = strlen(szSubstr);

  for (int i = 0; i < len - substrlen; i++) {
    if (memcmp(szContent + i, szSubstr, substrlen) == 0)
      return const_cast<char*>(szContent + i);
  }

  return nullptr;
}
