// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "m7m_parser.h"

#include <algorithm>
#include <cstdlib>
#include <string>
#include <string_view>

#include "crypto/base64.h"

namespace {
// Bounded substring search over [hay, hay+len): the input is a binary
// buffer without a NUL terminator, so strstr/strlen must not be used.
const char* findIn(const char* hay, size_t len, std::string_view needle) {
  if (needle.size() > len) return nullptr;
  const char* const e = hay + len;
  const char* it = std::search(hay, e, needle.begin(), needle.end());
  return it == e ? nullptr : it;
}
}  // namespace

M7MParser::M7MParser() {}

int M7MParser::Load(const char* m7m, int m7mlen) {
  if (m7m == nullptr || m7mlen <= 0) return -1;
  const char* const fileEnd = m7m + m7mlen;

  const char* begin = findIn(m7m, m7mlen, "boundary=\"");
  if (begin == nullptr) return -1;
  begin += 10;

  const char* end = findIn(begin, fileEnd - begin, "\"");
  if (end == nullptr) return -1;

  const std::string boundary = "--" + std::string(begin, end);
  const size_t boundaryLen = boundary.size();

  // Part 1 lies between the first and the second boundary, part 2 between the
  // second and the third.
  const char* b1 = findIn(m7m, m7mlen, boundary);
  if (b1 == nullptr) return -1;
  const char* firstPart = b1 + boundaryLen;

  const char* b2 = findIn(firstPart, fileEnd - firstPart, boundary);
  if (b2 == nullptr) return -1;
  const char* firstEnd = b2;

  const char* secondPart = b2 + boundaryLen;
  const char* b3 = findIn(secondPart, fileEnd - secondPart, boundary);
  if (b3 == nullptr) return -1;
  const char* secondEnd = b3;

  auto addPart = [this](const char* part, const char* partEnd) -> bool {
    static constexpr std::string_view kSep = "\r\n\r\n";
    const char* body = findIn(part, partEnd - part, kSep);
    if (body == nullptr) return false;
    const std::string_view headers(part, body - part);
    body += kSep.size();
    const size_t bodyLen = partEnd - body;
    if (headers.find("pkcs7-mime") != std::string_view::npos)
      m_p7m.append(ByteArray(reinterpret_cast<const BYTE*>(body), bodyLen));
    else if (headers.find("timestamp") != std::string_view::npos)
      m_tsr.append(ByteArray(reinterpret_cast<const BYTE*>(body), bodyLen));
    return true;
  };

  if (!addPart(firstPart, firstEnd)) return -1;
  if (!addPart(secondPart, secondEnd)) return -1;

  return 0;
}

int M7MParser::GetP7M(ByteDynArray& p7m) {
  p7m.append(m_p7m);
  return 0;
}

int M7MParser::GetTSR(ByteDynArray& tsr) {
  if (m_tsr.size() == 0) return -1;
  if (m_tsr.data()[0] != 0x30) {
    std::string encoded(reinterpret_cast<const char*>(m_tsr.data()),
                        static_cast<size_t>(m_tsr.size()));
    encoded.erase(std::remove_if(encoded.begin(), encoded.end(),
                                 [](char c) { return c == '\r' || c == '\n'; }),
                  encoded.end());

    ByteDynArray decoded;
    CBase64().Decode(encoded.c_str(), decoded);

    tsr.append(ByteArray(decoded.data(), decoded.size()));
  } else {
    tsr.append(m_tsr);
  }

  return 0;
}
