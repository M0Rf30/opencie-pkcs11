// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn_parser.h"

#include <algorithm>
#include <limits>
#include <numeric>

#include "util/array.h"

extern CLog Log;

#define BitValue(a, b) ((a >> b) & 1)

namespace {
// Bounds the recursion depth of CASNParser::Parse on nested constructed
// types (SEQUENCE/SET). Each level costs one C++ stack frame; attacker-
// controlled input with deeply nested "30 02" chains would otherwise
// exhaust the stack. RFC 5280 profiles need far fewer than this.
constexpr size_t kMaxAsn1NestingDepth = 32;
}  // namespace

size_t GetASN1DataLenght(const ByteArray &data) {
  if (data.size() == 0) throw logged_error("Excessive length in ASN.1");

  size_t l = 1;
  const uint8_t *cur = data.data();

  size_t len = 0;
  uint8_t curv = cur[0];

  if ((curv & 0x1f) == 0x1f) {
    while (true) {
      l++;
      cur++;
      if (l >= data.size()) throw logged_error("Excessive length in ASN.1");
      curv = cur[0];
      if ((curv & 0x80) != 0x80) break;
    }
  }

  // cur[1] (the length field's first octet) must be within the buffer
  // before it is read.
  if (l >= data.size()) throw logged_error("Excessive length in ASN.1");
  size_t remaining = data.size() - l;

  size_t llen = 0;
  if (cur[1] == 0x80) {
    if (remaining < 2) throw logged_error("Excessive length in ASN.1");
    llen = 1;
    len = data.size() - l - 2;
  } else if (BitValue(cur[1], 7) == 1) {
    llen = (cur[1] & 0x7f);
    // Bounds-check before reading llen more octets, and reject encodings
    // that could not possibly fit in a size_t.
    if (llen > sizeof(size_t) || remaining < llen + 1)
      throw logged_error("Excessive length in ASN.1");
    for (size_t k = 0; k < llen; k++) {
      len <<= 8;
      len |= cur[k + 2];
    }
    llen++;
  } else {
    llen = 1;
    len = cur[1];
  }
  // Compose the result without wrapping: `len` can be attacker-controlled
  // up to SIZE_MAX via the 8-octet long form above.
  size_t header = l + llen;
  if (len > std::numeric_limits<size_t>::max() - header)
    throw logged_error("Excessive length in ASN.1");
  return header + len;
}
bool CASNTag::isSequence() {
  return forcedSequence || ((tag.size() >= 1) && (tag[0] & 0x20) == 0x20);
}

size_t CASNTag::ContentLen() {
  if (!isSequence())
    return content.size();
  else {
    return std::accumulate(
        tags.begin(), tags.end(), size_t(0),
        [](size_t sum, const auto &tag2) { return sum + tag2->EncodeLen(); });
  }
}

size_t CASNTag::tagInt() {
  return std::accumulate(
      tag.begin(), tag.end(), size_t(0),
      [](size_t val, uint8_t byte) { return (val << 8) | byte; });
}

void CASNTag::Reparse() {
  CASNParser parser;
  // For bit strings, skip the unused-bits count byte
  if (tag.size() == 1 && tag[0] == 3) {
    ByteArray input(content.mid(1));
    parser.Parse(input);
  } else
    parser.Parse(content);
  if (parser.tags.size() > 0) {
    forcedSequence = true;
    std::move(parser.tags.begin(), parser.tags.end(), std::back_inserter(tags));
    parser.tags.clear();
    content.clear();
  }
}

size_t CASNTag::EncodeLen() {
  size_t tlen = tag.size();
  size_t clen = ContentLen();
  size_t llen = ASN1LLength(clen);
  return tlen + llen + clen;
}

void CASNTag::Encode(ByteArray &data, size_t &len) {
  int tlen = static_cast<int>(tag.size());
  if (tlen == 1 && tag[0] == 3 && forcedSequence)
    throw logged_error("Bit string reparsed not handled in encode!");
  data.copy(ByteArray(&tag[0], tlen));
  size_t clen = ContentLen();
  size_t llen = ASN1LLength(clen);
  ByteArray input2(data.mid(tlen));
  putASN1Length(clen, input2);

  if (!isSequence()) {
    data.mid(tlen + llen).copy(content);
    len = tlen + llen + clen;
  } else {
    size_t ptrPos = tlen + llen;
    for (const auto &tag2 : tags) {
      size_t taglen;
      ByteArray cur_input(data.mid(ptrPos));
      tag2->Encode(cur_input, taglen);
      ptrPos += taglen;
    }
    len = ptrPos;
  }
}

CASNTag &CASNTag::Child(std::size_t num, uint8_t expectedTag) {
  if (num >= tags.size())
    throw logged_error("ASN.1 structure verification error");
  if (tags[num]->tag.size() == 1 && tags[num]->tag[0] == expectedTag)
    return *tags[num];
  else
    throw logged_error("ASN.1 tag verification error");
}
CASNTag &CASNTag::CheckTag(uint8_t checkTag) {
  if (tag.size() != 1 || tag[0] != checkTag)
    throw logged_error("ASN.1 tag verification error");
  return *this;
}
void CASNTag::Verify(ByteArray checkContent) {
  if (content != checkContent)
    throw logged_error("ASN.1 tag verification error");
}

CASNTag::CASNTag(void) {
  forcedSequence = false;
  startPos = -1;
  endPos = -1;
}

CASNParser::CASNParser(void) {}

size_t CASNParser::CalcLen() {
  return std::accumulate(
      tags.begin(), tags.end(), size_t(0),
      [](size_t sum, const auto &tag) { return sum + tag->EncodeLen(); });
}

void CASNParser::Encode(const ByteArray &data, const CASNTagArray &tags) {
  size_t ptrPos = 0;
  for (const auto &tag : tags) {
    size_t len;
    ByteArray input(data.mid(ptrPos));
    tag->Encode(input, len);
    ptrPos += len;
  }
}

void CASNParser::Encode(ByteDynArray &data) {
  size_t reqSize = CalcLen();
  data.resize(reqSize);
  Encode(data, tags);
}

void CASNParser::Parse(const ByteArray &data) {
  init_func tags.clear();
  Parse(data, tags, 0);
}

void CASNParser::Parse(const ByteArray &data, CASNTagArray &outTags,
                       size_t startseq, size_t depth) {
  init_func if (depth > kMaxAsn1NestingDepth) throw logged_error(
      "Excessive nesting depth in ASN.1");

  size_t l = 0;
  uint8_t *cur = data.data();
  while (l < data.size()) {
    size_t len = 0;

    std::vector<uint8_t> tagv;
    uint8_t curv = cur[0];
    tagv.push_back(curv);

    if ((curv & 0x1f) == 0x1f) {
      while (true) {
        l++;
        cur++;
        if (l >= data.size()) throw logged_error("Excessive length in ASN.1");
        curv = cur[0];
        tagv.push_back(curv);
        if ((curv & 0x80) != 0x80)
          // last byte of the tag
          break;
      }
    }

    // cur[1] (the length field's first octet) must be within the buffer
    // before it is read.
    if (data.size() - l < 2) throw logged_error("Excessive length in ASN.1");
    size_t remaining = data.size() - l;

    int llen = 0;
    if (cur[1] == 0x80) {
      llen = 1;
      len = data.size() - l - 2;
    } else if (BitValue(cur[1], 7) == 1) {
      llen = (cur[1] & 0x7f);
      // Bounds-check before reading llen more octets, and reject encodings
      // that could not possibly fit in a size_t.
      if (static_cast<size_t>(llen) > sizeof(size_t) ||
          remaining < static_cast<size_t>(llen) + 2)
        throw logged_error("Excessive length in ASN.1");
      for (int k = 0; k < llen; k++) {
        len <<= 8;
        len |= cur[k + 2];
      }
      llen++;
    } else {
      llen = 1;
      len = cur[1];
    }
    if (tagv.size() > 0 && tagv[0] == 0 && len == 0) {
      return;
    }
    // Compare via subtraction against the remaining buffer size instead of
    // adding into `len`: `len` is attacker-controlled and can be up to
    // SIZE_MAX, so `l + (len + llen + 1) > data.size()` can wrap around and
    // pass even though `len` reaches far past the buffer.
    size_t header = static_cast<size_t>(llen) + 1;
    if (header > remaining || len > remaining - header)
      throw logged_error("Excessive length in ASN.1");

    auto tag = std::unique_ptr<CASNTag>(new CASNTag());
    tag->startPos = startseq + l;
    tag->tag = tagv;
    if (tag->isSequence()) {
      ByteArray input(&cur[llen + 1], len);
      Parse(input, tag->tags, startseq + l + llen + 1, depth + 1);
    } else {
      // single value
      tag->content = ByteDynArray(ByteArray(&cur[llen + 1], len));
    }
    l += len + llen + 1;
    cur += len + llen + 1;
    tag->endPos = tag->startPos + len + llen + 1;
    outTags.emplace_back(std::move(tag));
  }
}
