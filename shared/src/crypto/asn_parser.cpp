// SPDX-License-Identifier: LGPL-3.0-or-later
#include "asn_parser.h"

#include <algorithm>
#include <numeric>

#include "util/array.h"

extern CLog Log;

#define BitValue(a, b) ((a >> b) & 1)

size_t GetASN1DataLenght(const ByteArray &data) {
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

  size_t llen = 0;
  if (cur[1] == 0x80) {
    llen = 1;
    len = data.size() - l - 2;
  } else if (BitValue(cur[1], 7) == 1) {
    llen = (cur[1] & 0x7f);
    for (size_t k = 0; k < llen; k++) {
      len <<= 8;
      len |= cur[k + 2];
    }
    llen++;
  } else {
    llen = 1;
    len = cur[1];
  }
  return l + llen + len;
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

CASNTag &CASNTag::Child(std::size_t num, uint8_t tag) {
  if (num >= tags.size())
    throw logged_error("ASN.1 structure verification error");
  if (tags[num]->tag.size() == 1 && tags[num]->tag[0] == tag)
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

void CASNParser::Parse(const ByteArray &data, CASNTagArray &tags,
                       size_t startseq) {
  init_func size_t l = 0;
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

    int llen = 0;
    if (cur[1] == 0x80) {
      llen = 1;
      len = data.size() - l - 2;
    } else if (BitValue(cur[1], 7) == 1) {
      llen = (cur[1] & 0x7f);
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
    if (l + (len + llen + 1) > data.size())
      throw logged_error("Excessive length in ASN.1");

    auto tag = std::unique_ptr<CASNTag>(new CASNTag());
    tag->startPos = startseq + l;
    tag->tag = tagv;
    if (tag->isSequence()) {
      ByteArray input(&cur[llen + 1], len);
      Parse(input, tag->tags, startseq + l + llen + 1);
    } else {
      // single value
      tag->content = ByteDynArray(ByteArray(&cur[llen + 1], len));
    }
    l += len + llen + 1;
    cur += len + llen + 1;
    tag->endPos = tag->startPos + len + llen + 1;
    tags.emplace_back(std::move(tag));
  }
}
