// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file array.cpp
 * @brief Implementation of ByteArray (view) and ByteDynArray (owning) classes.
 *
 * Contains memory manipulation, slicing, searching, ASN.1 helpers,
 * and hex-string parsing routines.
 */

#include "util/array.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

ByteArray::ByteArray() {
  _data = nullptr;
  _size = 0;
}

ByteArray::ByteArray(uint8_t *data, size_t size) {
  _data = data;
  _size = size;
}
ByteArray::ByteArray(const uint8_t *data, size_t size) {
  _data = const_cast<uint8_t *>(data);
  _size = size;
}

ByteDynArray::ByteDynArray(ByteDynArray &&src) noexcept {
  _data = src._data;
  _size = src._size;
  src._data = nullptr;
  src._size = 0;
}

ByteArray::ByteArray(const ByteArray &ba, size_t start) {
  if (start > ba.size()) throw logged_error("Derived array too large");

  _size = ba.size() - start;
  _data = ba._data + start;
}

ByteArray::ByteArray(const ByteArray &ba, size_t start, size_t size) {
  if (start > ba.size() || size > ba.size() - start)
    throw logged_error("Derived array too large");
  _size = size;
  _data = ba._data + start;
}

ByteArray::ByteArray(const ByteArray &src) {
  _size = src._size;
  _data = src._data;
};

ByteDynArray &ByteDynArray::operator=(ByteDynArray &&src) noexcept {
  if (this == &src) return *this;
  clear();
  _data = src._data;
  _size = src._size;
  src._data = nullptr;
  src._size = 0;
  return *this;
}

bool ByteArray::operator==(const ByteArray &src) const {
  if (_size != src._size) return false;
  if (_size == 0) return true;
  return (memcmp(_data, src._data, _size) == 0);
};

int ByteArray::atoi() const {
  int val = 0;
  for (size_t i = 0; i < _size; i++) {
    if (val > (INT_MAX / 10)) throw std::overflow_error("overflow");
    val = (val * 10) + _data[i] - '0';
  }
  return val;
}
bool ByteArray::operator<(const ByteArray &src) const {
  size_t cmpLen = std::min(_size, src._size);
  int cmp = cmpLen > 0 ? memcmp(_data, src._data, cmpLen) : 0;
  if (cmp != 0) return cmp < 0;
  return _size < src._size;
};

bool ByteArray::operator>(const ByteArray &src) const {
  size_t cmpLen = std::min(_size, src._size);
  int cmp = cmpLen > 0 ? memcmp(_data, src._data, cmpLen) : 0;
  if (cmp != 0) return cmp > 0;
  return _size > src._size;
};

bool ByteArray::operator!=(const ByteArray &src) const {
  return !(*this == src);
};

void ByteArray::copy(const ByteArray &src, size_t start) {
  if (start > _size || src._size > _size - start)
    throw logged_error(
        stdPrintf("Source array size %zu too large to copy; maximum size %zu",
                  src._size + start, _size));
  if (src._size > 0 && src._data)
    std::memcpy(_data + start, src._data, src._size);
}

void ByteArray::rightcopy(const ByteArray &src, size_t end) {
  if (end > _size || src._size > _size - end)
    throw logged_error(
        stdPrintf("Source array size %zu too large to copy; maximum size %zu",
                  src._size + end, _size));
  if (src._size > 0 && src._data)
    std::memcpy(_data + _size - end - src._size, src._data, src._size);
}

ByteArray &ByteArray::fill(const uint8_t value) {
  for (size_t i = 0; i < _size; i++) _data[i] = value;
  return *this;
}

/** @brief Helper class for one-time random number generator initialization. */
class init_rnd {
 public:
  init_rnd() {}
} _initRand;

ByteArray &ByteArray::random() {
  if (RAND_bytes(_data, static_cast<int>(_size)) != 1)
    throw logged_error("RAND_bytes failed");
  return *this;
}

ByteArray &ByteArray::reverse() {
  size_t dwHalfSize = _size >> 1;
  for (size_t i = 0; i < dwHalfSize; i++) {
    uint8_t temp = _data[i];
    _data[i] = _data[_size - i - 1];
    _data[_size - i - 1] = temp;
  }
  return *this;
}

ByteArray ByteArray::right(size_t size) const {
  if (size > _size) throw logged_error("Derived array too large");
  return (ByteArray(*this, _size - size, size));
}

ByteArray ByteArray::left(size_t size) const {
  if (size > _size) throw logged_error("Derived array too large");
  return (ByteArray(*this, 0, size));
}

ByteArray ByteArray::mid(size_t start) const {
  if (start > _size) throw logged_error("Derived array too large");
  return (ByteArray(*this, start, _size - start));
}

ByteArray ByteArray::mid(size_t start, size_t size) const {
  if (start > _size || size > _size - start)
    throw logged_error("Derived array too large");
  return (ByteArray(*this, start, size));
}

ByteArray ByteArray::revmid(size_t toend) const {
  if (toend > _size) throw logged_error("Derived array too large");
  return (ByteArray(*this, 0, _size - toend));
}

ByteArray ByteArray::revmid(size_t toend, size_t size) const {
  if (toend > _size || size > _size - toend)
    throw logged_error("Derived array too large");
  return (ByteArray(*this, _size - toend - size, size));
}

ByteArray::~ByteArray() {
  // Reset fields but do NOT free memory (non-owning view).
  _size = 0;
  _data = nullptr;
}

ByteDynArray ByteArray::getASN1Tag(unsigned int tag) const {
  size_t tl = ASN1TLength(tag);
  size_t ll = ASN1LLength(size());
  ByteDynArray result(tl + ll + size());
  putASN1Tag(tag, result);
  ByteArray input(result.mid(tl));
  putASN1Length(size(), input);
  result.mid(tl + ll).copy(*this);
  return result;
}

void ByteDynArray::alloc_copy(const ByteArray &src) {
  clear();
  _data = new uint8_t[src.size()];
  _size = src.size();
  copy(src);
  return;
}

ByteDynArray::ByteDynArray() {
  _size = 0;
  _data = nullptr;
};

ByteDynArray::ByteDynArray(const ByteDynArray &src) : ByteDynArray() {
  alloc_copy(src);
};

ByteDynArray::ByteDynArray(const ByteArray &src) : ByteDynArray() {
  alloc_copy(src);
};

ByteDynArray::ByteDynArray(const std::string &hexdata) : ByteDynArray() {
  readHexData(hexdata, *this);
}

ByteDynArray::ByteDynArray(size_t size) {
  _data = new uint8_t[size];
  _size = size;
};
ByteDynArray::~ByteDynArray() { clear(); }

ByteDynArray &ByteDynArray::operator=(const ByteDynArray &src) {
  if (this != &src) alloc_copy(src);
  return *this;
}

void ByteDynArray::resize(size_t size, bool bKeepData) {
  if (!bKeepData) {
    clear();
    _data = new uint8_t[size];
    _size = size;
  } else {
    uint8_t *pbtNewData = new uint8_t[size];
    size_t dwMinSize = std::min(size, _size);
    if (dwMinSize > 0) std::memcpy(pbtNewData, _data, dwMinSize);
    clear();
    _data = pbtNewData;
    _size = size;
  }
}

void ByteDynArray::clear() {
  if (_data != nullptr) {
    if (_size > 0) OPENSSL_cleanse(_data, _size);
    delete[] _data;
  }
  _data = nullptr;
  _size = 0;
}

ByteDynArray &ByteDynArray::append(const ByteArray &src) {
  if (src.size() > 0) {
    resize(_size + src.size(), true);
    rightcopy(src);
  }
  return *this;
}

ByteDynArray &ByteDynArray::push(const uint8_t data) {
  resize(_size + 1, true);
  _data[_size - 1] = data;
  return *this;
}

uint8_t *ByteDynArray::detach() {
  uint8_t *data = _data;
  _data = nullptr;
  _size = 0;

  return data;
}
bool ByteArray::indexOf(const ByteArray &data, size_t &position) const {
  if (data.size() == 0) return 0;
  if (_size < data.size()) return false;
  size_t start = _size - data.size();
  for (size_t i = 0; i <= start; i++) {
    bool ok = true;
    for (unsigned int j = 0; j < data.size(); j++) {
      if (_data[i + j] != data[j]) {
        ok = false;
        break;
      }
    }
    if (ok) {
      position = i;
      return true;
    }
  }
  return false;
}

ByteDynArray &ByteDynArray::setASN1Tag(unsigned int tag,
                                       const ByteArray &content) {
  size_t tl = ASN1TLength(tag);
  size_t ll = ASN1LLength(content.size());
  resize(tl + ll + content.size());
  putASN1Tag(tag, *this);
  ByteArray input = mid(tl);
  putASN1Length(content.size(), input);
  mid(tl + ll).copy(content);
  return *this;
}
void ByteDynArray::load(const char *fname) {
  // The only users are the small on-disk cache files, so a hard cap keeps a
  // planted huge/sparse file from exhausting memory (finding SU-03).
  constexpr size_t kMaxLoadSize = 1024 * 1024;
#ifdef _WIN32
  std::ifstream file(fname, std::ios::in | std::ios::binary);
  if (!file) throw logged_error("ByteDynArray::load: cannot open file");
  file.seekg(0, file.end);
  auto fsize = file.tellg();
  file.seekg(0, file.beg);
  if (fsize < 0)
    throw logged_error("ByteDynArray::load: cannot determine file size");
  if (static_cast<uint64_t>(fsize) > kMaxLoadSize)
    throw logged_error("ByteDynArray::load: file too large");
  resize(static_cast<size_t>(fsize), false);
  if (fsize > 0) {
    file.read(reinterpret_cast<char *>(_data), fsize);
    if (file.gcount() != fsize)
      throw logged_error("ByteDynArray::load: short read");
  }
#else
  // O_NOFOLLOW: refuse a symlink at the final component. O_NONBLOCK: opening
  // a FIFO must not hang. The type check below rejects anything but a
  // regular file.
  int fd = open(fname, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd == -1) throw logged_error("ByteDynArray::load: cannot open file");
  struct stat st {};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    throw logged_error("ByteDynArray::load: not a regular file");
  }
  if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > kMaxLoadSize) {
    close(fd);
    throw logged_error("ByteDynArray::load: file too large");
  }
  size_t fsize = static_cast<size_t>(st.st_size);
  try {
    resize(fsize, false);
  } catch (...) {
    close(fd);
    throw;
  }
  size_t done = 0;
  while (done < fsize) {
    ssize_t n = read(fd, _data + done, fsize - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      close(fd);
      throw logged_error("ByteDynArray::load: short read");
    }
    done += static_cast<size_t>(n);
  }
  close(fd);
#endif
}
