// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file array.h
 * @brief Core byte array classes for raw memory manipulation.
 *
 * Provides ByteArray (non-owning view) and ByteDynArray (owning,
 * heap-allocated) for working with raw byte buffers throughout the CIE PKCS#11
 * library.
 *
 * **Ownership model:**
 * - ByteArray is a lightweight, non-owning view over an existing byte buffer.
 *   It stores a pointer and a size but never allocates or frees memory.
 *   Copying a ByteArray copies the pointer, not the data.
 * - ByteDynArray extends ByteArray with heap ownership. It allocates memory
 *   via `new[]`, copies data on construction/assignment, and frees memory
 *   in its destructor. Move semantics transfer ownership without copying.
 *
 * Also includes ASN.1 tag/length encoding helpers and hex-string conversion
 * utilities used by smart card communication routines.
 */

#pragma once
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "defines.h"
#include "util_exception.h"

#ifndef min1
/** @brief Safe minimum macro (avoids conflicts with std::min). */
#define min1(a, b) ((a) < (b)) ? (a) : (b)
#endif

class ByteArray;     ///< Forward declaration of non-owning byte view.
class ByteDynArray;  ///< Forward declaration of owning byte array.

/** @brief printf-style string formatter returning std::string. */
std::string stdPrintf(const char *format, ...);
/** @brief Encode an ASN.1 tag into the given byte array. */
void putASN1Tag(unsigned int tag, ByteArray &data);
/** @brief Encode an ASN.1 length into the given byte array. */
void putASN1Length(size_t len, ByteArray &data);
/** @brief Return the encoded byte-length of an ASN.1 tag value. */
size_t ASN1TLength(unsigned int tag);
/** @brief Return the encoded byte-length of an ASN.1 length field. */
size_t ASN1LLength(size_t len);

/**
 * @brief Non-owning view over a contiguous byte buffer.
 *
 * ByteArray stores a raw pointer and a size. It does **not** own the memory
 * it points to — the caller must ensure the underlying buffer outlives
 * every ByteArray that references it.
 *
 * Slicing operations (left, right, mid, revmid) return new ByteArray views
 * into the same underlying buffer (zero-copy).
 *
 * @note Copy constructor and assignment copy the pointer, not the data.
 */
class ByteArray {
 protected:
  size_t _size;    ///< Number of bytes in the view.
  uint8_t *_data;  ///< Pointer to the first byte (not owned).

 public:
  /** @brief Construct an empty (null) byte array. */
  ByteArray();
  /** @brief Construct a view over a mutable buffer. */
  ByteArray(uint8_t *data, size_t size);
  /** @brief Construct a view over a const buffer (const_cast internally). */
  ByteArray(const uint8_t *data, size_t size);
  /** @brief Construct a sub-view starting at @p start for @p size bytes. */
  ByteArray(const ByteArray &ba, size_t start, size_t size);
  /** @brief Construct a sub-view from @p start to the end. */
  ByteArray(const ByteArray &ba, size_t start);
  /** @brief Copy constructor — copies the pointer, not the data. */
  ByteArray(const ByteArray &src);
  /** @brief Default copy-assignment — copies the pointer, not the data. */
  ByteArray &operator=(const ByteArray &src) = default;
  /** @brief Byte-wise equality comparison. */
  bool operator==(const ByteArray &src) const;
  /** @brief Lexicographic less-than comparison. */
  bool operator<(const ByteArray &src) const;
  /** @brief Lexicographic greater-than comparison. */
  bool operator>(const ByteArray &src) const;
  /** @brief Byte-wise inequality comparison. */
  bool operator!=(const ByteArray &src) const;
  /** @brief Check whether the view has zero length. */
  bool isEmpty() const { return (_size == 0); }

  /** @brief Check whether the data pointer is null. */
  inline bool isNull() const { return (_data == nullptr); }

  /** @brief Return a raw pointer to the underlying data. */
  inline uint8_t *data() const { return _data; }

  /**
   * @brief Bounds-checked element access.
   * @param pos Zero-based index.
   * @return Reference to the byte at @p pos.
   * @throws logged_error if @p pos >= size().
   */
  inline uint8_t &operator[](size_t pos) const {
    if (pos >= _size)
      throw logged_error(
          stdPrintf("Array access at position %i not allowed; "
                    "maximum size %i",
                    pos, _size));
    return _data[pos];
  }

  /** @brief Return the number of bytes in this view. */
  inline size_t size() const { return (_size); }

  /**
   * @brief Copy bytes from @p src into this array at @p start offset.
   * @throws logged_error if src would exceed this array's bounds.
   */
  void copy(const ByteArray &src, size_t start = 0);
  /**
   * @brief Copy bytes from @p src, right-aligned within this array.
   * @param end Number of bytes to leave free at the right edge.
   * @throws logged_error if src would exceed this array's bounds.
   */
  void rightcopy(const ByteArray &src, size_t end = 0);

  /** @brief Fill every byte with @p value. @return *this for chaining. */
  ByteArray &fill(const uint8_t value);
  /** @brief Fill with cryptographically random bytes (via OpenSSL RAND_bytes).
   * @return *this. */
  ByteArray &random();
  /** @brief Reverse byte order in-place. @return *this for chaining. */
  ByteArray &reverse();

  /** @brief Return a view of the last @p size bytes. */
  ByteArray right(size_t size) const;
  /** @brief Return a view of the first @p size bytes. */
  ByteArray left(size_t size) const;
  /** @brief Return a view from @p start to the end. */
  ByteArray mid(size_t start) const;
  /** @brief Return a view of @p size bytes starting at @p start. */
  ByteArray mid(size_t start, size_t size) const;
  /** @brief Return a view from the beginning, excluding the last @p toend
   * bytes. */
  ByteArray revmid(size_t toend) const;
  /** @brief Return a view of @p size bytes, ending @p toend bytes from the end.
   */
  ByteArray revmid(size_t toend, size_t size) const;
  /**
   * @brief Search for a sub-array within this array.
   * @param[in]  data     Sub-array to find.
   * @param[out] position Set to the first match index on success.
   * @return true if found.
   */
  bool indexOf(const ByteArray &data, size_t &position) const;

  /** @brief Interpret the bytes as ASCII decimal digits and convert to int. */
  int atoi() const;
  /** @brief Wrap this array's data inside an ASN.1 TLV with the given @p tag.
   */
  ByteDynArray getASN1Tag(unsigned int tag) const;

  /** @brief Virtual destructor (resets pointer/size, does NOT free memory). */
  virtual ~ByteArray();
};

/** @brief Parse a hex string (with optional spaces/prefixes) into a
 * ByteDynArray. */
void readHexData(const std::string &data, ByteDynArray &ba);
/** @brief Count how many bytes a hex string represents. */
size_t countHexData(const std::string &data);
/** @brief Decode a hex string directly into a pre-allocated byte buffer. */
size_t setHexData(const std::string &data, uint8_t *buf);

/**
 * @brief Owning, heap-allocated byte array.
 *
 * ByteDynArray inherits from ByteArray and adds memory ownership.
 * It allocates memory via `new[]` and frees it in the destructor.
 * Copy construction/assignment perform deep copies; move semantics
 * transfer ownership without copying.
 *
 * The variadic set() template allows building a buffer from a sequence
 * of byte values, ByteArrays, and hex strings in a single call.
 */
class ByteDynArray : public ByteArray {
  /** @brief Allocate and deep-copy from another array. */
  void alloc_copy(const ByteArray &src);

 public:
  /** @brief Construct an empty (null) owning array. */
  ByteDynArray();
  /** @brief Deep-copy construct from a non-owning ByteArray. */
  explicit ByteDynArray(const ByteArray &src);
  /** @brief Deep-copy construct from another ByteDynArray. */
  ByteDynArray(const ByteDynArray &src);
  /** @brief Allocate an uninitialized buffer of @p size bytes. */
  explicit ByteDynArray(size_t size);
  /** @brief Construct by parsing a hex string (e.g. "0A 1B 2C"). */
  explicit ByteDynArray(const std::string &hexdata);
  /** @brief Move constructor — transfers ownership, leaves @p src empty. */
  ByteDynArray(ByteDynArray &&src);

  /** @brief Destructor — frees the owned buffer. */
  ~ByteDynArray() override;
  /** @brief Deep-copy assignment operator. */
  ByteDynArray &operator=(const ByteDynArray &src);
  /** @brief Move assignment — transfers ownership. */
  ByteDynArray &operator=(ByteDynArray &&src);

  /**
   * @brief Resize the buffer.
   * @param size New size in bytes.
   * @param bKeepData If true, preserve existing data up to min(old, new) size.
   */
  void resize(size_t size, bool bKeepData = false);
  /** @brief Free the buffer and reset to empty. */
  void clear();
  /** @brief Append @p src to this array (resizes automatically). */
  ByteDynArray &append(const ByteArray &src);
  /** @brief Append a single byte. */
  ByteDynArray &push(const uint8_t data);
  /**
   * @brief Release ownership and return the raw pointer.
   * @return Pointer to the buffer (caller takes ownership).
   * @note This array becomes empty after detach.
   */
  uint8_t *detach();

 private:
  static size_t internalSet(ByteArray *ba, uint8_t data) {
    if (ba != nullptr) (*ba)[0] = data;
    return 1;
  }

  static size_t internalSet(const ByteArray *ba, const ByteArray *data) {
    if (ba != nullptr) const_cast<ByteArray *>(ba)->copy(*data);
    return data->size();
  }

  static size_t internalSet(const ByteArray *ba, const std::string &data) {
    if (ba != nullptr)
      return setHexData(data, const_cast<ByteArray *>(ba)->data());
    return countHexData(data);
  }

  static size_t internalSet(ByteArray * /*ba*/) { return 0; }

 public:
  /**
   * @brief Build this array's content from a variadic sequence of parts.
   *
   * Each argument can be a uint8_t (single byte), a ByteArray pointer,
   * or a hex std::string. The array is resized to the total and parts
   * are written sequentially.
   *
   * @tparam Arg0  Type of the first argument.
   * @tparam Args  Types of remaining arguments.
   * @return *this for chaining.
   */
  template <typename Arg0, typename... Args>
  ByteDynArray &set(Arg0 &&arg0, Args &&...args) {
    size_t totSize =
        internalSet((ByteArray *)nullptr, std::forward<Arg0>(arg0));

    size_t totSize2 = 0;
    int dummy[] = {
        0, ((void)(totSize2 +=
                   internalSet((ByteArray *)nullptr, std::forward<Args>(args))),
            0)...};

    resize(totSize + totSize2);

    ByteArray buffer(*this);
    buffer = buffer.mid(internalSet(&buffer, std::forward<Arg0>(arg0)));
    int dummy2[] = {0, ((void)(buffer = buffer.mid(internalSet(
                                   &buffer, std::forward<Args>(args)))),
                        0)...};

    (void)dummy;
    (void)dummy2;
    return *this;
  }

  /** @brief Build an ASN.1 TLV from @p tag and @p content, storing result in
   * this array. */
  ByteDynArray &setASN1Tag(unsigned int tag, const ByteArray &content);
  /** @brief Load the entire contents of file @p fname into this array. */
  void load(const char *fname);
};

/** @brief Create a ByteArray view over a local variable. */
#define VarToByteArray(a) \
  (ByteArray(reinterpret_cast<uint8_t *>(&(a)), sizeof(a)))
/** @brief Create an owning ByteDynArray copy of a local variable. */
#define VarToByteDynArray(a) (ByteDynArray(VarToByteArray(a)))
/** @brief Reinterpret a ByteArray's data as a value of type @p b. */
#define ByteArrayToVar(a, b) (*(reinterpret_cast<b *>((a).data())))
