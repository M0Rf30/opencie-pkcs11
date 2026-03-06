// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file asn1_generic_sequence.h
 * @brief Generic ASN.1 SEQUENCE with runtime field composition.
 *
 * Provides an ordered, indexed collection of ASN.1 objects that can
 * be built up at runtime. Serves as the base for both CASN1Sequence
 * (tag 0x30) and CASN1SetOf (tag 0x31).
 */

#pragma once

#include "asn1_object.h"

/** @brief Maximum number of elements in a generic sequence. */
#define MAXSIZE 100

/**
 * @brief Generic ASN.1 constructed type with positional element access.
 *
 * Manages an ordered array of child ASN.1 objects, supporting add,
 * remove, replace, and sequential iteration. Concrete subclasses
 * (CASN1Sequence, CASN1SetOf) set the appropriate tag.
 */
class CASN1GenericSequence : public CASN1Object {
 public:
  /**
   * @brief Constructs a generic sequence with a specific tag.
   * @param btTag The ASN.1 tag byte (e.g., 0x30 for SEQUENCE, 0x31 for SET).
   */
  CASN1GenericSequence(BYTE btTag);

  /**
   * @brief Constructs a generic sequence by reading from a BufferedReader.
   * @param reader The reader positioned at the constructed TLV.
   */
  CASN1GenericSequence(BufferedReader& reader);

  /**
   * @brief Constructs a generic sequence by decoding a DER byte array.
   * @param content DER-encoded bytes.
   */
  CASN1GenericSequence(const ByteDynArray& content);

  /**
   * @brief Constructs a generic sequence from a generic ASN.1 object.
   * @param obj The ASN.1 object to reinterpret as a constructed type.
   */
  CASN1GenericSequence(const CASN1Object& obj);

  /**
   * @brief Copy constructor.
   * @param obj The generic sequence to copy.
   */
  CASN1GenericSequence(const CASN1GenericSequence& obj);

  /**
   * @brief Constructs a generic sequence from a raw byte buffer.
   * @param value Pointer to DER-encoded data.
   * @param len   Length of the data in bytes.
   */
  CASN1GenericSequence(const BYTE* value, long len);

  virtual ~CASN1GenericSequence();

  /**
   * @brief Assignment operator.
   * @param obj The generic sequence to assign from.
   * @return Reference to this object.
   */
  CASN1GenericSequence& operator=(const CASN1GenericSequence&);

  /**
   * @brief Appends an ASN.1 object to the end of the sequence.
   * @param obj The element to add.
   */
  void addElement(const CASN1Object& obj);

  /**
   * @brief Inserts an ASN.1 object at the specified position.
   * @param pObj The element to insert.
   * @param nPos Zero-based index for insertion.
   */
  void addElementAt(const CASN1Object& pObj, int nPos);

  /**
   * @brief Returns the element at the given position.
   * @param nPos Zero-based index.
   * @return The ASN.1 object at that position.
   */
  CASN1Object elementAt(int nPos);

  /**
   * @brief Returns the next element during sequential iteration.
   * @return The next ASN.1 object in sequence.
   */
  CASN1Object nextElement();

  /**
   * @brief Returns the element at the given position, or empty if absent.
   * @param nPos Zero-based index.
   * @return The ASN.1 object at that position, or a default object if not
   * present.
   */
  CASN1Object elementAtOpt(int nPos);

  /**
   * @brief Returns the next element during sequential iteration, or empty if
   * none.
   * @return The next ASN.1 object, or a default object if past the end.
   */
  CASN1Object nextElementOpt();

  /**
   * @brief Replaces the element at the specified position.
   * @param obj  The new ASN.1 object.
   * @param nPos Zero-based index.
   */
  void setElementAt(const CASN1Object& obj, int nPos);

  /**
   * @brief Removes the element at the specified position.
   * @param nPos Zero-based index.
   */
  void removeElementAt(int nPos);

  /** @brief Removes all elements from the sequence. */
  void removeAll();

  /**
   * @brief Checks whether an element exists at the given position.
   * @param nPos Zero-based index.
   * @return True if an element is present at that position.
   */
  bool isPresent(int nPos) const;

  /**
   * @brief Returns the number of elements in the sequence.
   * @return Element count.
   */
  unsigned int size() const;

  /**
   * @brief Decodes elements from a DER byte array into this sequence.
   * @param content DER-encoded bytes.
   */
  void fromByteArray(const ByteDynArray& content);

 protected:
 private:
  unsigned int m_nextOffset;  ///< Current offset for sequential iteration.

  unsigned int* m_pnOffsets;   ///< Array of byte offsets for each element.
  unsigned int m_nOffsetsMax;  ///< Allocated capacity of the offsets array.
  int m_nSize;                 ///< Current number of elements.

  /**
   * @brief Computes internal byte offsets for element access.
   * @return Number of elements parsed.
   */
  int makeOffset();
};
