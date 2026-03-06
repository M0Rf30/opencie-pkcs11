// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file asn1_exception.h
 * @brief Exception classes for ASN.1 parsing and validation errors.
 *
 * Defines a hierarchy of exception types thrown during ASN.1 DER
 * decoding: generic errors, parsing failures, object-not-found
 * conditions, invalid OIDs, and unexpected content types.
 */

#pragma once

#include <cstdio>
#include <cstring>

#include "util/definitions.h"

/**
 * @brief Base exception for ASN.1 operations.
 *
 * Carries a human-readable error message that can be retrieved
 * via GetErrorMessage().
 */
class CASN1Exception {
 public:
  /**
   * @brief Constructs an ASN.1 exception with a message.
   * @param lpszMsg Null-terminated error description.
   */
  CASN1Exception(const char* lpszMsg) : m_lpszMsg(lpszMsg) {}

  virtual ~CASN1Exception() {}

  /**
   * @brief Copies the error message into a caller-supplied buffer.
   * @param lpszError Output buffer for the error string.
   * @param nMaxError Size of @p lpszError in bytes.
   * @return true if the message fits in the buffer, false otherwise.
   */
  virtual bool GetErrorMessage(char* lpszError, UINT nMaxError) {
    if (nMaxError < strlen(m_lpszMsg)) return false;

    snprintf(lpszError, nMaxError, "%s", m_lpszMsg);

    return true;
  }

 public:
  /** @brief The error description string. */
  const char* m_lpszMsg;
};

/**
 * @brief Thrown when DER parsing encounters malformed or unexpected data.
 */
class CASN1ParsingException : public CASN1Exception {
 public:
  CASN1ParsingException() : CASN1Exception("Bad ASN1Object parsed") {}

  virtual ~CASN1ParsingException() {}
};

/**
 * @brief Thrown when a required ASN.1 element is not found in a structure.
 */
class CASN1ObjectNotFoundException : public CASN1Exception {
 public:
  /**
   * @brief Constructs with the name of the missing element.
   * @param lpszClass Name or description of the element not found.
   */
  CASN1ObjectNotFoundException(const char* lpszClass)
      : CASN1Exception(lpszClass) {}

  virtual ~CASN1ObjectNotFoundException() {}
};

/**
 * @brief Thrown when an OID does not match the expected value.
 */
class CASN1BadObjectIdException : public CASN1Exception {
 public:
  /**
   * @brief Constructs with a description of the OID mismatch.
   * @param strClass Description or expected OID string.
   */
  CASN1BadObjectIdException(const char* strClass) : CASN1Exception(strClass) {}

  virtual ~CASN1BadObjectIdException() {}
};

/**
 * @brief Thrown when a ContentInfo has an unexpected or invalid content type.
 */
class CBadContentTypeException : public CASN1Exception {
 public:
  CBadContentTypeException() : CASN1Exception("Bad Content Type") {}

  virtual ~CBadContentTypeException() {}
};
