// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdio>
#include <cstring>

#include "Util/definitions.h"
class CASN1Exception {
 public:
  CASN1Exception(const char* lpszMsg) : m_lpszMsg(lpszMsg) {}

  virtual ~CASN1Exception() {}

  virtual bool GetErrorMessage(char* lpszError, UINT nMaxError) {
    if (nMaxError < strlen(m_lpszMsg)) return false;

    snprintf(lpszError, nMaxError, "%s", m_lpszMsg);

    return true;
  }

 public:
  const char* m_lpszMsg;
};

class CASN1ParsingException : public CASN1Exception {
 public:
  CASN1ParsingException() : CASN1Exception("Bad ASN1Object parsed") {}

  virtual ~CASN1ParsingException() {}
};

class CASN1ObjectNotFoundException : public CASN1Exception {
 public:
  CASN1ObjectNotFoundException(const char* lpszClass)
      : CASN1Exception(lpszClass) {}

  virtual ~CASN1ObjectNotFoundException() {}
};

class CASN1BadObjectIdException : public CASN1Exception {
 public:
  CASN1BadObjectIdException(const char* strClass) : CASN1Exception(strClass) {}

  virtual ~CASN1BadObjectIdException() {}
};

class CBadContentTypeException : public CASN1Exception {
 public:
  CBadContentTypeException() : CASN1Exception("Bad Content Type") {}

  virtual ~CBadContentTypeException() {}
};

