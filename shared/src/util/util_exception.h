// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file util_exception.h
 * @brief Exception types for the CIE PKCS#11 library.
 *
 * Defines exception classes for logged errors, smart card status word
 * errors, and Windows API errors.
 */

#pragma once

#include <memory>
#include <stdexcept>

#include "defines.h"

/**
 * @brief Exception that logs its message upon construction.
 *
 * Derives from std::runtime_error. The error message is written
 * to the diagnostic log when the exception is created.
 */
class logged_error : public std::runtime_error {
 public:
  /**
   * @brief Construct from an rvalue string.
   * @param message Error message (moved).
   */
  logged_error(std::string &&message) : logged_error(message.c_str()) {}

  /**
   * @brief Construct from a const string reference.
   * @param message Error message.
   */
  logged_error(const std::string &message);

  /**
   * @brief Construct from a C string.
   * @param message Error message.
   */
  logged_error(const char *message);
};

/**
 * @brief Exception representing a smart card status word error.
 *
 * Carries the ISO 7816 status word (SW1-SW2) returned by the card.
 */
class scard_error : public logged_error {
 public:
  StatusWord sw; /**< ISO 7816 status word (e.g. 0x6982 = access denied). */

  /**
   * @brief Construct from a status word.
   * @param sw The ISO 7816 status word returned by the card.
   */
  scard_error(StatusWord sw);
};

/**
 * @brief Exception representing a Windows API error.
 */
class windows_error : public logged_error {
 public:
  /**
   * @brief Construct from a Windows error code.
   * @param ris HRESULT or Win32 error code.
   */
  windows_error(long ris);
};
