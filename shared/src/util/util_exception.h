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
  explicit logged_error(std::string &&message)
      : logged_error(message.c_str()) {}

  /**
   * @brief Construct from a const string reference.
   * @param message Error message.
   */
  explicit logged_error(const std::string &message)
      : logged_error(message.c_str()) {}

  /**
   * @brief Construct from a C string.
   * @param message Error message.
   */
  explicit logged_error(const char *message);
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
  explicit scard_error(StatusWord sw);
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
  explicit windows_error(long ris);
};

/**
 * @brief Exception representing a smart-card *transport* failure: the
 * command APDU could not be delivered, or the bytes that came back
 * cannot be trusted.
 *
 * Thrown for an SCardTransmit()/transceive() failure, a response shorter
 * than the mandatory 2-byte status word, or a Secure Messaging
 * MAC/decrypt failure caused by a garbled frame (all symptomatic of an
 * RF link drop on contactless readers/NFC rather than the card
 * deliberately answering with an ISO 7816 status word).
 *
 * Deliberately distinct from scard_error: callers may safely retry a
 * card_link_error with a fresh card reset + full PACE/DH + SM (a link
 * drop, not a card decision), but must NEVER retry a scard_error that
 * carries a PIN status word (63Cx/6983/6700/6300) -- doing so could
 * consume an extra wrong-PIN attempt. See cie_read_dgs()/CardAuthenticateEx()
 * retry policy for the call sites that rely on this distinction.
 */
class card_link_error : public logged_error {
 public:
  /**
   * @brief Construct from a description of the transport failure.
   * @param message Human-readable description (e.g. "SCardTransmit
   *                failed: (...)", "short/empty smart card response",
   *                "Secure Messaging MAC verification failed").
   */
  explicit card_link_error(const std::string &message, bool retryable = true);

  /**
   * @brief False when the link dropped while a PIN/PUK VERIFY was in
   * flight: the card may have received and counted a wrong PIN whose
   * answer we never saw, so automatically resending it could consume a
   * second attempt. RetryOnCardLinkError() rethrows these immediately.
   */
  bool retryable() const noexcept { return retryable_; }

 private:
  bool retryable_;
};
