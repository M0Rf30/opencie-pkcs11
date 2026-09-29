// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file retry.h
 * @brief Bounded retry helper for card_link_error (transport/link failures).
 *
 * A card_link_error means the bytes we got back from the card cannot be
 * trusted (SCardTransmit()/transceive() failure, a short/empty response,
 * or a Secure Messaging MAC/decrypt failure from a garbled frame) -- NOT
 * that the card sent back an explicit ISO 7816 status word we disagree
 * with (that is scard_error, never retried here).
 *
 * Retrying such a failure with a fresh card reset + full PACE/DH + SM is
 * safe from a PIN-safety point of view: a correct PIN VERIFY never
 * decrements the retry counter, and PIN status words (63Cx/6983/6700/
 * 6300) are surfaced as ordinary return values by the CIE PIN-verification
 * call sites, not as exceptions -- so this helper is structurally never
 * invoked again after the card has reported a PIN status word.
 */

#pragma once

#include <chrono>
#include <string>
#include <thread>
#include <utility>

#include "logger/logger.h"
#include "util/util_exception.h"

/**
 * @brief Call @p fn up to @p maxAttempts times, retrying only when it
 * throws card_link_error, with a short backoff between attempts.
 *
 * @param opName       Name used in log messages (e.g. "readBothDGs").
 * @param maxAttempts  Total attempts including the first (e.g. 3 == 1
 *                     initial try + 2 retries).
 * @param fn           Callable taking the 1-based attempt number and
 *                     returning Fn's result. May throw card_link_error to
 *                     trigger a retry, or any other exception to abort
 *                     immediately without retrying.
 * @return Whatever @p fn returned on the attempt that did not throw
 *         card_link_error.
 * @throws card_link_error if every attempt failed with a link error.
 * @throws Anything else @p fn throws (never retried).
 */
template <typename Fn>
auto RetryOnCardLinkError(const char *opName, int maxAttempts, Fn &&fn)
    -> decltype(fn(1)) {
  for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
    try {
      return fn(attempt);
    } catch (const card_link_error &e) {
      if (!e.retryable() || attempt >= maxAttempts) {
        CieIDLogger::Logger::getInstance().error(
            "%s - card link error after %d attempt(s), giving up: %s", opName,
            attempt, e.what());
        throw;
      }
      CieIDLogger::Logger::getInstance().error(
          "%s - card link error (attempt %d/%d), retrying after reset: %s",
          opName, attempt, maxAttempts, e.what());
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  }
  // Unreachable: the loop above always either returns or throws on its
  // last iteration.
  throw logged_error(std::string(opName) +
                     ": RetryOnCardLinkError loop exited unexpectedly");
}
