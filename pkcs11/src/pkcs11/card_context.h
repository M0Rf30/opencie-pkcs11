// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file card_context.h
 * @brief PC/SC resource manager context wrapper.
 *
 * CCardContext manages a SCARDCONTEXT handle obtained via
 * SCardEstablishContext. It supports lazy creation, validation, and automatic
 * renewal of the context.
 */

#pragma once

#include "pcsc/smart_card_transport.h"

/**
 * @brief RAII wrapper around a PC/SC SCARDCONTEXT.
 *
 * The context is established on construction and released on destruction.
 * Use validate() to check that the handle is still usable and renew() to
 * tear down and re-establish it.
 */
class CCardContext {
 public:
  ISmartCardTransport &transport;
  SCARDCONTEXT hContext;

  CCardContext(ISmartCardTransport &transport);
  ~CCardContext(void);

  /** @brief Implicit conversion so the object can be passed where a raw handle
   * is expected. */
  operator SCARDCONTEXT();

  /** @brief Verify that hContext is still valid; throws on failure. */
  void validate();

  /** @brief Release the current context and establish a fresh one. */
  void renew();

 private:
  /** @brief Internal helper: call SCardEstablishContext and store the handle.
   */
  void getContext();
};
