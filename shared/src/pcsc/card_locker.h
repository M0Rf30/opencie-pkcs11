// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file card_locker.h
 * @brief RAII guard for smart card locking and transaction management.
 *
 * Provides the CCardLocker class that acquires and releases an exclusive lock
 * on a smart card handle, ensuring safe concurrent access.
 */

#pragma once

#include "pcsc/smart_card_transport.h"
#include "pcsc/token.h"
#include "util/syncro_mutex.h"

/**
 * @brief RAII guard that locks a smart card for exclusive access.
 *
 * Acquires a lock on the smart card on construction (or via Lock()) and
 * releases it on destruction (or via Unlock()), preventing concurrent
 * operations from interfering with each other.
 */
class CCardLocker {
  ISmartCardTransport &transport;
  SCARDHANDLE hCard;

 public:
  /**
   * @brief Constructs a CCardLocker for the given card handle.
   * @param transport Smart card transport abstraction.
   * @param card      Handle to the smart card to lock.
   */
  CCardLocker(ISmartCardTransport &transport, SCARDHANDLE card);

  /** Destructor; releases the card lock if still held. */
  ~CCardLocker(void);

  /** Acquires exclusive access to the smart card. */
  void Lock();

  /** Releases exclusive access to the smart card. */
  void Unlock();
};
