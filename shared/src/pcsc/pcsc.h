// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file pcsc.h
 * @brief PC/SC subsystem interface helpers for smart card reader access.
 *
 * Provides RAII wrappers for PC/SC connections and transactions as well as a
 * background reader-monitor that fires callbacks on card insertion/removal.
 */

#pragma once

#include <string>
#include <thread>
#include <vector>

#include "pcsc/smart_card_transport.h"
#include "util/array.h"

/**
 * @brief RAII wrapper for a PC/SC smart card connection.
 *
 * Manages the lifetime of an SCARDHANDLE obtained via SCardConnect. The
 * connection is automatically released when the object goes out of scope.
 */
class safeConnection {
 public:
  ISmartCardTransport &transport; /**< Underlying smart card transport layer. */
  SCARDCONTEXT hContext;          /**< PC/SC resource manager context. */
  SCARDHANDLE hCard;              /**< Handle to the connected smart card. */

  /**
   * @brief Opens a new connection to a named reader.
   * @param transport  Smart card transport abstraction.
   * @param hContext   PC/SC resource manager context.
   * @param szReader   Name of the reader to connect to.
   * @param dwShareMode Sharing mode (e.g. SCARD_SHARE_SHARED).
   */
  safeConnection(ISmartCardTransport &transport, SCARDCONTEXT hContext,
                 LPCSTR szReader, DWORD dwShareMode);

  /**
   * @brief Wraps an already-established card handle.
   * @param transport Smart card transport abstraction.
   * @param hCard     Existing card handle to manage.
   */
  safeConnection(ISmartCardTransport &transport, SCARDHANDLE hCard);

  /** Disconnects from the smart card on destruction. */
  ~safeConnection();

  /** Implicit conversion to the underlying SCARDHANDLE. */
  operator SCARDHANDLE();
};

/**
 * @brief RAII wrapper for a PC/SC transaction (SCardBeginTransaction).
 *
 * Begins a transaction on construction and ends it on destruction, ensuring
 * exclusive card access within the scope.
 */
class safeTransaction {
  ISmartCardTransport &transport;
  SCARDHANDLE hCard;
  bool locked;
  DWORD dwDisposition;

 public:
  /**
   * @brief Begins a transaction on the given connection.
   * @param transport     Smart card transport abstraction.
   * @param conn          Active safe connection to transact on.
   * @param dwDisposition Action to take when the transaction ends
   *                      (e.g. SCARD_LEAVE_CARD).
   */
  safeTransaction(ISmartCardTransport &transport, const safeConnection &conn,
                  DWORD dwDisposition);

  /** Manually ends the transaction before destruction. */
  void unlock();

  /** Returns true if the transaction is still active. */
  bool isLocked();

  /** Ends the transaction if still active. */
  ~safeTransaction();
};

/**
 * @brief Monitors smart card readers for card insertion and removal events.
 *
 * Spawns a background thread that watches the PC/SC subsystem for reader
 * status changes and invokes a user-supplied callback on each event.
 */
class readerMonitor {
  ISmartCardTransport &transport;
  SCARDCONTEXT hContext;
  std::thread Thread;
  void *appData;
  void (*readerEvent)(std::string &reader, bool insert, void *appData);
  bool stopMonitor;

 public:
  /**
   * @brief Starts monitoring smart card readers.
   * @param transport   Smart card transport abstraction.
   * @param readerEvent Callback invoked on card insertion or removal.
   *                    @p reader is the reader name, @p insert is true on
   *                    insertion and false on removal.
   * @param appData     Opaque pointer forwarded to the callback.
   */
  readerMonitor(ISmartCardTransport &transport,
                void (*readerEvent)(std::string &reader, bool insert,
                                    void *appData),
                void *appData);

  /** Stops the monitor thread and releases resources. */
  ~readerMonitor();
};
