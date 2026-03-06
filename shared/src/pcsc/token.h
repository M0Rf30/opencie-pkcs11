// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file token.h
 * @brief Smart card token abstraction for CIE (Carta d'Identità Elettronica).
 *
 * Provides the CToken class that represents a connection to a smart card token
 * and supports APDU transmission, binary reads, and card reset operations.
 */

#pragma once

#include "pcsc/apdu.h"
#include "pcsc/scard_types.h"
#include "util/syncro_mutex.h"

/** Global PC/SC resource manager context handle. */
extern SCARDCONTEXT hContext;

/**
 * @brief Perform Security Operation (PSO) types for the smart card.
 */
enum CardPSO { Op_PSO_DEC, Op_PSO_ENC, Op_PSO_CDS };

class CCardLocker;

/**
 * @brief Represents a smart card token and provides APDU-level communication.
 *
 * CToken encapsulates the logic for transmitting APDU commands to a CIE smart
 * card, reading binary data, selecting the Master File (MF), and resetting the
 * card. An optional transmit callback allows interception of raw APDU I/O.
 */
class CToken {
 public:
  /**
   * @brief Callback type invoked for every APDU transmit operation.
   * @param data   User-supplied opaque pointer.
   * @param apdu   Pointer to the outgoing APDU byte buffer.
   * @param apduSize Length of the APDU buffer in bytes.
   * @param resp   Pointer to the response byte buffer.
   * @param respSize Pointer receiving the response length in bytes.
   * @return HRESULT indicating success or failure.
   */
  using TokenTransmitCallback = HRESULT (*)(void *data, uint8_t *apdu,
                                            DWORD apduSize, uint8_t *resp,
                                            DWORD *respSize);

 private:
  TokenTransmitCallback transmitCallback;
  void *transmitCallbackData;

 public:
  /** Constructs a CToken with no active connection. */
  CToken();

  /** Destructor. */
  ~CToken();

  /** Selects the Master File (MF) on the smart card. */
  void SelectMF();

  /**
   * @brief Reads binary data from the card.
   * @param start Offset (in bytes) from which to start reading.
   * @param size  Number of bytes to read.
   * @return A ByteDynArray containing the data read from the card.
   */
  ByteDynArray BinaryRead(WORD start, BYTE size);

  /**
   * @brief Resets the smart card.
   * @param unpower If true, the card is fully powered down; otherwise a warm
   *                reset is performed.
   */
  void Reset(bool unpower = false);

  /**
   * @brief Sets the transmit callback and its associated user data.
   * @param func Pointer to the callback function.
   * @param data Opaque pointer passed to the callback on each invocation.
   */
  void setTransmitCallback(TokenTransmitCallback func, void *data);

  /**
   * @brief Replaces the user data pointer passed to the transmit callback.
   * @param data New opaque pointer.
   */
  void setTransmitCallbackData(void *data);

  /**
   * @brief Returns the current transmit callback user data pointer.
   * @return Opaque pointer previously set via setTransmitCallback() or
   *         setTransmitCallbackData().
   */
  void *getTransmitCallbackData();

  /**
   * @brief Transmits a structured APDU command to the card.
   * @param apdu Reference to the APDU command to send.
   * @param resp Pointer to a ByteDynArray receiving the response data.
   * @return StatusWord (SW1-SW2) returned by the card.
   */
  StatusWord Transmit(APDU &apdu, ByteDynArray *resp);

  /**
   * @brief Transmits a raw byte-array APDU command to the card.
   * @param apdu Raw APDU bytes.
   * @param resp Pointer to a ByteDynArray receiving the response data.
   * @return StatusWord (SW1-SW2) returned by the card.
   */
  StatusWord Transmit(ByteArray apdu, ByteDynArray *resp);
};
