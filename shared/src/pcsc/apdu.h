// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file apdu.h
 * @brief APDU (Application Protocol Data Unit) command structure.
 *
 * Defines the APDU class used to construct ISO 7816-4 command APDUs for
 * communication with CIE smart cards.
 */

#pragma once
#include <cstdint>
#include <functional>

class CToken;

/**
 * @brief Represents an ISO 7816-4 APDU command.
 *
 * Encapsulates the header (CLA, INS, P1, P2), optional data field, and
 * optional expected-length (LE) byte of a smart card command APDU.  Multiple
 * constructors cover the four standard ISO 7816 APDU cases.
 */
class APDU {
 public:
  /** Constructs an empty APDU with default values. */
  APDU();

  /**
   * @brief Case 4 APDU: command data and expected response length.
   * @param CLA   Class byte.
   * @param INS   Instruction byte.
   * @param P1    Parameter 1.
   * @param P2    Parameter 2.
   * @param LC    Length of the command data field.
   * @param pData Pointer to the command data bytes.
   * @param LE    Expected length of the response data.
   */
  APDU(uint8_t CLA, uint8_t INS, uint8_t P1, uint8_t P2, uint8_t LC,
       uint8_t *pData, uint8_t LE);

  /**
   * @brief Case 3 APDU: command data, no expected response.
   * @param CLA   Class byte.
   * @param INS   Instruction byte.
   * @param P1    Parameter 1.
   * @param P2    Parameter 2.
   * @param LC    Length of the command data field.
   * @param pData Pointer to the command data bytes.
   */
  APDU(uint8_t CLA, uint8_t INS, uint8_t P1, uint8_t P2, uint8_t LC,
       uint8_t *pData);

  /**
   * @brief Case 2 APDU: no command data, expected response length.
   * @param CLA Class byte.
   * @param INS Instruction byte.
   * @param P1  Parameter 1.
   * @param P2  Parameter 2.
   * @param LE  Expected length of the response data.
   */
  APDU(uint8_t CLA, uint8_t INS, uint8_t P1, uint8_t P2, uint8_t LE);

  /**
   * @brief Case 1 APDU: header only, no data and no expected response.
   * @param CLA Class byte.
   * @param INS Instruction byte.
   * @param P1  Parameter 1.
   * @param P2  Parameter 2.
   */
  APDU(uint8_t CLA, uint8_t INS, uint8_t P1, uint8_t P2);

  /** Destructor. */
  ~APDU();

  uint8_t btINS;     ///< Instruction byte of the APDU.
  uint8_t btCLA;     ///< Class byte of the APDU.
  uint8_t btP1;      ///< Parameter 1 of the APDU.
  uint8_t btP2;      ///< Parameter 2 of the APDU.
  uint8_t btLC;      ///< Length of the command data field.
  bool bLC;          ///< Flag: include the data field? (cases 3 and 4).
  uint8_t *pbtData;  ///< Pointer to the APDU command data field.
  uint8_t btLE;      ///< Expected response length byte.
  bool bLE;          ///< Flag: include LE? (cases 2 and 4).
};
