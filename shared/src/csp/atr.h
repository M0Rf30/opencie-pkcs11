// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file atr.h
 * @brief ATR (Answer To Reset) parsing for CIE smart card
 * identification.
 *
 * Provides structures and functions to parse the ATR byte
 * sequence returned
 * by a smart card upon reset. This is used to identify the
 * CIE card type
 * and manufacturer (e.g., Gemalto, STMicroelectronics, NXP,
 * Actalis, Bit4id).
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

/** @brief Enumeration of known CIE card types by manufacturer and revision. */
enum CIE_Type {
  CIE_Unknown,
  CIE_Gemalto,
  CIE_Gemalto2,
  CIE_STM,
  CIE_STM2,
  CIE_STM3,
  CIE_NXP,
  CIE_ACTALIS,
  CIE_ACTALIS2,
  CIE_BIT4ID,
  CIE_BIT4ID2,
  CIE_BIT4ID3
};

/** @brief Structure associating a CIE card type with its ATR byte sequence. */
struct cie_atr {
  CIE_Type cie_type;        /**< Identified card type. */
  std::string type;         /**< Human-readable manufacturer/model name. */
  std::vector<uint8_t> atr; /**< Raw ATR byte sequence. */
};

/**
 * @brief Get the manufacturer name for a given ATR.
 * @param atr  Raw ATR
 * byte sequence from the smart card.
 * @return Human-readable manufacturer
 * string, or empty if unrecognized.
 */
std::string get_manufacturer(const std::vector<uint8_t>& atr);

/**
 * @brief Determine the CIE card type from a given ATR.
 * @param atr  Raw
 * ATR byte sequence from the smart card.
 * @return The matching CIE_Type, or
 * CIE_Unknown if the ATR is not recognized.
 */
CIE_Type get_type(const std::vector<uint8_t>& atr);
