// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

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
  CIE_BIT4ID3,
  CIE_ACTALIS3
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

/**
 * @brief Collapse a revision-specific CIE_Type onto its behavioural family.
 *
 * Gemalto2 -> Gemalto, ACTALIS2/3 -> ACTALIS, BIT4ID2/3 -> BIT4ID; every
 * other value (including CIE_Unknown, STM*, NXP) is returned unchanged.
 * This is the type the IAS protocol layer switches on.
 */
CIE_Type cie_family(CIE_Type type);

/**
 * @brief Determine the CIE family for an ATR, tolerating unlisted variants.
 *
 * First tries an exact table match (see get_type()) and collapses it with
 * cie_family(). If nothing matches but the ATR carries the "ITJ4"
 * applet-family historical bytes (80 31 80 65 49 54 4A 34) with an unlisted
 * variant byte, CIE_ACTALIS is returned (and *usedFallback set to true).
 * @param atr           Raw ATR byte sequence from the smart card.
 * @param usedFallback  Optional; set to true only if the family fallback was
 *                      needed.
 * @return The CIE family, or CIE_Unknown if the chip is unsupported.
 */
CIE_Type get_family_type(const std::vector<uint8_t>& atr,
                         bool* usedFallback = nullptr);

/** @brief Format an ATR as upper-case space-separated hex (for logs). */
std::string atr_to_hex(const std::vector<uint8_t>& atr);
