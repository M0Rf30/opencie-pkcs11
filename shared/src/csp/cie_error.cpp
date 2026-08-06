// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "csp/cie_error.h"

namespace {

struct CieErrorRecord {
  cie_error_kind kind = CIE_ERR_NONE;
  uint16_t sw = 0;
};

thread_local CieErrorRecord g_lastError;

}  // namespace

extern "C" cie_error_kind CK_ENTRY cie_classify_sw(uint16_t sw) {
  if (sw >= 0x63C0 && sw <= 0x63CF) return CIE_ERR_WRONG_PIN;

  switch (sw) {
    case 0x9000:
      return CIE_ERR_NONE;
    case 0x6300:
    case 0x6700:
      return CIE_ERR_WRONG_PIN;
    case 0x6983:
      return CIE_ERR_PIN_BLOCKED;
    case 0x6984:
      return CIE_ERR_PIN_NOT_SET;
    case 0x6982:
      return CIE_ERR_SECURITY_NOT_SATISFIED;
    case 0x6A82:
      return CIE_ERR_FILE_NOT_FOUND;
    case 0x6A80:
    case 0x6A86:
    case 0x6A88:
    case 0x6B00:
      return CIE_ERR_WRONG_PARAMS;
    case 0x6D00:
    case 0x6E00:
      return CIE_ERR_INS_NOT_SUPPORTED;
    default:
      return CIE_ERR_UNKNOWN;
  }
}

extern "C" CK_RV CK_ENTRY cie_last_error(cie_error_kind* outKind,
                                         uint16_t* outSw) {
  if (outKind != nullptr) *outKind = g_lastError.kind;
  if (outSw != nullptr) *outSw = g_lastError.sw;
  return CKR_OK;
}

void cie_record_sw_error(uint16_t sw) {
  g_lastError.kind = cie_classify_sw(sw);
  g_lastError.sw = sw;
}

void cie_record_transport_error() {
  g_lastError.kind = CIE_ERR_CARD_COMMUNICATION;
  g_lastError.sw = 0;
}

void cie_clear_error() {
  g_lastError.kind = CIE_ERR_NONE;
  g_lastError.sw = 0;
}
