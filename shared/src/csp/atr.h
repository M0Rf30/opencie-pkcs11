#pragma once

#include <cstdint>

#include <string>
#include <vector>

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

struct cie_atr {
  CIE_Type cie_type;
  std::string type;
  std::vector<uint8_t> atr;
};
std::string get_manufacturer(const std::vector<uint8_t>& atr);
CIE_Type get_type(const std::vector<uint8_t>& atr);

