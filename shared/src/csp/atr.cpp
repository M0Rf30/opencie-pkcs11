#include "csp/atr.h"

#include <algorithm>

#include "logger/logger.h"

using namespace CieIDLogger;
using namespace std;

cie_atr atr_list[] = {{CIE_Type::CIE_NXP,
                       "NXP",
                       {0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4E, 0x58, 0x50}},
                      {CIE_Type::CIE_Gemalto,
                       "Gemalto",
                       {0x80, 0x31, 0x80, 0x65, 0xB0, 0x85, 0x04, 0x00, 0x11}},
                      {CIE_Type::CIE_Gemalto2,
                       "Gemalto2",
                       {0x80, 0x31, 0x80, 0x65, 0xB0, 0x85, 0x03, 0x00, 0xEF}},
                      {CIE_Type::CIE_STM,
                       "STM",
                       {0x80, 0x66, 0x47, 0x50, 0x00, 0xB8, 0x00, 0x7F}},
                      {CIE_Type::CIE_STM2, "STM2", {0x80, 0x80, 0x01, 0x01}},
                      {CIE_Type::CIE_STM3,
                       "STM3",
                       {0x80, 0x01, 0x80, 0x66, 0x47, 0x50, 0x00, 0xB8, 0x00,
                        0x94, 0x82, 0x90, 0x00, 0xC5}},
                      {CIE_Type::CIE_ACTALIS,
                       "Actalis",
                       {0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4A,
                        0x34, 0x41, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00, 0x88}},
                      {CIE_Type::CIE_ACTALIS2,
                       "Actalis2023",
                       {0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4A,
                        0x34, 0x43, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00, 0x8A}},
                      {CIE_Type::CIE_BIT4ID,
                       "Bit4Id",
                       {0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4A,
                        0x34, 0x42, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00, 0x8B}},
                      {CIE_Type::CIE_BIT4ID2,
                       "Bit4Id2023",
                       {0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4A,
                        0x34, 0x44, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00, 0x8D}},
                      {CIE_Type::CIE_BIT4ID3,
                       "Bit4id_B9547",
                       {0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4A,
                        0x34, 0x49, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00, 0x80}}};

template <typename T>
bool IsSubset(const std::vector<T>& A, const std::vector<T>& B) {
  if (A.size() < B.size()) return false;

  std::vector<T> sortedA(A);
  std::vector<T> sortedB(B);
  sort(sortedA.begin(), sortedA.end());
  sort(sortedB.begin(), sortedB.end());
  return includes(sortedA.begin(), sortedA.end(), sortedB.begin(), sortedB.end());
}

string get_manufacturer(const vector<uint8_t>& atr) {
  for (const cie_atr& el : atr_list) {
    if (IsSubset(atr, el.atr)) {
      LOG_INFO("ReadCIEType - get_manufacturer() CIE %s detected",
               el.type.c_str());
      return el.type;
    }
  }
  LOG_INFO("ReadCIEType - get_manufacturer() Unkown CIE detected");
  return "";
}

CIE_Type get_type(const vector<uint8_t>& atr) {
  for (const cie_atr& el : atr_list) {
    if (IsSubset(atr, el.atr)) {
      LOG_INFO("ReadCIEType - cie_type() CIE %s detected", el.type.c_str());
      return el.cie_type;
    }
  }
  LOG_INFO("ReadCIEType - cie_type() Unkown CIE detected");
  return CIE_Type::CIE_Unknown;
}
