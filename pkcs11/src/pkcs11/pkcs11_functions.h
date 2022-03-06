#pragma once

#include "pcsc/scard_types.h"

#include "pkcs11/cryptoki.h"

#define MAXVAL 0xffffff
#define MAXSESSIONS MAXVAL

#ifdef _WIN32
#define CK_ENTRY __declspec(dllexport)
#else
#define CK_ENTRY __attribute__((visibility("default")))
#endif
#define LIBRARY_VERSION_MAJOR 2
#define LIBRARY_VERSION_MINOR 0

#define PIN_LEN 8
#define USER_PIN_ID 0x10


#include "logger/logger.h"
extern "C" {
CK_RV CK_ENTRY C_UpdateSlotList();
}
