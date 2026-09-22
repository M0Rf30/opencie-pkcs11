// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pcsc/transport_factory.h"

#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif

#if defined(__linux__) && !defined(__ANDROID__)
#include <cstdlib>
#include <cstring>

#include "pcsc/linux_nfc_transport.h"
#endif

SmartCardTransportPtr createSmartCardTransport() {
#if defined(__ANDROID__)
  return std::make_shared<AndroidNFCTransport>();
#else
#if defined(__linux__)
  /* Linux phones (postmarketOS and friends) have no PC/SC reader: their NFC
   * controller is driven by the kernel NFC subsystem. Opt in explicitly so
   * desktop Linux keeps using pcscd unchanged. */
  const char *backend = std::getenv("OPENCIE_NFC_BACKEND");
  if (backend && std::strcmp(backend, "kernel") == 0)
    return std::make_shared<LinuxNFCTransport>();
#endif
  return std::make_shared<PCSCTransport>();
#endif
}
