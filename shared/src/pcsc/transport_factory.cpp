// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pcsc/transport_factory.h"

#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif

SmartCardTransportPtr createSmartCardTransport() {
#if defined(__ANDROID__)
  return std::make_shared<AndroidNFCTransport>();
#else
  return std::make_shared<PCSCTransport>();
#endif
}
