// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * Transport factory for the platform smart-card backend.
 *
 * Centralizing selection here keeps PKCS#11 operations independent of the
 * platform transport. A future Linux raw-NFC transport can be selected here
 * without changing every operation path.
 */
#pragma once

#include "smart_card_transport.h"

/** Returns the runtime smart-card transport for the current platform. */
SmartCardTransportPtr createSmartCardTransport();
