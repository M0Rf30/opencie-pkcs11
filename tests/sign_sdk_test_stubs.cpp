// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Link-time stubs for pkcs11 smart-card/UI glue symbols.
//
// shared/src/csp/ias.cpp (part of libcie_shared) declares and calls these,
// and gets pulled into the sign-sdk test binary transitively because
// sign-sdk/src/cie_sign_api.cpp (part of libcie_sign_sdk) references the
// IAS class. The certificate/cert_store tests in this directory never
// construct an IAS instance or exercise a code path that reaches these
// functions; they only exist here to satisfy the linker without dragging
// in the real implementations (pkcs11/src/pkcs11/cie_p11_template.cpp and
// pkcs11/src/csp/cie_enable.cpp), which pull in PC/SC card-session and UI
// notification plumbing unrelated to ASN.1 parsing.
#include <cstddef>
#include <cstdint>

#include "util/array.h"

void GetPublicKeyFromCert(const uint8_t* /*certDer*/, size_t /*certLen*/,
                          ByteDynArray& /*pubKeyOut*/,
                          ByteDynArray& /*issuerOut*/,
                          ByteDynArray& /*serialOut*/) {}

void notifyCardNotRegistered(const char* /*szPAN*/) {}
