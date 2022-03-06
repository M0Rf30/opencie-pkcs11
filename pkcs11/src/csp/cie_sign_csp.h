// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "csp/cie_enable.h"
#include "pkcs11/cryptoki.h"

typedef CK_CALLBACK_FUNCTION(CK_RV, SIGN_COMPLETED_CALLBACK)(const int ret);

using cie_sign_fn = CK_RV (*)(const char* inFilePath, const char* type,
                               const char* pin, const char* pan, int page,
                               float x, float y, float w, float h,
                               const char* imagePathFile,
                               const char* outFilePath,
                               PROGRESS_CALLBACK progressCallBack,
                               SIGN_COMPLETED_CALLBACK completedCallBack);

