// SPDX-License-Identifier: LGPL-3.0-or-later
#include "sign/cie_sign.h"

#include <cstring>

#include "logger/logger.h"
#include "sign/cie_sign_api.h"

using namespace CieIDLogger;

CIESign::CIESign(IAS* ias) { this->ias = ias; }

CIESign::~CIESign() = default;

uint16_t CIESign::sign(const char* inFilePath, const char* type,
                       const char* pin, int page, float x, float y, float w,
                       float h, const unsigned char* imageData,
                       int imageDataLen, const char* outFilePath) {
  uint16_t response;

  CIE_SIGN_CTX ctx = nullptr;
  long ret = 0;

  try {
    ctx = cie_sign_sign_init();

    ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_IAS_INSTANCE, (this->ias));
    if (ret != 0) {
      throw ret;
    }
    ret =
        cie_sign_sign_set(ctx, CIE_SIGN_OPT_CADES, reinterpret_cast<void*>(1));
    if (ret != 0) {
      throw ret;
    }
    ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PIN,
                            static_cast<void*>(const_cast<char*>(pin)));
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_INPUTFILE,
                            static_cast<void*>(const_cast<char*>(inFilePath)));
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_OUTPUTFILE,
                            static_cast<void*>(const_cast<char*>(outFilePath)));
    if (ret != 0) {
      throw ret;
    }

    if (strcmp(type, "xml") == 0) {
      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_INPUTFILE_TYPE,
                              reinterpret_cast<void*>(CIE_SIGN_FILETYPE_XML));
      if (ret != 0) {
        throw ret;
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_DETACHED,
                              reinterpret_cast<void*>(0));
      if (ret != 0) {
        throw ret;
      }
    } else if (strcmp(type, "pdf") == 0) {
      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_SUBFILTER,
                              static_cast<void*>(const_cast<char*>(
                                  CIE_SIGN_PDF_SUBFILTER_ETSI_CADES)));
      if (ret != 0) {
        throw ret;
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_PAGE,
                              static_cast<void*>(&page));
      if (ret != 0) {
        throw ret;
      }

      ret =
          cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_LEFT, static_cast<void*>(&x));
      if (ret != 0) {
        throw ret;
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_BOTTOM,
                              static_cast<void*>(&y));
      if (ret != 0) {
        throw ret;
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_WIDTH,
                              static_cast<void*>(&w));
      if (ret != 0) {
        throw ret;
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_HEIGHT,
                              static_cast<void*>(&h));
      if (ret != 0) {
        throw ret;
      }

      if (imageData && imageDataLen > 0) {
        ret = cie_sign_sign_set(
            ctx, CIE_SIGN_OPT_PDF_IMAGEDATA,
            static_cast<void*>(const_cast<unsigned char*>(imageData)));
        if (ret != 0) {
          throw ret;
        }
        ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_PDF_IMAGEDATA_LEN,
                                reinterpret_cast<void*>(imageDataLen));
        if (ret != 0) {
          throw ret;
        }
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_INPUTFILE_TYPE,
                              reinterpret_cast<void*>(CIE_SIGN_FILETYPE_PDF));
      if (ret != 0) {
        throw ret;
      }
    } else {
      ret = cie_sign_sign_set(
          ctx, CIE_SIGN_OPT_INPUTFILE_TYPE,
          reinterpret_cast<void*>(CIE_SIGN_FILETYPE_PLAINTEXT));

      if (ret != 0) {
        throw ret;
      }

      ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_DETACHED,
                              reinterpret_cast<void*>(0));
      if (ret != 0) {
        throw ret;
      }
    }

    ret = cie_sign_sign_set(ctx, CIE_SIGN_OPT_VERIFY_USER_CERTIFICATE, 0);
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_sign_sign(ctx);
    if (ret != 0) {
      throw ret;
    }
  } catch (long err) {
    LOG_ERROR("CIESign::sign error %d", err);
  }

  if (ctx) cie_sign_sign_cleanup(ctx);

  response = ret;

  return response;
}
