#include "sign/cie_sign.h"

#include <cstring>

#include "logger/logger.h"
#include "sign/disigonsdk.h"

using namespace CieIDLogger;

CIESign::CIESign(IAS* ias) { this->ias = ias; }

uint16_t CIESign::sign(const char* inFilePath, const char* type,
                       const char* pin, int page, float x, float y, float w,
                       float h, const char* imagePathFile,
                       const char* outFilePath) {
  uint16_t response;

  DISIGON_CTX ctx = nullptr;
  long ret = 0;

  try {
    ctx = disigon_sign_init();

#if 0
        ret = disigon_set(DISIGON_OPT_LOG_LEVEL, reinterpret_cast<void*>(LOG_TYPE_DEBUG));
        if (ret != 0) {
            throw ret;
        }
#endif

    ret = disigon_sign_set(ctx, DISIGON_OPT_IAS_INSTANCE, (this->ias));
    if (ret != 0) {
      throw ret;
    }
    ret = disigon_sign_set(ctx, DISIGON_OPT_CADES, reinterpret_cast<void*>(1));
    if (ret != 0) {
      throw ret;
    }
    ret = disigon_sign_set(ctx, DISIGON_OPT_PIN,
                           static_cast<void*>(const_cast<char*>(pin)));
    if (ret != 0) {
      throw ret;
    }

    ret = disigon_sign_set(ctx, DISIGON_OPT_INPUTFILE,
                           static_cast<void*>(const_cast<char*>(inFilePath)));
    if (ret != 0) {
      throw ret;
    }

    ret = disigon_sign_set(ctx, DISIGON_OPT_OUTPUTFILE,
                           static_cast<void*>(const_cast<char*>(outFilePath)));
    if (ret != 0) {
      throw ret;
    }

    if (strcmp(type, "pdf") == 0) {
      ret = disigon_sign_set(
          ctx, DISIGON_OPT_PDF_SUBFILTER,
          static_cast<void*>(const_cast<char*>(DISIGON_PDF_SUBFILTER_ETSI_CADES)));
      if (ret != 0) {
        throw ret;
      }

      ret = disigon_sign_set(ctx, DISIGON_OPT_PDF_PAGE,
                             static_cast<void*>(&page));
      if (ret != 0) {
        throw ret;
      }

      ret = disigon_sign_set(ctx, DISIGON_OPT_PDF_LEFT, static_cast<void*>(&x));
      if (ret != 0) {
        throw ret;
      }

      ret =
          disigon_sign_set(ctx, DISIGON_OPT_PDF_BOTTOM, static_cast<void*>(&y));
      if (ret != 0) {
        throw ret;
      }

      ret =
          disigon_sign_set(ctx, DISIGON_OPT_PDF_WIDTH, static_cast<void*>(&w));
      if (ret != 0) {
        throw ret;
      }

      ret =
          disigon_sign_set(ctx, DISIGON_OPT_PDF_HEIGHT, static_cast<void*>(&h));
      if (ret != 0) {
        throw ret;
      }

      if (imagePathFile) {
        ret = disigon_sign_set(
            ctx, DISIGON_OPT_PDF_IMAGEPATH,
            static_cast<void*>(const_cast<char*>(imagePathFile)));
        if (ret != 0) {
          throw ret;
        }
      }

      ret = disigon_sign_set(ctx, DISIGON_OPT_INPUTFILE_TYPE,
                             reinterpret_cast<void*>(DISIGON_FILETYPE_PDF));
      if (ret != 0) {
        throw ret;
      }
    } else {
      if ((strstr(inFilePath, "p7m") != nullptr) ||
          (strstr(inFilePath, "p7s") != nullptr))
        ret = disigon_sign_set(ctx, DISIGON_OPT_INPUTFILE_TYPE,
                               reinterpret_cast<void*>(DISIGON_FILETYPE_P7M));
      else
        ret = disigon_sign_set(
            ctx, DISIGON_OPT_INPUTFILE_TYPE,
            reinterpret_cast<void*>(DISIGON_FILETYPE_PLAINTEXT));

      if (ret != 0) {
        throw ret;
      }

      ret = disigon_sign_set(ctx, DISIGON_OPT_DETACHED,
                             reinterpret_cast<void*>(0));
      if (ret != 0) {
        throw ret;
      }
    }

    ret = disigon_sign_set(ctx, DISIGON_OPT_VERIFY_USER_CERTIFICATE, 0);
    if (ret != 0) {
      throw ret;
    }

    ret = disigon_sign_sign(ctx);
    if (ret != 0) {
      throw ret;
    }
  } catch (long err) {
    LOG_ERROR("CIESign::sign error %d", err);
  }

  if (ctx) disigon_sign_cleanup(ctx);

  response = ret;

  return response;
}
