// SPDX-License-Identifier: LGPL-3.0-or-later
#include "sign/cie_verify.h"

#include "logger/logger.h"

using namespace CieIDLogger;

CIEVerify::CIEVerify() {}

CIEVerify::~CIEVerify() {}

long CIEVerify::verify(const char* input_file, VERIFY_RESULT* verifyResult,
                       const char* proxy_address, int proxy_port,
                       const char* userPass) {
  try {
    CIE_SIGN_CTX ctx;

    long ret;
    ctx = cie_sign_verify_init();

#if 1
    ret = cie_sign_set_int(CIE_SIGN_OPT_LOG_LEVEL, LOG_TYPE_DEBUG);
#endif

    ret =
        cie_sign_verify_set(ctx, CIE_SIGN_OPT_INPUTFILE,
                            static_cast<void*>(const_cast<char*>(input_file)));
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_verify_set(ctx, CIE_SIGN_OPT_INPUTFILE_TYPE,
                              reinterpret_cast<void*>(CIE_SIGN_FILETYPE_AUTO));
    if (ret != 0) {
      throw ret;
    }

    // PARAMETRO 0 non usa verifica OCSP
    // PARAMETRO 1 OK OCSP
    ret = cie_sign_verify_set(ctx, CIE_SIGN_OPT_VERIFY_REVOCATION,
                              reinterpret_cast<void*>(1));
    if (ret != 0) {
      throw ret;
    }

    if (proxy_address) {
      ret = cie_sign_verify_set(
          ctx, CIE_SIGN_OPT_PROXY,
          static_cast<void*>(const_cast<char*>(proxy_address)));
      if (ret != 0) {
        throw ret;
      }

      if (proxy_port == 0) {
        LOG_ERROR("CIEVerify::invalid proxy port");
        return CIE_SIGN_ERROR_INVALID_SIGOPT;
      } else {
        ret = cie_sign_verify_set(ctx, CIE_SIGN_OPT_PROXY_PORT, &proxy_port);
        if (ret != 0) {
          throw ret;
        }

        if (userPass) {
          ret = cie_sign_verify_set(
              ctx, CIE_SIGN_OPT_PROXY_USRPASS,
              static_cast<void*>(const_cast<char*>(userPass)));
          if (ret != 0) {
            throw ret;
          }
        }
      }
    }

    ret = cie_sign_verify_verify(ctx, verifyResult);
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_verify_cleanup(ctx);
    if (ret != 0) {
      throw ret;
    }

    return ret;

  } catch (long err) {
    LOG_ERROR("CIEVerify::verify error: %lx", err);
  }

  return 0;
}

long CIEVerify::get_file_from_p7m(const char* input_file,
                                  const char* output_file) {
  try {
    CIE_SIGN_CTX ctx;

    long ret;
    ctx = cie_sign_verify_init();

#if 1
    ret = cie_sign_set_int(CIE_SIGN_OPT_LOG_LEVEL, LOG_TYPE_DEBUG);
#endif

    ret =
        cie_sign_verify_set(ctx, CIE_SIGN_OPT_INPUTFILE,
                            static_cast<void*>(const_cast<char*>(input_file)));
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_verify_set(ctx, CIE_SIGN_OPT_INPUTFILE_TYPE,
                              reinterpret_cast<void*>(CIE_SIGN_FILETYPE_AUTO));
    if (ret != 0) {
      throw ret;
    }

    ret =
        cie_sign_verify_set(ctx, CIE_SIGN_OPT_OUTPUTFILE,
                            static_cast<void*>(const_cast<char*>(output_file)));
    if (ret != 0) {
      throw ret;
    }

    ret = cie_sign_get_file_from_p7m(ctx);
    if (ret != 0) {
      throw ret;
    }

    return ret;
  } catch (long err) {
    LOG_ERROR("CIEVerify::verify error: %lx", err);
    return err;
  }
}
