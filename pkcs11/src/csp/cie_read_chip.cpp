// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_read_chip.cpp
 * @brief Read ICAO 9303 data groups from the CIE chip.
 *
 * Implements two public entry points:
 *   - cie_read_mrz  : reads EF.DG1 (MRZ) after PACE, returns raw TLV bytes
 *   - cie_read_photo: reads EF.DG2 (portrait) after PACE, returns PNG bytes
 *
 * DG2 contains a JPEG2000 (JP2) image wrapped in a BioAPI BIR TLV structure.
 * cie_read_photo extracts the JP2 payload, decodes it with OpenJPEG, and
 * re-encodes the result as PNG so Flutter's Image.memory() can display it
 * without any additional Dart-side decoding.
 */

#include <time.h>

#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "csp/cie_enable.h"
#include "csp/ias.h"
#include "logger/logger.h"
#include "pkcs11/pkcs11_functions.h"
#if defined(__ANDROID__)
#include "pcsc/android_nfc_transport.h"
#else
#include "pcsc/pcsc_transport.h"
#endif

// OpenJPEG for JPEG2000 decoding (HAVE_LIBOPENJP2 defined by meson when found)
#ifdef HAVE_LIBOPENJP2
#define HAVE_OPENJPEG 1
#include <openjpeg.h>
#endif

// libpng for PNG encoding
#include <png.h>

using namespace CieIDLogger;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#define ROLE_USER 1

/** @brief Silent progress callback used internally during chip reads. */
static CK_RV noopProgress(const int /*progress*/, const char* /*szMessage*/) {
  return CKR_OK;
}

// ---------------------------------------------------------------------------
// JP2 → PNG conversion
// ---------------------------------------------------------------------------

#ifdef HAVE_OPENJPEG

/**
 * @brief Find the start of the JP2/JPEG image payload inside a DG2 TLV blob.
 *
 * DG2 is a BioAPI BIR structure.  The actual image bytes are wrapped in
 * tag 0x5F2E (Biometric Data Block) or 0x7F2E (Biometric Information Group).
 * We scan for either tag and return a pointer to the image payload.
 *
 * @param data     Raw DG2 TLV bytes.
 * @param dataLen  Length of @p data.
 * @param imgLen   On success, set to the length of the image payload.
 * @return Pointer into @p data at the start of the image, or nullptr.
 */
static const uint8_t* findDG2ImagePayload(const uint8_t* data, size_t dataLen,
                                          size_t* imgLen) {
  // Walk BER-TLV looking for tag 0x5F2E or 0x7F2E
  size_t i = 0;
  while (i + 2 < dataLen) {
    // Decode tag (1 or 2 bytes)
    uint32_t tag = data[i];
    size_t tagLen = 1;
    if ((tag & 0x1f) == 0x1f) {
      // Multi-byte tag
      if (i + 1 >= dataLen) break;
      tag = (tag << 8) | data[i + 1];
      tagLen = 2;
    }
    i += tagLen;
    if (i >= dataLen) break;

    // Decode length
    size_t valLen = 0;
    if (data[i] <= 0x7f) {
      valLen = data[i];
      i += 1;
    } else if (data[i] == 0x81 && i + 1 < dataLen) {
      valLen = data[i + 1];
      i += 2;
    } else if (data[i] == 0x82 && i + 2 < dataLen) {
      valLen = (static_cast<size_t>(data[i + 1]) << 8) | data[i + 2];
      i += 3;
    } else if (data[i] == 0x83 && i + 3 < dataLen) {
      valLen = (static_cast<size_t>(data[i + 1]) << 16) |
               (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
      i += 4;
    } else {
      break;
    }

    if (i + valLen > dataLen) break;

    if (tag == 0x5F2E || tag == 0x7F2E) {
      // Found the biometric data block — scan for the actual image signature
      // within the payload (JPEG SOI or JP2 file signature box).
      const uint8_t* payload = data + i;
      for (size_t k = 0; k + 3 < valLen; ++k) {
        // JPEG SOI: FF D8 FF
        if (payload[k] == 0xFF && payload[k + 1] == 0xD8 &&
            payload[k + 2] == 0xFF) {
          *imgLen = valLen - k;
          return payload + k;
        }
        // JP2 file signature box: 00 00 00 0C 6A 50 20 20
        if (k + 7 < valLen && payload[k] == 0x00 && payload[k + 1] == 0x00 &&
            payload[k + 2] == 0x00 && payload[k + 3] == 0x0C &&
            payload[k + 4] == 0x6A && payload[k + 5] == 0x50) {
          *imgLen = valLen - k;
          return payload + k;
        }
        // JPEG2000 codestream (J2C): FF 4F FF 51
        if (k + 3 < valLen && payload[k] == 0xFF && payload[k + 1] == 0x4F &&
            payload[k + 2] == 0xFF && payload[k + 3] == 0x51) {
          *imgLen = valLen - k;
          return payload + k;
        }
      }
      // No image signature found — return whole value as fallback
      *imgLen = valLen;
      return payload;
    }

    // Check if constructed (bit 5 of first tag byte set) — recurse
    uint8_t firstTagByte = (tagLen == 2) ? static_cast<uint8_t>(tag >> 8)
                                         : static_cast<uint8_t>(tag);
    if (firstTagByte & 0x20) {
      // Constructed — recurse by not skipping the value
      continue;
    }

    i += valLen;
  }
  return nullptr;
}

/**
 * @brief Decode a JPEG2000 (JP2) buffer and encode the result as PNG.
 *
 * @param jp2Data   JP2 image bytes.
 * @param jp2Len    Length of @p jp2Data.
 * @param pngOut    On success, set to a malloc'd buffer containing PNG bytes.
 * @param pngLen    On success, set to the length of @p pngOut.
 * @return true on success.
 */
static bool jp2ToPng(const uint8_t* jp2Data, size_t jp2Len, uint8_t** pngOut,
                     size_t* pngLen) {
  *pngOut = nullptr;
  *pngLen = 0;

  // --- OpenJPEG decode ---
  opj_dparameters_t params;
  opj_set_default_decoder_parameters(&params);

  opj_codec_t* codec = opj_create_decompress(OPJ_CODEC_JP2);
  if (!codec) return false;

  // Suppress OpenJPEG log output
  opj_set_info_handler(codec, nullptr, nullptr);
  opj_set_warning_handler(codec, nullptr, nullptr);
  opj_set_error_handler(codec, nullptr, nullptr);

  if (!opj_setup_decoder(codec, &params)) {
    opj_destroy_codec(codec);
    return false;
  }

  // Build a read-only memory stream from the JP2 buffer
  struct MemStream {
    const uint8_t* data;
    size_t len;
    size_t pos;
  } ms {jp2Data, jp2Len, 0};

  opj_stream_t* stream = opj_stream_create(jp2Len, OPJ_TRUE);
  if (!stream) {
    opj_destroy_codec(codec);
    return false;
  }
  opj_stream_set_user_data(stream, &ms, nullptr);
  opj_stream_set_user_data_length(stream, static_cast<OPJ_UINT64>(jp2Len));
  opj_stream_set_read_function(
      stream, [](void* buf, OPJ_SIZE_T nb, void* ud) -> OPJ_SIZE_T {
        auto* m = static_cast<MemStream*>(ud);
        if (m->pos >= m->len) return static_cast<OPJ_SIZE_T>(-1);
        size_t avail = m->len - m->pos;
        size_t n = (nb < avail) ? nb : avail;
        memcpy(buf, m->data + m->pos, n);
        m->pos += n;
        return static_cast<OPJ_SIZE_T>(n);
      });
  opj_stream_set_skip_function(stream, [](OPJ_OFF_T nb, void* ud) -> OPJ_OFF_T {
    auto* m = static_cast<MemStream*>(ud);
    size_t newPos = m->pos + static_cast<size_t>(nb);
    if (newPos > m->len) newPos = m->len;
    m->pos = newPos;
    return static_cast<OPJ_OFF_T>(nb);
  });
  opj_stream_set_seek_function(stream, [](OPJ_OFF_T pos, void* ud) -> OPJ_BOOL {
    auto* m = static_cast<MemStream*>(ud);
    if (static_cast<size_t>(pos) > m->len) return OPJ_FALSE;
    m->pos = static_cast<size_t>(pos);
    return OPJ_TRUE;
  });

  opj_image_t* image = nullptr;
  if (!opj_read_header(stream, codec, &image)) {
    opj_stream_destroy(stream);
    opj_destroy_codec(codec);
    return false;
  }

  if (!opj_decode(codec, stream, image) || !opj_end_decompress(codec, stream)) {
    opj_image_destroy(image);
    opj_stream_destroy(stream);
    opj_destroy_codec(codec);
    return false;
  }

  opj_stream_destroy(stream);
  opj_destroy_codec(codec);

  const OPJ_UINT32 w = image->comps[0].w;
  const OPJ_UINT32 h = image->comps[0].h;
  const int ncomps = static_cast<int>(image->numcomps);

  if (w == 0 || h == 0 || ncomps < 1) {
    opj_image_destroy(image);
    return false;
  }

  // --- libpng encode ---
  // Write PNG into a memory buffer via custom write callback
  struct PngBuf {
    std::vector<uint8_t> data;
  } buf;

  png_structp png =
      png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png) {
    opj_image_destroy(image);
    return false;
  }

  png_infop info = png_create_info_struct(png);
  if (!info) {
    png_destroy_write_struct(&png, nullptr);
    opj_image_destroy(image);
    return false;
  }

  if (setjmp(png_jmpbuf(png))) {
    png_destroy_write_struct(&png, &info);
    opj_image_destroy(image);
    return false;
  }

  int stride = (ncomps >= 3) ? 3 : 1;

  // Pre-reserve PNG output buffer to avoid repeated reallocations.
  buf.data.reserve(static_cast<size_t>(w) * h * stride + 4096);

  // Custom write callback — appends to buf.data
  png_set_write_fn(
      png, &buf,
      [](png_structp p, png_bytep d, png_size_t n) {
        auto* b = static_cast<PngBuf*>(png_get_io_ptr(p));
        b->data.insert(b->data.end(), d, d + n);
      },
      nullptr);

  int colorType = (ncomps >= 3) ? PNG_COLOR_TYPE_RGB : PNG_COLOR_TYPE_GRAY;
  png_set_IHDR(png, info, w, h, 8, colorType, PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
  png_write_info(png, info);

  // Single reusable row buffer — avoids h separate heap allocations.
  const OPJ_INT32 prec = image->comps[0].prec;
  const OPJ_INT32 shift = (prec > 8) ? (prec - 8) : 0;
  std::vector<uint8_t> row(static_cast<size_t>(w) * stride);
  for (OPJ_UINT32 y = 0; y < h; ++y) {
    for (OPJ_UINT32 x = 0; x < w; ++x) {
      if (ncomps >= 3) {
        row[x * 3 + 0] =
            static_cast<uint8_t>(image->comps[0].data[y * w + x] >> shift);
        row[x * 3 + 1] =
            static_cast<uint8_t>(image->comps[1].data[y * w + x] >> shift);
        row[x * 3 + 2] =
            static_cast<uint8_t>(image->comps[2].data[y * w + x] >> shift);
      } else {
        row[x] = static_cast<uint8_t>(image->comps[0].data[y * w + x] >> shift);
      }
    }
    png_write_row(png, row.data());
  }

  png_write_end(png, nullptr);
  png_destroy_write_struct(&png, &info);
  opj_image_destroy(image);

  // Transfer ownership to caller
  *pngLen = buf.data.size();
  *pngOut = static_cast<uint8_t*>(malloc(*pngLen));
  if (!*pngOut) return false;
  memcpy(*pngOut, buf.data.data(), *pngLen);
  return true;
}

#endif  // HAVE_OPENJPEG

namespace {
/** @brief RAII guard releasing a PC/SC SCARDCONTEXT exactly once. */
class ScardContextGuard {
 public:
  ScardContextGuard(std::shared_ptr<ISmartCardTransport> transport,
                    SCARDCONTEXT hCardContext)
      : transport_(std::move(transport)), hContext_(hCardContext) {}
  ~ScardContextGuard() {
    if (hContext_) transport_->ReleaseContext(hContext_);
  }
  ScardContextGuard(const ScardContextGuard&) = delete;
  ScardContextGuard& operator=(const ScardContextGuard&) = delete;

 private:
  std::shared_ptr<ISmartCardTransport> transport_;
  SCARDCONTEXT hContext_;
};
}  // namespace

/**
 * @brief Single-session helper: PACE once, read DG1 and DG2 in sequence.
 *
 * Avoids the cost of a second full PACE session when both data groups are
 * needed.  The SM session (sessENC/sessMAC/sessSSC) persists across the two
 * ReadDG calls because they operate on the same IAS object.
 *
 * @param szPIN      NUL-terminated 8-digit numeric PIN.
 * @param dg1Out     Buffer for raw DG1 TLV bytes.
 * @param dg1Len     In: capacity; out: bytes written.
 * @param dg2Out     Buffer for raw DG2 TLV bytes.
 * @param dg2Len     In: capacity; out: bytes written.
 * @return CKR_OK on success.
 */
static CK_RV readBothDGs(const char* szPIN, uint8_t* dg1Out, size_t* dg1Len,
                         uint8_t* dg2Out, size_t* dg2Len) {
  if (!szPIN || !dg1Out || !dg1Len || !dg2Out || !dg2Len)
    return CKR_ARGUMENTS_BAD;
  if (strnlen(szPIN, 9) != 8) return CKR_PIN_LEN_RANGE;
  for (int i = 0; i < 8; ++i)
    if (szPIN[i] < '0' || szPIN[i] > '9') return CKR_PIN_INVALID;

  char* readers = nullptr;
  try {
#if defined(__ANDROID__)
    auto transport = std::make_shared<AndroidNFCTransport>();
#else
    auto transport = std::make_shared<PCSCTransport>();
#endif
    SCARDCONTEXT hSC = 0;
    long nRet = transport->EstablishContext(SCARD_SCOPE_USER, &hSC);
    if (nRet != SCARD_S_SUCCESS) return CKR_DEVICE_ERROR;
    ScardContextGuard hScGuard(transport, hSC);

    DWORD len = 0;
    nRet = transport->ListReaders(hSC, nullptr, &len);
    if (nRet != SCARD_S_SUCCESS || len <= 1) {
      return CKR_TOKEN_NOT_PRESENT;
    }
    readers = static_cast<char*>(malloc(len));
    if (!readers) {
      return CKR_HOST_MEMORY;
    }
    nRet = transport->ListReaders(hSC, readers, &len);
    if (nRet != SCARD_S_SUCCESS) {
      free(readers);
      return CKR_TOKEN_NOT_PRESENT;
    }

    bool found = false;
    for (char* cur = readers; cur[0] != '\0'; cur += strnlen(cur, len) + 1) {
      safeConnection conn(*transport, hSC, cur, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      // ATR — pre-allocate max size (ISO 7816: ATR ≤ 33 bytes)
      std::vector<BYTE> atrBuf(34);
      DWORD atrLen = static_cast<DWORD>(atrBuf.size());
      nRet = transport->GetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING,
                                  atrBuf.data(), &atrLen);
      if (nRet != SCARD_S_SUCCESS) continue;

      ByteArray atrBa(atrBuf.data(), atrLen);
      IAS ias(TokenTransmitCallback, atrBa);
      ias.SetCardContext(&conn);

      ias.token.Reset();
      ias.SelectAID_IAS();
      ias.ReadPAN();
      ias.SelectAID_CIE();

      ByteDynArray dappData;
      ias.ReadDappPubKey(dappData);

      ias.InitEncKey();

      int attempts = 0;
      LONG rs =
          CardAuthenticateEx(&ias, ROLE_USER, FULL_PIN,
                             reinterpret_cast<BYTE*>(const_cast<char*>(szPIN)),
                             static_cast<DWORD>(strnlen(szPIN, 9)), nullptr,
                             nullptr, noopProgress, &attempts);

      if (rs == static_cast<LONG>(SCARD_W_WRONG_CHV)) {
        free(readers);
        return CKR_PIN_INCORRECT;
      }
      if (rs == static_cast<LONG>(SCARD_W_CHV_BLOCKED)) {
        free(readers);
        return CKR_PIN_LOCKED;
      }
      if (rs != SCARD_S_SUCCESS) {
        free(readers);
        return CKR_GENERAL_ERROR;
      }

      // Read DG1 then DG2 on the same SM session — no second PACE needed.
      ByteDynArray dg1Data, dg2Data;
      try {
        ias.ReadDG1(dg1Data);
        ias.ReadDG2(dg2Data);
      } catch (const std::exception& e) {
        LOG_ERROR("readBothDGs - DG read threw: %s", e.what());
        free(readers);
        return CKR_GENERAL_ERROR;
      }

      if (dg1Data.size() > *dg1Len || dg2Data.size() > *dg2Len) {
        free(readers);
        return CKR_BUFFER_TOO_SMALL;
      }
      memcpy(dg1Out, dg1Data.data(), dg1Data.size());
      *dg1Len = dg1Data.size();
      memcpy(dg2Out, dg2Data.data(), dg2Data.size());
      *dg2Len = dg2Data.size();
      found = true;
      break;
    }

    free(readers);
    if (!found) return CKR_TOKEN_NOT_RECOGNIZED;

  } catch (const std::exception& ex) {
    LOG_ERROR("readBothDGs - exception: %s", ex.what());
    free(readers);
    return CKR_GENERAL_ERROR;
  } catch (...) {
    LOG_ERROR("readBothDGs - unknown exception");
    free(readers);
    return CKR_GENERAL_ERROR;
  }
  return CKR_OK;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

extern "C" {

/**
 * @brief Read DG1 (MRZ) and DG2 (photo) in a single PACE session.
 *
 * Eliminates the cost of a second full DH key exchange + PIN verify that
 * would occur if cie_read_mrz and cie_read_photo were called separately.
 * The photo is returned as PNG bytes (JP2 decoded via OpenJPEG).
 *
 * @param pin         NUL-terminated 8-digit numeric PIN.
 * @param mrzOut      Buffer for raw DG1 TLV bytes (≥ 4096 bytes recommended).
 * @param mrzLen      In: capacity; out: bytes written.
 * @param photoOut    Buffer for PNG photo bytes (≥ 524288 bytes recommended).
 * @param photoLen    In: capacity; out: bytes written.
 * @return CKR_OK on success, a PKCS#11 error code otherwise.
 */
CK_RV CK_ENTRY cie_read_dgs(const char* pin, char* mrzOut, size_t* mrzLen,
                            unsigned char* photoOut, size_t* photoLen) {
  LOG_INFO("***** Starting cie_read_dgs *****");

  std::vector<uint8_t> dg2Raw(*photoLen);
  size_t dg2RawLen = dg2Raw.size();

  CK_RV rv = readBothDGs(pin, reinterpret_cast<uint8_t*>(mrzOut), mrzLen,
                         dg2Raw.data(), &dg2RawLen);
  if (rv != CKR_OK) {
    LOG_INFO("***** cie_read_dgs ended (readBothDGs), rv=%lu *****",
             static_cast<unsigned long>(rv));
    return rv;
  }
  dg2Raw.resize(dg2RawLen);

#ifdef HAVE_OPENJPEG
  size_t imgLen = 0;
  const uint8_t* imgPtr =
      findDG2ImagePayload(dg2Raw.data(), dg2RawLen, &imgLen);
  if (imgPtr && imgLen > 0) {
    uint8_t* pngBuf = nullptr;
    size_t pngLen = 0;
    if (jp2ToPng(imgPtr, imgLen, &pngBuf, &pngLen)) {
      if (pngLen <= *photoLen) {
        memcpy(photoOut, pngBuf, pngLen);
        *photoLen = pngLen;
        free(pngBuf);
        LOG_INFO("***** cie_read_dgs ended (PNG %zu bytes) *****", pngLen);
        return CKR_OK;
      }
      free(pngBuf);
      *photoLen = pngLen;
      return CKR_BUFFER_TOO_SMALL;
    }
    LOG_ERROR("cie_read_dgs - jp2ToPng failed");
  } else {
    LOG_ERROR("cie_read_dgs - could not locate image payload in DG2");
  }
#endif

  if (dg2RawLen > *photoLen) return CKR_BUFFER_TOO_SMALL;
  memcpy(photoOut, dg2Raw.data(), dg2RawLen);
  *photoLen = dg2RawLen;
  LOG_INFO("***** cie_read_dgs ended (raw DG2 %zu bytes) *****", dg2RawLen);
  return CKR_OK;
}

}  // extern "C"
