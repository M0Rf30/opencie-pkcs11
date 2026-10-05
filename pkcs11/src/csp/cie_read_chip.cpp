// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_read_chip.cpp
 * @brief Read ICAO 9303 data groups from the CIE chip.
 *
 * Public entry points:
 *   - cie_read_dgs_can(): authenticates to the eMRTD application with
 *     ICAO 9303-11 PACE using the 6-digit Card Access Number (CAN), then
 *     reads EF.DG1 (MRZ) and EF.DG2 (portrait) through the resulting Secure
 *     Messaging channel (see csp/pace.h). The PIN is never involved.
 *   - cie_read_dgs(): PIN based fallback (IAS DH + VERIFY PIN) for readers
 *     that cannot send the extended-length APDUs the CAN PACE needs.
 *
 * DG2 contains a JPEG2000 (JP2) image wrapped in a BioAPI BIR TLV structure.
 * It is extracted, decoded with OpenJPEG and re-encoded as PNG so Flutter's
 * Image.memory() can display it without any additional Dart-side decoding.
 */

#include <time.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "csp/cie_enable.h"
#include "csp/cie_error.h"
#include "csp/ias.h"
#include "csp/pace.h"
#include "logger/logger.h"
#include "pcsc/token.h"
#include "pcsc/transport_factory.h"
#include "pkcs11/pkcs11_functions.h"
#include "util/retry.h"
#include "util/util_exception.h"

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

/**
 * @brief Turn a raw DG2 TLV into the PNG photo (or the raw DG2 when the
 * JPEG2000 payload cannot be decoded) in the caller's buffer.
 *
 * @param op  Entry-point name for log messages.
 */
static CK_RV dg2ToPhoto(const std::vector<uint8_t>& dg2Raw,
                        unsigned char* photoOut, size_t* photoLen,
                        const char* op) {
  const size_t dg2RawLen = dg2Raw.size();
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
        LOG_INFO("***** %s ended (PNG %zu bytes) *****", op, pngLen);
        return CKR_OK;
      }
      free(pngBuf);
      *photoLen = pngLen;
      return CKR_BUFFER_TOO_SMALL;
    }
    LOG_ERROR("%s - jp2ToPng failed", op);
  } else {
    LOG_ERROR("%s - could not locate image payload in DG2", op);
  }
#endif

  if (dg2RawLen > *photoLen) return CKR_BUFFER_TOO_SMALL;
  memcpy(photoOut, dg2Raw.data(), dg2RawLen);
  *photoLen = dg2RawLen;
  LOG_INFO("***** %s ended (raw DG2 %zu bytes) *****", op, dg2RawLen);
  return CKR_OK;
}

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

/**
 * Thrown when the reader/transport refuses an extended-length APDU (the
 * 2048-bit DH group of the CIE needs 264-byte GENERAL AUTHENTICATE data).
 * Not a link drop: nothing CAN-related was sent yet.
 */
class ExtendedApduRejected : public std::runtime_error {
 public:
  ExtendedApduRejected()
      : std::runtime_error("reader rejected an extended-length APDU") {}
};

/** Translate a failed pace::Result into the exception/CK_RV contract. */
CK_RV failFromResult(const char* op, const pace::Result& r) {
  if (r.linkError) throw card_link_error(r.detail);
  LOG_ERROR("readBothDGs - %s failed: %s", op, r.detail.c_str());
  if (r.sw != 0 && r.sw != 0x9000) cie_record_sw_error(r.sw);
  return CKR_GENERAL_ERROR;
}

/** True when a failed EF.CardAccess read means "no PACE on this chip". */
bool cardAccessMissing(uint16_t sw) {
  return sw == 0x6A82 || sw == 0x6A83 || sw == 0x6A88 || sw == 0x6D00 ||
         sw == 0x6E00 || sw == 0x6986 || sw == 0x6982 || sw == 0x6985;
}
}  // namespace

/**
 * @brief Single attempt of the single-session helper: PACE once, read DG1
 * and DG2 in sequence.
 *
 * Avoids the cost of a second full PACE session when both data groups are
 * needed.  The SM session (sessENC/sessMAC/sessSSC) persists across the two
 * ReadDG calls because they operate on the same IAS object.
 *
 * A card_link_error (RF link drop / short response / SM MAC failure --
 * see util/util_exception.h) propagates to the caller uncaught so
 * readBothDGs() can retry the whole attempt with a fresh connection; any
 * other exception is handled here and turned into a CK_RV.
 *
 * @param szPIN      NUL-terminated 8-digit numeric PIN.
 * @param dg1Out     Buffer for raw DG1 TLV bytes.
 * @param dg1Len     In: capacity; out: bytes written.
 * @param dg2Out     Buffer for raw DG2 TLV bytes.
 * @param dg2Len     In: capacity; out: bytes written.
 * @return CKR_OK on success.
 * @throws card_link_error on a transport/link failure -- not handled
 *         here, see readBothDGs().
 */
static CK_RV readBothDGsOnce(const char* szPIN, uint8_t* dg1Out, size_t* dg1Len,
                             uint8_t* dg2Out, size_t* dg2Len) {
  char* readers = nullptr;
  try {
    auto transport = createSmartCardTransport();
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
    bool sawUnsupported = false;
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
      try {
        ias.SelectAID_IAS();
      } catch (const cie_unsupported_card_error& e) {
        // Unsupported chip in this reader: keep scanning the other readers.
        LOG_ERROR("readBothDGs - %s", e.what());
        sawUnsupported = true;
        continue;
      }
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
      } catch (const card_link_error&) {
        // Let readBothDGs() retry the whole attempt from scratch; freed
        // once by the outer catch below.
        throw;
      } catch (const scard_error& e) {
        // Card answered with a definite status word (e.g. 6A82 file not
        // found): record it so cie_last_error() reports the real cause.
        // Not a link drop, so never retried by readBothDGs().
        LOG_ERROR("readBothDGs - DG read failed with sw=%04x: %s",
                  static_cast<unsigned>(e.sw), e.what());
        cie_record_sw_error(static_cast<uint16_t>(e.sw));
        free(readers);
        return CKR_GENERAL_ERROR;
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
    if (!found) {
      if (sawUnsupported) cie_record_unsupported_card();
      return CKR_TOKEN_NOT_RECOGNIZED;
    }

  } catch (const card_link_error&) {
    free(readers);
    throw;
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

/**
 * @brief Read DG1 and DG2, retrying the whole attempt (fresh connection,
 * reset, PACE/DH, SM, VERIFY PIN, DG1+DG2 read) up to two more times if a
 * card_link_error (RF link drop / short response / SM MAC failure) is
 * detected.
 *
 * A card_link_error means the previous attempt never got a trustworthy
 * status word back from the card, so no PIN attempt is known to have
 * been consumed by a *wrong* PIN; retrying with the same PIN is safe
 * (see util/retry.h and AGENTS.md PIN-safety rules). A wrong/blocked PIN
 * is reported by readBothDGsOnce() as an ordinary CK_RV, never as an
 * exception, so it is never retried here.
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

  try {
    return RetryOnCardLinkError("cie_read_dgs", 3, [&](int attempt) {
      if (attempt == 1)
        return readBothDGsOnce(szPIN, dg1Out, dg1Len, dg2Out, dg2Len);
      // After a link drop the card is often still off the reader (it was
      // lifted or slid). Give the user up to ~10 s to put it back instead
      // of failing with "token not recognized" on the first poll.
      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(10);
      CK_RV rv;
      do {
        rv = readBothDGsOnce(szPIN, dg1Out, dg1Len, dg2Out, dg2Len);
        if (rv != CKR_TOKEN_NOT_RECOGNIZED && rv != CKR_TOKEN_NOT_PRESENT)
          return rv;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
      } while (std::chrono::steady_clock::now() < deadline);
      LOG_ERROR("cie_read_dgs - card did not return to the reader");
      return rv;
    });
  } catch (const card_link_error& e) {
    LOG_ERROR("readBothDGs - giving up after retries: %s", e.what());
    cie_record_transport_error();
    return CKR_DEVICE_ERROR;
  } catch (const std::exception& ex) {
    LOG_ERROR("readBothDGs - exception: %s", ex.what());
    return CKR_GENERAL_ERROR;
  } catch (...) {
    LOG_ERROR("readBothDGs - unknown exception");
    return CKR_GENERAL_ERROR;
  }
}

/**
 * @brief Single attempt: PACE with the CAN once, then read DG1 and DG2 on
 * the same Secure Messaging channel.
 *
 * A card_link_error (RF link drop / short response / SM MAC failure -- see
 * util/util_exception.h) propagates to the caller uncaught so readBothDGsCan()
 * can retry the whole attempt with a fresh connection; any other
 * exception is handled here and turned into a CK_RV.
 *
 * A wrong CAN is returned as CKR_PIN_INCORRECT (never an exception, so it
 * is never retried) and recorded as CIE_ERR_WRONG_CAN. A chip that offers
 * no supported PACE protocol is CKR_FUNCTION_NOT_SUPPORTED.
 *
 * @param can        NUL-terminated 6-digit CAN.
 * @param dg1Out     Buffer for raw DG1 TLV bytes.
 * @param dg1Len     In: capacity; out: bytes written.
 * @param dg2Out     Buffer for raw DG2 TLV bytes.
 * @param dg2Len     In: capacity; out: bytes written.
 * @return CKR_OK on success.
 * @throws card_link_error on a transport/link failure -- not handled
 *         here, see readBothDGsCan().
 */
static CK_RV readBothDGsCanOnce(const char* can, uint8_t* dg1Out,
                                size_t* dg1Len, uint8_t* dg2Out,
                                size_t* dg2Len) {
  char* readers = nullptr;
  try {
    auto transport = createSmartCardTransport();
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
    bool sawUnsupported = false;
    bool sawResetRequired = false;
    for (char* cur = readers; cur[0] != '\0'; cur += strnlen(cur, len) + 1) {
      safeConnection conn(*transport, hSC, cur, SCARD_SHARE_SHARED);
      if (!conn.hCard) continue;

      CToken token;
      token.setTransmitCallback(TokenTransmitCallback, &conn);
      // Fresh card state: PACE must start from the MF, before any IAS/CIE
      // application is selected.
      token.Reset();

      const pace::Transmit tx = [&token](const pace::Bytes& apdu,
                                         pace::Bytes& resp) -> uint16_t {
        ByteDynArray r;
        const ByteArray in(const_cast<uint8_t*>(apdu.data()), apdu.size());
        // The final GENERAL AUTHENTICATE carries our authentication token:
        // if the link drops while it is in flight the card may have counted
        // a wrong CAN whose answer we never saw, so it must not be resent.
        const bool mutualAuth =
            apdu.size() >= 2 && apdu[0] == 0x00 && apdu[1] == 0x86;
        // Longer than any short-APDU reader can carry (ACR122U/libccid
        // refuse >~260 bytes with SCARD_E_NOT_TRANSACTED and friends).
        const bool extended = apdu.size() > 261;
        StatusWord sw;
        try {
          sw = token.Transmit(in, &r);
        } catch (const card_link_error& e) {
          if (extended) {
            const std::string msg = e.what();
            if (msg.find("80100016") != std::string::npos ||
                msg.find("80100004") != std::string::npos ||
                msg.find("80100008") != std::string::npos)
              throw ExtendedApduRejected();
          }
          if (mutualAuth)
            throw card_link_error(
                std::string("link lost during PACE mutual authentication: ") +
                    e.what(),
                /*retryable=*/false);
          throw;
        }
        resp.assign(r.data(), r.data() + r.size());
        return static_cast<uint16_t>(sw);
      };

      // 1. EF.CardAccess -> PACE protocol
      pace::Bytes cardAccess;
      pace::Result res = pace::readCardAccess(tx, cardAccess);
      if (res.status != pace::Status::Ok && cardAccessMissing(res.sw)) {
        // Some chips (Actalis) keep the MF files hidden after the CIE
        // application was used, and a warm reset doesn't always clear that
        // on a contactless reader (e.g. right after enrolment). Power-cycle
        // the card once and try again before calling PACE unsupported.
        LOG_INFO("readBothDGs - EF.CardAccess %s after reset; power-cycling",
                 res.detail.c_str());
        token.Reset(/*unpower=*/true);
        cardAccess.clear();
        res = pace::readCardAccess(tx, cardAccess);
      }
      if (res.status != pace::Status::Ok && res.sw == 0x6A82) {
        // A warm/SCardReconnect power-cycle can leave the RF field up on
        // CCID contactless readers, so the chip never forgets the CIE
        // application. Drop the field for real (disconnect with unpower,
        // wait, reconnect) and read once more.
        LOG_INFO(
            "readBothDGs - EF.CardAccess still %s after unpower; "
            "cycling the reader field",
            res.detail.c_str());
        switch (conn.powerCycleField(cur)) {
          case FieldCycleResult::Ok:
            // conn.hCard is the new handle; the callback context is the
            // same connection object, re-armed here for clarity.
            token.setTransmitCallback(TokenTransmitCallback, &conn);
            cardAccess.clear();
            res = pace::readCardAccess(tx, cardAccess);
            break;
          case FieldCycleResult::Unsupported:
            LOG_INFO("readBothDGs - field power-cycle not available here");
            break;
          case FieldCycleResult::CardRemoved:
            // Retryable: the next attempt waits for the card to come back.
            throw card_link_error(
                "card removed during the reader field power-cycle");
          case FieldCycleResult::Failed:
            throw card_link_error(
                "reconnect failed after the reader field power-cycle");
        }
      }
      if (res.status != pace::Status::Ok && res.sw == 0x6A82) {
        LOG_ERROR(
            "readBothDGs - EF.CardAccess still %s after the field "
            "power-cycle: card must be lifted and placed back on the reader",
            res.detail.c_str());
        sawResetRequired = true;
        continue;
      }
      if (res.status != pace::Status::Ok) {
        if (cardAccessMissing(res.sw)) {
          LOG_ERROR("readBothDGs - no EF.CardAccess (%s): PACE unsupported",
                    res.detail.c_str());
          sawUnsupported = true;
          continue;
        }
        free(readers);
        return failFromResult("EF.CardAccess", res);
      }
      pace::Params params;
      if (!pace::selectProtocol(pace::parseCardAccess(cardAccess), params)) {
        LOG_ERROR("readBothDGs - EF.CardAccess has no supported PACE OID");
        sawUnsupported = true;
        continue;
      }
      LOG_INFO("readBothDGs - PACE protocol: %s",
               pace::describe(params).c_str());

      // 2. PACE with the CAN (never retried on a wrong CAN)
      std::unique_ptr<pace::SecureChannel> channel;
      res = pace::performPace(tx, can, params, channel);
      if (res.status == pace::Status::WrongCan) {
        LOG_ERROR("readBothDGs - %s", res.detail.c_str());
        cie_record_wrong_can();
        free(readers);
        return CKR_PIN_INCORRECT;
      }
      if (res.status == pace::Status::Unsupported) {
        sawUnsupported = true;
        continue;
      }
      if (res.status != pace::Status::Ok) {
        free(readers);
        return failFromResult("PACE", res);
      }

      // 3. eMRTD application + DG1/DG2 over Secure Messaging
      pace::Bytes dg1Data, dg2Data;
      res = pace::selectEmrtdApplication(tx, *channel);
      if (res.status == pace::Status::Ok)
        res = pace::readFileSm(tx, *channel, 0x0101, dg1Data);
      if (res.status == pace::Status::Ok)
        res = pace::readFileSm(tx, *channel, 0x0102, dg2Data);
      if (res.status != pace::Status::Ok) {
        free(readers);
        return failFromResult("eMRTD read", res);
      }
      LOG_INFO("readBothDGs - DG1 %zu bytes, DG2 %zu bytes", dg1Data.size(),
               dg2Data.size());

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
    if (!found) {
      if (sawResetRequired) {
        // Context driven kind (never from a raw SW): the user has to lift
        // the card and put it back. Same CK_RV as ever for older callers.
        cie_record_card_reset_required(0x6A82);
        return CKR_FUNCTION_NOT_SUPPORTED;
      }
      if (sawUnsupported) {
        cie_record_unsupported_card();
        return CKR_FUNCTION_NOT_SUPPORTED;
      }
      return CKR_TOKEN_NOT_RECOGNIZED;
    }

  } catch (const ExtendedApduRejected& e) {
    // Reader limitation, not a card decision and not a wrong CAN: the app
    // can offer the PIN based fallback (cie_read_dgs).
    LOG_ERROR("readBothDGs - %s", e.what());
    cie_record_sw_error(0x6D00);  // CIE_ERR_INS_NOT_SUPPORTED
    free(readers);
    return CKR_DEVICE_ERROR;
  } catch (const card_link_error&) {
    free(readers);
    throw;
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

/**
 * @brief Read DG1 and DG2, retrying the whole attempt (fresh connection,
 * reset, PACE, SM, DG1+DG2 read) up to two more times if a
 * card_link_error (RF link drop / short response / SM MAC failure) is
 * detected.
 *
 * A wrong CAN is reported by readBothDGsCanOnce() as an ordinary CK_RV, never
 * as an exception, so it is never retried here with the same CAN; a link
 * drop while the PACE mutual-authentication token is in flight is marked
 * non-retryable for the same reason.
 *
 * @param can        NUL-terminated 6-digit CAN.
 * @param dg1Out     Buffer for raw DG1 TLV bytes.
 * @param dg1Len     In: capacity; out: bytes written.
 * @param dg2Out     Buffer for raw DG2 TLV bytes.
 * @param dg2Len     In: capacity; out: bytes written.
 * @return CKR_OK on success.
 */
static CK_RV readBothDGsCan(const char* can, uint8_t* dg1Out, size_t* dg1Len,
                            uint8_t* dg2Out, size_t* dg2Len) {
  if (!can || !dg1Out || !dg1Len || !dg2Out || !dg2Len)
    return CKR_ARGUMENTS_BAD;
  if (strnlen(can, 7) != 6) return CKR_ARGUMENTS_BAD;
  for (int i = 0; i < 6; ++i)
    if (can[i] < '0' || can[i] > '9') return CKR_ARGUMENTS_BAD;

  try {
    return RetryOnCardLinkError("cie_read_dgs_can", 3, [&](int attempt) {
      if (attempt == 1)
        return readBothDGsCanOnce(can, dg1Out, dg1Len, dg2Out, dg2Len);
      // After a link drop the card is often still off the reader (it was
      // lifted or slid). Give the user up to ~10 s to put it back instead
      // of failing with "token not recognized" on the first poll.
      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(10);
      CK_RV rv;
      do {
        rv = readBothDGsCanOnce(can, dg1Out, dg1Len, dg2Out, dg2Len);
        if (rv != CKR_TOKEN_NOT_RECOGNIZED && rv != CKR_TOKEN_NOT_PRESENT)
          return rv;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
      } while (std::chrono::steady_clock::now() < deadline);
      LOG_ERROR("cie_read_dgs_can - card did not return to the reader");
      return rv;
    });
  } catch (const card_link_error& e) {
    LOG_ERROR("readBothDGs - giving up after retries: %s", e.what());
    cie_record_transport_error();
    return CKR_DEVICE_ERROR;
  } catch (const std::exception& ex) {
    LOG_ERROR("readBothDGs - exception: %s", ex.what());
    return CKR_GENERAL_ERROR;
  } catch (...) {
    LOG_ERROR("readBothDGs - unknown exception");
    return CKR_GENERAL_ERROR;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

extern "C" {

/**
 * @brief Read DG1 (MRZ) and DG2 (photo) in a single PACE session, PIN based.
 *
 * Fallback for readers that cannot carry the extended-length APDUs the CAN
 * PACE needs (see cie_read_dgs_can). Uses the IAS DH key exchange and a PIN
 * VERIFY. The photo is returned as PNG bytes (JP2 decoded via OpenJPEG).
 *
 * @param pin         NUL-terminated 8-digit numeric PIN.
 * @param mrzOut      Buffer for raw DG1 TLV bytes (>= 4096 bytes recommended).
 * @param mrzLen      In: capacity; out: bytes written.
 * @param photoOut    Buffer for PNG photo bytes (>= 524288 bytes recommended).
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
  cie_clear_error();
  dg2Raw.resize(dg2RawLen);
  return dg2ToPhoto(dg2Raw, photoOut, photoLen, "cie_read_dgs");
}

/**
 * @brief Read DG1 (MRZ) and DG2 (photo) in a single PACE session with the CAN.
 *
 * Authenticates with the CAN (ICAO 9303-11 PACE) and reads both data groups
 * on the same Secure Messaging channel. The photo is returned as PNG bytes
 * (JP2 decoded via OpenJPEG).
 *
 * Failure modes the caller can tell apart through cie_last_error():
 *  - wrong CAN: CKR_PIN_INCORRECT + CIE_ERR_WRONG_CAN (never retried);
 *  - chip without a supported PACE protocol: CKR_FUNCTION_NOT_SUPPORTED +
 *    CIE_ERR_UNSUPPORTED_CARD;
 *  - reader/transport refusing the extended-length APDUs PACE needs:
 *    CKR_DEVICE_ERROR + CIE_ERR_INS_NOT_SUPPORTED (use cie_read_dgs).
 *
 * @param can         NUL-terminated string of exactly 6 ASCII digits.
 * @param mrzOut      Buffer for raw DG1 TLV bytes (>= 4096 bytes recommended).
 * @param mrzLen      In: capacity; out: bytes written.
 * @param photoOut    Buffer for PNG photo bytes (>= 524288 bytes recommended).
 * @param photoLen    In: capacity; out: bytes written.
 * @return CKR_OK on success, a PKCS#11 error code otherwise.
 */
CK_RV CK_ENTRY cie_read_dgs_can(const char* can, char* mrzOut, size_t* mrzLen,
                                unsigned char* photoOut, size_t* photoLen) {
  LOG_INFO("***** Starting cie_read_dgs_can *****");
  if (!can || !mrzOut || !mrzLen || !photoOut || !photoLen)
    return CKR_ARGUMENTS_BAD;
  cie_clear_error();

  std::vector<uint8_t> dg2Raw(*photoLen);
  size_t dg2RawLen = dg2Raw.size();

  CK_RV rv = readBothDGsCan(can, reinterpret_cast<uint8_t*>(mrzOut), mrzLen,
                            dg2Raw.data(), &dg2RawLen);
  if (rv != CKR_OK) {
    LOG_INFO("***** cie_read_dgs_can ended (readBothDGsCan), rv=%lu *****",
             static_cast<unsigned long>(rv));
    return rv;
  }
  cie_clear_error();
  dg2Raw.resize(dg2RawLen);
  return dg2ToPhoto(dg2Raw, photoOut, photoLen, "cie_read_dgs_can");
}

}  // extern "C"
