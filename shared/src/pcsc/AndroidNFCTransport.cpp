/*
 * AndroidNFCTransport.cpp — Android NFC (IsoDep) backend implementation.
 *
 * Maps ISmartCardTransport operations to JNI calls on android.nfc.tech.IsoDep:
 *
 *   EstablishContext  →  no-op (returns synthetic context)
 *   ListReaders       →  "NFC\0\0" if IsoDep is set
 *   Connect           →  IsoDep.connect()
 *   Disconnect        →  IsoDep.close()
 *   Reconnect         →  close() + connect()
 *   Transmit          →  IsoDep.transceive()
 *   GetAttrib         →  synthetic ATR from historical bytes
 *   BeginTransaction  →  no-op (NFC is single-threaded)
 *   EndTransaction    →  no-op
 */

#if defined(__ANDROID__)

#include "pcsc/AndroidNFCTransport.h"

#include <android/log.h>

#include <algorithm>
#include <cstring>

#define LOG_TAG "CIE-NFC"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ===== Global JNI state ===== */

static JavaVM *g_jvm = nullptr;
static jobject g_isoDep = nullptr;
static std::mutex g_globalMutex;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
  g_jvm = vm;
  LOGI("JNI_OnLoad: JavaVM cached");
  return JNI_VERSION_1_6;
}

extern "C" void CIE_SetNFCTag(JNIEnv *env, jobject isoDep) {
  std::lock_guard<std::mutex> lock(g_globalMutex);
  if (g_isoDep) {
    env->DeleteGlobalRef(g_isoDep);
    g_isoDep = nullptr;
  }
  if (isoDep) {
    g_isoDep = env->NewGlobalRef(isoDep);
    LOGI("CIE_SetNFCTag: IsoDep reference stored");
  }
}

extern "C" void CIE_ClearNFCTag(JNIEnv *env) {
  std::lock_guard<std::mutex> lock(g_globalMutex);
  if (g_isoDep) {
    env->DeleteGlobalRef(g_isoDep);
    g_isoDep = nullptr;
    LOGI("CIE_ClearNFCTag: IsoDep reference cleared");
  }
}

/* ===== JNIEnv helper ===== */

JNIEnv *AndroidNFCTransport::getEnv() {
  JNIEnv *env = nullptr;
  if (!g_jvm) return nullptr;

  jint status = g_jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
  if (status == JNI_OK) return env;

  if (status == JNI_EDETACHED) {
    if (g_jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) return env;
    LOGE("getEnv: AttachCurrentThread failed");
  }
  return nullptr;
}

/* ===== Method ID caching ===== */

void AndroidNFCTransport::cacheMethodIDs(JNIEnv *env) {
  jclass localClass = env->FindClass("android/nfc/tech/IsoDep");
  if (!localClass) {
    LOGE("cacheMethodIDs: IsoDep class not found");
    return;
  }
  isoDepClass_ = static_cast<jclass>(env->NewGlobalRef(localClass));
  env->DeleteLocalRef(localClass);

  connectId_ = env->GetMethodID(isoDepClass_, "connect", "()V");
  closeId_ = env->GetMethodID(isoDepClass_, "close", "()V");
  transceiveId_ = env->GetMethodID(isoDepClass_, "transceive", "([B)[B");
  isConnectedId_ = env->GetMethodID(isoDepClass_, "isConnected", "()Z");
  getHistBytesId_ =
      env->GetMethodID(isoDepClass_, "getHistoricalBytes", "()[B");
  getHiLayerRespId_ =
      env->GetMethodID(isoDepClass_, "getHiLayerResponse", "()[B");
}

/* ===== ATR construction =====
 *
 * Build a PC/SC-compatible ATR from NFC tag data:
 *   NFC-A  →  historical bytes from IsoDep.getHistoricalBytes()
 *   NFC-B  →  higher-layer response from IsoDep.getHiLayerResponse()
 *
 * ATR format: TS | T0 | TD1 | TD2 | T1..Tk | TCK
 *   TS   = 0x3B (direct convention)
 *   T0   = 0x80 | k (TD1 present, k historical bytes)
 *   TD1  = 0x80 (TD2 present, protocol T=0)
 *   TD2  = 0x01 (protocol T=1)
 *   TCK  = XOR of bytes T0..Tk
 */

void AndroidNFCTransport::buildATR(JNIEnv *env) {
  cachedATR_.clear();

  /* Try NFC-A historical bytes first */
  auto jHistBytes =
      static_cast<jbyteArray>(env->CallObjectMethod(isoDep_, getHistBytesId_));
  if (!env->ExceptionCheck() && jHistBytes) {
    jsize len = env->GetArrayLength(jHistBytes);
    std::vector<uint8_t> hist(len);
    env->GetByteArrayRegion(jHistBytes, 0, len,
                            reinterpret_cast<jbyte *>(hist.data()));
    env->DeleteLocalRef(jHistBytes);

    cachedATR_.push_back(0x3B);                                    /* TS */
    cachedATR_.push_back(0x80 | (len & 0x0F));                     /* T0 */
    cachedATR_.push_back(0x80);                                    /* TD1 */
    cachedATR_.push_back(0x01);                                    /* TD2 */
    cachedATR_.insert(cachedATR_.end(), hist.begin(), hist.end()); /* Tk */

    uint8_t tck = 0;
    for (size_t i = 1; i < cachedATR_.size(); ++i) tck ^= cachedATR_[i];
    cachedATR_.push_back(tck);

    LOGI("buildATR: built from NFC-A historical bytes (%d bytes)", len);
    return;
  }
  env->ExceptionClear();

  /* Fall back to NFC-B higher-layer response */
  auto jHiLayer = static_cast<jbyteArray>(
      env->CallObjectMethod(isoDep_, getHiLayerRespId_));
  if (!env->ExceptionCheck() && jHiLayer) {
    jsize len = env->GetArrayLength(jHiLayer);
    std::vector<uint8_t> hi(len);
    env->GetByteArrayRegion(jHiLayer, 0, len,
                            reinterpret_cast<jbyte *>(hi.data()));
    env->DeleteLocalRef(jHiLayer);

    cachedATR_.push_back(0x3B);
    cachedATR_.push_back(0x80 | (len & 0x0F));
    cachedATR_.push_back(0x80);
    cachedATR_.push_back(0x01);
    cachedATR_.insert(cachedATR_.end(), hi.begin(), hi.end());

    uint8_t tck = 0;
    for (size_t i = 1; i < cachedATR_.size(); ++i) tck ^= cachedATR_[i];
    cachedATR_.push_back(tck);

    LOGI("buildATR: built from NFC-B hi-layer response (%d bytes)", len);
    return;
  }
  env->ExceptionClear();

  /* Fallback: minimal ATR with no historical bytes */
  cachedATR_ = {0x3B, 0x80, 0x80, 0x01, 0x01};
  LOGI("buildATR: using minimal fallback ATR");
}

/* ===== Constructor / Destructor ===== */

AndroidNFCTransport::AndroidNFCTransport()
    : isoDep_(nullptr),
      isoDepClass_(nullptr),
      connectId_(nullptr),
      closeId_(nullptr),
      transceiveId_(nullptr),
      isConnectedId_(nullptr),
      getHistBytesId_(nullptr),
      getHiLayerRespId_(nullptr) {
  JNIEnv *env = getEnv();
  if (!env) {
    LOGE("AndroidNFCTransport: no JNIEnv available");
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_globalMutex);
    if (g_isoDep) {
      isoDep_ = env->NewGlobalRef(g_isoDep);
    }
  }

  if (!isoDep_) {
    LOGE("AndroidNFCTransport: no IsoDep set (call CIE_SetNFCTag first)");
    return;
  }

  cacheMethodIDs(env);
  buildATR(env);
}

AndroidNFCTransport::~AndroidNFCTransport() {
  JNIEnv *env = getEnv();
  if (!env) return;

  if (connected_) {
    env->CallVoidMethod(isoDep_, closeId_);
    env->ExceptionClear();
    connected_ = false;
  }

  if (isoDep_) env->DeleteGlobalRef(isoDep_);
  if (isoDepClass_) env->DeleteGlobalRef(isoDepClass_);
}

/* ===== ISmartCardTransport implementation ===== */

LONG AndroidNFCTransport::EstablishContext(DWORD /*dwScope*/,
                                           LPSCARDCONTEXT phContext) {
  if (!phContext) return SCARD_E_INVALID_PARAMETER;
  *phContext = kDummyContext;
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::ReleaseContext(SCARDCONTEXT /*hContext*/) {
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::IsValidContext(SCARDCONTEXT hContext) {
  return (hContext == kDummyContext) ? SCARD_S_SUCCESS : SCARD_E_INVALID_HANDLE;
}

LONG AndroidNFCTransport::ListReaders(SCARDCONTEXT /*hContext*/,
                                      LPSTR mszReaders, LPDWORD pcchReaders) {
  /* Multi-string: "NFC\0\0" — one reader named "NFC", terminated by double NUL
   */
  static const char kReaderName[] = "NFC";
  const DWORD needed = sizeof(kReaderName) + 1; /* "NFC\0\0" = 5 bytes */

  if (!pcchReaders) return SCARD_E_INVALID_PARAMETER;

  if (!isoDep_) {
    *pcchReaders = 0;
    return SCARD_E_NO_READERS_AVAILABLE;
  }

  if (!mszReaders) {
    *pcchReaders = needed;
    return SCARD_S_SUCCESS;
  }

  if (*pcchReaders < needed) {
    *pcchReaders = needed;
    return SCARD_E_INSUFFICIENT_BUFFER;
  }

  std::memcpy(mszReaders, kReaderName, sizeof(kReaderName));
  mszReaders[sizeof(kReaderName)] = '\0'; /* double NUL terminator */
  *pcchReaders = needed;
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::GetStatusChange(SCARDCONTEXT /*hContext*/,
                                          DWORD /*dwTimeout*/,
                                          SCARD_READERSTATE *rgReaderStates,
                                          DWORD cReaders) {
  for (DWORD i = 0; i < cReaders; ++i) {
    if (isoDep_) {
      rgReaderStates[i].dwEventState =
          SCARD_STATE_PRESENT | SCARD_STATE_CHANGED;

      /* Copy cached ATR into the reader state */
      DWORD atrLen =
          std::min(static_cast<DWORD>(cachedATR_.size()),
                   static_cast<DWORD>(sizeof(rgReaderStates[i].rgbAtr)));
      std::memcpy(rgReaderStates[i].rgbAtr, cachedATR_.data(), atrLen);
      rgReaderStates[i].cbAtr = atrLen;
    } else {
      rgReaderStates[i].dwEventState = SCARD_STATE_EMPTY | SCARD_STATE_CHANGED;
      rgReaderStates[i].cbAtr = 0;
    }
  }
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::Cancel(SCARDCONTEXT /*hContext*/) {
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::Connect(SCARDCONTEXT /*hContext*/,
                                  LPCSTR /*szReader*/, DWORD /*dwShareMode*/,
                                  DWORD /*dwPreferredProtocols*/,
                                  LPSCARDHANDLE phCard,
                                  LPDWORD pdwActiveProtocol) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!isoDep_) return SCARD_E_NO_READERS_AVAILABLE;
  if (!phCard || !pdwActiveProtocol) return SCARD_E_INVALID_PARAMETER;

  JNIEnv *env = getEnv();
  if (!env) return SCARD_E_NO_SERVICE;

  env->CallVoidMethod(isoDep_, connectId_);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    LOGE("Connect: IsoDep.connect() failed");
    return SCARD_E_NOT_TRANSACTED;
  }

  connected_ = true;
  *phCard = kDummyHandle;
  *pdwActiveProtocol = SCARD_PROTOCOL_T1; /* NFC ISO-DEP ≈ T=1 */
  LOGI("Connect: IsoDep connected");
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::Disconnect(SCARDHANDLE /*hCard*/,
                                     DWORD /*dwDisposition*/) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!connected_) return SCARD_S_SUCCESS;

  JNIEnv *env = getEnv();
  if (!env) return SCARD_E_NO_SERVICE;

  env->CallVoidMethod(isoDep_, closeId_);
  env->ExceptionClear();
  connected_ = false;
  LOGI("Disconnect: IsoDep closed");
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::Reconnect(SCARDHANDLE hCard, DWORD dwShareMode,
                                    DWORD dwPreferredProtocols,
                                    DWORD /*dwInitialization*/,
                                    LPDWORD pdwActiveProtocol) {
  Disconnect(hCard, SCARD_LEAVE_CARD);
  return Connect(kDummyContext, "NFC", dwShareMode, dwPreferredProtocols,
                 &hCard, pdwActiveProtocol);
}

LONG AndroidNFCTransport::Transmit(SCARDHANDLE /*hCard*/,
                                   const SCARD_IO_REQUEST * /*pioSendPci*/,
                                   LPCBYTE pbSendBuffer, DWORD cbSendLength,
                                   LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!connected_ || !isoDep_) return SCARD_W_REMOVED_CARD;
  if (!pbSendBuffer || !pbRecvBuffer || !pcbRecvLength)
    return SCARD_E_INVALID_PARAMETER;

  JNIEnv *env = getEnv();
  if (!env) return SCARD_E_NO_SERVICE;

  /* Create Java byte[] from APDU */
  jbyteArray jApdu = env->NewByteArray(static_cast<jsize>(cbSendLength));
  env->SetByteArrayRegion(jApdu, 0, static_cast<jsize>(cbSendLength),
                          reinterpret_cast<const jbyte *>(pbSendBuffer));

  /* Call IsoDep.transceive(byte[]) → byte[] */
  auto jResp = static_cast<jbyteArray>(
      env->CallObjectMethod(isoDep_, transceiveId_, jApdu));
  env->DeleteLocalRef(jApdu);

  if (env->ExceptionCheck() || !jResp) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    LOGE("Transmit: transceive failed");
    connected_ = false;
    return SCARD_E_NOT_TRANSACTED;
  }

  jsize respLen = env->GetArrayLength(jResp);
  if (static_cast<DWORD>(respLen) > *pcbRecvLength) {
    env->DeleteLocalRef(jResp);
    *pcbRecvLength = static_cast<DWORD>(respLen);
    return SCARD_E_INSUFFICIENT_BUFFER;
  }

  env->GetByteArrayRegion(jResp, 0, respLen,
                          reinterpret_cast<jbyte *>(pbRecvBuffer));
  env->DeleteLocalRef(jResp);

  *pcbRecvLength = static_cast<DWORD>(respLen);
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::BeginTransaction(SCARDHANDLE /*hCard*/) {
  /* NFC is inherently single-session; no transaction locking needed. */
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::EndTransaction(SCARDHANDLE /*hCard*/,
                                         DWORD /*dwDisposition*/) {
  return SCARD_S_SUCCESS;
}

LONG AndroidNFCTransport::GetAttrib(SCARDHANDLE /*hCard*/, DWORD dwAttrId,
                                    LPBYTE pbAttr, LPDWORD pcbAttrLen) {
  if (dwAttrId != SCARD_ATTR_ATR_STRING)
    return SCARD_E_INVALID_PARAMETER; /* Only ATR is supported */

  if (!pcbAttrLen) return SCARD_E_INVALID_PARAMETER;

  DWORD atrSize = static_cast<DWORD>(cachedATR_.size());

  if (!pbAttr) {
    *pcbAttrLen = atrSize;
    return SCARD_S_SUCCESS;
  }

  if (*pcbAttrLen < atrSize) {
    *pcbAttrLen = atrSize;
    return SCARD_E_INSUFFICIENT_BUFFER;
  }

  std::memcpy(pbAttr, cachedATR_.data(), atrSize);
  *pcbAttrLen = atrSize;
  return SCARD_S_SUCCESS;
}

#endif /* __ANDROID__ */
