// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file mechanism.cpp
 * @brief Cryptographic mechanism implementations (RSA, SHA, MD5)
 */

#include "pkcs11/mechanism.h"

#include "crypto/rsa.h"
#include "pkcs11/p11_object.h"
#include "pkcs11/session.h"
#include "util/util.h"

extern CLog Log;

static BYTE SHA1_RSAcode[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                              0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
static BYTE MD5_RSAcode[] = {0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
                             0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                             0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
static ByteArray baSHA1DigestInfo(SHA1_RSAcode, sizeof(SHA1_RSAcode));
static ByteArray baMD5DigestInfo(MD5_RSAcode, sizeof(MD5_RSAcode));

namespace p11 {

CMechanism::CMechanism(CK_MECHANISM_TYPE type,
                       std::shared_ptr<CSession> Session)
    : mtType(type), pSession(std::move(Session)) {}
CMechanism::~CMechanism() {}

CVerify::CVerify(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session)
    : CMechanism(type, std::move(Session)), hVerifyKey(0) {}
CVerify::~CVerify() {}

CVerifyRecover::CVerifyRecover(CK_MECHANISM_TYPE type,
                               std::shared_ptr<CSession> Session)
    : CMechanism(type, std::move(Session)), hVerifyRecoverKey(0) {}
CVerifyRecover::~CVerifyRecover() {}

CDigest::CDigest(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session)
    : CMechanism(type, std::move(Session)) {}
CDigest::~CDigest() {}

CSign::CSign(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session)
    : CMechanism(type, std::move(Session)), hSignKey(0) {}
CSign::~CSign() {}

CSignRecover::CSignRecover(CK_MECHANISM_TYPE type,
                           std::shared_ptr<CSession> Session)
    : CMechanism(type, std::move(Session)), hSignRecoverKey(0) {}
CSignRecover::~CSignRecover() {}

/* ******************** */
/*		   SHA1	        */
/* ******************** */
CDigestSHA::CDigestSHA(std::shared_ptr<CSession> Session)
    : CDigest(CKM_SHA_1, std::move(Session)) {}
CDigestSHA::~CDigestSHA() {}

void CDigestSHA::DigestInit() { data.clear(); }

void CDigestSHA::DigestUpdate(ByteArray &Part) { data.append(Part); }

void CDigestSHA::DigestFinal(ByteArray &Digest) {
  ByteDynArray dataOut(SHA_DIGEST_LENGTH);
  dataOut = sha1.Digest(data);
  Digest.copy(dataOut);
}

CK_ULONG CDigestSHA::DigestLength() { return SHA_DIGEST_LENGTH; }

ByteArray CDigestSHA::DigestInfo() { return baSHA1DigestInfo; }

ByteDynArray CDigestSHA::DigestGetOperationState() {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

void CDigestSHA::DigestSetOperationState(ByteArray & /*OperationState*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

/* ******************** */
/*		   SHA256	        */
/* ******************** */
CDigestSHA256::CDigestSHA256(std::shared_ptr<CSession> Session)
    : CDigest(CKM_SHA_1, std::move(Session)) {}
CDigestSHA256::~CDigestSHA256() {}

void CDigestSHA256::DigestInit() { data.clear(); }

void CDigestSHA256::DigestUpdate(ByteArray &Part) { data.append(Part); }

void CDigestSHA256::DigestFinal(ByteArray &Digest) {
  ByteDynArray dataOut(SHA256_DIGEST_LENGTH);
  dataOut = sha256.Digest(data);
  Digest.copy(dataOut);
}

CK_ULONG CDigestSHA256::DigestLength() { return SHA256_DIGEST_LENGTH; }

ByteArray CDigestSHA256::DigestInfo() { return baSHA1DigestInfo; }

ByteDynArray CDigestSHA256::DigestGetOperationState() {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

void CDigestSHA256::DigestSetOperationState(ByteArray & /*OperationState*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

/* ******************** */
/*		   MD5	        */
/* ******************** */
CDigestMD5::CDigestMD5(std::shared_ptr<CSession> Session)
    : CDigest(CKM_MD5, std::move(Session)) {}
CDigestMD5::~CDigestMD5() {}

void CDigestMD5::DigestInit() { data.clear(); }

void CDigestMD5::DigestUpdate(ByteArray &Part) { data.append(Part); }

void CDigestMD5::DigestFinal(ByteArray &Digest) {
  ByteDynArray dataOut(MD5_DIGEST_LENGTH);
  dataOut = md5.Digest(data);  //, dataOut);
  Digest.copy(dataOut);
}

CK_ULONG CDigestMD5::DigestLength() { return MD5_DIGEST_LENGTH; }

ByteArray CDigestMD5::DigestInfo() { return baMD5DigestInfo; }

ByteDynArray CDigestMD5::DigestGetOperationState() {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

void CDigestMD5::DigestSetOperationState(ByteArray & /*OperationState*/) {
  throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

/* ******************** */
/*		Verify RSA		*/
/* ******************** */
CVerifyRSA::CVerifyRSA(CK_MECHANISM_TYPE type,
                       std::shared_ptr<CSession> Session)
    : CVerify(type, std::move(Session)) {}
CVerifyRSA::~CVerifyRSA() {}

bool CVerifyRSA::VerifySupportMultipart() { return false; }

CK_ULONG CVerifyRSA::VerifyLength() {
  std::shared_ptr<CP11Object> pObject =
      pSession->pSlot->GetObjectFromID(hVerifyKey);
  ER_ASSERT(pObject != nullptr, ERR_CANT_GET_OBJECT)
  ER_ASSERT(pObject->ObjClass == CKO_PUBLIC_KEY, ERR_WRONG_OBJECT_TYPE)
  auto pPublicKey = std::static_pointer_cast<CP11PublicKey>(pObject);

  ByteArray *baKeyModule = pPublicKey->getAttribute(CKA_MODULUS);
  ER_ASSERT(!baKeyModule->isNull(), ERR_CANT_GET_PUBKEY_MODULUS)
  return static_cast<CK_ULONG>(baKeyModule->size());
}

ByteDynArray CVerifyRSA::VerifyDecryptSignature(ByteArray &Signature) {
  ByteArray *baKeyExponent = nullptr, *baKeyModule = nullptr;

  std::shared_ptr<CP11Object> pObject =
      pSession->pSlot->GetObjectFromID(hVerifyKey);
  ER_ASSERT(pObject != nullptr, ERR_CANT_GET_OBJECT)
  ER_ASSERT(pObject->ObjClass == CKO_PUBLIC_KEY, ERR_WRONG_OBJECT_TYPE)
  auto pPublicKey = std::static_pointer_cast<CP11PublicKey>(pObject);

  baKeyExponent = pPublicKey->getAttribute(CKA_PUBLIC_EXPONENT);
  ER_ASSERT(baKeyExponent != nullptr, ERR_CANT_GET_PUBKEY_EXPONENT)

  baKeyModule = pPublicKey->getAttribute(CKA_MODULUS);
  ER_ASSERT(baKeyModule != nullptr, ERR_CANT_GET_PUBKEY_MODULUS)

  if (Signature.size() != baKeyModule->size())
    throw p11_error(CKR_SIGNATURE_LEN_RANGE);

  CRSA rsa(*baKeyModule, *baKeyExponent);
  return rsa.RSA_PURE(Signature);
}

ByteDynArray CVerifyRSA::VerifyGetOperationState() { return ByteDynArray(); }

void CVerifyRSA::VerifySetOperationState(ByteArray &OperationState) {
  if (OperationState.size() != 0) throw p11_error(CKR_SAVED_STATE_INVALID);
}

/* ******************** */
/*	VerifyRecover RSA	*/
/* ******************** */
CVerifyRecoverRSA::CVerifyRecoverRSA(CK_MECHANISM_TYPE type,
                                     std::shared_ptr<CSession> Session)
    : CVerifyRecover(type, std::move(Session)) {}
CVerifyRecoverRSA::~CVerifyRecoverRSA() {}

CK_ULONG CVerifyRecoverRSA::VerifyRecoverLength() {
  std::shared_ptr<CP11Object> pObject =
      pSession->pSlot->GetObjectFromID(hVerifyRecoverKey);
  ER_ASSERT(pObject != nullptr, ERR_CANT_GET_OBJECT)
  ER_ASSERT(pObject->ObjClass == CKO_PUBLIC_KEY, ERR_WRONG_OBJECT_TYPE)
  auto pPublicKey = std::static_pointer_cast<CP11PublicKey>(pObject);

  ByteArray *baKeyModule = pPublicKey->getAttribute(CKA_MODULUS);
  ER_ASSERT(baKeyModule != nullptr, ERR_CANT_GET_PUBKEY_MODULUS)
  return static_cast<CK_ULONG>(baKeyModule->size());
}

ByteDynArray CVerifyRecoverRSA::VerifyRecoverDecryptSignature(
    ByteArray &Signature) {
  ByteArray *baKeyExponent = nullptr, *baKeyModule = nullptr;

  std::shared_ptr<CP11Object> pObject =
      pSession->pSlot->GetObjectFromID(hVerifyRecoverKey);
  ER_ASSERT(pObject != nullptr, ERR_CANT_GET_OBJECT)
  ER_ASSERT(pObject->ObjClass == CKO_PUBLIC_KEY, ERR_WRONG_OBJECT_TYPE)
  auto pPublicKey = std::static_pointer_cast<CP11PublicKey>(pObject);

  pPublicKey->getAttribute(CKA_PUBLIC_EXPONENT);
  ER_ASSERT(baKeyExponent != nullptr, ERR_CANT_GET_PUBKEY_EXPONENT);

  baKeyModule = pPublicKey->getAttribute(CKA_MODULUS);
  ER_ASSERT(baKeyModule != nullptr, ERR_CANT_GET_PUBKEY_MODULUS)

  if (Signature.size() != baKeyModule->size())
    throw p11_error(CKR_SIGNATURE_LEN_RANGE);

  CRSA rsa(*baKeyModule, *baKeyExponent);
  return rsa.RSA_PURE(Signature);
}

ByteDynArray CVerifyRecoverRSA::VerifyRecoverGetOperationState() {
  return ByteDynArray();
}

void CVerifyRecoverRSA::VerifyRecoverSetOperationState(
    ByteArray &OperationState) {
  if (OperationState.size() != 0) throw p11_error(CKR_SAVED_STATE_INVALID);
}

/* ******************** */
/*		SignRSA			*/
/* ******************** */
CSignRSA::CSignRSA(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session)
    : CSign(type, std::move(Session)) {}
CSignRSA::~CSignRSA() {}

bool CSignRSA::SignSupportMultipart() { return false; }

CK_ULONG CSignRSA::SignLength() {
  std::shared_ptr<CP11Object> pObject =
      pSession->pSlot->GetObjectFromID(hSignKey);
  ER_ASSERT(pObject != nullptr, ERR_CANT_GET_OBJECT)
  ER_ASSERT(pObject->ObjClass == CKO_PRIVATE_KEY, ERR_WRONG_OBJECT_TYPE)
  auto pPrivateKey = std::static_pointer_cast<CP11PrivateKey>(pObject);

  ByteArray *baKeyModule = pPrivateKey->getAttribute(CKA_MODULUS);
  ER_ASSERT(baKeyModule != nullptr, ERR_CANT_GET_PUBKEY_MODULUS)
  return static_cast<CK_ULONG>(baKeyModule->size());
}

ByteDynArray CSignRSA::SignGetOperationState() { return ByteDynArray(); }

void CSignRSA::SignSetOperationState(ByteArray &OperationState) {
  if (OperationState.size() != 0) throw p11_error(CKR_SAVED_STATE_INVALID);
}

/* ******************** */
/*	SignRecoverRSA		*/
/* ******************** */
CSignRecoverRSA::CSignRecoverRSA(CK_MECHANISM_TYPE type,
                                 std::shared_ptr<CSession> Session)
    : CSignRecover(type, std::move(Session)) {}
CSignRecoverRSA::~CSignRecoverRSA() {}

CK_ULONG CSignRecoverRSA::SignRecoverLength() {
  std::shared_ptr<CP11Object> pObject =
      pSession->pSlot->GetObjectFromID(hSignRecoverKey);
  ER_ASSERT(pObject != nullptr, ERR_CANT_GET_OBJECT)
  ER_ASSERT(pObject->ObjClass == CKO_PRIVATE_KEY, ERR_WRONG_OBJECT_TYPE)
  auto pPrivateKey = std::static_pointer_cast<CP11PrivateKey>(pObject);

  ByteArray *baKeyModule = pPrivateKey->getAttribute(CKA_MODULUS);
  ER_ASSERT(baKeyModule != nullptr, ERR_CANT_GET_PUBKEY_MODULUS)
  return static_cast<CK_ULONG>(baKeyModule->size());
}

ByteDynArray CSignRecoverRSA::SignRecoverGetOperationState() {
  return ByteDynArray();
}

void CSignRecoverRSA::SignRecoverSetOperationState(ByteArray &OperationState) {
  if (OperationState.size() != 0) throw p11_error(CKR_SAVED_STATE_INVALID);
}

/* ******************** */
/*		RSA_PKCS1		*/
/* ******************** */
CRSA_PKCS1::CRSA_PKCS1(std::shared_ptr<CSession> Session)
    : CSignRSA(CKM_RSA_PKCS, Session),
      CSignRecoverRSA(CKM_RSA_PKCS, Session),
      CVerifyRSA(CKM_RSA_PKCS, Session),
      CVerifyRecoverRSA(CKM_RSA_PKCS, Session) {}
CRSA_PKCS1::~CRSA_PKCS1() {}

void CRSA_PKCS1::VerifyInit(CK_OBJECT_HANDLE PublicKey) {
  hVerifyKey = PublicKey;
}

void CRSA_PKCS1::VerifyUpdate(ByteArray &Part) {
  auto dwSize = baVerifyBuffer.size();
  baVerifyBuffer.resize(dwSize + Part.size(), true);
  baVerifyBuffer.mid(dwSize, Part.size()).copy(Part);
}

void CRSA_PKCS1::VerifyFinal(ByteArray &Signature) {
  ByteDynArray baPlainSignature;
  CK_ULONG ulVerifyLength = VerifyLength();

  if (Signature.size() != ulVerifyLength)
    throw p11_error(CKR_SIGNATURE_LEN_RANGE);

  // max k-11 (PKCS#11 specs)
  if (baVerifyBuffer.size() > ulVerifyLength - 11)
    throw p11_error(CKR_DATA_LEN_RANGE);

  baPlainSignature = VerifyDecryptSignature(Signature);

  ByteDynArray baExpectedResult(ulVerifyLength);
  baExpectedResult.rightcopy(baVerifyBuffer);
  PutPaddingBT1(baExpectedResult, baVerifyBuffer.size());

  if (baPlainSignature == baExpectedResult)
    return;
  else
    throw p11_error(CKR_SIGNATURE_INVALID);
}

void CRSA_PKCS1::VerifyRecoverInit(CK_OBJECT_HANDLE PublicKey) {
  hVerifyRecoverKey = PublicKey;
}

ByteDynArray CRSA_PKCS1::VerifyRecover(ByteArray &Signature) {
  CK_ULONG ulVerifyRecoverLength = VerifyRecoverLength();

  if (Signature.size() != ulVerifyRecoverLength)
    throw p11_error(CKR_SIGNATURE_LEN_RANGE);

  ByteDynArray baPlainSignature = VerifyRecoverDecryptSignature(Signature);

  // if I can't remove the padding, the signature has
  // something wrong
  size_t dwPadLen;
  try {
    dwPadLen = RemovePaddingBT1(baPlainSignature);
  } catch (...) {
    throw p11_error(CKR_SIGNATURE_INVALID);
  }

  // the returned data cannot be longer
  // than k-11!! (PKCS#11 specs)
  auto Data = baPlainSignature.mid(dwPadLen);
  if (Data.size() > ulVerifyRecoverLength - 11)
    throw p11_error(CKR_DATA_LEN_RANGE);
  return ByteDynArray(Data);
}

void CRSA_PKCS1::SignInit(CK_OBJECT_HANDLE PrivateKey) {
  hSignKey = PrivateKey;
}

void CRSA_PKCS1::SignReset() { baSignBuffer.clear(); }

void CRSA_PKCS1::SignUpdate(ByteArray &Part) {
  auto dwSize = baSignBuffer.size();
  baSignBuffer.resize(dwSize + Part.size(), true);
  baSignBuffer.mid(dwSize, Part.size()).copy(Part);
}

ByteDynArray CRSA_PKCS1::SignFinal() {
  CK_ULONG ulSignatureLength = SignLength();

  // at most k-11 bytes (PKCS#11 specs)
  if (baSignBuffer.size() > ulSignatureLength - 11)
    throw p11_error(CKR_DATA_LEN_RANGE);

  return baSignBuffer;
}

void CRSA_PKCS1::SignRecoverInit(CK_OBJECT_HANDLE PrivateKey) {
  hSignRecoverKey = PrivateKey;
}

ByteDynArray CRSA_PKCS1::SignRecover(ByteArray &Data) {
  CK_ULONG ulSignatureLength = SignRecoverLength();

  // at most k-11 bytes (PKCS#11 specs)
  if (Data.size() > ulSignatureLength - 11) throw p11_error(CKR_DATA_LEN_RANGE);

  return ByteDynArray(Data);
}

/* ************************ */
/*		SignRSA_withDigest	*/
/* ************************ */

CSignRSAwithDigest::CSignRSAwithDigest(CK_MECHANISM_TYPE type,
                                       std::shared_ptr<CSession> Session,
                                       CDigest *Digest)
    : CSignRSA(type, std::move(Session)), pDigest(Digest) {}
CSignRSAwithDigest::~CSignRSAwithDigest() {}

bool CSignRSAwithDigest::SignSupportMultipart() { return true; }

void CSignRSAwithDigest::SignInit(CK_OBJECT_HANDLE hPrivateKey) {
  hSignKey = hPrivateKey;
  pDigest->DigestInit();
}

void CSignRSAwithDigest::SignReset() { pDigest->DigestInit(); }

void CSignRSAwithDigest::SignUpdate(ByteArray &Part) {
  pDigest->DigestUpdate(Part);
}

ByteDynArray CSignRSAwithDigest::SignFinal() {
  CK_ULONG ulDigestLength = pDigest->DigestLength();

  ByteDynArray SignBuffer(ulDigestLength);
  pDigest->DigestFinal(SignBuffer);

  ByteDynArray baDigestInfo(pDigest->DigestInfo());

  return ByteDynArray(baDigestInfo.append(SignBuffer));
}

ByteDynArray CSignRSAwithDigest::SignGetOperationState() {
  return pDigest->DigestGetOperationState();
}

void CSignRSAwithDigest::SignSetOperationState(ByteArray &OperationState) {
  pDigest->DigestSetOperationState(OperationState);
}

/* ************************ */
/*	VerifyRSA_withDigest	*/
/* ************************ */

CVerifyRSAwithDigest::CVerifyRSAwithDigest(CK_MECHANISM_TYPE type,
                                           std::shared_ptr<CSession> Session,
                                           CDigest *Digest)
    : CVerifyRSA(type, std::move(Session)), pDigest(Digest) {}
CVerifyRSAwithDigest::~CVerifyRSAwithDigest() {}

bool CVerifyRSAwithDigest::VerifySupportMultipart() { return true; }

void CVerifyRSAwithDigest::VerifyInit(CK_OBJECT_HANDLE PublicKey) {
  hVerifyKey = PublicKey;
  pDigest->DigestInit();
}

void CVerifyRSAwithDigest::VerifyUpdate(ByteArray &Part) {
  pDigest->DigestUpdate(Part);
}

void CVerifyRSAwithDigest::VerifyFinal(ByteArray &Signature) {
  ByteDynArray baPlainSignature;
  CK_ULONG ulVerifyLength = VerifyLength();

  if (Signature.size() != ulVerifyLength)
    throw p11_error(CKR_SIGNATURE_LEN_RANGE);

  baPlainSignature = VerifyDecryptSignature(Signature);

  ByteDynArray baExpectedResult(ulVerifyLength);
  CK_ULONG ulDigestLen = pDigest->DigestLength();
  ByteArray baDigestInfo = pDigest->DigestInfo();

  ByteArray ba1 = baExpectedResult.right(ulDigestLen);
  pDigest->DigestFinal(ba1);
  baExpectedResult.rightcopy(baDigestInfo, ulDigestLen);
  PutPaddingBT1(baExpectedResult, ulDigestLen + baDigestInfo.size());

  if (baPlainSignature == baExpectedResult)
    return;
  else
    throw p11_error(CKR_SIGNATURE_INVALID);
}

ByteDynArray CVerifyRSAwithDigest::VerifyGetOperationState() {
  return pDigest->DigestGetOperationState();
}

void CVerifyRSAwithDigest::VerifySetOperationState(ByteArray &OperationState) {
  pDigest->DigestSetOperationState(OperationState);
}
/* ******************** */
/*		RSA_withMD5		*/
/* ******************** */
CRSAwithMD5::CRSAwithMD5(std::shared_ptr<CSession> Session)
    : CSignRSAwithDigest(CKM_MD5_RSA_PKCS, Session, &md5),
      CVerifyRSAwithDigest(CKM_MD5_RSA_PKCS, Session, &md5),
      md5(Session) {}
CRSAwithMD5::~CRSAwithMD5() {}

/* ******************** */
/*		RSA_withSHA1	*/
/* ******************** */
CRSAwithSHA1::CRSAwithSHA1(std::shared_ptr<CSession> Session)
    : CSignRSAwithDigest(CKM_SHA1_RSA_PKCS, Session, &sha1),
      CVerifyRSAwithDigest(CKM_SHA1_RSA_PKCS, Session, &sha1),
      sha1(Session) {}
CRSAwithSHA1::~CRSAwithSHA1() {}

/* ******************** */
/*		RSA_withSHA1	*/
/* ******************** */
CRSAwithSHA256::CRSAwithSHA256(std::shared_ptr<CSession> Session)
    : CSignRSAwithDigest(CKM_SHA256_RSA_PKCS, Session, &sha256),
      CVerifyRSAwithDigest(CKM_SHA256_RSA_PKCS, Session, &sha256),
      sha256(Session) {}
CRSAwithSHA256::~CRSAwithSHA256() {}

}  // namespace p11
