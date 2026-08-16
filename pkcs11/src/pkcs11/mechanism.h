// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file mechanism.h
 * @brief PKCS#11 cryptographic mechanism class hierarchy.
 *
 * Defines the abstract base classes for digest, sign, verify, and their
 * concrete RSA implementations.  The hierarchy mirrors the Cryptoki
 * mechanism model: each active operation (e.g. C_SignInit -> C_SignUpdate ->
 * C_SignFinal) is represented by a mechanism object held by the session.
 */

#pragma once
#include <memory>

#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "pkcs11/cryptoki.h"

namespace p11 {

class CSession;

/**
 * @brief Base class for all PKCS#11 cryptographic mechanisms.
 *
 * Holds the mechanism type and a back-pointer to the owning session.
 */
class CMechanism {
 public:
  CK_MECHANISM_TYPE mtType;
  CMechanism(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CMechanism(void);
  std::shared_ptr<CSession> pSession;
};

/**
 * @brief Abstract base for message-digest mechanisms (CKM_SHA_1, CKM_SHA256,
 * CKM_MD5).
 *
 * Subclasses wrap a specific hash algorithm and support incremental
 * (Init/Update/Final) hashing as well as operation-state serialization for
 * C_GetOperationState.
 */
class CDigest : public CMechanism {
 public:
  ByteDynArray data;

  CDigest(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CDigest();

  virtual void DigestInit() = 0;
  virtual void DigestUpdate(ByteArray &Part) = 0;
  virtual void DigestFinal(ByteArray &Digest) = 0;
  virtual CK_ULONG DigestLength() = 0;
  /** @brief Return the DER-encoded DigestInfo prefix for this algorithm. */
  virtual ByteArray DigestInfo() = 0;
  virtual ByteDynArray DigestGetOperationState() = 0;
  virtual void DigestSetOperationState(ByteArray &OperationState) = 0;
};

/**
 * @brief Abstract base for signature-verification mechanisms.
 *
 * Supports multi-part verification (VerifyUpdate/VerifyFinal) and raw
 * signature decryption for PKCS#1 v1.5 unpadding.
 */
class CVerify : public CMechanism {
 public:
  CK_OBJECT_HANDLE hVerifyKey;

  CVerify(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CVerify();

  virtual bool VerifySupportMultipart() = 0;
  virtual void VerifyInit(CK_OBJECT_HANDLE PublicKey) = 0;
  virtual void VerifyUpdate(ByteArray &Part) = 0;
  virtual void VerifyFinal(ByteArray &Signature) = 0;
  virtual CK_ULONG VerifyLength() = 0;
  /** @brief Decrypt the RSA signature to recover the DigestInfo plaintext. */
  virtual ByteDynArray VerifyDecryptSignature(ByteArray &Signature) = 0;
  virtual ByteDynArray VerifyGetOperationState() = 0;
  virtual void VerifySetOperationState(ByteArray &OperationState) = 0;
};

/** @brief RSA-based verification providing modular-exponentiation and
 * key-length queries. */
class CVerifyRSA : public CVerify {
 public:
  CVerifyRSA(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CVerifyRSA() override;

  bool VerifySupportMultipart() override;
  ByteDynArray VerifyDecryptSignature(ByteArray &Signature) override;
  CK_ULONG VerifyLength() override;
  ByteDynArray VerifyGetOperationState() override;
  void VerifySetOperationState(ByteArray &OperationState) override;
};

/** @brief Abstract base for single-part verification with data recovery. */
class CVerifyRecover : public CMechanism {
 public:
  CK_OBJECT_HANDLE hVerifyRecoverKey;

  CVerifyRecover(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CVerifyRecover();

  virtual void VerifyRecoverInit(CK_OBJECT_HANDLE PublicKey) = 0;
  virtual ByteDynArray VerifyRecover(ByteArray &Signature) = 0;
  virtual CK_ULONG VerifyRecoverLength() = 0;
  virtual ByteDynArray VerifyRecoverDecryptSignature(ByteArray &Signature) = 0;
  virtual ByteDynArray VerifyRecoverGetOperationState() = 0;
  virtual void VerifyRecoverSetOperationState(ByteArray &OperationState) = 0;
};

/** @brief RSA-based verify-recover providing raw RSA public-key operation. */
class CVerifyRecoverRSA : public CVerifyRecover {
 public:
  CVerifyRecoverRSA(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CVerifyRecoverRSA() override;

  ByteDynArray VerifyRecoverDecryptSignature(ByteArray &Signature) override;
  CK_ULONG VerifyRecoverLength() override;
  ByteDynArray VerifyRecoverGetOperationState() override;
  void VerifyRecoverSetOperationState(ByteArray &OperationState) override;
};

/**
 * @brief Abstract base for signing mechanisms.
 *
 * Supports multi-part signing (SignUpdate/SignFinal) and operation-state
 * serialization.  Concrete subclasses delegate the actual RSA private-key
 * operation to the card template.
 */
class CSign : public CMechanism {
 public:
  CK_OBJECT_HANDLE hSignKey;

  CSign(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CSign();

  virtual bool SignSupportMultipart() = 0;
  virtual void SignInit(CK_OBJECT_HANDLE PrivateKey) = 0;
  virtual void SignReset() = 0;
  virtual void SignUpdate(ByteArray &Part) = 0;
  virtual ByteDynArray SignFinal() = 0;
  virtual CK_ULONG SignLength() = 0;
  virtual ByteDynArray SignGetOperationState() = 0;
  virtual void SignSetOperationState(ByteArray &OperationState) = 0;
};

/** @brief RSA-based signing providing key-length queries and state
 * serialization. */
class CSignRSA : public CSign {
 public:
  CSignRSA(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CSignRSA() override;

  CK_ULONG SignLength() override;
  bool SignSupportMultipart() override;
  ByteDynArray SignFinal() override = 0;
  ByteDynArray SignGetOperationState() override;
  void SignSetOperationState(ByteArray &OperationState) override;
};

/** @brief Abstract base for single-part sign-with-recovery mechanisms. */
class CSignRecover : public CMechanism {
 public:
  CK_OBJECT_HANDLE hSignRecoverKey;

  CSignRecover(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CSignRecover();

  virtual void SignRecoverInit(CK_OBJECT_HANDLE PrivateKey) = 0;
  virtual ByteDynArray SignRecover(ByteArray &baData) = 0;
  virtual CK_ULONG SignRecoverLength() = 0;
  virtual ByteDynArray SignRecoverGetOperationState() = 0;
  virtual void SignRecoverSetOperationState(ByteArray &OperationState) = 0;
};

/** @brief RSA-based sign-recover providing key-length queries and state
 * serialization. */
class CSignRecoverRSA : public CSignRecover {
 public:
  CSignRecoverRSA(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session);
  virtual ~CSignRecoverRSA() override;

  CK_ULONG SignRecoverLength() override;
  ByteDynArray SignRecoverGetOperationState() override;
  void SignRecoverSetOperationState(ByteArray &OperationState) override;
};

/** @brief SHA-1 digest mechanism (CKM_SHA_1). */
class CDigestSHA : public CDigest {
 public:
  CDigestSHA(std::shared_ptr<CSession> Session);
  virtual ~CDigestSHA() override;

  CSHA1 sha1;

  void DigestInit() override;
  void DigestUpdate(ByteArray &Part) override;
  void DigestFinal(ByteArray &Digest) override;
  CK_ULONG DigestLength() override;
  ByteArray DigestInfo() override;
  ByteDynArray DigestGetOperationState() override;
  void DigestSetOperationState(ByteArray &OperationState) override;
};

/** @brief SHA-256 digest mechanism (CKM_SHA256). */
class CDigestSHA256 : public CDigest {
 public:
  CDigestSHA256(std::shared_ptr<CSession> Session);
  virtual ~CDigestSHA256() override;

  CSHA256 sha256;

  void DigestInit() override;
  void DigestUpdate(ByteArray &Part) override;
  void DigestFinal(ByteArray &Digest) override;
  CK_ULONG DigestLength() override;
  ByteArray DigestInfo() override;
  ByteDynArray DigestGetOperationState() override;
  void DigestSetOperationState(ByteArray &OperationState) override;
};

/** @brief MD5 digest mechanism (CKM_MD5). */
class CDigestMD5 : public CDigest {
 public:
  CDigestMD5(std::shared_ptr<CSession> Session);
  virtual ~CDigestMD5() override;

  CMD5 md5;

  void DigestInit() override;
  void DigestUpdate(ByteArray &Part) override;
  void DigestFinal(ByteArray &Digest) override;
  CK_ULONG DigestLength() override;
  ByteArray DigestInfo() override;
  ByteDynArray DigestGetOperationState() override;
  void DigestSetOperationState(ByteArray &OperationState) override;
};

/**
 * @brief Combined RSA PKCS#1 v1.5 sign/verify/sign-recover/verify-recover
 * mechanism.
 *
 * Used for CKM_RSA_PKCS where the application supplies pre-formatted
 * data (e.g. a DER-encoded DigestInfo) and the mechanism only applies
 * PKCS#1 v1.5 padding before the raw RSA operation on the card.
 */
class CRSA_PKCS1
    : public CSignRSA,
      public CSignRecoverRSA,
      public CVerifyRSA,
      public CVerifyRecoverRSA { /*, public CEncryptRSA, public CDecryptRSA*/
 public:
  CRSA_PKCS1(std::shared_ptr<CSession> Session);
  virtual ~CRSA_PKCS1() override;

  ByteDynArray baVerifyBuffer;
  ByteDynArray baSignBuffer;

  void VerifyInit(CK_OBJECT_HANDLE PublicKey) override;
  void VerifyUpdate(ByteArray &Part) override;
  void VerifyFinal(ByteArray &Signature) override;

  void VerifyRecoverInit(CK_OBJECT_HANDLE PublicKey) override;
  ByteDynArray VerifyRecover(ByteArray &Signature) override;

  void SignInit(CK_OBJECT_HANDLE PrivateKey) override;
  void SignReset() override;
  void SignUpdate(ByteArray &Part) override;
  ByteDynArray SignFinal() override;

  void SignRecoverInit(CK_OBJECT_HANDLE PrivateKey) override;
  ByteDynArray SignRecover(ByteArray &baData) override;
};

/**
 * @brief RSA signing with integrated hashing (e.g. CKM_SHA1_RSA_PKCS).
 *
 * Delegates the hash computation to the provided CDigest, then applies
 * PKCS#1 v1.5 DigestInfo wrapping before the on-card RSA operation.
 */
class CSignRSAwithDigest : public CSignRSA {
 public:
  CSignRSAwithDigest(CK_MECHANISM_TYPE type, std::shared_ptr<CSession> Session,
                     CDigest *Digest);
  virtual ~CSignRSAwithDigest() override;

  CDigest *pDigest;
  bool SignSupportMultipart() override;
  void SignInit(CK_OBJECT_HANDLE PrivateKey) override;
  void SignReset() override;
  void SignUpdate(ByteArray &Part) override;
  ByteDynArray SignFinal() override;
  ByteDynArray SignGetOperationState() override;
  void SignSetOperationState(ByteArray &OperationState) override;
};

/** @brief RSA verification with integrated hashing (e.g. CKM_SHA1_RSA_PKCS). */
class CVerifyRSAwithDigest : public CVerifyRSA {
 public:
  CVerifyRSAwithDigest(CK_MECHANISM_TYPE type,
                       std::shared_ptr<CSession> Session, CDigest *Digest);
  virtual ~CVerifyRSAwithDigest() override;

  CDigest *pDigest;
  bool VerifySupportMultipart() override;
  void VerifyInit(CK_OBJECT_HANDLE PublicKey) override;
  void VerifyUpdate(ByteArray &Part) override;
  void VerifyFinal(ByteArray &Signature) override;
  ByteDynArray VerifyGetOperationState() override;
  void VerifySetOperationState(ByteArray &OperationState) override;
};

/** @brief CKM_MD5_RSA_PKCS — combined MD5 hash + RSA PKCS#1 v1.5 sign/verify.
 */
class CRSAwithMD5 : public CSignRSAwithDigest, public CVerifyRSAwithDigest {
 public:
  CRSAwithMD5(std::shared_ptr<CSession> Session);
  virtual ~CRSAwithMD5() override;

  CDigestMD5 md5;
};

/** @brief CKM_SHA1_RSA_PKCS — combined SHA-1 hash + RSA PKCS#1 v1.5
 * sign/verify. */
class CRSAwithSHA1 : public CSignRSAwithDigest, public CVerifyRSAwithDigest {
 public:
  CRSAwithSHA1(std::shared_ptr<CSession> Session);
  virtual ~CRSAwithSHA1() override;

  CDigestSHA sha1;
};

/** @brief CKM_SHA256_RSA_PKCS — combined SHA-256 hash + RSA PKCS#1 v1.5
 * sign/verify. */
class CRSAwithSHA256 : public CSignRSAwithDigest, public CVerifyRSAwithDigest {
 public:
  CRSAwithSHA256(std::shared_ptr<CSession> Session);
  virtual ~CRSAwithSHA256() override;

  CDigestSHA256 sha256;
};

}  // namespace p11
