// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file session.h
 * @brief PKCS#11 session management and cryptographic operation state.
 *
 * Implements the CSession class that maps 1:1 to PKCS#11 sessions.
 * Each session is bound to a slot and holds the active digest, sign,
 * verify, and object-search state machines required by the Cryptoki API.
 * Also defines the p11_error exception used throughout the PKCS#11 layer.
 */

#pragma once

#include <memory>

#include "pcsc/scard_types.h"
#include "pkcs11/mechanism.h"
#include "pkcs11/p11_object.h"
#include "pkcs11/slot.h"

namespace p11 {

/**
 * @brief Exception carrying a PKCS#11 CK_RV error code.
 *
 * Thrown from session and slot operations and caught by the C_* wrapper
 * functions that convert it into the corresponding CK_RV return value.
 */
class p11_error : public logged_error {
  CK_RV p11ErrorCode;

 public:
  p11_error(CK_RV p11ErrorCode, const char *message)
      : logged_error(message), p11ErrorCode(p11ErrorCode) {}
  p11_error(CK_RV p11ErrorCode)
      : p11_error(p11ErrorCode,
                  stdPrintf("%s:%08x", "PKCS#11 error", p11ErrorCode).c_str()) {
  }
  CK_RV getP11ErrorCode() { return p11ErrorCode; }
};

/** @brief Tag identifiers for fields within a serialized operation state. */
enum OperationStateTag {
  OS_Flags,
  OS_User,
  OS_Digest,
  OS_Sign,
  OS_Verify,
  OS_Encrypt,
  OS_Decrypt,
  OS_Algo,
  OS_Data,
  OS_Key
};

using SessionMap = std::map<CK_SESSION_HANDLE, std::shared_ptr<CSession>>;

class CCardTemplate;
class CP11PublicKey;
class CP11PrivateKey;

/**
 * @brief A PKCS#11 session opened on a specific slot.
 *
 * Manages the lifecycle of find-object iterators, digest/sign/verify
 * operations, login/logout, and PIN management.  All instances are
 * stored in the global g_mSessions map keyed by session handle.
 */
class CSession : public std::enable_shared_from_this<CSession> {
 private:
  static DWORD
      dwSessionCnt;  ///< Counter for generating unique session handles.

 public:
  static SessionMap g_mSessions;  ///< Global map of active sessions.

  CK_SESSION_HANDLE hSessionHandle;
  CK_SLOT_ID slotID;
  CK_FLAGS flags;
  CK_VOID_PTR pApplication;
  CK_NOTIFY notify;

  std::shared_ptr<CSlot> pSlot;  ///< Slot this session is bound to.
  CSession();
  static std::shared_ptr<CSession> GetSessionFromID(
      CK_SESSION_HANDLE hSessionHandle);
  static CK_SESSION_HANDLE AddSession(std::unique_ptr<CSession> pSession);
  static void DeleteSession(CK_SESSION_HANDLE hSessionHandle);
  static CK_SLOT_ID GetNewSessionID();

  /** @brief Fill @p RandomData with hardware-generated random bytes from the
   * card. */
  void GenerateRandom(ByteArray &RandomData);

  /// @name Object search (C_FindObjects*)
  /// @{
  void FindObjectsInit(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
  void FindObjects(CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                   CK_ULONG_PTR pulObjectCount);
  void FindObjectsFinal();
  std::vector<CK_OBJECT_HANDLE>
      findResult;  ///< Handles matching the current search.
  bool bFindInit;  ///< True while a find operation is active.
  /// @}

  /// @name Authentication (C_Login / C_Logout)
  /// @{
  void Login(CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
  void Logout();
  /// @}

  /// @name PIN management (C_InitPIN / C_SetPIN)
  /// @{
  void InitPIN(ByteArray &Pin);
  void SetPIN(ByteArray &OldPin, ByteArray &NewPin);
  /// @}

  /// @name Object attribute operations
  /// @{
  void SetAttributeValue(CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount);
  CK_RV GetAttributeValue(CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount);
  CK_ULONG GetObjectSize(CK_OBJECT_HANDLE hObject);
  CK_OBJECT_HANDLE CreateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
  void DestroyObject(CK_OBJECT_HANDLE hObject);
  /// @}

  /// @name Key generation
  /// @{
  CK_OBJECT_HANDLE GenerateKey(CK_MECHANISM_PTR pMechanism,
                               CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
  void GenerateKeyPair(CK_MECHANISM_PTR pMechanism,
                       CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                       CK_ULONG ulPublicKeyAttributeCount,
                       CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                       CK_ULONG ulPrivateKeyAttributeCount,
                       CK_OBJECT_HANDLE_PTR phPublicKey,
                       CK_OBJECT_HANDLE_PTR phPrivateKey);
  /// @}

  /// @name Message digest operations (C_Digest*)
  /// @{
  void DigestInit(CK_MECHANISM_PTR pMechanism);
  void Digest(ByteArray &Data, ByteArray &Digest);
  void DigestUpdate(ByteArray &Data);
  void DigestFinal(ByteArray &Digest);
  std::unique_ptr<CDigest> pDigestMechanism;
  /// @}

  /// @name Signature verification (C_Verify*)
  /// @{
  void VerifyInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
  void Verify(ByteArray &Data, ByteArray &Signature);
  void VerifyUpdate(ByteArray &Data);
  void VerifyFinal(ByteArray &Signature);
  std::unique_ptr<CVerify> pVerifyMechanism;
  /// @}

  /// @name Signature verification with recovery (C_VerifyRecover*)
  /// @{
  void VerifyRecoverInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
  void VerifyRecover(ByteArray &Signature, ByteArray &Data);
  std::unique_ptr<CVerifyRecover> pVerifyRecoverMechanism;
  /// @}

  /// @name Signing operations (C_Sign*)
  /// @{
  void SignInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
  void Sign(ByteArray &Data, ByteArray &Signature);
  void SignUpdate(ByteArray &Data);
  void SignFinal(ByteArray &Signature);
  std::unique_ptr<CSign> pSignMechanism;
  /// @}

  /// @name Signing with recovery (C_SignRecover*)
  /// @{
  void SignRecoverInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
  void SignRecover(ByteArray &Data, ByteArray &Signature);
  std::unique_ptr<CSignRecover> pSignRecoverMechanism;
  /// @}

  /// @name Operation state save/restore (C_GetOperationState /
  /// C_SetOperationState)
  /// @{
  void SetOperationState(ByteArray &OperationState);
  void GetOperationState(ByteArray &OperationState);
  /// @}

  /** @brief True if a read-only session exists on this slot. */
  bool ExistsRO();
  /** @brief True if a read-write SO session exists on this slot. */
  bool ExistsSO_RW();
};

}  // namespace p11
