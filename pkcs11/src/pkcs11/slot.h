// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file slot.h
 * @brief PKCS#11 slot representation mapping physical smart card readers.
 *
 * A slot holds the object map for the card currently inserted in the reader.
 * All sessions opened on a given card share the slot's object map.  When a card
 * is removed every session is closed and the object map is cleared.
 */

#pragma once

#include "pkcs11/cryptoki.h"
#include "util/syncro_mutex.h"

#pragma pack()
#include <atomic>
#include <map>
#include <memory>
#include <thread>
#include <vector>

#include "pkcs11/card_context.h"

namespace p11 {

using SlotMap = std::map<CK_SLOT_ID, std::shared_ptr<class CSlot>>;
using HandleObjMap =
    std::map<CK_OBJECT_HANDLE, std::shared_ptr<class CP11Object>>;
using ObjHandleMap =
    std::map<std::shared_ptr<class CP11Object>, CK_OBJECT_HANDLE>;

using P11ObjectVector = std::vector<std::shared_ptr<class CP11Object>>;

class CCardTemplate;

/// Sentinel value indicating no user is logged in.
#define CKU_NOBODY 0xffffff

/** @brief Possible card insertion/removal events detected by the monitor. */
enum class SlotEvent { NoEvent, Removed, Inserted };

/**
 * @brief Represents a single PKCS#11 slot backed by a physical card reader.
 *
 * Each CSlot owns two bidirectional maps (handle-to-object and
 * object-to-handle) so that PKCS#11 object handles are unique per slot.  Static
 * members manage the global slot list and the background card-event monitor
 * thread.
 */
class CSlot {
 private:
  static DWORD
      dwSlotCnt;  ///< Global counter for assigning unique PKCS#11 slot IDs.
  ByteDynArray GetATR();

 public:
  ISmartCardTransport &transport;
  SCARDHANDLE hCard;
  /** @brief Establish a PC/SC connection to the card in this slot. */
  void Connect();
  DWORD dwSessionCount;  ///< Number of open sessions on this slot.

  static SlotMap g_mSlots;  ///< Global map of all known slots.
  static bool
      bMonitorUpdate;  ///< Flag set when the monitor thread detects a change.

  CK_SLOT_ID hSlot;  ///< PKCS#11 slot identifier.

  std::string szName;  ///< Name of the associated card reader.

  bool bUpdated;  ///< True when the object map is in sync with the inserted
                  ///< card.

  ByteDynArray baSerial;
  std::shared_ptr<CCardTemplate> pSerialTemplate;

  ByteDynArray baATR;
  void GetATR(ByteArray &ATR);

  DWORD dwP11ObjCnt;  ///< Counter for generating unique object handles.
  HandleObjMap
      HandleP11Map;  ///< Handle -> object lookup (resolves app-provided IDs).
  ObjHandleMap
      ObjP11Map;  ///< Object -> handle lookup (assigns IDs on first use).

  /** @brief Allocate a new unique PKCS#11 object handle for this slot. */
  CK_OBJECT_HANDLE GetNewObjectID();

  /**
   * @brief Return the handle for @p pObject, creating one if it does not exist.
   */
  CK_OBJECT_HANDLE GetIDFromObject(const std::shared_ptr<CP11Object> &pObject);

  /** @brief Remove the handle associated with @p pObject. */
  void DelObjectHandle(const std::shared_ptr<CP11Object> &pObject);

  /** @brief Look up the object corresponding to @p hObjectHandle. */
  std::shared_ptr<CP11Object> GetObjectFromID(CK_OBJECT_HANDLE hObjectHandle);

  CK_USER_TYPE User;  ///< Currently logged-in user type, or CKU_NOBODY.

  CSlot(ISmartCardTransport &transport, const char *szName);
  ~CSlot();

  static CK_SLOT_ID GetNewSlotID();
  /** @brief Enumerate readers via PC/SC and create a CSlot for each. */
  static void InitSlotList(ISmartCardTransport &transport);
  static void DeleteSlotList();
  static std::shared_ptr<CSlot> GetSlotFromID(CK_SLOT_ID hSlotId);
  static std::shared_ptr<CSlot> GetSlotFromReaderName(const char *name);
  static CK_SLOT_ID AddSlot(std::shared_ptr<CSlot> pSlot);
  static void DeleteSlot(CK_SLOT_ID hSlotId);
  /** @brief Read card objects and populate the object map. */
  void Init();
  /** @brief Release slot resources and clear the object map. */
  void Final();

  void AddP11Object(std::shared_ptr<CP11Object> object);
  std::shared_ptr<CP11Object> FindP11Object(CK_OBJECT_CLASS objClass,
                                            CK_ATTRIBUTE_TYPE attr,
                                            CK_BYTE *val, int valLen);
  void DelP11Object(const std::shared_ptr<CP11Object> &pObject);
  void ClearP11Objects();
  /** @brief Check whether a card is physically present in the reader. */
  bool IsTokenPresent();

  P11ObjectVector P11Objects;  ///< All PKCS#11 objects exposed by the card.

  std::shared_ptr<CCardTemplate>
      pTemplate;  ///< Card template (valid when bUpdated is true).

  void *pTemplateData;  ///< Opaque template-specific data managed by the card
                        ///< plugin.

  static std::thread Thread;  ///< Background card-event monitor thread.
  static std::atomic<CCardContext *>
      ThreadContext;  ///< PC/SC context used by the monitor.

  SlotEvent lastEvent;

  /** @brief Populate a CK_SLOT_INFO structure for this slot. */
  void GetInfo(CK_SLOT_INFO_PTR pInfo);
  /** @brief Populate a CK_TOKEN_INFO structure for the inserted card. */
  void GetTokenInfo(CK_TOKEN_INFO_PTR pInfo);
  /** @brief Close every session open on this slot. */
  void CloseAllSessions();

  size_t SessionCount();
  size_t RWSessionCount();

  CCardContext Context;  ///< PC/SC context for card operations on this slot.
};

}  // namespace p11
