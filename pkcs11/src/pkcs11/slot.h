// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

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
 * @brief std::thread wrapper that never calls std::terminate() if it is
 * destroyed while still joinable.
 *
 * CSlot::Thread (below) is a namespace-scope static. When the host
 * process exits without ever calling C_Finalize() -- e.g. NSS
 * command-line tools such as `pdfsig` that skip NSS_Shutdown -- its
 * destructor runs directly from exit()'s atexit-handler processing,
 * *before* this library's __attribute__((destructor)) hook
 * (DllMainDetach, pkcs11_functions.cpp) gets a chance to run via
 * _dl_fini(); confirmed with gdb (`std::thread::~thread` for
 * CSlot::Thread called straight out of exit(), no DllMainDetach frame
 * anywhere on the stack). A plain std::thread's destructor calls
 * std::terminate() whenever joinable() is still true at that point
 * ("terminate called without an active exception"), aborting the whole
 * process.
 *
 * At that point in process teardown the destruction order of *other*
 * namespace-scope statics across translation units (p11Mutex,
 * p11slotEvent, g_transport in pkcs11_functions.cpp) is unspecified, so
 * this destructor must not depend on any of them being alive. It only
 * flips lock-free atomics (std::atomic<bool> has a trivial, side-effect
 * free destructor, so writing them stays safe regardless of the other
 * TU's teardown state) to ask the monitor loop to notice it must stop on
 * its own, then detaches: detach() only touches this object's own thread
 * handle (pthread_detach()), so it can never call std::terminate() and
 * never touches memory owned by another static. An earlier version also
 * cancelled the pending PC/SC call through the monitor thread's
 * transport reference to unblock it immediately; that reference
 * ultimately resolves to the polymorphic g_transport global in another
 * translation unit, and calling a virtual method through it after
 * g_transport was already destroyed produced "pure virtual method
 * called" -- exactly the class of crash this type exists to prevent. See
 * the destructor definition in slot.cpp.
 *
 * The normal shutdown path (C_Finalize / DllMainDetach) is unaffected:
 * it calls Thread.join() explicitly while every other static is still
 * fully alive, so joinable() is already false by the time this
 * destructor runs during ordinary program exit -- this is then a no-op.
 */
class ScopedMonitorThread : public std::thread {
 public:
  using std::thread::thread;

  ScopedMonitorThread &operator=(std::thread &&other) noexcept {
    std::thread::operator=(std::move(other));
    return *this;
  }

  ~ScopedMonitorThread();
};

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
  static std::atomic<bool>
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

  static ScopedMonitorThread Thread;  ///< Background card-event monitor thread.
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
