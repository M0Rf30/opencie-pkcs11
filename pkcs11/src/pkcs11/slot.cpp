// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file slot.cpp
 * @brief PKCS#11 slot management and card monitoring implementation
 */

#include "pkcs11/slot.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>

#include "csp/atr.h"
#include "logger/logger.h"
#include "pkcs11/card_template.h"
#include "pkcs11_functions.h"
#include "util/syncro_event.h"
#include "util/util.h"

using namespace CieIDLogger;

extern CLog Log;

extern std::mutex p11Mutex;
extern auto_reset_event p11slotEvent;
extern std::atomic<bool> bP11Terminate;
extern std::atomic<bool> bP11Initialized;

extern uint8_t NXP_ATR[];
extern uint8_t Gemalto_ATR[];
extern uint8_t Gemalto2_ATR[];
extern uint8_t STM_ATR[];
extern uint8_t STM2_ATR[];

extern ByteArray baNXP_ATR;
extern ByteArray baGemalto_ATR;
extern ByteArray baGemalto2_ATR;
extern ByteArray baSTM_ATR;
extern ByteArray baSTM2_ATR;
extern ByteArray baSTM3_ATR;

namespace p11 {

DWORD CSlot::dwSlotCnt = 0;
SlotMap CSlot::g_mSlots;
std::thread CSlot::Thread;
std::atomic<CCardContext *> CSlot::ThreadContext {nullptr};
bool CSlot::bMonitorUpdate = false;

CSlot::CSlot(ISmartCardTransport &transport, const char *szReader)
    : transport(transport), Context(transport) {
  szName = szReader;
  lastEvent = SlotEvent::NoEvent;
  bUpdated = 0;
  User = CKU_NOBODY;
  dwP11ObjCnt = 0;
  dwSessionCount = 0;
  pTemplate = nullptr;
  // slotMutex.Create(mutexName(szReader));
  pSerialTemplate = nullptr;
  hCard = 0;
  hSlot = 0;
  pTemplateData = nullptr;
}

CSlot::~CSlot() { Final(); }

CK_SLOT_ID CSlot::GetNewSlotID() { init_func return ++dwSlotCnt; }

static DWORD slotMonitor(SlotMap *pSlotMap) {
  while (true) {
    CCardContext Context(pSlotMap->begin()->second->transport);
    CSlot::ThreadContext = &Context;
    size_t dwSlotNum = pSlotMap->size();
    std::vector<SCARD_READERSTATE> state(dwSlotNum);
    std::vector<std::shared_ptr<CSlot>> slot(dwSlotNum);
    LONG ris;
    {
      std::unique_lock<std::mutex> lock(p11Mutex);
      size_t i = 0;
      for (auto &[id, pSlot] : *pSlotMap) {
        if (!bP11Initialized) {
          CSlot::ThreadContext = nullptr;
          return 0;
        }

        state[i].szReader = pSlot->szName.c_str();
        slot[i] = pSlot;
        if ((ris = pSlotMap->begin()->second->transport.GetStatusChange(
                 Context, 0, &state[i], 1)) != S_OK) {
          if (ris != SCARD_E_TIMEOUT) {
            LOG_ERROR("slotMonitor - SCardGetStatusChange error: %08X", ris);
            // don't use ExitThread!!!
            // otherwise I don't call destructors, and everything hangs
            // ESPECIALLY the p11Mutex
            CSlot::ThreadContext = nullptr;
            return 1;
          }
        }
        state[i].dwCurrentState =
            state[i].dwEventState & (~SCARD_STATE_CHANGED);
        i++;
      }
    }
    CSlot::bMonitorUpdate = false;
    while (true) {
      Context.validate();
      ris = pSlotMap->begin()->second->transport.GetStatusChange(
          Context, 1000, state.data(), static_cast<DWORD>(dwSlotNum));
      if (ris != S_OK) {
        if (CSlot::bMonitorUpdate || ris == SCARD_E_SYSTEM_CANCELLED ||
            ris == SCARD_E_SERVICE_STOPPED || ris == SCARD_E_INVALID_HANDLE ||
            ris == ERROR_INVALID_HANDLE) {
          LOG_DEBUG("slotMonitor - Monitor Update");
          break;
        }
        if (ris == SCARD_E_CANCELLED || bP11Terminate || !bP11Initialized) {
          LOG_DEBUG("slotMonitor - Terminate");
          p11slotEvent.set();
          CSlot::ThreadContext = nullptr;
          // no exitThread, vedi sopra;
          return 0;
        }
        if (ris != SCARD_E_TIMEOUT && ris != SCARD_E_NO_READERS_AVAILABLE) {
          LOG_ERROR("slotMonitor - SCardGetStatusChange error: %08X", ris);
          p11slotEvent.set();
          CSlot::ThreadContext = nullptr;
          // no exitThread, vedi sopra;
          return 1;
        }
        if (ris == SCARD_E_NO_READERS_AVAILABLE) {
          LOG_INFO("slotMonitor - No smart card reader connected: %08X", ris);
          CSlot::ThreadContext = nullptr;
          // no exitThread, vedi sopra;
          return 1;
        }
      }
      if (bP11Terminate || !bP11Initialized) {
        LOG_INFO("slotMonitor - Terminate");
        p11slotEvent.set();
        CSlot::ThreadContext = nullptr;
        // no exitThread, see above;
        return 0;
      }

      for (size_t i = 0; i < dwSlotNum; i++) {
        if ((state[i].dwCurrentState & SCARD_STATE_PRESENT) &&
            ((state[i].dwEventState & SCARD_STATE_EMPTY) ||
             (state[i].dwEventState & SCARD_STATE_UNAVAILABLE))) {
          // a card has been removed!!
          // synchronize on the main p11 mutex
          // functions currently executing that access the
          // card will fail miserably, but if you remove the card
          // while I'm signing it's not my fault!

          std::unique_lock<std::mutex> lock(p11Mutex);

          slot[i]->lastEvent = SlotEvent::Removed;
          slot[i]->Final();
          slot[i]->baATR.clear();
          p11slotEvent.set();
        }
        if (((state[i].dwCurrentState & SCARD_STATE_UNAVAILABLE) ||
             (state[i].dwCurrentState & SCARD_STATE_EMPTY)) &&
            (state[i].dwEventState & SCARD_STATE_PRESENT)) {
          // a card has been inserted!!
          std::unique_lock<std::mutex> lock(p11Mutex);

          slot[i]->lastEvent = SlotEvent::Inserted;
          ByteArray ba;
          slot[i]->GetATR(ba);
          p11slotEvent.set();
        }
        state[i].dwCurrentState =
            state[i].dwEventState & (~SCARD_STATE_CHANGED);
      }
    }
    CSlot::ThreadContext = nullptr;
  }
  // no exitThread, vedi sopra;
  return 0;
}

CK_SLOT_ID CSlot::AddSlot(std::shared_ptr<CSlot> pSlot) {
  init_func pSlot->hSlot = static_cast<CK_SLOT_ID>(pSlot->GetNewSlotID());
  auto id = pSlot->hSlot;
  g_mSlots.insert(std::make_pair(pSlot->hSlot, std::move(pSlot)));
  return id;
}

void CSlot::DeleteSlot(CK_SLOT_ID hSlotId) {
  init_func std::shared_ptr<CSlot> pSlot = GetSlotFromID(hSlotId);

  if (!pSlot) throw p11_error(CKR_SLOT_ID_INVALID);

  pSlot->CloseAllSessions();
  pSlot->Final();
}

std::shared_ptr<CSlot> CSlot::GetSlotFromReaderName(const char *name) {
  init_func for (auto &[id, slot] : g_mSlots) {
    if (strcmp(slot->szName.c_str(), name) == 0) {
      return slot;
    }
  }
  return nullptr;
}

std::shared_ptr<CSlot> CSlot::GetSlotFromID(CK_SLOT_ID hSlotId) {
  init_func auto pPair = g_mSlots.find(hSlotId);
  if (pPair == g_mSlots.end()) {
    return nullptr;
  }
  return pPair->second;
}

void CSlot::DeleteSlotList() {
  init_func

      if (Thread.joinable()) Thread.join();

  for (auto &[id, slot] : CSlot::g_mSlots) {
    DeleteSlot(slot->hSlot);
  }
}

void CSlot::InitSlotList(ISmartCardTransport &transport) {
  // InitSlotList must update the slot list;
  // i.e., it must add slots that weren't there before and
  // delete those that are no longer present
  init_func bool bMapChanged = false;
  DWORD readersLen = 0;

  CCardContext Context(transport);

  if (!bP11Initialized) return;

  auto ris = Context.transport.ListReaders(Context, nullptr, &readersLen);
  if (ris != S_OK) {
    if (ris == SCARD_E_NO_READERS_AVAILABLE || ris == SCARD_E_NO_SERVICE)
      return;
    throw windows_error(ris);
  }
  std::string readers;
  readers.resize(readersLen + 1);
  if ((ris = Context.transport.ListReaders(Context, &readers[0],
                                           &readersLen)) != SCARD_S_SUCCESS)
    throw windows_error(ris);

  const char *szReaderName = readers.c_str();

  while (*szReaderName != 0) {
    if (!bP11Initialized) return;

    // let's see if this slot was already there before
    LOG_INFO("InitSlotList - reader:%s", szReaderName);
    std::shared_ptr<CSlot> pSlot = GetSlotFromReaderName(szReaderName);
    if (pSlot == nullptr) {
      auto pSlot2 = std::make_shared<CSlot>(transport, szReaderName);
      AddSlot(pSlot2);
      bMapChanged = true;
    }
    szReaderName = szReaderName + strnlen(szReaderName, readersLen) + 1;
  }
  // now I check if all slots in the map are still there
  for (auto it = g_mSlots.begin(); it != g_mSlots.end(); ++it) {
    if (!bP11Initialized) return;

    LOG_DEBUG("InitSlotList - %s", it->second->szName.c_str());
    const char *name = it->second->szName.c_str();

    const char *szReaderName2 = readers.c_str();
    // char *szReaderName=szReaderAlloc;
    bool bFound = false;
    while (*szReaderName2 != 0) {
      if (strcmp(name, szReaderName2) == 0) {
        bFound = true;
        break;
      }
      szReaderName2 = szReaderName2 + strnlen(szReaderName2, readersLen) + 1;
    }
    if (!bFound) {
      CK_SLOT_ID ID = it->second->hSlot;
      it--;
      DeleteSlot(ID);
      bMapChanged = true;
    }
  }
  bMonitorUpdate = bMapChanged;

  if (!bP11Initialized) return;

  if (!Thread.joinable()) Thread = std::thread(slotMonitor, &g_mSlots);
}

bool CSlot::IsTokenPresent() {
  init_func SCARD_READERSTATE state;
  memset(&state, 0, sizeof(SCARD_READERSTATE));
  state.szReader = szName.c_str();

  Context.validate();
  bool retry = false;
  while (true) {
    LONG ris = transport.GetStatusChange(Context, 0, &state, 1);
    if (ris == S_OK) {
      if ((state.dwEventState & SCARD_STATE_UNAVAILABLE) ==
          SCARD_STATE_UNAVAILABLE)
        throw p11_error(CKR_DEVICE_REMOVED);
      if ((state.dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT)
        return true;
      else
        return false;
    } else {
      if (ris == SCARD_E_SERVICE_STOPPED || ris == SCARD_E_INVALID_HANDLE ||
          ris == ERROR_INVALID_HANDLE) {
        // I need to get a new context and retry
        if (!retry)
          retry = true;
        else
          throw windows_error(ris);
        Context.renew();
        continue;
      }
      if (ris == SCARD_E_NO_READERS_AVAILABLE)
        throw p11_error(CKR_DEVICE_REMOVED);
      throw windows_error(ris);
    }
  }
}

void CSlot::GetInfo(CK_SLOT_INFO_PTR pInfo) {
  init_func pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
  // verify that there is a card inserted

  if (IsTokenPresent()) pInfo->flags |= CKF_TOKEN_PRESENT;

  memset(pInfo->slotDescription, 0, 64);
  size_t SDLen = min1(64, szName.size() - 1);
  std::memcpy(pInfo->slotDescription, szName.c_str(), SDLen);

  memset(pInfo->manufacturerID, 0, 32);
  // I don't know exactly why, but in R1 the manufacturerID is the first 32
  // characters of slotDescription
  size_t MIDLen = min1(32, szName.size());
  std::memcpy(pInfo->manufacturerID, szName.c_str(), MIDLen);

  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;

  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;
}

void CSlot::GetTokenInfo(CK_TOKEN_INFO_PTR pInfo) {
  init_func

      if (pTemplate == nullptr) pTemplate = CCardTemplate::GetTemplate(*this);

  if (pTemplate == nullptr) throw p11_error(CKR_TOKEN_NOT_RECOGNIZED);

  memset(pInfo->label, ' ', sizeof(pInfo->label));
  std::memcpy(reinterpret_cast<char *>(pInfo->label), pTemplate->szName.c_str(),
              min1(pTemplate->szName.length(), sizeof(pInfo->label)));
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));

  LOG_DEBUG("[PKCS11] GetTokenInfo - CIE ATR:");
  LOG_BUFFER(baATR.data(), baATR.size());

  std::string manifacturer;

  std::vector<uint8_t> atr_vector(baATR.data(), baATR.data() + baATR.size());
  manifacturer = get_manufacturer(atr_vector);

  if (manifacturer.size() == 0) {
    throw p11_error(CKR_TOKEN_NOT_RECOGNIZED, "CIE not recognized");
  }

  LOG_INFO("[PKCS11] GetTokenInfo - CIE Detected: %s", manifacturer.c_str());

  std::memcpy(reinterpret_cast<char *>(pInfo->manufacturerID),
              manifacturer.c_str(), manifacturer.size());

  if (baSerial.isEmpty() || pSerialTemplate != pTemplate) {
    pSerialTemplate = pTemplate;
    baSerial = pTemplate->FunctionList.templateGetSerial(*this);
  }

  std::string model;
  pTemplate->FunctionList.templateGetModel(*this, model);

  memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
  size_t UIDsize = min1(sizeof(pInfo->serialNumber), baSerial.size());
  std::memcpy(pInfo->serialNumber, baSerial.data(), UIDsize);

  memset(pInfo->model, ' ', sizeof(pInfo->model));
  std::memcpy(pInfo->model, model.c_str(),
              min1(model.length(), sizeof(pInfo->model)));

  CK_FLAGS dwFlags;
  pTemplate->FunctionList.templateGetTokenFlags(*this, dwFlags);
  pInfo->flags = dwFlags;

  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulMaxSessionCount = MAXSESSIONS;
  size_t dwSessCount = SessionCount();

  pInfo->ulSessionCount = static_cast<CK_ULONG>(dwSessCount);
  size_t dwRWSessCount = RWSessionCount();

  pInfo->ulRwSessionCount = dwRWSessCount;
  pInfo->ulMaxRwSessionCount = MAXSESSIONS;

  pInfo->ulMinPinLen = 8;
  pInfo->ulMaxPinLen = 8;

  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;

  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;

  std::memcpy(reinterpret_cast<char *>(pInfo->utcTime), "1234567890123456",
              16);  // OK
}

void CSlot::CloseAllSessions() {
  init_func

      auto it = CSession::g_mSessions.begin();
  while (it != CSession::g_mSessions.end()) {
    if (it->second->pSlot.get() == this) {
      CSession *pSession = it->second.get();
      ++it;
      CSession::DeleteSession(pSession->hSessionHandle);
    } else
      ++it;
  }
}

void CSlot::Init() {
  init_func if (!bUpdated) {
    if (pTemplate == nullptr) pTemplate = CCardTemplate::GetTemplate(*this);

    if (pTemplate == nullptr) throw p11_error(CKR_TOKEN_NOT_RECOGNIZED);

    pTemplate->FunctionList.templateInitCard(pTemplateData, *this);
    bUpdated = true;
  }
}

void CSlot::Final() {
  if (bUpdated) {
    // delete template data
    pTemplate->FunctionList.templateFinalCard(pTemplateData);
    pTemplate = nullptr;

    baATR.clear();
    baSerial.clear();

    P11Objects.clear();

    // delete all sessions
    auto it = CSession::g_mSessions.begin();
    while (it != CSession::g_mSessions.end()) {
      if (it->second->pSlot.get() == this) {
        it = CSession::g_mSessions.erase(it);
        dwSessionCount--;
      } else
        ++it;
    }
    // dwSessionCount should already be 0...
    // but for safety I set it manually

    User = CKU_NOBODY;
    dwSessionCount = 0;
    bUpdated = false;
  }
}

std::shared_ptr<CP11Object> CSlot::FindP11Object(CK_OBJECT_CLASS objClass,
                                                 CK_ATTRIBUTE_TYPE attr,
                                                 CK_BYTE *val, int valLen) {
  for (const auto &obj : P11Objects) {
    if (obj->ObjClass == objClass) {
      ByteArray *attrVal = obj->getAttribute(attr);
      if (attrVal && attrVal->size() == static_cast<size_t>(
                                            valLen)) {  // Cast valLen to size_t
        if (memcmp(attrVal->data(), val, valLen) == 0) {
          return obj;
        }
      }
    }
  }
  return nullptr;
}

void CSlot::AddP11Object(std::shared_ptr<CP11Object> p11obj) {
  init_func p11obj->pSlot = this;
  P11Objects.emplace_back(std::move(p11obj));
}

void CSlot::ClearP11Objects() {
  init_func P11Objects.clear();
  ObjP11Map.clear();
  HandleP11Map.clear();
}

void CSlot::DelP11Object(const std::shared_ptr<CP11Object> &object) {
  init_func bool bFound = false;
  for (auto it = P11Objects.begin(); it != P11Objects.end(); ++it) {
    if (*it == object) {
      bFound = true;
      P11Objects.erase(it);
      break;
    }
  }
  ER_ASSERT(bFound, ERR_FIND_OBJECT)

  auto itObj = ObjP11Map.find(object);
  if (itObj != ObjP11Map.end()) {
    auto itHandle = HandleP11Map.find(itObj->second);
    ObjP11Map.erase(itObj);
    if (itHandle != HandleP11Map.end()) HandleP11Map.erase(itHandle);
  }
}

size_t CSlot::SessionCount() { init_func return dwSessionCount; }

size_t CSlot::RWSessionCount() {
  init_func size_t dwRWSessCount = 0;
  for (auto &[handle, session] : CSession::g_mSessions) {
    if (session->pSlot.get() == this && (session->flags & CKF_RW_SESSION) != 0)
      dwRWSessCount++;
  }
  return dwRWSessCount;
}

CK_OBJECT_HANDLE CSlot::GetIDFromObject(
    const std::shared_ptr<CP11Object> &pObject) {
  init_func

      if (pObject->IsPrivate() &&
          User != CKU_USER) throw p11_error(CKR_USER_NOT_LOGGED_IN);

  auto pPair = ObjP11Map.find(pObject);
  if (pPair == ObjP11Map.end()) {
    // didn't find the object in the object map;
    // I need to add it

    CK_OBJECT_HANDLE hObject = static_cast<CK_OBJECT_HANDLE>(
        reinterpret_cast<uintptr_t>(&pObject));  // GetNewObjectID();
    ObjP11Map[pObject] = hObject;
    HandleP11Map[hObject] = pObject;
    return hObject;
  }
  return pPair->second;
}

void CSlot::DelObjectHandle(const std::shared_ptr<CP11Object> &pObject) {
  init_func auto pPair = ObjP11Map.find(pObject);
  if (pPair != ObjP11Map.end()) {
    auto pPair2 = HandleP11Map.find(pPair->second);
    if (pPair2 != HandleP11Map.end()) HandleP11Map.erase(pPair2);
    ObjP11Map.erase(pPair);
  }
}

std::shared_ptr<CP11Object> CSlot::GetObjectFromID(
    CK_OBJECT_HANDLE hObjectHandle) {
  init_func auto pPair = HandleP11Map.find(hObjectHandle);
  if (pPair == HandleP11Map.end()) return nullptr;

  return pPair->second;
}

void CSlot::Connect() {
  init_func DWORD dwProtocol;

  Context.validate();
  bool retry = false;
  while (true) {
    LONG ris = transport.Connect(Context, szName.c_str(), SCARD_SHARE_SHARED,
                                 SCARD_PROTOCOL_T1, &hCard, &dwProtocol);
    if (ris == SCARD_S_SUCCESS) {
      return;
    } else {
      if (ris == SCARD_E_SERVICE_STOPPED || ris == SCARD_E_INVALID_HANDLE ||
          ris == ERROR_INVALID_HANDLE) {
        if (!retry)
          retry = true;
        else {
          throw windows_error(ris);
        }
        Context.renew();
      } else {
        throw windows_error(ris);
      }
    }
  }
}

#ifndef SCARD_ATTR_VALUE
#define SCARD_ATTR_VALUE(Class, Tag) \
  ((((uint32_t)(Class)) << 16) | ((uint32_t)(Tag)))
#endif
#ifndef SCARD_CLASS_ICC_STATE
#define SCARD_CLASS_ICC_STATE 9 /**< ICC State specific definitions */
#endif
#ifndef SCARD_ATTR_ATR_STRING
#define SCARD_ATTR_ATR_STRING             \
  SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, \
                   0x0303) /**< Answer to reset (ATR) string. */
#endif

ByteDynArray CSlot::GetATR() {
  init_func

      DWORD atrLen = 40;
  char ATR[40];
  long ret = transport.GetAttrib(this->hCard, SCARD_ATTR_ATR_STRING,
                                 reinterpret_cast<uint8_t *>(ATR), &atrLen);
  if (ret == SCARD_S_SUCCESS) {
    LOG_INFO("CSlot::GetATR() - ATR:");
    LOG_BUFFER(reinterpret_cast<BYTE *>(ATR), atrLen);
    return ByteDynArray(ByteArray(reinterpret_cast<BYTE *>(ATR), atrLen));
  } else {
    LOG_INFO("CSlot::GetATR() - no card inserted");
    return ByteDynArray(ByteArray());
  }
}

void CSlot::GetATR(ByteArray &ATR) {
  init_func if (baATR.size() != 0) {
    ATR = baATR;
    return;
  }
  baATR = GetATR();
  ATR = baATR;
}

}  // namespace p11
