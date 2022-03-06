#pragma once

#include "pkcs11/cryptoki.h"
#include "Util/syncro_mutex.h"

#pragma pack()
#include <atomic>
#include <map>
#include <memory>
#include <thread>
#include <vector>

#include "pkcs11/card_context.h"

namespace p11 {

using SlotMap = std::map<CK_SLOT_ID, std::shared_ptr<class CSlot>>;
using HandleObjMap = std::map<CK_OBJECT_HANDLE, std::shared_ptr<class CP11Object>>;
using ObjHandleMap = std::map<std::shared_ptr<class CP11Object>, CK_OBJECT_HANDLE>;

using P11ObjectVector = std::vector<std::shared_ptr<class CP11Object>>;

// lo slot contiene la mappa degli oggetti della carta che ci
// sta dentro; quindi ogni sessione su quella carta condivide
// la mappa di oggetti dello slot. Quando sfilo la carta
// devo chiudere tutte le sessioni e cancellare la mappa di oggetti
// corrente

class CCardTemplate;

#define CKU_NOBODY 0xffffff

enum class SlotEvent { NoEvent, Removed, Inserted };

class CSlot {
 private:
  static DWORD dwSlotCnt;  // counter degli slot (ID P11)
  ByteDynArray GetATR();

 public:
  ISmartCardTransport &transport;
  SCARDHANDLE hCard;
  void Connect();
  DWORD dwSessionCount;  // numero di session aperte su questo slot

  static SlotMap g_mSlots;     // mappa globale degli slot
  static bool bMonitorUpdate;  // mappa globale degli slot

  CK_SLOT_ID hSlot;  // ID P11 dello slot

  std::string szName;  // nome del lettore associato

  bool bUpdated;  // flag: la mappa degli oggetti è aggiornata alla carta
  // che attualmente è nel lettore?

  ByteDynArray baSerial;
  std::shared_ptr<CCardTemplate> pSerialTemplate;

  ByteDynArray baATR;
  void GetATR(ByteArray &ATR);

  DWORD dwP11ObjCnt;          // counter degli oggetti (ID P11)
  HandleObjMap HandleP11Map;  // mi servono due mappe per gestire correttamente
  ObjHandleMap ObjP11Map;     // gli ID oggetti specifici per uno slot
  // una per tradurre gli ID passati dall'applicazione,
  // un'altra per sapere se un oggetto restituito
  // ha già un ID o meno

  CK_OBJECT_HANDLE GetNewObjectID();
  CK_OBJECT_HANDLE GetIDFromObject(const std::shared_ptr<CP11Object> &pObject);
  // restituisce l'handle di sessione dell'oggetto corrispondente
  // pObject, e lo crea se non esiste
  void DelObjectHandle(const std::shared_ptr<CP11Object> &pObject);
  // cancella l'handle dell'oggetto pObject
  std::shared_ptr<CP11Object> GetObjectFromID(CK_OBJECT_HANDLE hObjectHandle);

  CK_USER_TYPE User;

  CSlot(ISmartCardTransport &transport, const char *szName);
  ~CSlot();
  static CK_SLOT_ID GetNewSlotID();
  static void InitSlotList(ISmartCardTransport &transport);
  static void DeleteSlotList();
  static std::shared_ptr<CSlot> GetSlotFromID(CK_SLOT_ID hSlotId);
  static std::shared_ptr<CSlot> GetSlotFromReaderName(const char *name);
  static CK_SLOT_ID AddSlot(std::shared_ptr<CSlot> pSlot);
  static void DeleteSlot(CK_SLOT_ID hSlotId);
  void Init();
  void Final();

  void AddP11Object(std::shared_ptr<CP11Object> object);
  std::shared_ptr<CP11Object> FindP11Object(CK_OBJECT_CLASS objClass,
                                            CK_ATTRIBUTE_TYPE attr,
                                            CK_BYTE *val, int valLen);
  void DelP11Object(const std::shared_ptr<CP11Object> &pObject);
  void ClearP11Objects();
  bool IsTokenPresent();

  P11ObjectVector P11Objects;  // vettore degli oggetti

  std::shared_ptr<CCardTemplate> pTemplate;  // template della carta
  // (aggiornato se bUpdated=true

  void *pTemplateData;
  // i dati specifici del template della carta,
  // gestiti dalla DLL manager

  static std::thread Thread;           // thread monitor degli eventi
  static std::atomic<CCardContext *> ThreadContext;  // context del monitor degli eventi

  SlotEvent lastEvent;

  void GetInfo(CK_SLOT_INFO_PTR pInfo);
  void GetTokenInfo(CK_TOKEN_INFO_PTR pInfo);
  void CloseAllSessions();

  size_t SessionCount();
  size_t RWSessionCount();

  CCardContext Context;
};

}  // namespace p11
