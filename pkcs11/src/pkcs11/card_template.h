#pragma once

#include <memory>
#include <string>

#include "pkcs11/session.h"

namespace p11 {

class CCardTemplate;

using templateInitLibraryFunc = void (*)(class CCardTemplate &Template,
                                        void *templateData);
using templateInitCardFunc = void (*)(void *&pTemplateData, CSlot &pSlot);
using templateFinalCardFunc = void (*)(void *pTemplateData);
using templateInitSessionFunc = void (*)(void *pTemplateData);
using templateFinalSessionFunc = void (*)(void *pTemplateData);
using templateMatchCardFunc = bool (*)(CSlot &pSlot);
using templateGetSerialFunc = ByteDynArray (*)(CSlot &pSlot);
using templateGetModelFunc = void (*)(CSlot &pSlot, std::string &szModel);
using templateGetTokenFlagsFunc = void (*)(CSlot &pSlot, CK_FLAGS &dwFlags);
using templateLoginFunc = void (*)(void *pTemplateData, CK_USER_TYPE userType,
                                  ByteArray &Pin);
using templateLogoutFunc = void (*)(void *pTemplateData, CK_USER_TYPE userType);
using templateReadObjectAttributesFunc = void (*)(void *pCardTemplateData,
                                                 CP11Object *pObject);
using templateSignFunc = void (*)(void *pCardTemplateData,
                                 CP11PrivateKey *pPrivKey,
                                 ByteArray &baSignBuffer,
                                 ByteDynArray &baSignature,
                                 CK_MECHANISM_TYPE mechanism, bool bSilent);
using templateSignRecoverFunc = void (*)(void *pCardTemplateData, CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer,
    ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent);
using templateDecryptFunc = void (*)(void *pCardTemplateData,
                                    CP11PrivateKey *pPrivKey,
                                    ByteArray &baEncryptedData,
                                    ByteDynArray &baData,
                                    CK_MECHANISM_TYPE mechanism, bool bSilent);
using templateGenerateRandomFunc = void (*)(void *pCardTemplateData,
                                           ByteArray &baRandomData);
using templateInitPINFunc = void (*)(void *pCardTemplateData, ByteArray &baPin);
using templateSetPINFunc = void (*)(void *pCardTemplateData, ByteArray &baOldPin,
                                   ByteArray &baNewPin, CK_USER_TYPE User);
using templateGetObjectSizeFunc = CK_ULONG (*)(void *pCardTemplateData,
                                              CP11Object *pObject);
using templateSetKeyPINFunc = void (*)(void *pTemplateData, CP11Object *pObject,
                                      ByteArray &Pin);
using templateSetAttributeFunc = void (*)(void *pTemplateData,
                                         CP11Object *pObject,
                                         CK_ATTRIBUTE_PTR pTemplate,
                                         CK_ULONG ulCount);
using templateCreateObjectFunc = std::shared_ptr<CP11Object> (*)(void *pTemplateData, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
using templateDestroyObjectFunc = void (*)(void *pTemplateData,
                                          CP11Object &Object);
using templateGenerateKeyFunc = std::shared_ptr<CP11Object> (*)(void *pCardTemplateData, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
using templateGenerateKeyPairFunc = void (*)(void *pCardTemplateData, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    std::shared_ptr<CP11Object> &pPublicKey,
    std::shared_ptr<CP11Object> &pPrivateKey);

class TemplateFuncList {
 public:
  templateInitLibraryFunc templateInitLibrary;
  templateInitCardFunc templateInitCard;
  templateFinalCardFunc templateFinalCard;
  templateInitSessionFunc templateInitSession;
  templateFinalSessionFunc templateFinalSession;
  templateMatchCardFunc templateMatchCard;
  templateGetSerialFunc templateGetSerial;
  templateGetModelFunc templateGetModel;
  templateLoginFunc templateLogin;
  templateLogoutFunc templateLogout;
  templateReadObjectAttributesFunc templateReadObjectAttributes;
  templateSignFunc templateSign;
  templateSignRecoverFunc templateSignRecover;
  templateDecryptFunc templateDecrypt;
  templateGenerateRandomFunc templateGenerateRandom;
  templateInitPINFunc templateInitPIN;
  templateSetPINFunc templateSetPIN;
  templateGetObjectSizeFunc templateGetObjectSize;
  templateSetKeyPINFunc templateSetKeyPIN;
  templateSetAttributeFunc templateSetAttribute;
  templateCreateObjectFunc templateCreateObject;
  templateDestroyObjectFunc templateDestroyObject;
  templateGetTokenFlagsFunc templateGetTokenFlags;
  templateGenerateKeyFunc templateGenerateKey;
  templateGenerateKeyPairFunc templateGenerateKeyPair;
};

using TemplateVector = std::vector<std::shared_ptr<CCardTemplate>>;
using templateFuncListFunc = void (*)(TemplateFuncList *);

class CCardTemplate {
 public:
  CCardTemplate(void);
  ~CCardTemplate(void);

  static TemplateVector g_mCardTemplates;

  static void AddTemplate(std::shared_ptr<CCardTemplate> pTemplate);

  static void InitTemplateList();
  static void DeleteTemplateList();

  static std::shared_ptr<CCardTemplate> GetTemplate(CSlot &pSlot);

  void InitLibrary(const char *szPath, void *templateData);
  TemplateFuncList FunctionList;

  std::string szName;
  std::string szManifacturer;
};

};  // namespace p11
