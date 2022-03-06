#pragma once
#include "pcsc/scard_types.h"

#include "pkcs11/card_template.h"
#include "pkcs11/slot.h"

void CIEtemplateInitLibrary(class p11::CCardTemplate &Template, void *templateData);
void CIEtemplateInitCard(void *&pTemplateData, p11::CSlot &pSlot);
void CIEtemplateFinalCard(void *pTemplateData);
void CIEtemplateInitSession(void *pTemplateData);
void CIEtemplateFinalSession(void *pTemplateData);
bool CIEtemplateMatchCard(p11::CSlot &pSlot);
ByteDynArray CIEtemplateGetSerial(p11::CSlot &pSlot);
void CIEtemplateGetModel(p11::CSlot &pSlot, std::string &szModel);
void CIEtemplateGetTokenFlags(p11::CSlot &pSlot, CK_FLAGS &dwFlags);
void CIEtemplateLogin(void *pTemplateData, CK_USER_TYPE userType,
                      ByteArray &Pin);
void CIEtemplateLogout(void *pTemplateData, CK_USER_TYPE userType);
void CIEtemplateReadObjectAttributes(void *pCardTemplateData,
                                     p11::CP11Object *pObject);
void CIEtemplateSign(void *pCardTemplateData, p11::CP11PrivateKey *pPrivKey,
                     ByteArray &baSignBuffer, ByteDynArray &baSignature,
                     CK_MECHANISM_TYPE mechanism, bool bSilent);
void CIEtemplateSignRecover(void *pCardTemplateData, p11::CP11PrivateKey *pPrivKey,
                            ByteArray &baSignBuffer, ByteDynArray &baSignature,
                            CK_MECHANISM_TYPE mechanism, bool bSilent);
void CIEtemplateDecrypt(void *pCardTemplateData, p11::CP11PrivateKey *pPrivKey,
                        ByteArray &baEncryptedData, ByteDynArray &baData,
                        CK_MECHANISM_TYPE mechanism, bool bSilent);
void CIEtemplateGenerateRandom(void *pCardTemplateData,
                               ByteArray &baRandomData);
void CIEtemplateInitPIN(void *pCardTemplateData, ByteArray &baPin);
void CIEtemplateSetPIN(void *pCardTemplateData, ByteArray &baOldPin,
                       ByteArray &baNewPin, CK_USER_TYPE User);
CK_ULONG CIEtemplateGetObjectSize(void *pCardTemplateData, p11::CP11Object *pObject);
void CIEtemplateSetKeyPIN(void *pTemplateData, p11::CP11Object *pObject,
                          ByteArray &Pin);
void CIEtemplateSetAttribute(void *pTemplateData, p11::CP11Object *pObject,
                             CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
std::shared_ptr<p11::CP11Object> CIEtemplateCreateObject(void *pTemplateData,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount);
void CIEtemplateDestroyObject(void *pTemplateData, p11::CP11Object &Object);
std::shared_ptr<p11::CP11Object> CIEtemplateGenerateKey(void *pCardTemplateData,
                                                   CK_MECHANISM_PTR pMechanism,
                                                   CK_ATTRIBUTE_PTR pTemplate,
                                                   CK_ULONG ulCount);
void CIEtemplateGenerateKeyPair(void *pCardTemplateData,
                                CK_MECHANISM_PTR pMechanism,
                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                CK_ULONG ulPublicKeyAttributeCount,
                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                CK_ULONG ulPrivateKeyAttributeCount,
                                std::shared_ptr<p11::CP11Object> &pPublicKey,
                                std::shared_ptr<p11::CP11Object> &pPrivateKey);
