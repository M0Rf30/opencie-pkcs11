// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file cie_p11_template.h
 * @brief CIE (Carta d'Identita Elettronica) card template plugin for PKCS#11.
 *
 * Declares the concrete callback functions that implement the card template
 * interface (see card_template.h) for Italian CIE 3.0 smart cards.  These
 * functions handle ATR matching, IAS-ECC authentication, certificate/key
 * enumeration, PIN management, and RSA signing via the on-card applet.
 */

#pragma once
#include "pcsc/scard_types.h"
#include "pkcs11/card_template.h"
#include "pkcs11/slot.h"

/** @brief Populate the card template with CIE-specific metadata and callbacks.
 */
void CIEtemplateInitLibrary(class p11::CCardTemplate &Template,
                            void *templateData);

/** @brief Read CIE card objects (certificates, keys) and populate the slot. */
void CIEtemplateInitCard(void *&pTemplateData, p11::CSlot &pSlot);

/** @brief Release CIE-specific per-card data. */
void CIEtemplateFinalCard(void *pTemplateData);

/** @brief Per-session initialization (currently a no-op for CIE). */
void CIEtemplateInitSession(void *pTemplateData);

/** @brief Per-session finalization (currently a no-op for CIE). */
void CIEtemplateFinalSession(void *pTemplateData);

/** @brief Return true if the card in @p pSlot is a CIE (matched by ATR). */
bool CIEtemplateMatchCard(p11::CSlot &pSlot);

/** @brief Read the card serial number from the CIE. */
ByteDynArray CIEtemplateGetSerial(p11::CSlot &pSlot);

/** @brief Fill @p szModel with the CIE model string. */
void CIEtemplateGetModel(p11::CSlot &pSlot, std::string &szModel);

/** @brief Set CIE-specific token flags (e.g. write-protected). */
void CIEtemplateGetTokenFlags(p11::CSlot &pSlot, CK_FLAGS &dwFlags);

/** @brief Authenticate the user to the CIE card via IAS-ECC secure messaging.
 */
void CIEtemplateLogin(void *pTemplateData, CK_USER_TYPE userType,
                      ByteArray &Pin);

/** @brief End the authenticated session on the CIE card. */
void CIEtemplateLogout(void *pTemplateData, CK_USER_TYPE userType);

/** @brief Lazy-read the full attribute set for a PKCS#11 object from the card.
 */
void CIEtemplateReadObjectAttributes(void *pCardTemplateData,
                                     p11::CP11Object *pObject);

/** @brief Perform an RSA signature operation using the CIE on-card private key.
 */
void CIEtemplateSign(void *pCardTemplateData, p11::CP11PrivateKey *pPrivKey,
                     ByteArray &baSignBuffer, ByteDynArray &baSignature,
                     CK_MECHANISM_TYPE mechanism, bool bSilent);

/** @brief Perform an RSA sign-recover operation using the CIE private key. */
void CIEtemplateSignRecover(void *pCardTemplateData,
                            p11::CP11PrivateKey *pPrivKey,
                            ByteArray &baSignBuffer, ByteDynArray &baSignature,
                            CK_MECHANISM_TYPE mechanism, bool bSilent);

/** @brief Perform RSA decryption using the CIE on-card private key. */
void CIEtemplateDecrypt(void *pCardTemplateData, p11::CP11PrivateKey *pPrivKey,
                        ByteArray &baEncryptedData, ByteDynArray &baData,
                        CK_MECHANISM_TYPE mechanism, bool bSilent);

/** @brief Generate random bytes using the card's hardware RNG. */
void CIEtemplateGenerateRandom(void *pCardTemplateData,
                               ByteArray &baRandomData);

/** @brief Initialize the user PIN on the CIE card. */
void CIEtemplateInitPIN(void *pCardTemplateData, ByteArray &baPin);

/** @brief Change the user or SO PIN on the CIE card. */
void CIEtemplateSetPIN(void *pCardTemplateData, ByteArray &baOldPin,
                       ByteArray &baNewPin, CK_USER_TYPE User);

/** @brief Return the on-card size of the specified PKCS#11 object. */
CK_ULONG CIEtemplateGetObjectSize(void *pCardTemplateData,
                                  p11::CP11Object *pObject);

/** @brief Associate a key-specific PIN with a PKCS#11 object. */
void CIEtemplateSetKeyPIN(void *pTemplateData, p11::CP11Object *pObject,
                          ByteArray &Pin);

/** @brief Write attribute values back to the CIE card. */
void CIEtemplateSetAttribute(void *pTemplateData, p11::CP11Object *pObject,
                             CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/** @brief Create a new PKCS#11 object on the CIE card from the given template.
 */
std::shared_ptr<p11::CP11Object> CIEtemplateCreateObject(
    void *pTemplateData, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/** @brief Destroy a PKCS#11 object on the CIE card. */
void CIEtemplateDestroyObject(void *pTemplateData, p11::CP11Object &Object);

/** @brief Generate a symmetric key on the CIE card. */
std::shared_ptr<p11::CP11Object> CIEtemplateGenerateKey(
    void *pCardTemplateData, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/** @brief Generate an RSA key pair on the CIE card. */
void CIEtemplateGenerateKeyPair(void *pCardTemplateData,
                                CK_MECHANISM_PTR pMechanism,
                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                CK_ULONG ulPublicKeyAttributeCount,
                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                CK_ULONG ulPrivateKeyAttributeCount,
                                std::shared_ptr<p11::CP11Object> &pPublicKey,
                                std::shared_ptr<p11::CP11Object> &pPrivateKey);
