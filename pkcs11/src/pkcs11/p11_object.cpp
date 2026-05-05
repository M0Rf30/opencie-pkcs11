
// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file p11_object.cpp
 * @brief PKCS#11 object attribute management implementation
 */

#include "pkcs11/p11_object.h"

#include "pkcs11/card_template.h"

extern CLog Log;

namespace p11 {

CP11Object::CP11Object(CK_OBJECT_CLASS objClass, void* TemplateData) {
  ObjClass = objClass;
  pTemplateData = TemplateData;
  bReadValue = false;
  pSlot = nullptr;
  addAttribute(CKA_CLASS, ByteArray(reinterpret_cast<BYTE*>(&ObjClass),
                                    sizeof(CK_OBJECT_CLASS)));
}

void CP11Object::addAttribute(CK_ATTRIBUTE_TYPE type, ByteArray data) {
  init_func attributes[type] = ByteDynArray(data);
}

ByteArray* CP11Object::getAttribute(CK_ATTRIBUTE_TYPE type) {
  init_func AttributeMap::const_iterator pPair;
  pPair = attributes.find(type);
  if (pPair == attributes.end()) {
    return nullptr;
  }
  return (ByteArray*)&pPair->second;
}

CK_ULONG CP11Object::GetAttributeValue(CK_ATTRIBUTE_PTR pTemplate,
                                       CK_ULONG ulCount) {
  init_func

      bool attribInvalid = false;

  for (unsigned int i = 0; i < ulCount; i++) {
    CK_ULONG ulValLen = pTemplate[i].ulValueLen;

    ByteArray* attr = getAttribute(pTemplate[i].type);
    if (attr != nullptr) {
      if (pTemplate[i].pValue == nullptr) {
        pTemplate[i].ulValueLen = static_cast<CK_ULONG>(attr->size());
      } else {
        if (attr->size() > ulValLen) throw p11_error(CKR_BUFFER_TOO_SMALL);

        ByteArray(static_cast<uint8_t*>(pTemplate[i].pValue), attr->size())
            .copy(*attr);
        pTemplate[i].ulValueLen = static_cast<CK_ULONG>(attr->size());
      }
    } else {
      pTemplate[i].ulValueLen = -1;
      attribInvalid = true;
    }
  }

  return attribInvalid ? CKR_ATTRIBUTE_TYPE_INVALID : CKR_OK;
}

CK_ULONG CP11Object::GetObjectSize() {
  init_func
      // I need to at least read it from the card to know its size
      if (!bReadValue) {
    pSlot->pTemplate->FunctionList.templateReadObjectAttributes(
        pSlot->pTemplateData, this);
  }
  return pSlot->pTemplate->FunctionList.templateGetObjectSize(
      pSlot->pTemplateData, this);
}

void CP11Object::SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  init_func for (DWORD i = 0; i < ulCount; i++) {
    addAttribute(pTemplate[i].type,
                 ByteArray(static_cast<BYTE*>(pTemplate[i].pValue),
                           pTemplate[i].ulValueLen));
  }
}
CP11Certificate::CP11Certificate(void* TemplateData)
    : CP11Object(CKO_CERTIFICATE, TemplateData) {
  bReadValue = false;
}

void CP11Certificate::SetAttributes(CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulCount) {
  init_func CP11Object::SetAttributes(pTemplate, ulCount);
  bReadValue = true;
}

ByteArray* CP11Certificate::getAttribute(CK_ATTRIBUTE_TYPE type) {
  init_func

      AttributeMap::iterator it = attributes.find(type);
  if (it == attributes.end() && !bReadValue) {
    pSlot->pTemplate->FunctionList.templateReadObjectAttributes(
        pSlot->pTemplateData, this);
  }

  return CP11Object::getAttribute(type);
}

CP11Data::CP11Data(void* TemplateData) : CP11Object(CKO_DATA, TemplateData) {
  bReadValue = false;
}

ByteArray* CP11Data::getAttribute(CK_ATTRIBUTE_TYPE type) {
  init_func AttributeMap::iterator it = attributes.find(type);
  if (it == attributes.end() && !bReadValue) {
    pSlot->pTemplate->FunctionList.templateReadObjectAttributes(
        pSlot->pTemplateData, this);
  }

  return CP11Object::getAttribute(type);
}

void CP11Data::SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  init_func CP11Object::SetAttributes(pTemplate, ulCount);
  bReadValue = true;
}

bool CP11Object::IsPrivate() {
  init_func ByteArray* baVal = getAttribute(CKA_PRIVATE);

  if (baVal == nullptr)
    return false;
  else
    return (ByteArrayToVar(*baVal, CK_BBOOL) == TRUE);
}

CP11PrivateKey::CP11PrivateKey(void* TemplateData)
    : CP11Object(CKO_PRIVATE_KEY, TemplateData) {
  bReadValue = false;
}

ByteArray* CP11PrivateKey::getAttribute(CK_ATTRIBUTE_TYPE type) {
  init_func

      if (type == CKA_PRIME_1 || type == CKA_PRIME_2 ||
          type == CKA_EXPONENT_1 || type == CKA_EXPONENT_2 ||
          type == CKA_COEFFICIENT) throw p11_error(CKR_ATTRIBUTE_SENSITIVE);

  AttributeMap::iterator it = attributes.find(type);
  if (it == attributes.end() && !bReadValue) {
    pSlot->pTemplate->FunctionList.templateReadObjectAttributes(
        pSlot->pTemplateData, this);
  }

  return CP11Object::getAttribute(type);
}

CP11PublicKey::CP11PublicKey(void* TemplateData)
    : CP11Object(CKO_PUBLIC_KEY, TemplateData) {
  bReadValue = false;
}

ByteArray* CP11PublicKey::getAttribute(CK_ATTRIBUTE_TYPE type) {
  init_func

      AttributeMap::iterator it = attributes.find(type);
  if (it == attributes.end() && !bReadValue) {
    pSlot->pTemplate->FunctionList.templateReadObjectAttributes(
        pSlot->pTemplateData, this);
  }

  return CP11Object::getAttribute(type);
}

}  // namespace p11
