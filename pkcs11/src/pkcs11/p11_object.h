// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file p11_object.h
 * @brief PKCS#11 object class hierarchy (certificates, keys, data objects).
 *
 * Models the Cryptoki object classes stored on the smart card.  Each object
 * owns an attribute map that is lazily populated from the card on first access.
 * Subclasses override getAttribute() to enforce class-specific attribute rules.
 */

#pragma once

#include <map>

#include "pkcs11/slot.h"

namespace p11 {

using AttributeMap = std::map<CK_ATTRIBUTE_TYPE, ByteDynArray>;

class CSession;

/**
 * @brief Base class for all PKCS#11 objects stored on the card.
 *
 * Holds the object class (CKO_CERTIFICATE, CKO_PRIVATE_KEY, etc.) and
 * a map of CK_ATTRIBUTE_TYPE -> value.  The pTemplateData pointer provides
 * access to card-specific data needed when reading attributes from the card.
 */
class CP11Object {
 public:
  bool bReadValue;  ///< True once full attribute values have been read from the
                    ///< card.
  static size_t P11ObjectCnt;

  CSlot *pSlot;
  void *pTemplateData;  ///< Opaque card-template data for attribute reads.

  CP11Object(CK_OBJECT_CLASS objClass, void *TemplateData);
  CK_OBJECT_CLASS ObjClass;  ///< PKCS#11 object class (CKO_*).
  AttributeMap attributes;   ///< Map of attribute type -> raw value.
  void addAttribute(CK_ATTRIBUTE_TYPE type, ByteArray data);

  /**
   * @brief Look up an attribute by type.
   * @return Pointer to the attribute value, or nullptr if the attribute
   *         is not part of this object's attribute set.
   */
  virtual ByteArray *getAttribute(CK_ATTRIBUTE_TYPE type);

  virtual CK_ULONG GetAttributeValue(CK_ATTRIBUTE_PTR pTemplate,
                                     CK_ULONG ulCount);
  virtual void SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
  virtual CK_ULONG GetObjectSize();
  virtual ~CP11Object() = default;
  /** @brief True if CKA_PRIVATE is set for this object. */
  bool IsPrivate();
};

/** @brief PKCS#11 certificate object (CKO_CERTIFICATE). */
class CP11Certificate : public CP11Object {
 public:
  CP11Certificate(void *TemplateData);
  virtual ByteArray *getAttribute(CK_ATTRIBUTE_TYPE type);
  virtual void SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
};

/** @brief PKCS#11 data object (CKO_DATA). */
class CP11Data : public CP11Object {
 public:
  CP11Data(void *TemplateData);
  virtual ByteArray *getAttribute(CK_ATTRIBUTE_TYPE type);
  virtual void SetAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
};

/** @brief PKCS#11 public key object (CKO_PUBLIC_KEY). */
class CP11PublicKey : public CP11Object {
 public:
  CP11PublicKey(void *TemplateData);
  virtual ByteArray *getAttribute(CK_ATTRIBUTE_TYPE type);
};

/** @brief PKCS#11 private key object (CKO_PRIVATE_KEY). */
class CP11PrivateKey : public CP11Object {
 public:
  CP11PrivateKey(void *TemplateData);
  virtual ByteArray *getAttribute(CK_ATTRIBUTE_TYPE type);
};

}  // namespace p11
