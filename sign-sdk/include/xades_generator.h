// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file xades_generator.h
 * @brief XAdES digital signature generation.
 */

#pragma once

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

#include <string>
#include <vector>

#include "signature_generator.h"

/**
 * Generates XAdES-BES or XAdES-T digital signatures over XML documents.
 *
 * Extends CSignatureGeneratorBase to produce XMLDSig with optional XAdES
 * qualifying properties.
 */
class CXAdESGenerator : public CSignatureGeneratorBase {
 public:
  explicit CXAdESGenerator(CBaseSigner* pCryptoki);
  explicit CXAdESGenerator(CSignatureGeneratorBase* pGenerator);

  virtual ~CXAdESGenerator(void) override;

  /** Enable or disable XAdES qualifying properties (vs plain XMLDSig). */
  void SetXAdES(bool xades);

  /** Set the filename of the document being signed (embedded in the signature).
   */
  void SetFileName(const char* szFileName);

  /** Produce the XAdES-signed XML document. */
  virtual long Generate(ByteDynArray& xadesData, BOOL bDetached,
                        BOOL bVerifyRevocation) override;

 private:
  bool m_bXAdES;

  xmlDocPtr CreateSignedInfo(xmlDocPtr pDocument,
                             const std::string& strQualifyingPropertiesB64Hash,
                             bool bDetached, const char* szFileName);
  xmlDocPtr CreateQualifyingProperties(xmlDocPtr pDocument,
                                       CCertificate* pCertificate);

  void CanonicalizeAndHashBase64(xmlDocPtr pDoc, std::string& strDocHashB64,
                                 std::string& strCanonical);

  char m_szID[100];
  char m_szFileName[MAX_PATH];
};
