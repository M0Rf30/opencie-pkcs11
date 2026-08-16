// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once
/*
 *  iDigitalSApp
 *
 *  Created by svp on 14/10/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */
/*
OCSPRequest     ::=     SEQUENCE {
    tbsRequest                  TBSRequest,
    optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

TBSRequest      ::=     SEQUENCE {
    version             [0] EXPLICIT Version DEFAULT v1,
    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    requestList             SEQUENCE OF Request,
    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }

Signature       ::=     SEQUENCE {
    signatureAlgorithm   AlgorithmIdentifier,
    signature            BIT STRING,
    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

Version  ::=  INTEGER  {  v1(0) }

Request ::=     SEQUENCE {
    reqCert                    CertID,
    singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }

CertID ::= SEQUENCE {
 hashAlgorithm            AlgorithmIdentifier,
 issuerNameHash     OCTET STRING, -- Hash of Issuer's DN
 issuerKeyHash      OCTET STRING, -- Hash of Issuers public key
 serialNumber       CertificateSerialNumber }
*/

#include "asn1/asn1_sequence.h"
#include "asn1/certificate.h"

class COCSPRequest : public CASN1Sequence {
 public:
  explicit COCSPRequest(BufferedReader& reader);

  explicit COCSPRequest(const CASN1Object& contentInfo);

  explicit COCSPRequest(CCertificate& certificate);

  /**
   * Computes the OCSP CertID components (issuerNameHash, issuerKeyHash) for
   * `certificate` using the same SHA-1-based algorithm this SDK uses when
   * building a request, so a response's CertID can be matched against it.
   * `issuerNameHash`/`issuerKeyHash` must be empty on entry; they are
   * populated via append, not assignment.
   */
  static void ComputeCertID(CCertificate& certificate,
                            ByteDynArray& issuerNameHash,
                            ByteDynArray& issuerKeyHash);
};
