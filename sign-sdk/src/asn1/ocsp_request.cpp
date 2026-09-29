// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

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

 issuerNameHash is the hash of the Issuer's distinguished name. The
 hash shall be calculated over the DER encoding of the issuer's name
 field in the certificate being checked. issuerKeyHash is the hash of
 the Issuer's public key. The hash shall be calculated over the value
 (excluding tag and length) of the subject public key field in the
 issuer's certificate. The hash algorithm used for both these hashes,
 is identified in hashAlgorithm. serialNumber is the serial number of
 the certificate for which status is being requested.
 */

#include "ocsp_request.h"

#include "asn1/algorithm_identifier.h"
#include "cert_store.h"
#include "crypto/sha1.h"

COCSPRequest::COCSPRequest(BufferedReader& reader) : CASN1Sequence(reader) {}

COCSPRequest::COCSPRequest(const CASN1Object& ocspRequest)
    : CASN1Sequence(ocspRequest) {}

void COCSPRequest::ComputeCertID(CCertificate& certificate,
                                 ByteDynArray& issuerNameHash,
                                 ByteDynArray& issuerKeyHash) {
  CName issuerName(certificate.getIssuer());

  ByteDynArray baIssuerName;
  issuerName.toByteArray(baIssuerName);

  issuerNameHash.append(
      CSHA1().Digest(ByteArray(baIssuerName.data(), baIssuerName.size())));

  // issuerKeyHash (RFC 6960 SS4.1.1) is the SHA-1 hash of the issuer's
  // public key, computed the same way as a Subject Key Identifier under
  // RFC 5280 SS4.2.1.2 method (1). A CA populating a subject certificate's
  // Authority Key Identifier per SS4.2.1.1 copies its own Subject Key
  // Identifier byte-for-byte into that field's keyIdentifier -- as CIE's
  // CAs do -- so the certificate's own AKI keyIdentifier already *is*
  // issuerKeyHash; no further hashing or unwrapping needed.
  //
  // getAuthorithyKeyIdentifier() now returns exactly those raw bytes (see
  // its definition), so this used to additionally re-wrap the result in a
  // CASN1Sequence and pull out element 0 to peel back an extra ASN.1
  // layer that the old (buggy) accessor left in place. With the accessor
  // fixed, doing that again corrupts a well-formed key id by trying to
  // parse its raw bytes as nested TLV content.
  CASN1OctetString authorityKeyIdentifier(
      certificate.getAuthorithyKeyIdentifier());
  issuerKeyHash.append(*authorityKeyIdentifier.getValue());
}

COCSPRequest::COCSPRequest(CCertificate& certificate) {
  CASN1Sequence tbsRequest;

  CASN1Sequence requestList;

  CASN1Sequence request;

  CASN1Sequence certId;

  CASN1Integer serialNumber(certificate.getSerialNumber());

  CAlgorithmIdentifier hashAlgorithm(szSHA1OID);

  ByteDynArray baIssuerNameHash;
  ByteDynArray baIssuerKeyHash;
  ComputeCertID(certificate, baIssuerNameHash, baIssuerKeyHash);

  certId.addElement(hashAlgorithm);
  certId.addElement(CASN1OctetString(baIssuerNameHash));
  certId.addElement(CASN1OctetString(baIssuerKeyHash));
  certId.addElement(serialNumber);

  request.addElement(certId);

  requestList.addElement(request);

  tbsRequest.addElement(requestList);

  addElement(tbsRequest);
}
