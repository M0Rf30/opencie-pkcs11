// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cryptopp/eccrypto.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>

#include <string>

#include "Util/definitions.h"

using Buffer = std::vector<unsigned char>;

namespace lcp {
class CryptoppUtils {
 public:
  static void Base64ToSecBlock(const std::string& base64, CryptoPP::SecByteBlock& result);
  static Buffer Base64ToVector(const std::string& base64);
  static std::string RawToHex(const Buffer& key);
  static Buffer HexToRaw(const std::string& hex);
  static std::string GenerateUuid();

  class Cert {
   public:
    static std::string IntegerToString(const CryptoPP::Integer& integer);
    static void SkipNextSequence(CryptoPP::BERSequenceDecoder& parentSequence);

    static std::string ReadIntegerAsString(CryptoPP::BERSequenceDecoder& sequence);
    static CryptoPP::word32 ReadVersion(CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
                              CryptoPP::word32 defaultVersion);
    static void ReadOID(CryptoPP::BERSequenceDecoder& certificate, CryptoPP::OID& algorithmId);

    static void ReadSubjectPublicKeyRSA(
        CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
        CryptoPP::RSA::PublicKey& result);
    static void ReadSubjectPublicKeyECDSA(
        CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey& result);

    static void ReadDateTimeSequence(CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
                                     std::string& notBefore,
                                     std::string& notAfter);
    static void BERDecodeTime(CryptoPP::BufferedTransformation& bt,
                              std::string& time);

    static void PullToBeSignedData(const CryptoPP::SecByteBlock& rawCertificate,
                                   CryptoPP::SecByteBlock& result);

    static const BYTE ContextSpecificTagZero = 0xa0;
    static const BYTE ContextSpecificTagThree = 0xa3;
    static const BYTE ContextSpecificTagSixIA5String = 0x86;
  };
};
}  // namespace lcp

