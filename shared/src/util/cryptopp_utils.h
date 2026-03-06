// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file cryptopp_utils.h
 * @brief Crypto++ utility wrappers for certificate and key processing.
 *
 * Provides helper functions for Base64/hex encoding, UUID generation,
 * and X.509 certificate field parsing using the Crypto++ library.
 */

#pragma once

#include <cryptopp/eccrypto.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>

#include <string>

#include "util/definitions.h"

/** @brief Alias for a byte buffer (vector of unsigned char). */
using Buffer = std::vector<unsigned char>;

namespace lcp {

/**
 * @brief Collection of Crypto++ utility functions.
 *
 * Provides static methods for encoding/decoding operations and
 * an inner Cert class for X.509 certificate BER/DER parsing.
 */
class CryptoppUtils {
 public:
  /**
   * @brief Decode a Base64 string into a Crypto++ SecByteBlock.
   * @param base64 Base64-encoded input string.
   * @param[out] result Decoded byte block.
   */
  static void Base64ToSecBlock(const std::string& base64,
                               CryptoPP::SecByteBlock& result);

  /**
   * @brief Decode a Base64 string into a byte vector.
   * @param base64 Base64-encoded input string.
   * @return Decoded byte vector.
   */
  static Buffer Base64ToVector(const std::string& base64);

  /**
   * @brief Convert raw bytes to a hexadecimal string.
   * @param key Raw byte buffer.
   * @return Hex-encoded string.
   */
  static std::string RawToHex(const Buffer& key);

  /**
   * @brief Convert a hexadecimal string to raw bytes.
   * @param hex Hex-encoded string.
   * @return Raw byte buffer.
   */
  static Buffer HexToRaw(const std::string& hex);

  /**
   * @brief Generate a random UUID string.
   * @return UUID in standard string format.
   */
  static std::string GenerateUuid();

  /**
   * @brief X.509 certificate BER/DER parsing utilities.
   *
   * Provides static methods for reading fields from BER-encoded
   * X.509 certificates using Crypto++ decoders.
   */
  class Cert {
   public:
    /**
     * @brief Convert a Crypto++ Integer to its string representation.
     * @param integer Crypto++ Integer value.
     * @return Decimal string representation.
     */
    static std::string IntegerToString(const CryptoPP::Integer& integer);

    /**
     * @brief Skip the next BER sequence in a parent sequence decoder.
     * @param parentSequence Parent BER sequence decoder.
     */
    static void SkipNextSequence(CryptoPP::BERSequenceDecoder& parentSequence);

    /**
     * @brief Read a BER-encoded integer and return it as a string.
     * @param sequence BER sequence decoder positioned at the integer.
     * @return String representation of the integer.
     */
    static std::string ReadIntegerAsString(
        CryptoPP::BERSequenceDecoder& sequence);

    /**
     * @brief Read the certificate version field.
     * @param toBeSignedCertificate TBS certificate BER decoder.
     * @param defaultVersion Default version if the field is absent.
     * @return Certificate version number.
     */
    static CryptoPP::word32 ReadVersion(
        CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
        CryptoPP::word32 defaultVersion);

    /**
     * @brief Read an algorithm OID from a certificate.
     * @param certificate BER sequence decoder.
     * @param[out] algorithmId Parsed OID value.
     */
    static void ReadOID(CryptoPP::BERSequenceDecoder& certificate,
                        CryptoPP::OID& algorithmId);

    /**
     * @brief Read an RSA subject public key from a TBS certificate.
     * @param toBeSignedCertificate TBS certificate BER decoder.
     * @param[out] result Parsed RSA public key.
     */
    static void ReadSubjectPublicKeyRSA(
        CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
        CryptoPP::RSA::PublicKey& result);

    /**
     * @brief Read an ECDSA subject public key from a TBS certificate.
     * @param toBeSignedCertificate TBS certificate BER decoder.
     * @param[out] result Parsed ECDSA public key.
     */
    static void ReadSubjectPublicKeyECDSA(
        CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey& result);

    /**
     * @brief Read the validity period (notBefore/notAfter) from a TBS
     * certificate.
     * @param toBeSignedCertificate TBS certificate BER decoder.
     * @param[out] notBefore Start of validity period.
     * @param[out] notAfter End of validity period.
     */
    static void ReadDateTimeSequence(
        CryptoPP::BERSequenceDecoder& toBeSignedCertificate,
        std::string& notBefore, std::string& notAfter);

    /**
     * @brief Decode a BER-encoded time value (UTCTime or GeneralizedTime).
     * @param bt Buffered transformation containing the encoded time.
     * @param[out] time Decoded time string.
     */
    static void BERDecodeTime(CryptoPP::BufferedTransformation& bt,
                              std::string& time);

    /**
     * @brief Extract the TBS (To-Be-Signed) data from a raw certificate.
     * @param rawCertificate Raw DER-encoded certificate.
     * @param[out] result TBS portion of the certificate.
     */
    static void PullToBeSignedData(const CryptoPP::SecByteBlock& rawCertificate,
                                   CryptoPP::SecByteBlock& result);

    static const BYTE ContextSpecificTagZero =
        0xa0; /**< ASN.1 context-specific tag [0]. */
    static const BYTE ContextSpecificTagThree =
        0xa3; /**< ASN.1 context-specific tag [3]. */
    static const BYTE ContextSpecificTagSixIA5String =
        0x86; /**< ASN.1 context-specific tag [6] (IA5String). */
  };
};
}  // namespace lcp
