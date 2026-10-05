// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file pace.h
 * @brief ICAO 9303 part 11 PACE (CAN) + Secure Messaging for the eMRTD
 * application of the CIE.
 *
 * Self-contained (OpenSSL 3 only) so it can be unit-tested against the
 * ICAO 9303-11 worked examples without any card:
 *   - EF.CardAccess / PACEInfo parsing and protocol selection,
 *   - the PACE protocol with Generic Mapping (ECDH on the standardized
 *     NIST/Brainpool curves, DH on the RFC 5114 groups),
 *   - Secure Messaging (AES-CBC + CMAC, or 3DES + retail MAC),
 *   - reading eMRTD files (DG1, DG2) through the Secure Messaging channel.
 *
 * Only the CAN is ever used as PACE password: no PIN/PUK related APDU is
 * built by this module.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace pace {

using Bytes = std::vector<uint8_t>;

/**
 * @brief Raw APDU transport.
 *
 * Sends @p apdu, stores the response data (without the status word) in
 * @p resp and returns SW1SW2. A transport failure must be reported by
 * throwing (card_link_error in production), never by returning a fake SW.
 */
using Transmit = std::function<uint16_t(const Bytes& apdu, Bytes& resp)>;

/** @brief Session key/cipher suite of a PACE OID. */
enum class Cipher { TDES, AES128, AES192, AES256 };

/** @brief Mapping method of a PACE OID. */
enum class Mapping { GM, IM, CAM };

/** @brief A PACEInfo structure of EF.CardAccess. */
struct PaceInfo {
  Bytes oid;             ///< OID content octets (no tag/length)
  int version = 0;       ///< PACEInfo version (1 or 2)
  int parameterId = -1;  ///< standardized domain parameter id, -1 if absent
};

/** @brief A PACE protocol that this implementation can run. */
struct Params {
  Bytes oid;       ///< OID content octets sent in MSE:Set AT / token input
  bool ec = true;  ///< ECDH (true) or DH (false)
  Mapping mapping = Mapping::GM;
  Cipher cipher = Cipher::AES128;
  int parameterId = -1;
};

/** @brief Outcome of a PACE / file read step. */
enum class Status {
  Ok,
  WrongCan,     ///< mutual authentication failed: the CAN is wrong
  Unsupported,  ///< no usable PACE protocol on the chip
  Failed,       ///< card refused / malformed answer; see Result::sw
};

struct Result {
  Status status = Status::Failed;
  uint16_t sw = 0;         ///< last card status word, 0 if none
  std::string detail;      ///< short log-safe description (never secrets)
  bool linkError = false;  ///< untrustworthy bytes (SM MAC failure): retryable
};

// ---------------------------------------------------------------------------
// Low-level crypto helpers (exposed for the unit tests)
// ---------------------------------------------------------------------------
namespace crypto {
Bytes sha1(const Bytes& in);
Bytes sha256(const Bytes& in);
/** AES-ECB single-block encryption (used for the SM IV). */
Bytes aesEcbEncrypt(const Bytes& key, const Bytes& block);
/** CBC without padding; @p data must be block aligned. Empty on error. */
Bytes cbcEncrypt(Cipher c, const Bytes& key, const Bytes& iv,
                 const Bytes& data);
Bytes cbcDecrypt(Cipher c, const Bytes& key, const Bytes& iv,
                 const Bytes& data);
/** AES-CMAC (full 16-byte tag). */
Bytes aesCmac(const Bytes& key, const Bytes& data);
/** ISO 9797-1 MAC algorithm 3 (retail MAC), data already padded. */
Bytes retailMac(const Bytes& key16, const Bytes& paddedData);
/** ISO 9797-1 padding method 2 up to a multiple of @p block. */
Bytes pad(const Bytes& in, size_t block);
/** Remove padding method 2; false if malformed. */
bool unpad(Bytes& data);
}  // namespace crypto

/** @brief Cipher block size (8 for 3DES, 16 for AES). */
size_t blockSize(Cipher c);

/** @brief Session key length in bytes for @p c. */
size_t keyLength(Cipher c);

/**
 * @brief ICAO 9303-11 KDF: H(K || counter) truncated to the key length.
 *
 * @param counter 1 = KS_enc, 2 = KS_mac, 3 = K_pi.
 */
Bytes kdf(Cipher c, const Bytes& k, uint32_t counter);

/** @brief Decrypt the PACE nonce with K_pi (CBC, zero IV, no padding). */
Bytes decryptNonce(Cipher c, const Bytes& kpi, const Bytes& encNonce);

/** @brief Authentication token: MAC(KS_mac, 7F49{06 oid, tag pk}). */
Bytes authToken(const Params& p, const Bytes& ksMac, const Bytes& publicKey);

/** @brief The 7F49 input data object used for the tokens. */
Bytes tokenInput(const Params& p, const Bytes& publicKey);

// ---------------------------------------------------------------------------
// EF.CardAccess
// ---------------------------------------------------------------------------

/** @brief Parse every PACEInfo found in EF.CardAccess. */
std::vector<PaceInfo> parseCardAccess(const Bytes& cardAccess);

/**
 * @brief Pick the strongest PACE protocol that this module supports.
 *
 * Supports Generic Mapping (and CAM, whose PACE phase is identical) with
 * ECDH on the standardized curves 8..18 and DH on the RFC 5114 groups 0..2
 * (the CIE offers group 2 with 3DES), AES-128/192/256 or 3DES. Integrated
 * Mapping and proprietary domain parameters are not supported. The 2048-bit
 * DH groups need extended-length APDUs (ICAO 9303-11 9.3.1).
 */
bool selectProtocol(const std::vector<PaceInfo>& infos, Params& out);

/** @brief Human readable "ECDH-GM AES-128 brainpoolP256r1" (log safe). */
std::string describe(const Params& p);

// ---------------------------------------------------------------------------
// Generic Mapping engines
// ---------------------------------------------------------------------------

/**
 * @brief Generic Mapping state for one PACE run (ECDH or DH).
 *
 * Every method that creates a key pair accepts an optional fixed private
 * key: this is only meant for the known-answer tests, production code
 * always passes an empty vector (fresh random key).
 */
class GenericMapping {
 public:
  virtual ~GenericMapping() = default;
  /** Create the mapping key pair; returns the encoded public key. */
  virtual Bytes mappingPublicKey(const Bytes& fixedPrivate = {}) = 0;
  /** Compute the mapped generator from the chip's mapping key + nonce. */
  virtual bool mapNonce(const Bytes& chipMappingKey, const Bytes& nonce) = 0;
  /** Encoded mapped generator (for tests). */
  virtual Bytes mappedGenerator() const = 0;
  /** Create the key agreement key pair on the mapped parameters. */
  virtual Bytes agreementPublicKey(const Bytes& fixedPrivate = {}) = 0;
  /** Shared secret K with the chip's agreement public key. */
  virtual bool agree(const Bytes& chipPublicKey, Bytes& sharedSecret) = 0;
};

/** @brief Create the engine for @p p, or nullptr if unsupported. */
std::unique_ptr<GenericMapping> makeMapping(const Params& p);

/** @brief Name of standardized EC domain parameter @p id ("" if unknown). */
const char* curveName(int id);

// ---------------------------------------------------------------------------
// Secure Messaging
// ---------------------------------------------------------------------------

/**
 * @brief ICAO 9303-11 §9.8 Secure Messaging channel (command wrap /
 * response unwrap) with the PACE session keys.
 */
class SecureChannel {
 public:
  SecureChannel(Cipher c, Bytes ksEnc, Bytes ksMac, Bytes initialSsc = {});
  ~SecureChannel();
  SecureChannel(const SecureChannel&) = delete;
  SecureChannel& operator=(const SecureChannel&) = delete;
  SecureChannel(SecureChannel&&) noexcept;
  SecureChannel& operator=(SecureChannel&&) noexcept;

  /**
   * @brief Protect a short-APDU command.
   * @param data  command data (may be empty)
   * @param le    expected length 1..256 or -1 for "no Le"
   * @return the protected APDU (CLA|0C ... DO'8E' 00)
   */
  Bytes wrap(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
             const Bytes& data, int le);

  /**
   * @brief Verify and decrypt a protected response.
   * @param rdata response data field (DO'87'/'85', DO'99', DO'8E')
   * @param sw    inner SW from DO'99' on success
   * @return false when the response is malformed or the MAC is wrong
   */
  bool unwrap(const Bytes& rdata, Bytes& plain, uint16_t& sw);

  /** Undo the last SSC increment (card rejected the command unprocessed). */
  void rollbackSsc();

  const Bytes& ssc() const { return ssc_; }

 private:
  void incrementSsc();
  Bytes iv() const;
  Bytes mac(const Bytes& paddedInput) const;

  Cipher cipher_;
  Bytes ksEnc_, ksMac_, ssc_;
};

// ---------------------------------------------------------------------------
// Protocol drivers
// ---------------------------------------------------------------------------

/** @brief Test hooks (known-answer tests); production code uses defaults. */
struct Options {
  Bytes fixedMappingKey;    ///< fixed mapping private key (empty = random)
  Bytes fixedAgreementKey;  ///< fixed agreement private key (empty = random)
  Bytes password;           ///< K override (default: the ASCII CAN)
  uint8_t passwordRef = 2;  ///< MSE:Set AT password reference (2 = CAN)
};

/**
 * @brief Read EF.CardAccess (FID 011C / SFI 1C) from the MF, in plain.
 */
Result readCardAccess(const Transmit& tx, Bytes& out);

/**
 * @brief Run PACE with the CAN.
 *
 * On Status::Ok @p channel is the established Secure Messaging channel
 * (SSC = 0 as required by ICAO 9303-11). A wrong CAN is reported as
 * Status::WrongCan and is never retried by this function.
 */
Result performPace(const Transmit& tx, const std::string& can, const Params& p,
                   std::unique_ptr<SecureChannel>& channel,
                   const Options& opt = {});

/** @brief SELECT the eMRTD application through Secure Messaging. */
Result selectEmrtdApplication(const Transmit& tx, SecureChannel& ch);

/**
 * @brief SELECT an EF by FID and read it completely through Secure
 * Messaging (short APDUs only; READ BINARY odd-INS above offset 0x7FFF).
 */
Result readFileSm(const Transmit& tx, SecureChannel& ch, uint16_t fid,
                  Bytes& out);

}  // namespace pace
