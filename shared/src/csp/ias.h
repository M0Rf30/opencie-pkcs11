// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file ias.h
 * @brief IAS (Italian Authentication Services) smart card interface for CIE.
 *
 * Implements the IAS ECC specification for communicating with the Italian
 * CIE (Carta d'Identità Elettronica) electronic ID smart card. Provides
 * the core card communication layer including secure messaging, PIN/PUK
 * management, certificate retrieval, Diffie-Hellman key exchange, and
 * digital signature operations.
 */

#pragma once

#include <map>
#include <string_view>

#include "csp/atr.h"
#include "pcsc/token.h"

/** @name CIE Elementary File (EF) path constants
 *  Identifiers for elementary files on the CIE card filesystem.
 *  @{ */
constexpr const char *DirCIE = "CIE"; /**< CIE dedicated directory */
constexpr const char *EfDH = "EF.DH"; /**< Diffie-Hellman parameters EF */
constexpr const char *EfSerial = "EF.Serial"; /**< Card serial number EF */
constexpr const char *EfIdServizi =
    "EF.IdServizi";                             /**< Service identifier EF */
constexpr const char *EfCertCIE = "EF.CertCIE"; /**< CIE X.509 certificate EF */
constexpr const char *EfSOD = "EF.SOD"; /**< Security Object Document EF */
constexpr const char *EfIntAuth =
    "EF.IntAuth"; /**< Internal authentication EF */
constexpr const char *EfIntAuthServizi =
    "EF.IntAuthServizi"; /**< Service internal auth EF */
/** @} */

/** @brief Flag indicating a full (8-digit) PIN rather than a partial PIN. */
constexpr uint32_t FULL_PIN = 0x80000000;

extern bool switchDesktop;
extern BOOL CheckOneInstance(char *nome);
/** @brief RSA private exponent for external authentication with the CIE card.
 */
extern ByteArray baExtAuth_PrivExp;

/** @brief Dedicated File (DF) selectors on the CIE card. */
enum class CIE_DF { Root, IAS, CIE };

/** @brief Secure Messaging requirement for APDU commands. */
enum class CIE_RequestedSM { SM, NoSM, AnySM };

/**
 * @class IAS
 * @brief Core interface for communicating with the Italian CIE smart card.
 *
 * Implements the IAS ECC (Italian Authentication Services, Elliptic Curve
 * Cryptography) protocol for the CIE (Carta d'Identità Elettronica).
 * Handles APDU command exchange with optional Secure Messaging (SM),
 * PIN/PUK lifecycle management, Diffie-Hellman key exchange, certificate
 * retrieval, digital signatures, and SOD (Security Object Document)
 * verification.
 */
class IAS {
  CIE_Type type = CIE_Type::CIE_Unknown;
  ByteDynArray dh_g, dh_p, dh_q; /**< DH parameters: generator, prime, order */
  ByteDynArray sessENC, sessMAC,
      sessSSC; /**< Session keys for Secure Messaging */
  ByteDynArray dh_pubKey,
      dh_ICCpubKey; /**< Host and ICC Diffie-Hellman public keys */
  ByteDynArray CA_module, CA_pubexp, CA_privexp, CA_CHR, CA_CHA, CA_CAR, CA_AID;
  ByteDynArray IAS_AID;               /**< IAS application identifier */
  ByteDynArray CIE_AID;               /**< CIE application identifier */
  ByteDynArray ATR;                   /**< Answer To Reset bytes */
  ByteDynArray Certificate;           /**< Cached X.509 certificate */
  ByteDynArray CardEncKey, CardEncIv; /**< Card encryption key and IV */

  /** @brief Send an APDU command to the card (plaintext). */
  StatusWord SendAPDU(ByteArray head, ByteArray data, ByteDynArray &resp,
                      uint8_t *le = nullptr);
  /** @brief Send an APDU command to the card with Secure Messaging. */
  StatusWord SendAPDU_SM(ByteArray head, ByteArray data, ByteDynArray &resp,
                         uint8_t *le = nullptr);
  /** @brief Retrieve remaining response data via GET RESPONSE. */
  StatusWord getResp(ByteDynArray &Cardresp, StatusWord sw, ByteDynArray &resp);
  /** @brief Retrieve remaining response data via GET RESPONSE under SM. */
  StatusWord getResp_SM(ByteArray &Cardresp, StatusWord sw, ByteDynArray &resp);

  /** @brief Wrap an APDU in a Secure Messaging envelope. */
  ByteDynArray SM(ByteArray &keyEnc, ByteArray &keySig, ByteArray &apdu,
                  ByteArray &seq);
  /** @brief Unwrap a Secure Messaging response APDU. */
  StatusWord respSM(ByteArray &keyEnc, ByteArray &keySig, ByteArray &apdu,
                    ByteArray &seq, ByteDynArray &elabResp);

  /** @brief Read an elementary file by ID using Secure Messaging. */
  void readfile_SM(uint16_t id, ByteDynArray &content);
  /** @brief Read an elementary file by ID (plaintext). */
  void readfile(uint16_t id, ByteDynArray &content);

  /** @brief Increment the Secure Messaging sequence counter. */
  void increment(ByteArray &seq);
  /** @brief Detect and store the CIE card type from the ATR. */
  void ReadCIEType();

 public:
  /** @brief PC/SC token wrapper for low-level card communication. */
  CToken token;

  /**
   * @brief Construct an IAS instance for a specific card.
   * @param transmit  Callback function for transmitting APDUs to the card.
   * @param ATR       Answer To Reset bytes identifying the card.
   */
  IAS(CToken::TokenTransmitCallback transmit, ByteArray ATR);
  ~IAS();

  /** @brief Associate a PC/SC card context handle with this instance. */
  void SetCardContext(void *);
  /** @brief Select the IAS application on the card.
   *  @param SM  If true, use Secure Messaging for the SELECT command. */
  void SelectAID_IAS(bool SM = false);
  /** @brief Select the CIE application on the card.
   *  @param SM  If true, use Secure Messaging for the SELECT command. */
  void SelectAID_CIE(bool SM = false);

  ByteDynArray PAN;        /**< Primary Account Number (card identifier). */
  ByteDynArray DappModule; /**< DAPP RSA modulus for internal authentication. */
  ByteDynArray DappPubKey; /**< DAPP RSA public exponent. */

  /** @brief Read the PAN (Primary Account Number) from the card. */
  void ReadPAN();
  /** @brief Read the SOD (Security Object Document) from the card. */
  void ReadSOD(ByteDynArray &data);

  /** @brief Read the Diffie-Hellman parameters from the card. */
  void ReadDH(ByteDynArray &data);
  /** @brief Read the CIE X.509 certificate from the card. */
  void ReadCertCIE(ByteDynArray &data);
  /** @brief Read the DAPP public key from the card. */
  void ReadDappPubKey(ByteDynArray &data);
  /** @brief Read the service authentication public key from the card. */
  void ReadServiziPubKey(ByteDynArray &data);
  /** @brief Read the CIE serial number from the card. */
  void ReadSerialeCIE(ByteDynArray &data);
  /** @brief Read the service identifier from the card. */
  void ReadIdServizi(ByteDynArray &data);

  /** @brief Initialize the card encryption key from cached data. */
  void InitEncKey();
  /** @brief Initialize the Diffie-Hellman parameters from the card. */
  void InitDHParam();
  /** @brief Initialize the external authentication key parameters. */
  void InitExtAuthKeyParam();
  /** @brief Perform Diffie-Hellman key exchange to establish session keys. */
  void DHKeyExchange();
  /** @brief Execute the DAPP (internal authentication) protocol. */
  void DAPP();
  /** @brief Verify the cardholder PIN.
   *  @return Status word indicating success or failure with remaining attempts.
   */
  StatusWord VerifyPIN(ByteArray &PIN);
  /** @brief Verify the PUK (PIN Unblock Key).
   *  @return Status word indicating success or failure with remaining attempts.
   */
  StatusWord VerifyPUK(ByteArray &PUK);
  /** @brief Unblock a locked PIN using a previously verified PUK. */
  StatusWord UnblockPIN();
  /** @brief Change the PIN by providing the old and new PIN values. */
  StatusWord ChangePIN(ByteArray &oldPIN, ByteArray &newPIN);
  /** @brief Change the PIN (requires prior PUK verification). */
  StatusWord ChangePIN(ByteArray &newPIN);
  /** @brief Perform a digital signature operation using the card's private key.
   */
  void Sign(ByteArray &data, ByteDynArray &signedData);
  /** @brief Reset the card's authentication state (deauthenticate). */
  void Deauthenticate();
  /** @brief Retrieve the CIE X.509 certificate, using cache if available.
   *  @param askEnable  If true, prompt the user to enable the card if needed.
   */
  void GetCertificate(ByteDynArray &certificate, bool askEnable = true);
  /** @brief Retrieve the initial PIN assigned during card enrollment. */
  void GetFirstPIN(ByteDynArray &PIN);
  /** @brief Store card data (certificate and initial PIN) in the local cache.
   */
  void SetCache(const char *PAN, ByteArray &certificate, ByteArray &FirstPIN);
  /** @brief Check whether this card is enrolled (cached) on the local machine.
   */
  bool IsEnrolled();
  /** @brief Remove enrollment data for this card from the local cache. */
  bool Unenroll();
  /** @brief Check whether a card with the given PAN is enrolled locally. */
  static bool IsEnrolled(const char *szPAN);
  /** @brief Remove enrollment data for the given PAN from the local cache. */
  static bool Unenroll(const char *szPAN);
  /** @brief Display the PIN unblock icon/dialog to the user. */
  void IconaSbloccoPIN();

  /** @brief Determine the digest algorithm used in the SOD signature. */
  uint8_t GetSODDigestAlg(ByteArray &SOD);
  /** @brief Verify the SOD signature using RSA-PSS and extract hash set. */
  void VerificaSODPSS(ByteArray &SOD, std::map<uint8_t, ByteDynArray> &hashSet);
  /** @brief Verify the SOD signature and extract the data group hash set. */
  void VerificaSOD(ByteArray &SOD, std::map<uint8_t, ByteDynArray> &hashSet);

  /** @brief Progress callback invoked during long-running operations.
   *  @param progress  Percentage of completion (0-100).
   *  @param desc      Human-readable description of the current step.
   *  @param data      User-supplied context pointer (CallbackData). */
  void (*Callback)(int progress, const char *desc, void *data);
  /** @brief Opaque user data pointer passed to the Callback function. */
  void *CallbackData;

  /** @brief Remaining PUK verification attempts (set by UnblockPIN). */
  int attemptsRemaining;

  /** @brief True if Secure Messaging is currently active on this session. */
  bool ActiveSM;
  /** @brief The currently selected Dedicated File on the card. */
  CIE_DF ActiveDF;
};
