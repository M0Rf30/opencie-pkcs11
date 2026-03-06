// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file util.h
 * @brief General utility macros, error strings, and helper functions.
 *
 * Provides error message constants for PKCS#11 operations, hex data
 * conversion utilities, PKCS#1 padding functions, ISO padding helpers,
 * ASN.1 tag construction, and RAII scope-exit support.
 */

#pragma once

#include <string>

#include "util/array.h"
#include "util/definitions.h"
#include "util/log.h"

/** @name General Error Messages
 *  @{
 */
#define ERR_BAD_POINTER "Invalid pointer"
#define ERR_CANT_CREATE_MUTEX "Unable to create mutex"
#define ERR_CANT_CREATE_EVENT "Unable to create event"
/** @} */

/** @name Session Error Messages (session.cpp)
 *  @{
 */
#define ERR_SESSION_NOT_OPENED "Session not opened"
#define ERR_ADD_P11_OBJECT "Error creating P11 object"
#define ERR_GET_NEW_SESSION "Error getting new session ID"
#define ERR_CANT_GET_SESSION "Error determining session from ID"
#define ERR_SELECT_MF "Error selecting MF"
#define ERR_SELECT_GDO "Error selecting GDO"
#define ERR_PARSE_ASN "Error parsing ASN1"
#define ERR_PARSE_GDO "Error parsing GDO"
#define ERR_CANT_GET_OBJECT "Error determining object from ID"
#define ERR_CANT_READ_VALUE "Error reading attribute value"
#define ERR_CANT_WRITE_CERTIFICATE "Error writing certificate"
#define ERR_GET_ATTRIBUTE "Error extracting attribute"
#define ERR_READ_GDO "Error reading GDO"
#define ERR_CANT_ADD_SESSION "Error writing session to global map"
#define ERR_WRONG_OBJECT_TYPE "Incorrect object type"
#define ERR_UNCOMPRESS_DATA "Error decompressing data"
#define ERR_WRITE_GDO "Error writing GDO"
#define ERR_INIT_SESSION "Error initializing session"
#define ERR_INIT_TEMPLATE "Error initializing template"
#define ERR_CANT_LOGIN "Error during login"
#define ERR_RO_SESSION "Error verifying RO sessions"
#define ERR_SO_RW_SESSION "Error verifying SO R/W sessions"
#define ERR_GET_OBJECT_HANDLE "Error determining session object handle"
#define ERR_GET_NEW_OBJECT "Error getting new object ID"
#define ERR_GET_PRIVATE "Unable to determine if object is private"
#define ERR_CHECK_MECHANISM_PARAM "Error verifying mechanism parameters"
#define ERR_CANT_GET_PUBKEY_EXPONENT "Unable to read public key exponent"
#define ERR_CANT_GET_PUBKEY_LENGTH "Unable to read public key length"
#define ERR_CANT_GET_PUBKEY_MODULUS "Unable to read public key modulus"
#define ERR_PADDING "Error applying padding"
#define ERR_CRYPTO_ERROR "Error in cryptographic operation"
#define ERR_CANT_GET_PRIVKEY_LENGTH "Unable to read private key length"
#define ERR_CANT_SIGN "Unable to perform signature"
#define ERR_CANT_INITIALIZE_MECHANISM "Unable to initialize mechanism"
#define ERR_CANT_UPDATE_MECHANISM "Unable to add data to mechanism"
#define ERR_CANT_FINAL_MECHANISM "Unable to finalize mechanism"
#define ERR_CANT_GET_MECHANISM_LENGTH "Unable to find mechanism data length"
#define ERR_CANT_DECRYPT_SIGNATURE "Unable to decrypt signature"
#define ERR_CANT_GET_DIGEST_INFO "Unable to extract digestInfo"
#define ERR_CANT_GET_KEY_LENGTH "Unable to extract key length"
#define ERR_CANT_GET_DIGEST_LENGTH "Unable to extract digest length"
#define ERR_SESSION_COUNT "Error counting sessions"
#define ERR_GENERATE_RANDOM "Error generating random data"
#define ERR_FINAL_SESSION "Error closing session"
#define ERR_CANT_LOGOUT "Error during logout"
#define ERR_INIT_PIN "Error initializing PIN"
#define ERR_SET_ATTRIBUTE "Error setting attribute"
#define ERR_CREATE_OBJECT "Error creating object"
#define ERR_GET_OPERATION_STATE "Error on GetOperationState"
#define ERR_SET_OPERATION_STATE "Error on SetOperationState"
#define ERR_FIND_OBJECT "Unable to find object"
#define ERR_ENCODE_GDO "Error encoding GDO"
#define ERR_WRITE_DATA "Error writing data object"
#define ERR_CANT_DELETE_OBJECT "Error destroying object"
#define ERR_DELETE_FILE "Error deleting object from card"
#define ERR_MECHANISM_CACHE "Error in mechanism cache"
/** @} */

/** @name Token Error Messages (token.cpp)
 *  @{
 */
#define ERR_CANT_CONNECT "Unable to connect to card"
#define ERR_CANT_READ_ATR "Unable to read ATR"
#define ERR_CARD_NOT_CONNECTED "Card not connected"
#define ERR_TRANSMISSION_ERROR "Error sending APDU"
#define ERR_CANT_GET_CARD_ATTRIBUTE "Error in SCardGetAttribute"
#define ERR_READ_RECORD "Error reading record"
#define ERR_CANT_DISCONNECT "Error disconnecting from card"
#define ERR_CANT_ESTABLISH_CONTEXT "Unable to connect to smart card service"
/** @} */

/** @name Slot Error Messages (slot.cpp)
 *  @{
 */
#define ERR_GET_TEMPLATE "Error determining card template"
#define ERR_CANT_ADD_SLOT "Error writing slot to global map"
#define ERR_CANT_DELETE_SLOTLIST "Error deleting slot list"
#define ERR_CANT_GET_SLOT "Error determining slot from ID"
#define ERR_CANT_INIT_SLOTLIST "Error initializing slot list"
#define ERR_GET_NEW_SLOT "Error getting new slot ID"
#define ERR_SLOT_NOT_PRESENT "Slot not present"
#define ERR_TOKEN_PRESENT "Error verifying token presence"
#define ERR_CANT_FIND_PATH "Unable to find Path attribute"
#define ERR_CANT_WRITE_OBJECT "Unable to write object"
#define ERR_COMPRESS_DATA "Error compressing data"
#define ERR_SELECT_PATH "Unable to select DF"
#define ERR_READ_SERIAL "Unable to read card serial number"
#define ERR_SELECT_SERIAL "Unable to select card serial number"
#define ERR_CANT_CREATE_THREAD "Unable to create thread"
#define ERR_READ_MODEL "Unable to read card model"
#define ERR_DELETE_SLOT "Error deleting slot"
#define ERR_GETSLOTBYNAME "Unable to find slot by reader name"
/** @} */

/** @name P11 Object Error Messages (p11object.cpp)
 *  @{
 */
#define ERR_CANT_READ_FROM_CARD "Error reading object from card"
#define ERR_CANT_SET_VALUE "Error writing Value attribute"
#define ERR_CANT_FIND_ID "Unable to find ID attribute"
#define ERR_SELECT_EF "Unable to select EF"
#define ERR_READ_FILE "Unable to read EF"
#define ERR_CANT_READ_CERTIFICATE "Unable to read certificate"
#define ERR_ADD_ATTRIBUTE "Unable to add P11 attribute"
extern DWORD ERR_ATTRIBUTE_IS_SENSITIVE;
extern DWORD ERR_OBJECT_HASNT_ATTRIBUTE;
/** @} */

/** @name Card Template Error Messages (cardtemplate.cpp)
 *  @{
 */
#define ERR_CANT_INIT_TEMPLATES "Error initializing template list"
#define ERR_CANT_ADD_TEMPLATE "Error writing template to global list"
#define ERR_PARSE_XML_TEMPLATE "Error parsing card template XML file"
#define ERR_XML_TEMPLATE_STRUCT "Error in card template XML file structure"
#define ERR_CANT_LOAD_TEMPLATE_LIBRARY "Error loading template DLL"
#define ERR_CANT_LOAD_LIBRARY "Error loading DLL"
#define ERR_GET_LIBRARY_FUNCTION_LIST "Error loading TemplateGetFunctionList"
#define ERR_CALL_LIBRARY_FUNCTION_LIST "Error calling TemplateGetFunctionList"
#define ERR_INIT_LIBRARY "Error initializing library"
#define ERR_MATCH_CARD_TEMPLATE "Error matching card with template"
#define ERR_WRONG_TEMPLATE_DATA "Error in template parameters"
#define ERR_CANT_DELETE_TEMPLATES "Error deleting template list"
/** @} */

/** @name Card Data Error Messages (carddata.cpp)
 *  @{
 */
#define ERR_CANT_INITIALIZE_CARD_STRUCTURES \
  "Error initializing card data structures"
#define ERR_ADD_CNS_GDO "Error initializing CNS GDO"
#define ERR_CANT_FIND_PIN "Unable to find PIN object"
#define ERR_FIND_GDO_OBJECT "Error searching for GDO object"
#define ERR_VERIFY_PIN "Error verifying PIN"
#define ERR_CACHE_PIN "Error caching PIN"
#define ERR_FIND_GDO_ATTRIBUTE "Unable to find GDO object attribute value"
#define ERR_USE_PADDING "Unable to determine whether to use padding"
#define ERR_USE_SM "Unable to determine whether to use Secure Messaging"
#define ERR_GDO_TO_P11_OBJECT "Unable to create P11 object from GDO object"
#define ERR_KEY_UNSUITED "Key unsuitable for the mechanism used"
#define ERR_KEY_ALGO_UNKNOWN "Unknown key algorithm"
#define ERR_CANT_ENCRYPT_DATA "Error encrypting data"
#define ERR_PARSE_CERTIFICATE "Error parsing X509 certificate"
#define ERR_SM_KEYS_DERIVATION "Error deriving SM keys"
#define ERR_MASTER_DECYPHER "Error decrypting master keys"
#define ERR_GET_PIN "Unable to find cached PIN value"
#define ERR_SET_PIN "Unable to set cached PIN value"
#define ERR_USE_KEY "Unable to use key"
#define ERR_UI_PIN "Error in PIN request user interface"
#define ERR_UNBLOCK_PIN "Error unblocking PIN"
#define ERR_OBJECT_LABEL "Unable to find object label"
#define ERR_CANT_GET_PIN "Unable to find PIN value"
#define ERR_PIN_MAXLEN "Unable to find maximum PIN length"
#define ERR_CHANGE_PIN "Error changing PIN"
#define ERR_PIN_MINLEN "Unable to find minimum PIN length"
#define ERR_OBJECT_SIZE "Unable to find object size"
#define ERR_KEY_NOT_SECAUTH "Key is not protected with secondary authentication"
#define ERR_CHANGE_SECAUTH_PIN "Error changing secondary authentication PIN"
#define ERR_GET_SECAUTH_PIN "Unable to retrieve secondary authentication PIN"
#define ERR_SET_SECAUTH_PIN "Unable to set secondary authentication PIN"
#define ERR_UPDATE_FILE "Error updating EF"
#define ERR_WRITE_CERTIFICATE "Error writing certificate"
#define ERR_GET_TEMPLATE_ATTRIBUTE \
  "Error searching for attribute in P11 template"
#define ERR_UNBLOCK_SECAUTH_PIN "Error unblocking secondary authentication PIN"
#define ERR_UNBLOCK_CHANGE_PIN "Error changing and unblocking PIN"
#define ERR_PIN_DECRYPT "Error decrypting PIN"
#define ERR_CHECK_CERT "Error verifying empty certificate"
#define ERR_CREATE_CERTIFICATE "Error creating empty certificate"
#define ERR_NO_FREE_CERTIFICATE "Unable to find an available certificate in GDO"
#define ERR_ADD_RECORD "Unable to add record to file"
#define ERR_CHANGE_KEY_DATA "Unable to change key value"
#define ERR_CREATE_KEY "Error creating key"
#define ERR_NO_FREE_KEY "Unable to find an available key in GDO"
#define ERR_WRITE_KEY "Error writing key to card"
#define ERR_CHANGE_BSO_AC "Error changing key AC"
#define ERR_CREATE_DATA "Error creating data object"
#define ERR_CHECK_KEY "Error verifying active key"
#define ERR_ADD_BIO_GDO "Error initializing biometric GDO"
/** @} */

/** @name ASN.1 Error Messages
 *  @{
 */
#define ERR_ASN_TOINT "Unable to convert ASN value to integer"
#define ERR_ASNCOPY "Unable to copy ASN value"
#define ERR_ASN_CONTENTSIZE "Unable to find ASN TAG content length"
#define ERR_ASN_ENCODE "Unable to encode ASN structure"
#define ERR_ASN_ENCODEDSIZE "Unable to find ASN structure encoded length"
#define ERR_ASN_GETTAG "Unable to create object corresponding to ASN tag"
#define ERR_ASN_ISSEQUENCE "Unable to determine if ASN tag is a sequence"
#define ERR_ASN_LENGTH "Incorrect length in ASN structure"
/** @} */

/** @name Card Interface Error Messages (cardinterface)
 *  @{
 */
#define ERR_WRONG_PADDING_LENGTH "Error in padding buffer length"
#define ERR_CRYPTO_RSA "Error in RSA operation"
#define ERR_APDU_ENCODE "Error encoding APDU in SM"
#define ERR_CHALLENGE_LENGTH "Error in challenge length"
#define ERR_CRYPTO_DES "Error in 3DES operation"
#define ERR_CYPERTEXT_BLOCK "Error creating ciphertext block"
#define ERR_GENERATE_SW_RANDOM "Error generating random"
#define ERR_GIVE_RANDOM "Error sending random to card"
#define ERR_HEADER_BLOCK "Error creating header block"
#define ERR_MAC_BLOCK "Error creating MAC block"
#define ERR_NETLE_BLOCK "Error creating netLE block"
#define ERR_TLV "Error in TLV structure"
#define ERR_TLV_VALUE_LENGTH "Error in TLV value length"
#define ERR_DES_KEY_LENGTH "Error in DES key length"
#define ERR_CRYPTO_MAC "Error in MAC operation"
#define ERR_APDU_DECODE "Error decoding APDU in SM"
#define ERR_GET_CHALLENGE "Error in GetChallenge"
#define ERR_CANT_FIND_EF_SIZE "Unable to find EF size"
/** @} */

/** @brief Zero-fill a variable's memory. */
#define ZeroMem(var) memset(&var, 0, sizeof(var))

#ifndef _WIN32
typedef struct _SYSTEMTIME {
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
} SYSTEMTIME;
#endif

/**
 * @brief Convert a date/time string to a SYSTEMTIME structure.
 * @param dateTimeString Null-terminated date/time string.
 * @return Parsed SYSTEMTIME value.
 */
SYSTEMTIME convertStringToSystemTime(const char *dateTimeString);

/**
 * @brief Convert a single hexadecimal character to its byte value.
 * @param h Hexadecimal character ('0'-'9', 'a'-'f', 'A'-'F').
 * @return The 4-bit value (0-15).
 */
uint8_t hex2byte(char h);

/**
 * @brief Parse a hex string into a byte array.
 * @param data Hex-encoded string.
 * @param[out] ba Byte array to receive the decoded data.
 */
void readHexData(const std::string &data, ByteDynArray &ba);

/**
 * @brief Convert a single byte to a two-character hex string.
 * @param data Byte value.
 * @param uppercase If true, use uppercase hex digits.
 * @return Two-character hex string.
 */
std::string HexByte(uint8_t data, bool uppercase = true);

/**
 * @brief Dump a byte array as a hex string.
 * @param data Byte array to dump.
 * @param[out] dump String to receive the hex representation.
 * @return Reference to the dump string.
 */
std::string dumpHexData(ByteArray data, std::string &dump);

/** @overload */
std::string dumpHexData(ByteArray data, std::string &dump, bool withSpace,
                        bool uppercase = true);

/** @brief Dump a byte array as a lowercase hex string. */
std::string dumpHexDataLowerCase(ByteArray data, std::string &dump);

/** @brief Dump a byte array as a hex string (standalone). */
std::string dumpHexData(ByteArray data);

/** @name PKCS#1 Padding Functions
 *  Apply and remove PKCS#1 v1.5 block type padding.
 *  @{
 */
void PutPaddingBT0(ByteArray &ba, long dwLen);
void PutPaddingBT1(ByteArray &ba, unsigned long dwLen);
void PutPaddingBT2(ByteArray &ba, unsigned long dwLen);
unsigned long RemovePaddingBT1(ByteArray &paddedData);
unsigned long RemovePaddingBT2(ByteArray &paddedData);
unsigned long RemoveISOPad(ByteArray &paddedData);
/** @} */

/**
 * @brief Remove SHA-1 DigestInfo prefix from decrypted signature data.
 * @param paddedData Data to process.
 * @return Length of remaining data after prefix removal.
 */
unsigned long RemoveSha1(ByteArray &paddedData);

/**
 * @brief Remove SHA-256 DigestInfo prefix from decrypted signature data.
 * @param paddedData Data to process.
 * @return Length of remaining data after prefix removal.
 */
unsigned long RemoveSha256(ByteArray &paddedData);

/** @name ISO Padding Functions
 *  Apply and calculate ISO 9797-1 padding.
 *  @{
 */
unsigned long ANSIPadLen(unsigned long Len);
void ANSIPad(ByteArray &Data, unsigned long DataLen);
unsigned long ISOPadLen(unsigned long Len);
void ISOPad(const ByteArray &Data, unsigned long DataLen);
long ByteArrayToInt(ByteArray &ba);
ByteDynArray ISOPad(const ByteArray &data);
ByteDynArray ISOPad16(const ByteArray &data);
/** @} */

/**
 * @brief Get a human-readable Windows error message.
 * @param ris HRESULT error code.
 * @return Error description string.
 */
std::string WinErr(HRESULT ris);

/**
 * @brief Get a human-readable smart card error message.
 * @param dwSW Status word from the card.
 * @return Error description string.
 */
const char *CardErr(DWORD dwSW);

/**
 * @brief Get a human-readable system error message.
 * @param dwExcept System exception/error code.
 * @return Error description string.
 */
char *SystemErr(DWORD dwExcept);

/**
 * @brief Debug-print a byte array to the log.
 * @param ba Byte array to dump.
 */
void Debug(ByteArray ba);

/**
 * @brief Wrap content in an ASN.1 TLV tag.
 * @param tag ASN.1 tag number.
 * @param content Byte array with the tag content.
 * @return Encoded TLV byte array.
 */
ByteDynArray ASN1Tag(DWORD tag, ByteArray &content);

/**
 * @brief Format a string using printf-style arguments.
 * @param format printf-style format string.
 * @return Formatted string.
 */
std::string stdPrintf(const char *format, ...);

/**
 * @brief RAII scope-exit guard that invokes a callable on destruction.
 * @tparam t Callable type (typically a lambda).
 *
 * Executes the stored callable when the guard goes out of scope,
 * ensuring cleanup actions run even when exceptions are thrown.
 * The callable must be declared noexcept.
 */
template <typename t>
class scopeExitClass {
  t o;
  bool toDelete = true;

 public:
  /** @brief Construct with a callable to invoke on scope exit. */
  scopeExitClass(t in_o) : o(std::move(in_o)) {}

  /** @brief Move constructor. Disarms the source guard. */
  scopeExitClass(scopeExitClass &&se) : o(se.o) { se.toDelete = false; };
  scopeExitClass(scopeExitClass const &) = delete;

  /** @brief Destructor. Invokes the stored callable if still armed. */
  ~scopeExitClass() noexcept {
    static_assert(noexcept(o()), "lambda as noexcept.");
    if (toDelete) o();
  }
};

/**
 * @brief Create a scope-exit guard from a callable.
 * @tparam t Callable type.
 * @param o Callable to execute on scope exit (must be noexcept).
 * @return A scopeExitClass instance.
 */
template <typename t>
scopeExitClass<t> scopeExit(t o) {
  return {std::move(o)};
}
