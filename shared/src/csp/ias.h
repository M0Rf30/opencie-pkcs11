#pragma once

#include "csp/atr.h"
#include "pcsc/token.h"

#include <map>
#include <string_view>

constexpr const char* DirCIE = "CIE";
constexpr const char* EfDH = "EF.DH";
constexpr const char* EfSerial = "EF.Serial";
constexpr const char* EfIdServizi = "EF.IdServizi";
constexpr const char* EfCertCIE = "EF.CertCIE";
constexpr const char* EfSOD = "EF.SOD";
constexpr const char* EfIntAuth = "EF.IntAuth";
constexpr const char* EfIntAuthServizi = "EF.IntAuthServizi";

constexpr uint32_t FULL_PIN = 0x80000000;

extern bool switchDesktop;
extern BOOL CheckOneInstance(char *nome);
extern ByteArray baExtAuth_PrivExp;

enum class CIE_DF { Root, IAS, CIE };

enum class CIE_RequestedSM { SM, NoSM, AnySM };

class IAS {
  CIE_Type type = CIE_Type::CIE_Unknown;
  ByteDynArray dh_g, dh_p, dh_q;
  ByteDynArray sessENC, sessMAC, sessSSC;
  ByteDynArray dh_pubKey, dh_ICCpubKey;
  ByteDynArray CA_module, CA_pubexp, CA_privexp, CA_CHR, CA_CHA, CA_CAR, CA_AID;
  ByteDynArray IAS_AID;
  ByteDynArray CIE_AID;
  ByteDynArray ATR;
  ByteDynArray Certificate;
  ByteDynArray CardEncKey, CardEncIv;
  StatusWord SendAPDU(ByteArray head, ByteArray data, ByteDynArray &resp,
                      uint8_t *le = nullptr);
  StatusWord SendAPDU_SM(ByteArray head, ByteArray data, ByteDynArray &resp,
                         uint8_t *le = nullptr);
  StatusWord getResp(ByteDynArray &Cardresp, StatusWord sw, ByteDynArray &resp);
  StatusWord getResp_SM(ByteArray &Cardresp, StatusWord sw, ByteDynArray &resp);

  ByteDynArray SM(ByteArray &keyEnc, ByteArray &keySig, ByteArray &apdu,
                  ByteArray &seq);
  StatusWord respSM(ByteArray &keyEnc, ByteArray &keySig, ByteArray &apdu,
                    ByteArray &seq, ByteDynArray &elabResp);

  void readfile_SM(uint16_t id, ByteDynArray &content);
  void readfile(uint16_t id, ByteDynArray &content);

  void increment(ByteArray &seq);
  void ReadCIEType();

 public:
  CToken token;

  IAS(CToken::TokenTransmitCallback transmit, ByteArray ATR);
  ~IAS();

  void SetCardContext(void *);
  void SelectAID_IAS(bool SM = false);
  void SelectAID_CIE(bool SM = false);

  ByteDynArray PAN;
  ByteDynArray DappModule;
  ByteDynArray DappPubKey;

  void ReadPAN();
  void ReadSOD(ByteDynArray &data);

  void ReadDH(ByteDynArray &data);
  void ReadCertCIE(ByteDynArray &data);
  void ReadDappPubKey(ByteDynArray &data);
  void ReadServiziPubKey(ByteDynArray &data);
  void ReadSerialeCIE(ByteDynArray &data);
  void ReadIdServizi(ByteDynArray &data);

  void InitEncKey();
  void InitDHParam();
  void InitExtAuthKeyParam();
  void DHKeyExchange();
  void DAPP();
  StatusWord VerifyPIN(ByteArray &PIN);
  StatusWord VerifyPUK(ByteArray &PUK);
  StatusWord UnblockPIN();
  StatusWord ChangePIN(ByteArray &oldPIN, ByteArray &newPIN);
  StatusWord ChangePIN(ByteArray &newPIN);
  void Sign(ByteArray &data, ByteDynArray &signedData);
  void Deauthenticate();
  void GetCertificate(ByteDynArray &certificate, bool askEnable = true);
  void GetFirstPIN(ByteDynArray &PIN);
  void SetCache(const char *PAN, ByteArray &certificate, ByteArray &FirstPIN);
  bool IsEnrolled();
  bool Unenroll();
  static bool IsEnrolled(const char *szPAN);
  static bool Unenroll(const char *szPAN);
  void IconaSbloccoPIN();

  uint8_t GetSODDigestAlg(ByteArray &SOD);
  void VerificaSODPSS(ByteArray &SOD, std::map<uint8_t, ByteDynArray> &hashSet);
  void VerificaSOD(ByteArray &SOD, std::map<uint8_t, ByteDynArray> &hashSet);

  void (*Callback)(int progress, const char *desc, void *data);
  void *CallbackData;

  // usato da CardUnblockPin per comunicare i tentativi di verifica del PUK
  // rimasti
  int attemptsRemaining;

  bool ActiveSM;
  CIE_DF ActiveDF;
};
