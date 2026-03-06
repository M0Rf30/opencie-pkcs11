// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file tsa_client.h
 * @brief Time Stamp Authority (TSA) client for RFC 3161 timestamping.
 */

#pragma once

#include "asn1/time_stamp_token.h"

/**
 * HTTP client for requesting RFC 3161 time-stamp tokens from a TSA server.
 */
class CTSAClient {
 public:
  CTSAClient(void);
  virtual ~CTSAClient(void);

  /** Set the TSA server endpoint URL. */
  void SetTSAUrl(const char* szUrl);

  /**
   * Set HTTP Basic authentication credentials.
   *
   * @param szUsername  Username for TSA authentication.
   * @param szPassword  Password for TSA authentication.
   */
  void SetCredential(const char* szUsername, const char* szPassword);

  /** Set the authentication username. */
  void SetUsername(const char* szUsername);

  /** Set the authentication password. */
  void SetPassword(const char* szPassword);

  /**
   * Request a time-stamp token for the given message digest.
   *
   * @param digest            Message digest to timestamp.
   * @param szPolicyID        TSA policy OID (may be null).
   * @param ppTimeStampToken  Output pointer receiving the parsed token.
   * @return 0 on success, non-zero error code on failure.
   */
  long GetTimeStampToken(ByteDynArray& digest, const char* szPolicyID,
                         CTimeStampToken** ppTimeStampToken);

 private:
  char m_szTSAUrl[256];
  char m_szTSAUsername[256];
  char m_szTSAPassword[256];
};
