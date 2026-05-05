// SPDX-License-Identifier: LGPL-3.0-or-later
//
//  DigestInfo.c
//  CIESDK
//
//  Extracted from CIEEngine.c — make_digest_info is used by CIESigner.cpp
//  for constructing PKCS#1 DigestInfo structures.
//

#include <openssl/obj_mac.h>
#include <string.h>

// Make Digest Info
int make_digest_info(int algid, const unsigned char *pbtDigest,
                     size_t btDigestLen, unsigned char *pbtDigestInfo,
                     size_t *pbtDigestInfoLen) {
  size_t requestedLen;
  switch (algid) {
    case NID_sha1:
      requestedLen = 2 + 2 + 9 + 2 + btDigestLen;
      if (*pbtDigestInfoLen <
          requestedLen)  // buffer overflow protection before memcpy below
        return 0;

      pbtDigestInfo[0] = 0x30;
      pbtDigestInfo[1] = 2 + 9 + 2 + btDigestLen;
      pbtDigestInfo[2] = 0x30;
      pbtDigestInfo[3] = 0x09;
      pbtDigestInfo[4] = 0x06;
      pbtDigestInfo[5] = 0x05;
      pbtDigestInfo[6] = 0x2b;
      pbtDigestInfo[7] = 0x0e;
      pbtDigestInfo[8] = 0x03;
      pbtDigestInfo[9] = 0x02;
      pbtDigestInfo[10] = 0x1a;  // SHA1 02 1a
      pbtDigestInfo[11] = 0x05;
      pbtDigestInfo[12] = 0x00;
      pbtDigestInfo[13] = 0x04;
      pbtDigestInfo[14] = btDigestLen;
      // Copy the hash
      memcpy(pbtDigestInfo + 15, pbtDigest, btDigestLen);
      *pbtDigestInfoLen = 2 + 2 + 9 + 2 + btDigestLen;
      break;

    case NID_sha256:
      requestedLen = 2 + 2 + 9 + 6 + btDigestLen;
      if (*pbtDigestInfoLen <
          requestedLen)  // buffer overflow protection before memcpy below
        return 0;

      pbtDigestInfo[0] = 0x30;
      pbtDigestInfo[1] = 2 + 9 + 6 + btDigestLen;
      pbtDigestInfo[2] = 0x30;
      pbtDigestInfo[3] = 0x0D;
      pbtDigestInfo[4] = 0x06;
      pbtDigestInfo[5] = 0x09;
      pbtDigestInfo[6] = 0x60;
      pbtDigestInfo[7] = 0x86;
      pbtDigestInfo[8] = 0x48;
      pbtDigestInfo[9] = 0x01;
      pbtDigestInfo[10] = 0x65;
      pbtDigestInfo[11] = 0x03;
      pbtDigestInfo[12] = 0x04;
      pbtDigestInfo[13] = 0x02;
      pbtDigestInfo[14] = 0x01;
      pbtDigestInfo[15] = 0x05;
      pbtDigestInfo[16] = 0x00;
      pbtDigestInfo[17] = 0x04;
      pbtDigestInfo[18] = btDigestLen;
      // Copy the hash
      memcpy(pbtDigestInfo + 19, pbtDigest, btDigestLen);
      *pbtDigestInfoLen = 2 + 2 + 9 + 6 + btDigestLen;
      break;

    case NID_sha384:
      requestedLen = 2 + 2 + 9 + 6 + btDigestLen;
      if (*pbtDigestInfoLen <
          requestedLen)  // buffer overflow protection before memcpy below
        return 0;

      pbtDigestInfo[0] = 0x30;
      pbtDigestInfo[1] = 2 + 9 + 6 + btDigestLen;
      pbtDigestInfo[2] = 0x30;
      pbtDigestInfo[3] = 0x0D;
      pbtDigestInfo[4] = 0x06;
      pbtDigestInfo[5] = 0x09;
      pbtDigestInfo[6] = 0x60;
      pbtDigestInfo[7] = 0x86;
      pbtDigestInfo[8] = 0x48;
      pbtDigestInfo[9] = 0x01;
      pbtDigestInfo[10] = 0x65;
      pbtDigestInfo[11] = 0x03;
      pbtDigestInfo[12] = 0x04;
      pbtDigestInfo[13] = 0x02;
      pbtDigestInfo[14] = 0x02;
      pbtDigestInfo[15] = 0x05;
      pbtDigestInfo[16] = 0x00;
      pbtDigestInfo[17] = 0x04;
      pbtDigestInfo[18] = btDigestLen;
      // Copy the hash
      memcpy(pbtDigestInfo + 19, pbtDigest, btDigestLen);
      *pbtDigestInfoLen = 2 + 2 + 9 + 6 + btDigestLen;
      break;

    case NID_sha512:
      requestedLen = 2 + 2 + 9 + 6 + btDigestLen;
      if (*pbtDigestInfoLen <
          requestedLen)  // buffer overflow protection before memcpy below
        return 0;

      pbtDigestInfo[0] = 0x30;
      pbtDigestInfo[1] = 2 + 9 + 6 + btDigestLen;
      pbtDigestInfo[2] = 0x30;
      pbtDigestInfo[3] = 0x0D;
      pbtDigestInfo[4] = 0x06;
      pbtDigestInfo[5] = 0x09;
      pbtDigestInfo[6] = 0x60;
      pbtDigestInfo[7] = 0x86;
      pbtDigestInfo[8] = 0x48;
      pbtDigestInfo[9] = 0x01;
      pbtDigestInfo[10] = 0x65;
      pbtDigestInfo[11] = 0x03;
      pbtDigestInfo[12] = 0x04;
      pbtDigestInfo[13] = 0x02;
      pbtDigestInfo[14] = 0x03;
      pbtDigestInfo[15] = 0x05;
      pbtDigestInfo[16] = 0x00;
      pbtDigestInfo[17] = 0x04;
      pbtDigestInfo[18] = btDigestLen;
      // Copy the hash
      memcpy(pbtDigestInfo + 19, pbtDigest, btDigestLen);
      *pbtDigestInfoLen = 2 + 2 + 9 + 6 + btDigestLen;
      break;
  }
  return 1;
}
